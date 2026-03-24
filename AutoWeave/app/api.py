# app/api.py
from __future__ import annotations

import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, File, UploadFile
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from .services.merge import trim_aggregate_and_join
from .db import get_db
from .models import OwUser
from .auth import create_access_token, safe_decode_sub, hash_password, verify_password
from .mailer import send_email
from .delete_account import router as delete_account_router

router = APIRouter()
router.include_router(delete_account_router)

# =========================
# JWT / Security
# =========================
# Keep OAuth2PasswordBearer for compatibility (even if not currently used directly here).
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def build_frontend_url(path: str) -> str:
    # e.g. https://autoweave.sloxen.com
    base = (os.getenv("FRONTEND_BASE_URL") or "").strip().rstrip("/")
    if not base:
        # fallback: you can set FRONTEND_BASE_URL in Render env
        base = "https://autoweave.sloxen.com"
    if not path.startswith("/"):
        path = "/" + path
    return base + path


# =========================
# Pydantic Schemas
# =========================
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class ResendVerifyRequest(BaseModel):
    email: EmailStr


class VerifyRequest(BaseModel):
    token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)


class DeleteAccountRequest(BaseModel):
    # UX: user must type DELETE
    confirm: str
    password: str = Field(min_length=1, max_length=256)


# =========================
# Email helpers (edit text here)
# =========================
def email_verify_text(email: str, verify_link: str) -> str:
    return (
        f"Hi,\n\n"
        f"Thanks for creating an AutoWeave account.\n\n"
        f"Please verify your email by opening this link:\n"
        f"{verify_link}\n\n"
        f"If you did not request this, you can ignore this email.\n\n"
        f"— Sloxen™ Team\n"
    )


def email_reset_text(email: str, reset_link: str) -> str:
    return (
        f"Hi,\n\n"
        f"We received a request to reset the password for {email}.\n\n"
        f"Reset your password using this link:\n"
        f"{reset_link}\n\n"
        f"If you didn’t request this, you can ignore this email.\n\n"
        f"— Sloxen™ Team\n"
    )


# =========================
# Auth routes
# =========================
@router.post("/auth/register")
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()

    existing = db.query(OwUser).filter(OwUser.email == email).first()

    # If an active account exists, block as before
    if existing and not getattr(existing, "is_deleted", False):
        raise HTTPException(status_code=400, detail="Email already registered")

    # If a soft-deleted account exists, REACTIVATE it instead of creating a new row
    if existing and getattr(existing, "is_deleted", False):
        existing.is_deleted = False
        existing.deleted_at = None
        existing.password_hash = hash_password(payload.password)

        # force email verification again (safer)
        existing.is_verified = False
        existing.verify_hash = None
        existing.verify_expires_at = None
        existing.reset_hash = None
        existing.reset_expires_at = None

        existing.updated_at = utcnow()

        db.add(existing)
        db.commit()
        db.refresh(existing)

        verify_token = create_access_token(sub=existing.email)
        verify_link = build_frontend_url(f"/verify.html?token={verify_token}")

        send_email(
            to_email=existing.email,
            subject="Verify your AutoWeave account",
            text_body=email_verify_text(existing.email, verify_link),
        )
        return {"ok": True}

    # Otherwise: brand new user
    user = OwUser(
        email=email,
        password_hash=hash_password(payload.password),
        is_verified=False,
        verify_hash=None,
        verify_expires_at=None,
        reset_hash=None,
        reset_expires_at=None,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    verify_token = create_access_token(sub=user.email)
    verify_link = build_frontend_url(f"/verify.html?token={verify_token}")

    send_email(
        to_email=user.email,
        subject="Verify your AutoWeave account",
        text_body=email_verify_text(user.email, verify_link),
    )

    return {"ok": True}


@router.post("/auth/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = (
        db.query(OwUser)
        .filter(OwUser.email == email, OwUser.is_deleted == False)  # noqa: E712
        .first()
    )

    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not getattr(user, "is_verified", False):
        raise HTTPException(status_code=403, detail="Email not verified")

    # IMPORTANT: sub = user.id (string)
    token = create_access_token(sub=str(user.id))
    return {"access_token": token, "token_type": "bearer"}


@router.post("/auth/resend-verify")
def resend_verify(payload: ResendVerifyRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always respond ok to avoid user enumeration
    if not user:
        return {"ok": True}
    if getattr(user, "is_verified", False):
        return {"ok": True}

    verify_token = create_access_token(sub=user.email)
    verify_link = build_frontend_url(f"/verify.html?token={verify_token}")

    send_email(
        to_email=user.email,
        subject="Verify your AutoWeave account",
        text_body=email_verify_text(user.email, verify_link),
    )
    return {"ok": True}


@router.post("/auth/verify")
def verify(payload: VerifyRequest, db: Session = Depends(get_db)):
    sub = safe_decode_sub(payload.token)
    if not sub:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # verify token uses sub=email
    email = sub.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")

    user.is_verified = True
    user.updated_at = utcnow()
    db.add(user)
    db.commit()

    return {"ok": True}


@router.post("/auth/forgot")
def forgot_password(payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()

    # Always ok (avoid enumeration)
    if not user:
        return {"ok": True}

    reset_token = create_access_token(sub=user.email)  # reset by email
    reset_link = build_frontend_url(f"/reset.html?token={reset_token}")

    send_email(
        to_email=user.email,
        subject="Reset your AutoWeave password",
        text_body=email_reset_text(user.email, reset_link),
    )
    return {"ok": True}


@router.post("/auth/reset")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    sub = safe_decode_sub(payload.token)
    if not sub:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    email = sub.lower().strip()
    user = db.query(OwUser).filter(OwUser.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")

    user.password_hash = hash_password(payload.new_password)
    user.updated_at = utcnow()
    db.add(user)
    db.commit()
    return {"ok": True}


@router.post("/merge/autotrac")
async def merge_autotrac(
    time_entries_csv: UploadFile = File(...),
    incomes_csv: UploadFile = File(...),
    projects_csv: UploadFile | None = File(None),
):
    """
    Matches frontend FormData field names:
      - time_entries_csv (required)
      - incomes_csv (required)
      - projects_csv (optional)
    """
    return await trim_aggregate_and_join(time_entries_csv, incomes_csv, projects_csv)