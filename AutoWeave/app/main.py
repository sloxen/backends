from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

from .api import router as api_router
from .db import ensure_schema

def _split_origins(val: str) -> list[str]:
    return [o.strip() for o in (val or "").split(",") if o.strip()]

ALLOWED_ORIGINS = _split_origins(os.getenv("ALLOWED_ORIGINS", ""))

app = FastAPI(title="AutoWeave API")

@app.on_event("startup")
def _startup():
    ensure_schema()

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# IMPORTANT: prefix must match your frontend calls: /api/v1/auth/...
app.include_router(api_router, prefix="/api/v1")