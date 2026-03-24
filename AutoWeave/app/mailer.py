import os
import smtplib
from email.message import EmailMessage


def send_email(to_email: str, subject: str, text_body: str) -> None:
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_pass = os.getenv("SMTP_PASS", "").strip()

    email_from = (os.getenv("EMAIL_FROM") or smtp_user).strip()
    from_name = os.getenv("EMAIL_FROM_NAME", "Sloxen™").strip()

    if not (smtp_host and smtp_user and smtp_pass and email_from):
        raise RuntimeError("SMTP env vars not fully set (SMTP_HOST/PORT/USER/PASS, EMAIL_FROM).")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{email_from}>"
    msg["To"] = to_email
    msg.set_content(text_body)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as s:
        s.ehlo()
        s.starttls()
        s.ehlo()
        s.login(smtp_user, smtp_pass)
        s.send_message(msg)
