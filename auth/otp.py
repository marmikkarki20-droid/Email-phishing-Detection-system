from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
import hashlib
import os
from pathlib import Path
import secrets
import smtplib


OTP_TTL_SECONDS = 300
OTP_MAX_ATTEMPTS = 5
PROJECT_DIR = Path(__file__).resolve().parents[1]
WORKSPACE_DIR = PROJECT_DIR.parent
LOCAL_SMTP_ENV_FILES = (
    WORKSPACE_DIR / ".env",
    WORKSPACE_DIR / "smtp.env",
    PROJECT_DIR / ".env",
    PROJECT_DIR / "smtp.env",
)
_LOCAL_SMTP_ENV: dict[str, str] | None = None


class OTPDeliveryError(RuntimeError):
    pass


@dataclass
class EmailOTPChallenge:
    email: str
    salt: str
    code_hash: str
    expires_at: datetime
    attempts: int = 0


def start_email_otp(email: str) -> EmailOTPChallenge:
    code = f"{secrets.randbelow(1_000_000):06d}"
    salt = secrets.token_hex(16)
    challenge = EmailOTPChallenge(
        email=email,
        salt=salt,
        code_hash=_hash_code(code, salt),
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=OTP_TTL_SECONDS),
    )
    send_otp_email(email, code)
    return challenge


def verify_email_otp(challenge: EmailOTPChallenge | None, code: str) -> tuple[bool, str]:
    if challenge is None:
        return False, "No OTP challenge is active. Please sign in again."
    if datetime.now(timezone.utc) > challenge.expires_at:
        return False, "OTP expired. Please sign in again."
    if challenge.attempts >= OTP_MAX_ATTEMPTS:
        return False, "Too many OTP attempts. Please sign in again."
    if not code.isdigit() or len(code) != 6:
        challenge.attempts += 1
        return False, "OTP must be 6 digits."

    challenge.attempts += 1
    if secrets.compare_digest(_hash_code(code, challenge.salt), challenge.code_hash):
        return True, "OTP verified."
    return False, "Invalid OTP code."


def send_otp_email(email: str, code: str) -> None:
    host = _smtp_setting("PHISHGUARD_SMTP_HOST")
    from_addr = _smtp_setting("PHISHGUARD_SMTP_FROM")
    username = _smtp_setting("PHISHGUARD_SMTP_USERNAME")
    password = _smtp_setting("PHISHGUARD_SMTP_PASSWORD", strip=False)
    try:
        port = int(_smtp_setting("PHISHGUARD_SMTP_PORT", "587"))
    except ValueError as exc:
        raise OTPDeliveryError("PHISHGUARD_SMTP_PORT must be a number, for example 587.") from exc
    use_tls = _smtp_setting("PHISHGUARD_SMTP_TLS", "1").lower() not in {"0", "false", "no"}

    if not host or not from_addr:
        raise OTPDeliveryError(
            "Email OTP is not configured.\n\n"
            "Create smtp.env beside main.py from smtp.env.example, then set "
            "PHISHGUARD_SMTP_HOST and PHISHGUARD_SMTP_FROM."
        )
    if any(_looks_like_placeholder(value) for value in (from_addr, username, password)):
        raise OTPDeliveryError(
            "SMTP settings still contain placeholder values.\n\n"
            "Open smtp.env beside main.py, remove the 'your-' text, and use a real Gmail app password."
        )

    message = EmailMessage()
    message["Subject"] = "Your PhishGuard verification code"
    message["From"] = from_addr
    message["To"] = email
    message.set_content(
        "Your PhishGuard verification code is:\n\n"
        f"{code}\n\n"
        "This code expires in 5 minutes. If you did not try to sign in, ignore this email."
    )

    try:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            if use_tls:
                smtp.starttls()
            if username:
                smtp.login(username, password)
            smtp.send_message(message)
    except smtplib.SMTPAuthenticationError as exc:
        raise OTPDeliveryError(
            "Gmail rejected the SMTP login.\n\n"
            "Make sure PHISHGUARD_SMTP_USERNAME matches the Gmail account that created "
            "the app password in smtp.env."
        ) from exc
    except OSError as exc:
        raise OTPDeliveryError(f"Could not send OTP email: {exc}") from exc
    except smtplib.SMTPException as exc:
        raise OTPDeliveryError(f"Could not send OTP email: {exc}") from exc


def _hash_code(code: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{code}".encode("utf-8")).hexdigest()


def _smtp_setting(name: str, default: str = "", *, strip: bool = True) -> str:
    value = os.getenv(name)
    if value is None:
        value = _load_local_smtp_env().get(name, default)
    return value.strip() if strip else value


def _load_local_smtp_env() -> dict[str, str]:
    global _LOCAL_SMTP_ENV
    if _LOCAL_SMTP_ENV is not None:
        return _LOCAL_SMTP_ENV

    values: dict[str, str] = {}
    for env_file in LOCAL_SMTP_ENV_FILES:
        try:
            lines = env_file.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            continue
        except OSError:
            continue

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line.removeprefix("export ").strip()
            key, separator, value = line.partition("=")
            if not separator:
                continue
            key = key.strip()
            if key.startswith("PHISHGUARD_SMTP_"):
                values[key] = _clean_env_value(value)

    _LOCAL_SMTP_ENV = values
    return values


def _clean_env_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _looks_like_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    return normalized.startswith("your-") or normalized in {
        "your-email@gmail.com",
        "your-gmail-app-password",
        "your-real-gmail-app-password",
        "the-16-character-password-from-google",
    }
