from __future__ import annotations

from database.database import get_demo_otp as _db_get_demo_otp
from database.database import initialize, verify_user_otp


def verify_otp(username: str, code: str) -> tuple[bool, str]:
    """Validate a 6-digit OTP for the given username."""
    initialize()
    return verify_user_otp(username.strip(), code.strip())


def get_demo_otp(username: str) -> str | None:
    """Return the current TOTP code for demo flow testing."""
    initialize()
    return _db_get_demo_otp(username.strip())
