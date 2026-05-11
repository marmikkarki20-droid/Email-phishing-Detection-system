from __future__ import annotations

from database.database import authenticate_user, initialize


def login_user(username: str, password: str) -> tuple[bool, dict | None, str]:
    """Authenticate username/password against the secure storage backend."""
    initialize()

    row = authenticate_user(username.strip(), password)
    if not row:
        return False, None, "Invalid username or password"

    return True, dict(row), "Password authentication successful"
