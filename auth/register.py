from __future__ import annotations

from database.database import create_user, initialize


def register_user(username: str, password: str, role: str = "standard_user") -> tuple[bool, str]:
    """Create a new personal scanner account with a hashed password."""
    initialize()
    return create_user(username.strip(), password, "standard_user")
