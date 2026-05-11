from __future__ import annotations

from database.database import create_user, initialize


VALID_ROLES = {"admin", "security_analyst", "standard_user"}


def register_user(username: str, password: str, role: str = "standard_user") -> tuple[bool, str]:
    """Create a new user with hashed password and encrypted TOTP secret."""
    role = role.strip().lower()
    if role not in VALID_ROLES:
        return False, "Role must be admin, security_analyst, or standard_user"

    initialize()
    return create_user(username.strip(), password, role)
