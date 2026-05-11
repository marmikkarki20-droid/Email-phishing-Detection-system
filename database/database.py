from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sqlite3
from pathlib import Path
from typing import Any

import bcrypt
from cryptography.fernet import Fernet
import pyotp

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "reports"

DB_PATH = DATA_DIR / "phishguard.db"
SECRET_KEY_PATH = DATA_DIR / "secret.key"

SESSION_TIMEOUT_SECONDS = 900

_FERNET: Fernet | None = None


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_or_create_key() -> bytes:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if SECRET_KEY_PATH.exists():
        return SECRET_KEY_PATH.read_bytes()
    key = Fernet.generate_key()
    SECRET_KEY_PATH.write_bytes(key)
    return key


def _fernet() -> Fernet:
    global _FERNET
    if _FERNET is None:
        _FERNET = Fernet(_load_or_create_key())
    return _FERNET


def _encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def _decrypt(value: str) -> str:
    return _fernet().decrypt(value.encode("utf-8")).decode("utf-8")


def initialize() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    _load_or_create_key()
    _init_db()
    _seed_default_users()


def _init_db() -> None:
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                totp_secret_enc TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                mode TEXT NOT NULL,
                indicator_count INTEGER NOT NULL,
                summary TEXT NOT NULL,
                email_excerpt TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                event_type TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


def _seed_default_users() -> None:
    defaults = [
        ("admin", "Admin@123", "admin"),
        ("analyst", "Analyst@123", "security_analyst"),
        ("user", "User@123", "standard_user"),
    ]
    with _connect() as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if count > 0:
            return

        for username, password, role in defaults:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, role, totp_secret_enc, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    username,
                    hash_password(password),
                    role,
                    _encrypt(pyotp.random_base32()),
                    _now(),
                ),
            )
            conn.execute(
                """
                INSERT INTO security_events (username, event_type, status, details, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, "ACCOUNT_SEEDED", "SUCCESS", f"Created default {role} account", _now()),
            )


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def log_event(username: str | None, event_type: str, status: str, details: str) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO security_events (username, event_type, status, details, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, event_type, status, details, _now()),
        )


def authenticate_user(username: str, password: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username,),
        ).fetchone()

    if not row:
        log_event(username, "LOGIN", "FAIL", "Unknown username")
        return None

    if not verify_password(password, row["password_hash"]):
        log_event(username, "LOGIN", "FAIL", "Invalid password")
        return None

    log_event(username, "LOGIN", "SUCCESS", "Password authentication passed")
    return dict(row)


def verify_user_otp(username: str, code: str) -> tuple[bool, str]:
    with _connect() as conn:
        row = conn.execute(
            "SELECT totp_secret_enc FROM users WHERE username = ? AND is_active = 1",
            (username,),
        ).fetchone()

    if not row:
        log_event(username, "OTP", "FAIL", "User not found")
        return False, "User not found"

    if not code.isdigit() or len(code) != 6:
        log_event(username, "OTP", "FAIL", "Invalid OTP format")
        return False, "OTP must be 6 digits"

    secret = _decrypt(row["totp_secret_enc"])
    valid = bool(pyotp.TOTP(secret).verify(code, valid_window=1))
    if not valid:
        log_event(username, "OTP", "FAIL", "OTP verification failed")
        return False, "Invalid OTP"

    log_event(username, "OTP", "SUCCESS", "2FA verification passed")
    return True, "OTP verified"


def get_demo_otp(username: str) -> str | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT totp_secret_enc FROM users WHERE username = ? AND is_active = 1",
            (username,),
        ).fetchone()
    if not row:
        return None
    secret = _decrypt(row["totp_secret_enc"])
    return pyotp.TOTP(secret).now()


def create_user(username: str, password: str, role: str) -> tuple[bool, str]:
    if role not in {"admin", "security_analyst", "standard_user"}:
        return False, "Invalid role"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"

    with _connect() as conn:
        exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            return False, "Username already exists"

        conn.execute(
            """
            INSERT INTO users (username, password_hash, role, totp_secret_enc, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, hash_password(password), role, _encrypt(pyotp.random_base32()), _now()),
        )
    log_event(username, "USER_CREATE", "SUCCESS", f"Created user with role {role}")
    return True, "User created successfully"


def build_session(username: str, role: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        "username": username,
        "role": role,
        "started_at": now,
        "expires_at": now + timedelta(seconds=SESSION_TIMEOUT_SECONDS),
    }


def session_expired(session: dict[str, Any] | None) -> bool:
    if not session:
        return True
    return datetime.now(timezone.utc) >= session["expires_at"]


def save_scan(
    username: str,
    score: int,
    risk_level: str,
    mode: str,
    indicator_count: int,
    summary: str,
    email_text: str,
) -> None:
    excerpt = email_text.replace("\n", " ").strip()[:220]
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO scans (username, score, risk_level, mode, indicator_count, summary, email_excerpt, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (username, score, risk_level, mode, indicator_count, summary, excerpt, _now()),
        )


def list_recent_scans(limit: int = 40) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT username, score, risk_level, mode, indicator_count, created_at
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def list_security_events(limit: int = 80) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT username, event_type, status, details, created_at
            FROM security_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_connection() -> sqlite3.Connection:
    """Return direct SQLite connection used by PhishGuard."""
    initialize()
    return _connect()


def health_check() -> bool:
    """Simple DB check for demos and deployment validation."""
    initialize()
    with get_connection() as conn:
        conn.execute("SELECT 1")
    return True
