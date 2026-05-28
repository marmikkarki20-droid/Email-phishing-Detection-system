from __future__ import annotations

from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
import sqlite3
from pathlib import Path
from typing import Any

import bcrypt

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "reports"

DB_PATH = DATA_DIR / "phishguard.db"

SESSION_TIMEOUT_SECONDS = 900
ADMIN_ROLE = "admin"
STANDARD_USER_ROLE = "standard_user"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def _managed_connection():
    with closing(_connect()) as conn:
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def initialize() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    _init_db()
    _remove_legacy_demo_accounts()
    _seed_default_users()


def _init_db() -> None:
    with _managed_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
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
    _ensure_initial_admin()


def _ensure_initial_admin() -> None:
    promoted_username: str | None = None
    with _managed_connection() as conn:
        if _has_admin(conn):
            return

        first_user = conn.execute(
            """
            SELECT username
            FROM users
            WHERE is_active = 1
            ORDER BY id ASC
            LIMIT 1
            """
        ).fetchone()
        if not first_user:
            return

        promoted_username = first_user["username"]
        conn.execute(
            "UPDATE users SET role = ? WHERE username = ?",
            (ADMIN_ROLE, promoted_username),
        )

    log_event(promoted_username, "ADMIN_BOOTSTRAP", "SUCCESS", "First local account promoted to admin")


def _has_admin(conn: sqlite3.Connection) -> bool:
    return bool(
        conn.execute(
            "SELECT 1 FROM users WHERE role = ? AND is_active = 1 LIMIT 1",
            (ADMIN_ROLE,),
        ).fetchone()
    )


def _remove_legacy_demo_accounts() -> None:
    with _managed_connection() as conn:
        conn.execute("DELETE FROM users WHERE username IN ('admin', 'analyst', 'user', 'demo@phishguard.local')")


def _users_table_has_column(conn: sqlite3.Connection, column_name: str) -> bool:
    columns = conn.execute("PRAGMA table_info(users)").fetchall()
    return any(column["name"] == column_name for column in columns)


def _insert_user(conn: sqlite3.Connection, username: str, password: str, role: str) -> None:
    if _users_table_has_column(conn, "totp_secret_enc"):
        conn.execute(
            """
            INSERT INTO users (username, password_hash, role, totp_secret_enc, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, hash_password(password), role, "", _now()),
        )
        return

    conn.execute(
        """
        INSERT INTO users (username, password_hash, role, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (username, hash_password(password), role, _now()),
    )


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def log_event(username: str | None, event_type: str, status: str, details: str) -> None:
    with _managed_connection() as conn:
        conn.execute(
            """
            INSERT INTO security_events (username, event_type, status, details, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, event_type, status, details, _now()),
        )


def authenticate_user(username: str, password: str) -> dict[str, Any] | None:
    with _managed_connection() as conn:
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


def create_user(username: str, password: str, role: str) -> tuple[bool, str]:
    role = role if role in {ADMIN_ROLE, STANDARD_USER_ROLE} else STANDARD_USER_ROLE
    if len(password) < 8:
        return False, "Password must be at least 8 characters"

    with _managed_connection() as conn:
        exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            return False, "Username already exists"

        if not _has_admin(conn):
            role = ADMIN_ROLE
        elif role == ADMIN_ROLE:
            role = STANDARD_USER_ROLE

        _insert_user(conn, username, password, role)
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
    with _managed_connection() as conn:
        conn.execute(
            """
            INSERT INTO scans (username, score, risk_level, mode, indicator_count, summary, email_excerpt, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (username, score, risk_level, mode, indicator_count, summary, excerpt, _now()),
        )


def list_recent_scans(limit: int = 40, username: str | None = None) -> list[dict[str, Any]]:
    with _managed_connection() as conn:
        if username:
            rows = conn.execute(
                """
                SELECT username, score, risk_level, mode, indicator_count, created_at
                FROM scans
                WHERE username = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (username, limit),
            ).fetchall()
        else:
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
    with _managed_connection() as conn:
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
    with _managed_connection() as conn:
        conn.execute("SELECT 1")
    return True
