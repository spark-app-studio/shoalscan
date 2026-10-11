"""Named dashboard users: personal tokens, single-use invites, two roles, and an audit.

Users live in their own SQLite database in the dashboard's state directory
(`users.sqlite3`, mode 0600), next to the TLS key, and not in the history
database: `shoalscan record` writes the history, often from CI, and whoever
can write it must not be able to make themselves an admin.

- A user is made by an admin, on the command line or the dashboard, and
  gets a single-use invite that expires after 24 hours. The invite code is
  256 bits; only its SHA-256 is stored.
- Opening the invite gives the user their own 256-bit token, shown once to
  them and never to the admin. Only its SHA-256 is stored. A lost token
  means a new invite.
- Roles: an admin manages users, the Configuration page and scans; a member
  reads everything and reviews findings.
- Disabling a user, inviting them again or changing their role takes
  effect on their next request: sessions carry a credential version and are
  checked against this database every time.
- There is always at least one active admin: the last one cannot be
  disabled or made a member. The command line can always add an admin, so
  losing every token is never a lock-out.
- Every change is kept in `user_events`, with who made it and when.
"""

from __future__ import annotations

import hmac
import os
import re
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from shoalscan.dashboard.auth import MAX_SECRET_CHARS, sha256_hex
from shoalscan.errors import SetupError

USERS_FILE = "users.sqlite3"
ROLES = ("admin", "member")
INVITE_HOURS = 24
_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
# Compared against when a name is unknown, so a miss takes as long as a wrong token.
_DUMMY = sha256_hex("no such user")

MIGRATIONS: tuple[str, ...] = (
    # 1: users and the record of every change to them.
    """
    CREATE TABLE users (
        name TEXT PRIMARY KEY,
        role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
        token_sha256 TEXT,
        invite_sha256 TEXT UNIQUE,
        invite_expires_at TEXT,
        disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
        credential_version INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        created_by TEXT NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE user_events (
        id INTEGER PRIMARY KEY,
        at TEXT NOT NULL,
        who TEXT NOT NULL,
        user TEXT NOT NULL,
        action TEXT NOT NULL CHECK (action IN ('invite', 'join', 'reinvite', 'disable', 'enable', 'role')),
        detail TEXT NOT NULL DEFAULT ''
    );
    """,
)
SCHEMA_VERSION = len(MIGRATIONS)


@dataclass(frozen=True)
class User:
    name: str
    role: str
    credential_version: int


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_name(name: object) -> str:
    if not isinstance(name, str) or not _NAME.match(name):
        raise SetupError("a user name is 1 to 64 lowercase letters, digits, dots, dashes or underscores")
    return name


def validate_role(role: object) -> str:
    if role not in ROLES:
        raise SetupError(f"the role must be one of {', '.join(ROLES)}")
    return role


def open_users(state_dir: Path) -> sqlite3.Connection:
    """Open (creating if needed) the users database, private to this account."""
    path = state_dir / USERS_FILE
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    old = os.umask(0o077)
    try:
        conn = sqlite3.connect(str(path), timeout=30, isolation_level=None)
    finally:
        os.umask(old)
    try:
        conn.execute("PRAGMA busy_timeout = 30000")
        found = conn.execute("PRAGMA user_version").fetchone()[0]
        if found > SCHEMA_VERSION:
            raise SetupError(f"{path} is newer than this Shoalscan understands; upgrade Shoalscan")
        for version in range(found, SCHEMA_VERSION):
            conn.executescript(
                f"BEGIN IMMEDIATE;\n{MIGRATIONS[version]}\nPRAGMA user_version = {version + 1};\nCOMMIT;"
            )
        os.chmod(path, 0o600)
    except BaseException:
        conn.close()
        raise
    return conn


def _event(conn: sqlite3.Connection, who: str, user: str, action: str, detail: str = "") -> None:
    conn.execute(
        "INSERT INTO user_events (at, who, user, action, detail) VALUES (?, ?, ?, ?, ?)",
        (_stamp(_now()), who[:100], user, action, detail[:300]),
    )


def _new_invite(conn: sqlite3.Connection, name: str) -> tuple[str, str]:
    code = secrets.token_urlsafe(32)
    expires = _stamp(_now() + timedelta(hours=INVITE_HOURS))
    conn.execute(
        "UPDATE users SET invite_sha256 = ?, invite_expires_at = ? WHERE name = ?", (sha256_hex(code), expires, name)
    )
    return code, expires


def _active_admins(conn: sqlite3.Connection) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND token_sha256 IS NOT NULL"
    ).fetchone()[0]


def has_active_users(conn: sqlite3.Connection) -> bool:
    """True once anyone has joined. From then on, the shared legacy token no longer signs in."""
    return (
        conn.execute("SELECT 1 FROM users WHERE disabled = 0 AND token_sha256 IS NOT NULL LIMIT 1").fetchone()
        is not None
    )


# ------------------------------------------------------------------ changes


def add_user(conn: sqlite3.Connection, name: str, role: str, who: str) -> tuple[str, str]:
    """Make a user who has not joined yet. Returns their invite code and when it expires."""
    name, role = validate_name(name), validate_role(role)
    conn.execute("BEGIN IMMEDIATE")
    try:
        if conn.execute("SELECT 1 FROM users WHERE name = ?", (name,)).fetchone():
            raise SetupError(f"there is already a user named {name}")
        conn.execute(
            "INSERT INTO users (name, role, created_at, created_by) VALUES (?, ?, ?, ?)",
            (name, role, _stamp(_now()), who[:100]),
        )
        code, expires = _new_invite(conn, name)
        _event(conn, who, name, "invite", f"role {role}")
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return code, expires


def reinvite(conn: sqlite3.Connection, name: str, who: str) -> tuple[str, str]:
    """A new invite. The user's token stops working at once, and so do their sessions."""
    name = validate_name(name)
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT role, disabled FROM users WHERE name = ?", (name,)).fetchone()
        if row is None:
            raise SetupError(f"there is no user named {name}")
        if row[0] == "admin" and not row[1] and _active_admins(conn) == 1 and _has_token(conn, name):
            raise SetupError(f"{name} is the only active admin; add another admin first")
        conn.execute(
            "UPDATE users SET token_sha256 = NULL, credential_version = credential_version + 1 WHERE name = ?", (name,)
        )
        code, expires = _new_invite(conn, name)
        _event(conn, who, name, "reinvite")
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return code, expires


def _has_token(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT token_sha256 IS NOT NULL FROM users WHERE name = ?", (name,)).fetchone()[0] == 1


def redeem(conn: sqlite3.Connection, code: str) -> tuple[str, str] | None:
    """Use an invite: returns (name, the user's new token), or None for an unknown, used or expired code."""
    if not isinstance(code, str) or not code or len(code) > MAX_SECRET_CHARS:
        return None
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT name, invite_sha256, invite_expires_at, disabled FROM users WHERE invite_sha256 = ?",
            (sha256_hex(code),),
        ).fetchone()
        if row is None or not hmac.compare_digest(row[1], sha256_hex(code)) or row[3] or row[2] < _stamp(_now()):
            conn.execute("ROLLBACK")
            return None
        token = secrets.token_urlsafe(32)
        conn.execute(
            "UPDATE users SET token_sha256 = ?, invite_sha256 = NULL, invite_expires_at = NULL, "
            "credential_version = credential_version + 1 WHERE name = ?",
            (sha256_hex(token), row[0]),
        )
        _event(conn, row[0], row[0], "join")
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return row[0], token


def set_disabled(conn: sqlite3.Connection, name: str, disabled: bool, who: str) -> None:
    name = validate_name(name)
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT role, disabled FROM users WHERE name = ?", (name,)).fetchone()
        if row is None:
            raise SetupError(f"there is no user named {name}")
        if disabled and row[0] == "admin" and not row[1] and _active_admins(conn) == 1 and _has_token(conn, name):
            raise SetupError(f"{name} is the only active admin; add another admin first")
        conn.execute(
            "UPDATE users SET disabled = ?, credential_version = credential_version + 1 WHERE name = ?",
            (1 if disabled else 0, name),
        )
        _event(conn, who, name, "disable" if disabled else "enable")
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def set_role(conn: sqlite3.Connection, name: str, role: str, who: str) -> None:
    name, role = validate_name(name), validate_role(role)
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT role, disabled FROM users WHERE name = ?", (name,)).fetchone()
        if row is None:
            raise SetupError(f"there is no user named {name}")
        if (
            row[0] == "admin"
            and role != "admin"
            and not row[1]
            and _active_admins(conn) == 1
            and _has_token(conn, name)
        ):
            raise SetupError(f"{name} is the only active admin; add another admin first")
        conn.execute("UPDATE users SET role = ? WHERE name = ?", (role, name))
        _event(conn, who, name, "role", f"{row[0]} to {role}")
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


# ------------------------------------------------------------------ reading


def check(conn: sqlite3.Connection, name: str, token: str) -> User | None:
    """The user with this name and token, if they are active. Takes as long for an unknown name."""
    if not isinstance(name, str) or not isinstance(token, str) or not token or len(token) > MAX_SECRET_CHARS:
        return None
    row = conn.execute(
        "SELECT name, role, token_sha256, disabled, credential_version FROM users WHERE name = ?", (name,)
    ).fetchone()
    stored = row[2] if row is not None and row[2] else _DUMMY
    ok = hmac.compare_digest(sha256_hex(token), stored)
    if not ok or row is None or row[3] or not row[2]:
        return None
    return User(row[0], row[1], row[4])


def current(conn: sqlite3.Connection, name: str, credential_version: int) -> User | None:
    """The user a session belongs to, if it is still valid: active, and with the same credentials."""
    row = conn.execute(
        "SELECT name, role, disabled, credential_version, token_sha256 FROM users WHERE name = ?", (name,)
    ).fetchone()
    if row is None or row[2] or row[3] != credential_version or not row[4]:
        return None
    return User(row[0], row[1], row[3])


def list_users(conn: sqlite3.Connection) -> list[dict]:
    now = _stamp(_now())
    out = []
    for name, role, token, invite_expires, disabled, created_at, created_by in conn.execute(
        "SELECT name, role, token_sha256 IS NOT NULL, invite_expires_at, disabled, created_at, created_by FROM users "
        "ORDER BY name"
    ):
        if disabled:
            status = "disabled"
        elif token:
            status = "active"
        elif invite_expires and invite_expires >= now:
            status = "invited"
        else:
            status = "invite expired"
        out.append(
            {
                "name": name,
                "role": role,
                "status": status,
                "invite_expires_at": invite_expires if status == "invited" else None,
                "created_at": created_at,
                "created_by": created_by,
            }
        )
    return out


def events(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    rows = conn.execute(
        "SELECT at, who, user, action, detail FROM user_events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [{"at": a, "who": w, "user": u, "action": act, "detail": d} for a, w, u, act, d in rows]
