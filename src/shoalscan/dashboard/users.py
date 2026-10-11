"""Who may use the dashboard: people who sign in through the OpenID Connect provider.

The provider proves who someone is; this database decides what they may do.

- An admin is anyone whose ID token carries the admin claim (by default the
  `shoal-admin` group). The role comes from the provider at every sign-in:
  remove someone from the group there and their next sign-in is a member's,
  or is refused.
- Anyone else is refused unless an admin has allowed their email address;
  they are then a member, who reads everything and reviews findings.
- Only verified email addresses count. On someone's first sign-in their
  address is bound to the provider's subject for them, so a later account
  that reuses the address is refused.
- An admin can disable anyone but themselves, admins included; a disabled
  person is refused even with the admin claim. Sessions are checked against
  this database on every request, so a change takes effect at once.
- Every change, and every first sign-in, is kept in `user_events`.

The database is `users.sqlite3` in the dashboard's state directory (mode
0600), apart from the history database, which `shoalscan record` writes,
often from CI: nothing that can write the history can let someone in.
"""

from __future__ import annotations

import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from shoalscan.errors import SetupError

USERS_FILE = "users.sqlite3"
_EMAIL = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,190}\.?[A-Za-z0-9-]*$")

MIGRATIONS: tuple[str, ...] = (
    # 1: personal tokens and invites (an unreleased build; replaced by 2).
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
    # 2: sign-in through an OpenID Connect provider. People are kept by verified email.
    """
    DROP TABLE users;
    DROP TABLE user_events;
    CREATE TABLE users (
        email TEXT PRIMARY KEY,
        allowed INTEGER NOT NULL DEFAULT 0 CHECK (allowed IN (0, 1)),
        disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
        subject TEXT,
        last_role TEXT CHECK (last_role IN ('admin', 'member')),
        last_login_at TEXT,
        added_at TEXT NOT NULL,
        added_by TEXT NOT NULL,
        version INTEGER NOT NULL DEFAULT 0
    ) WITHOUT ROWID;
    CREATE TABLE user_events (
        id INTEGER PRIMARY KEY,
        at TEXT NOT NULL,
        who TEXT NOT NULL,
        user TEXT NOT NULL,
        action TEXT NOT NULL CHECK (action IN ('allow', 'disallow', 'disable', 'enable', 'first-login')),
        detail TEXT NOT NULL DEFAULT ''
    );
    """,
)
SCHEMA_VERSION = len(MIGRATIONS)


@dataclass(frozen=True)
class User:
    email: str
    role: str
    version: int


class SignInRefusedError(Exception):
    """Someone signed in at the provider but may not use the dashboard. `code` names why, for the login page."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalise_email(email: object) -> str:
    if not isinstance(email, str) or not _EMAIL.match(email.strip()) or len(email) > 254:
        raise SetupError(f"not an email address: {str(email)[:80]!r}")
    return email.strip().lower()


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
        (_now(), who[:254], user, action, detail[:300]),
    )


def _transaction(conn: sqlite3.Connection, work):
    conn.execute("BEGIN IMMEDIATE")
    try:
        result = work()
        conn.execute("COMMIT")
        return result
    except BaseException:
        conn.execute("ROLLBACK")
        raise


# ------------------------------------------------------------------ signing in


def sign_in(conn: sqlite3.Connection, claims: dict, admin: bool) -> User:
    """Decide whether the person behind checked ID token claims may use the dashboard, and as what."""
    email, subject = claims.get("email"), claims.get("sub")
    if claims.get("email_verified") is not True:
        raise SignInRefusedError("unverified", "your identity provider did not confirm your email address")
    try:
        email = normalise_email(email)
    except SetupError:
        raise SignInRefusedError("no_email", "your identity provider sent no usable email address") from None

    def work() -> User:
        row = conn.execute("SELECT allowed, disabled, subject, version FROM users WHERE email = ?", (email,)).fetchone()
        if row is not None and row[1]:
            raise SignInRefusedError("disabled", f"{email} is disabled on this dashboard")
        if row is not None and row[2] is not None and row[2] != subject:
            raise SignInRefusedError("other_account", f"{email} belongs to another account at your identity provider")
        if not admin and (row is None or not row[0]):
            raise SignInRefusedError(
                "not_allowed", f"{email} has not been given access to this dashboard; ask an admin"
            )
        role = "admin" if admin else "member"
        if row is None:
            conn.execute(
                "INSERT INTO users (email, subject, last_role, last_login_at, added_at, added_by) VALUES (?, ?, ?, ?, "
                "?, ?)",
                (email, subject, role, _now(), _now(), "identity provider"),
            )
            _event(conn, email, email, "first-login", f"as {role}")
            version = 0
        else:
            if row[2] is None:
                _event(conn, email, email, "first-login", f"as {role}")
            conn.execute(
                "UPDATE users SET subject = ?, last_role = ?, last_login_at = ? WHERE email = ?",
                (subject, role, _now(), email),
            )
            version = row[3]
        return User(email, role, version)

    return _transaction(conn, work)


def current(conn: sqlite3.Connection, email: str, role: str, version: int) -> bool:
    """Does a session still hold? Its person must not be disabled or changed since,
    and a member must still be allowed."""
    row = conn.execute("SELECT allowed, disabled, version FROM users WHERE email = ?", (email,)).fetchone()
    return row is not None and not row[1] and row[2] == version and (role == "admin" or bool(row[0]))


def has_admin(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM users WHERE last_role = 'admin' AND disabled = 0 LIMIT 1").fetchone() is not None


# ------------------------------------------------------------------ changes by admins


def allow(conn: sqlite3.Connection, email: str, who: str) -> None:
    """Let someone in as a member. Their first sign-in binds the address to their account at the provider."""
    email = normalise_email(email)

    def work() -> None:
        row = conn.execute("SELECT allowed FROM users WHERE email = ?", (email,)).fetchone()
        if row is not None and row[0]:
            raise SetupError(f"{email} is already allowed")
        if row is None:
            conn.execute(
                "INSERT INTO users (email, allowed, added_at, added_by) VALUES (?, 1, ?, ?)", (email, _now(), who[:254])
            )
        else:
            conn.execute("UPDATE users SET allowed = 1, version = version + 1 WHERE email = ?", (email,))
        _event(conn, who, email, "allow")

    _transaction(conn, work)


def disallow(conn: sqlite3.Connection, email: str, who: str) -> None:
    """Take back a member's access. (An admin's comes from the provider; disable them instead.)"""
    email = normalise_email(email)

    def work() -> None:
        if (
            conn.execute(
                "UPDATE users SET allowed = 0, version = version + 1 WHERE email = ? AND allowed = 1", (email,)
            ).rowcount
            == 0
        ):
            raise SetupError(f"{email} is not on the list of allowed people")
        _event(conn, who, email, "disallow")

    _transaction(conn, work)


def set_disabled(conn: sqlite3.Connection, email: str, disabled: bool, who: str) -> None:
    email = normalise_email(email)
    if disabled and email == who:
        raise SetupError("ask another admin to disable your own account")

    def work() -> None:
        if (
            conn.execute(
                "UPDATE users SET disabled = ?, version = version + 1 WHERE email = ?", (1 if disabled else 0, email)
            ).rowcount
            == 0
        ):
            raise SetupError(f"there is no one with the address {email}")
        _event(conn, who, email, "disable" if disabled else "enable")

    _transaction(conn, work)


# ------------------------------------------------------------------ reading


def list_users(conn: sqlite3.Connection) -> list[dict]:
    out = []
    for email, allowed, disabled, subject, role, last_login, added_at, added_by in conn.execute(
        "SELECT email, allowed, disabled, subject, last_role, last_login_at, added_at, added_by FROM users ORDER BY "
        "email"
    ):
        if disabled:
            status = "disabled"
        elif role == "admin":
            status = "admin (from the identity provider)"
        elif allowed:
            status = "allowed" if subject else "allowed, not signed in yet"
        else:
            status = "no access"
        out.append(
            {
                "email": email,
                "allowed": bool(allowed),
                "disabled": bool(disabled),
                "role": role,
                "status": status,
                "last_login_at": last_login,
                "added_at": added_at,
                "added_by": added_by,
            }
        )
    return out


def events(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    rows = conn.execute(
        "SELECT at, who, user, action, detail FROM user_events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [{"at": a, "who": w, "user": u, "action": act, "detail": d} for a, w, u, act, d in rows]
