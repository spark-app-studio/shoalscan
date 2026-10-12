"""Sessions, CSRF tokens, same-origin checks and the sign-in rate limit.

People sign in through an OpenID Connect provider (see `oidc` and `users`).
Sessions live in memory only, keyed by the SHA-256 of the cookie value;
every request checks a session against the users database, so it ends at
once when its person is disabled or loses access. An admin's role comes from
the provider's admin claim at sign-in, so admin sessions are kept short
(ADMIN_SESSION_MAX_SECONDS): taking someone out of the admin group at the
provider takes effect when their admin session runs out at the latest.
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import os
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

COOKIE_NAME = "__Host-shoalscan"
SESSION_IDLE_SECONDS = 8 * 3600
SESSION_MAX_SECONDS = 7 * 24 * 3600
# An admin signs in again after this long, which reads the admin claim again.
ADMIN_SESSION_MAX_SECONDS = 3600
MAX_SESSIONS = 100
# One person's sessions; past this, signing in again ends that person's oldest session.
MAX_SESSIONS_PER_USER = 10
MAX_SECRET_CHARS = 128


def session_lifetime(role: str) -> int:
    """How long a session may last at most, whatever its use."""
    return ADMIN_SESSION_MAX_SECONDS if role == "admin" else SESSION_MAX_SECONDS


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def write_private_file(path: Path, text: str) -> None:
    """Write a file atomically with mode 0600; it is never readable by others, even briefly."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


@dataclass
class Session:
    created: float
    last_used: float
    csrf: str
    tag: str = ""  # short and not secret: tells sessions apart in logs
    user: str | None = None  # the person's verified email address
    role: str = "member"
    credential_version: int = 0

    @property
    def who(self) -> str:
        """The name the audit records."""
        return self.user if self.user else f"dashboard user (session {self.tag})"


class Sessions:
    """`validate(session)` decides on every request whether a session still holds, and may update its role."""

    def __init__(self, validate: Callable[[Session], bool]):
        self.validate = validate
        self._lock = threading.Lock()
        self._items: dict[str, Session] = {}

    def create(self, user: str, role: str, credential_version: int) -> str:
        """A new session for `user`. A person over MAX_SESSIONS_PER_USER loses their own oldest session; only
        when every person is within that cap and the dashboard holds MAX_SESSIONS does the least recently used
        session of anyone go."""
        sid = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            for key in [k for k, v in self._items.items() if self._expired(v, now)]:
                del self._items[key]
            mine = sorted((k for k, v in self._items.items() if v.user == user), key=lambda k: self._items[k].created)
            for key in mine[: max(0, len(mine) - MAX_SESSIONS_PER_USER + 1)]:
                del self._items[key]
            if len(self._items) >= MAX_SESSIONS:
                oldest = min(self._items, key=lambda k: self._items[k].last_used)
                del self._items[oldest]
            self._items[sha256_hex(sid)] = Session(
                now, now, secrets.token_urlsafe(32), secrets.token_hex(4), user, role, credential_version
            )
        return sid

    @staticmethod
    def _expired(session: Session, now: float) -> bool:
        return now - session.last_used > SESSION_IDLE_SECONDS or now - session.created > session_lifetime(session.role)

    def get(self, sid: str | None) -> Session | None:
        if not sid or len(sid) > MAX_SECRET_CHARS:
            return None
        key = sha256_hex(sid)
        now = time.time()
        with self._lock:
            session = self._items.get(key)
            if session is None:
                return None
            if self._expired(session, now) or not self.validate(session):
                del self._items[key]
                return None
            session.last_used = now
            return session

    def end(self, sid: str | None) -> None:
        if sid and len(sid) <= MAX_SECRET_CHARS:
            with self._lock:
                self._items.pop(sha256_hex(sid), None)


class LoginLimiter:
    """At most `per_address` failed logins per address in a sliding window.
    Past `overall` failures in total, addresses that have failed recently are
    held off until the window passes; an address with no recent failures can
    always try, so a noisy neighbour cannot lock everyone out. A successful
    login clears its address's failures. The counts live in memory only, so
    restarting the dashboard clears them. The token has 256 bits; the limit
    keeps noise and log spam down rather than guarding against guessing."""

    def __init__(self, per_address: int = 5, overall: int = 50, window_seconds: float = 900.0):
        self.per_address, self.overall, self.window = per_address, overall, window_seconds
        self._lock = threading.Lock()
        self._by_address: dict[str, collections.deque] = {}
        self._all: collections.deque = collections.deque()

    def _trim(self, dq: collections.deque, now: float) -> None:
        while dq and now - dq[0] > self.window:
            dq.popleft()

    def allowed(self, address: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._trim(self._all, now)
            dq = self._by_address.get(address)
            if dq is not None:
                self._trim(dq, now)
            mine = len(dq) if dq else 0
            if mine >= self.per_address:
                return False
            return mine == 0 or len(self._all) < self.overall

    def succeeded(self, address: str) -> None:
        """A successful login clears the address's failures."""
        with self._lock:
            self._by_address.pop(address, None)

    def failed(self, address: str) -> None:
        now = time.monotonic()
        with self._lock:
            if address not in self._by_address and len(self._by_address) >= 10_000:
                self._by_address.pop(next(iter(self._by_address)))
            self._by_address.setdefault(address, collections.deque()).append(now)
            self._all.append(now)


def same_origin(host: str | None, origin: str | None, referer: str | None, allowed_hosts: frozenset[str]) -> bool:
    """True when a state-changing request comes from this dashboard's own pages."""
    if not host or host not in allowed_hosts:
        return False
    if origin:
        return origin == f"https://{host}"
    if referer:
        parts = urlsplit(referer)
        return parts.scheme == "https" and parts.netloc == host
    return False


def csrf_matches(session: Session, value: str | None) -> bool:
    return bool(value) and len(value) <= MAX_SECRET_CHARS and hmac.compare_digest(session.csrf, value)


def session_cookie(sid: str, role: str) -> str:
    return f"{COOKIE_NAME}={sid}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={session_lifetime(role)}"


def clear_cookie() -> str:
    return f"{COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"


def cookie_value(header: str | None) -> str | None:
    if not header or len(header) > 8192:
        return None
    for part in header.split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE_NAME:
            return value
    return None
