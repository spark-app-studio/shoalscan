"""Login token, sessions, CSRF tokens, same-origin checks and the login rate limit.

The login token is 256 bits from `secrets`. Only its SHA-256 is stored, in
a 0600 file; the token itself is printed once when it is made. Sessions live
in memory only, keyed by the SHA-256 of the cookie value, and end when the
token is rotated.
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

COOKIE_NAME = "__Host-shoalscan"
SESSION_IDLE_SECONDS = 8 * 3600
SESSION_MAX_SECONDS = 7 * 24 * 3600
MAX_SESSIONS = 100
MAX_SECRET_CHARS = 128


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


def create_token(hash_path: Path) -> str:
    """Make a new 256-bit login token, store its SHA-256, and return the token."""
    token = secrets.token_urlsafe(32)
    write_private_file(hash_path, sha256_hex(token) + "\n")
    return token


class TokenCheck:
    """Compares login attempts with the stored hash, re-reading the file when it changes."""

    def __init__(self, hash_path: Path):
        self.hash_path = hash_path
        self._lock = threading.Lock()
        self._stamp: tuple | None = None
        self._hash = ""

    def stored(self) -> str:
        with self._lock:
            try:
                st = os.stat(self.hash_path)
            except OSError:
                self._stamp, self._hash = None, ""
                return ""
            stamp = (st.st_ino, st.st_mtime_ns, st.st_size)
            if stamp != self._stamp:
                try:
                    value = self.hash_path.read_text(encoding="ascii").strip()
                except (OSError, UnicodeDecodeError):
                    value = ""
                self._hash = value if len(value) == 64 and all(c in "0123456789abcdef" for c in value) else ""
                self._stamp = stamp
            return self._hash

    def matches(self, candidate: str) -> bool:
        stored = self.stored()
        if not stored or not candidate or len(candidate) > MAX_SECRET_CHARS:
            return False
        # Comparing fixed-length digests in constant time leaks nothing about the token.
        return hmac.compare_digest(sha256_hex(candidate), stored)


@dataclass
class Session:
    created: float
    last_used: float
    csrf: str
    token_hash: str
    tag: str = ""  # short and not secret: tells sessions apart in the audit


class Sessions:
    def __init__(self, tokens: TokenCheck):
        self.tokens = tokens
        self._lock = threading.Lock()
        self._items: dict[str, Session] = {}

    def create(self) -> str:
        sid = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            if len(self._items) >= MAX_SESSIONS:
                oldest = min(self._items, key=lambda k: self._items[k].last_used)
                del self._items[oldest]
            self._items[sha256_hex(sid)] = Session(now, now, secrets.token_urlsafe(32), self.tokens.stored(), secrets.token_hex(4))
        return sid

    def get(self, sid: str | None) -> Session | None:
        if not sid or len(sid) > MAX_SECRET_CHARS:
            return None
        key = sha256_hex(sid)
        now = time.time()
        stored = self.tokens.stored()
        with self._lock:
            session = self._items.get(key)
            if session is None:
                return None
            expired = now - session.last_used > SESSION_IDLE_SECONDS or now - session.created > SESSION_MAX_SECONDS
            rotated = not stored or not hmac.compare_digest(session.token_hash, stored)
            if expired or rotated:
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


def session_cookie(sid: str) -> str:
    return f"{COOKIE_NAME}={sid}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={SESSION_MAX_SECONDS}"


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
