"""`shoalscan serve`: the dashboard, over HTTPS only, from the standard library.

- One TLS listener; there is no plain-HTTP port and no redirect from one.
- Every request must carry an allowed Host header (421 otherwise), which
  stops DNS-rebinding pages from talking to the dashboard.
- Only the login page, its script, the stylesheet and the icon answer without
  a session. Everything else needs the `__Host-` session cookie.
- Sign-in goes through an OpenID Connect provider (see `oidc`): the code
  flow with PKCE, state and nonce, and an RS256-checked ID token. Until it is
  configured, the dashboard serves only a setup wizard, which needs a
  one-time code printed on the server's console. Logout needs the session's
  CSRF token.
- Admins (the provider's admin claim) manage who may sign in, the
  Configuration page and scans; members (allowed by an admin) read
  everything and review findings. Roles are checked on the server for every
  request, and sessions against the users database.
- Static files come from a fixed table loaded at start-up; no request path
  is ever joined to a filesystem path.
- The database is opened read-only for every request.
- Request lines, bodies, connections and their lifetimes are bounded.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import re
import secrets
import socket
import socketserver
import ssl
import sys
import threading
import time
import tomllib
from collections import OrderedDict
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from shoalscan import PROJECT_URL, __version__, embeddings, history
from shoalscan.dashboard import auth, oidc, scanning, users
from shoalscan.dashboard.configedit import ConfigEditor
from shoalscan.dashboard.data import AGE_BUCKETS, FILE_KINDS, REVIEW_FILTERS, SEVERITIES, SORTS, Data
from shoalscan.dashboard.scancontrol import ScanControl
from shoalscan.errors import SetupError
from shoalscan.resources import data_path, default_lock_path

STATIC_DIR = Path(__file__).resolve().parent / "static"
LICENSE_URL = "https://www.apache.org/licenses/LICENSE-2.0"

HTML = "text/html; charset=utf-8"
# Published path -> (source, content type, public). The source is a file in
# the static directory, or "icon" for the shipped Shoalscan icon.
ROUTES: dict[str, tuple[str, str, bool]] = {
    "/": ("index.html", HTML, False),
    "/login": ("login.html", HTML, True),
    "/setup": ("setup.html", HTML, True),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8", False),
    "/static/model.js": ("model.js", "text/javascript; charset=utf-8", False),
    "/static/login.js": ("login.js", "text/javascript; charset=utf-8", True),
    "/static/setup.js": ("setup.js", "text/javascript; charset=utf-8", True),
    "/static/app.css": ("app.css", "text/css; charset=utf-8", True),
    "/static/shoalscan-icon.svg": ("icon", "image/svg+xml", True),
    "/favicon.ico": ("icon", "image/svg+xml", True),
}

MAX_URL = 4096
MAX_BODY = 2048
MAX_CONFIG_BODY = 64 * 1024  # a target with its policy text
CONFIG_POSTS = ("/api/config/target", "/api/config/enable", "/api/config/remove")
USER_POSTS = ("/api/users/allow", "/api/users/change")
SETUP_POSTS = ("/setup/test", "/setup/save")
SETUP_PATHS = frozenset({"/setup", "/static/setup.js"})
LOGIN_COOKIE = "__Host-shoalscan-login"
# Sent after a successful sign-in: a same-origin refresh, so the browser sends the new
# SameSite=Strict session cookie (a redirect chain begun at the provider would not).
SIGNED_IN_PAGE = (
    b'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=/">'
    b'<title>Signed in</title></head><body><p>Signed in. <a href="/">Continue to the dashboard</a>.</p></body></html>'
)
# GET endpoints only an admin may read.
ADMIN_GETS = frozenset({"/api/config", "/api/config/baseline", "/api/users", "/api/scan/status"})
MAX_REVIEW_BODY = 512 * 1024  # up to 500 finding keys and a description
MAX_CONNECTIONS = 64
MAX_CONNECTIONS_PER_ADDRESS = 16
# Connections that have not finished the TLS handshake cost a thread and a
# slot but prove nothing, so one address may hold only a few of them, briefly.
MAX_HANDSHAKING_PER_ADDRESS = 4
HANDSHAKE_TIMEOUT = 5.0
CONNECTION_LIFETIME = 60.0
API_PATHS = frozenset(
    {
        "/api/session",
        "/api/about",
        "/api/repos",
        "/api/overview",
        "/api/runs",
        "/api/run",
        "/api/findings",
        "/api/rule",
        "/api/stale",
        "/api/files",
        "/api/suppressions",
        "/api/changes",
        "/api/scan/status",
        "/api/config",
        "/api/config/baseline",
        "/api/finding",
        "/api/review/history",
        "/api/similar",
        "/api/users",
    }
)
_WEEK = re.compile(r"^\d{4}-\d{2}-\d{2}$")
GENERIC_ERRORS = {
    400: "bad request",
    408: "request timeout",
    413: "request body too large",
    414: "request URL too long",
    431: "request header fields too large",
    501: "method not supported",
    505: "HTTP version not supported",
}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
        "font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "Strict-Transport-Security": "max-age=31536000",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    # `same-origin` rather than `no-referrer`: with no referrer at all some
    # browsers send `Origin: null` on form posts, which the login refuses.
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cache-Control": "no-store",
}


@dataclass(frozen=True)
class ServeConfig:
    db: Path
    cert: Path
    key: Path
    auth_dir: Path  # oidc.toml and users.sqlite3
    bind: str
    port: int
    hosts: tuple[str, ...]
    state_dir: Path | None = None  # holds scan_targets.toml; scans are off without it
    allow_config: bool = False


def allowed_host_headers(hosts: tuple[str, ...], port: int) -> frozenset[str]:
    """The exact Host header values the dashboard answers to."""
    out = set()
    for host in hosts:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            name = host.lower()
        else:
            name = f"[{ip}]" if ip.version == 6 else str(ip)
        out.add(f"{name}:{port}")
        if port == 443:
            out.add(name)
    return frozenset(out)


def tls_context(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    try:
        ctx.load_cert_chain(str(cert), str(key))
    except (OSError, ssl.SSLError) as exc:
        raise SetupError(f"cannot load the TLS certificate and key ({cert}, {key}): {exc}") from None
    return ctx


def about_info() -> dict:
    """Scanners and rule sources with their pinned versions and licences, from tools.lock."""
    with open(default_lock_path(), "rb") as handle:
        lock = tomllib.load(handle)
    og, cs, rules = lock.get("opengrep", {}), lock.get("cosign", {}), lock.get("rules", {})
    gl, hl, zz, tv = lock.get("gitleaks"), lock.get("hadolint"), lock.get("zizmor"), lock.get("trivy")
    return {
        "shoalscan": {
            "version": __version__,
            "licence": "Apache-2.0",
            "project_url": PROJECT_URL,
            "licence_url": LICENSE_URL,
        },
        "scanners": [
            {
                "name": "Opengrep",
                "role": "pattern and taint scanner",
                "version": og.get("version"),
                "licence": og.get("license"),
                "source": og.get("source"),
            },
            {
                "name": "cosign",
                "role": "verifies the Opengrep signature at install",
                "version": cs.get("version"),
                "licence": cs.get("license"),
                "source": cs.get("source"),
            },
            *(
                [
                    {
                        "name": "Gitleaks",
                        "role": "secrets scanner (when enabled)",
                        "version": gl.get("version"),
                        "licence": gl.get("license"),
                        "source": gl.get("source"),
                    }
                ]
                if isinstance(gl, dict)
                else []
            ),
            *(
                [
                    {
                        "name": "Hadolint",
                        "role": "Dockerfile linter (when enabled)",
                        "version": hl.get("version"),
                        "licence": hl.get("license"),
                        "source": hl.get("source"),
                    }
                ]
                if isinstance(hl, dict)
                else []
            ),
            *(
                [
                    {
                        "name": "zizmor",
                        "role": "GitHub Actions auditor (when enabled)",
                        "version": zz.get("version"),
                        "licence": zz.get("license"),
                        "source": zz.get("source"),
                    }
                ]
                if isinstance(zz, dict)
                else []
            ),
            *(
                [
                    {
                        "name": "Trivy",
                        "role": "infrastructure-as-code checker (when enabled)",
                        "version": tv.get("version"),
                        "licence": tv.get("license"),
                        "source": tv.get("source"),
                    }
                ]
                if isinstance(tv, dict)
                else []
            ),
        ],
        "rule_sources": [
            {
                "name": "Opengrep community rules",
                "version": f"commit {rules.get('commit', '')[:12]}",
                "licence": rules.get("license"),
                "source": rules.get("repository"),
                "note": "downloaded by shoalscan install, never bundled",
            },
            {
                "name": "Shoalscan rules",
                "version": __version__,
                "licence": "Apache-2.0",
                "source": PROJECT_URL,
                "note": "ship with Shoalscan",
            },
            {
                "name": "Repository rules",
                "version": None,
                "licence": "the repository's own",
                "source": None,
                "note": "kept in each scanned repository",
            },
        ],
    }


class App:
    def __init__(self, config: ServeConfig):
        self.config = config
        self.allowed_hosts = allowed_host_headers(config.hosts, config.port)
        self.auth_dir = config.auth_dir
        # None until the setup wizard (or a hand-written oidc.toml) configures sign-in.
        self.oidc = oidc.load(self.auth_dir)
        self.setup_code = secrets.token_urlsafe(18) if self.oidc is None else None
        self.provider: oidc.Provider | None = None
        self._provider_lock = threading.Lock()
        self.logins = oidc.Logins()
        self.sessions = auth.Sessions(self.session_valid)
        self.limiter = auth.LoginLimiter()
        icon = data_path("assets/shoalscan-icon.svg").read_bytes()
        self.static = {
            path: icon if source == "icon" else (STATIC_DIR / source).read_bytes()
            for path, (source, _, _) in ROUTES.items()
        }
        self.about = about_info()
        self._cache: OrderedDict = OrderedDict()
        self._cache_lock = threading.Lock()
        # Fail at start-up, not on the first request, if the database is unusable.
        history.open_read_only(config.db).close()
        self.scans = ScanControl(config.state_dir, config.db) if config.state_dir else None
        self.config_editor = ConfigEditor(config.state_dir, config.db) if config.state_dir else None

    def users(self):
        return users.open_users(self.auth_dir)

    def session_valid(self, session: auth.Session) -> bool:
        """Does a session still hold? Its person must not be disabled or changed since."""
        if session.user is None:
            return False
        conn = self.users()
        try:
            return users.current(conn, session.user, session.role, session.credential_version)
        finally:
            conn.close()

    def provider_now(self) -> oidc.Provider:
        """The provider's endpoints and keys, read at the first sign-in and again every hour."""
        with self._provider_lock:
            if self.provider is None or time.monotonic() - self.provider.fetched_at > 3600:
                self.provider = oidc.discover(self.oidc)
            return self.provider

    def config_enabled(self) -> bool:
        """The Configuration page exists once scan_targets.toml does, or with serve --allow-config."""
        if self.config_editor is None:
            return False
        return self.config.allow_config or (self.config.state_dir / scanning.TARGETS_FILE).exists()

    def data(self) -> Data:
        return Data(history.open_read_only(self.config.db))

    def _cached(self, key: tuple, compute):
        """A small LRU of derived results; keys include the repository's version, so new runs refresh them."""
        with self._cache_lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
        value = compute()
        with self._cache_lock:
            self._cache[key] = value
            while len(self._cache) > 32:
                self._cache.popitem(last=False)
        return value

    def overview(self, data: Data, repo_id: int) -> dict:
        return self._cached(("overview", repo_id, data.version(repo_id)), lambda: data.overview(repo_id))

    def change_keys(self, data: Data, repo_id: int, week: str, change: str) -> list:
        return self._cached(
            ("changes", repo_id, data.version(repo_id), week, change), lambda: data.change_keys(repo_id, week, change)
        )


class DashboardServer(socketserver.ThreadingMixIn, HTTPServer):
    """Accepts TCP, then does the TLS handshake in the worker thread, so a slow
    client cannot stall the accept loop. A failed handshake closes the socket."""

    daemon_threads = True
    request_queue_size = 64

    def __init__(self, address, app: App, ctx: ssl.SSLContext):
        self.app = app
        self.ctx = ctx
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.per_address: dict[str, int] = {}
        self.handshaking: dict[str, int] = {}
        self.per_address_lock = threading.Lock()
        family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        self.address_family = family
        super().__init__(address, Handler)

    def _claim(self, address: str) -> bool:
        with self.per_address_lock:
            if self.per_address.get(address, 0) >= MAX_CONNECTIONS_PER_ADDRESS:
                return False
            if self.handshaking.get(address, 0) >= MAX_HANDSHAKING_PER_ADDRESS:
                return False
            self.per_address[address] = self.per_address.get(address, 0) + 1
            self.handshaking[address] = self.handshaking.get(address, 0) + 1
            return True

    @staticmethod
    def _decrement(counts: dict[str, int], address: str) -> None:
        left = counts.get(address, 1) - 1
        if left > 0:
            counts[address] = left
        else:
            counts.pop(address, None)

    def _handshake_done(self, address: str) -> None:
        with self.per_address_lock:
            self._decrement(self.handshaking, address)

    def _release(self, address: str, handshaking: bool = False) -> None:
        with self.per_address_lock:
            self._decrement(self.per_address, address)
            if handshaking:
                self._decrement(self.handshaking, address)

    def process_request(self, request, client_address):
        address = client_address[0]
        if not self._claim(address):
            self.shutdown_request(request)
            return
        if not self.slots.acquire(blocking=False):
            self._release(address, handshaking=True)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            self._release(address, handshaking=True)
            raise

    def process_request_thread(self, request, client_address):
        holder = [request]

        def cut() -> None:
            try:
                holder[0].shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(CONNECTION_LIFETIME, cut)
        timer.daemon = True
        timer.start()
        handshaking = True
        try:
            request.settimeout(HANDSHAKE_TIMEOUT)
            try:
                tls = self.ctx.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError):
                self.shutdown_request(request)
                return
            finally:
                self._handshake_done(client_address[0])
                handshaking = False
            holder[0] = tls
            try:
                self.finish_request(tls, client_address)
            except (ssl.SSLError, ConnectionError, TimeoutError):
                pass  # the client went away or was too slow; nothing to report
            except Exception as exc:  # noqa: BLE001 - one bad connection must not stop the server
                sys.stderr.write(f"shoalscan serve: connection error: {type(exc).__name__}\n")
            finally:
                self.shutdown_request(tls)
        finally:
            timer.cancel()
            self.slots.release()
            self._release(client_address[0], handshaking=handshaking)

    def shutdown_request(self, request):
        try:
            request.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        self.close_request(request)


def _one(query: dict, name: str, limit: int = 1024) -> str | None:
    values = query.get(name)
    if not values:
        return None
    value = values[0]
    if len(value) > limit:
        raise ValueError(f"{name} is too long")
    return value


def _age(query: dict) -> int | None:
    """An age bucket index; anything outside the buckets is an error, never clamped."""
    value = _one(query, "age", 2)
    if value in (None, ""):
        return None
    if not value.isdigit() or int(value) >= len(AGE_BUCKETS):
        raise ValueError("age")
    return int(value)


def _finding_key(query: dict) -> list[str]:
    """finding_key=["tool","rule","path","fingerprint"], as JSON in the query string."""
    value = _one(query, "finding_key", 5000)
    try:
        key = json.loads(value) if value else None
    except ValueError:
        key = None
    if not (isinstance(key, list) and len(key) == 4 and all(isinstance(p, str) and 0 < len(p) <= 1024 for p in key)):
        raise ValueError("finding_key")
    return key


def _review_filter(query: dict) -> str | None:
    value = _one(query, "review", 20)
    if value in (None, ""):
        return None
    if value not in REVIEW_FILTERS:
        raise ValueError("review")
    return value


def _sort(query: dict) -> str | None:
    value = _one(query, "sort", 20)
    if value in (None, ""):
        return None
    if value not in SORTS:
        raise ValueError("sort")
    return value


def _flag(query: dict, name: str) -> bool:
    value = _one(query, name, 1)
    if value not in (None, "", "0", "1"):
        raise ValueError(f"{name} must be 0 or 1")
    return value == "1"


def _threshold(query: dict) -> float:
    """threshold=0.85: the lowest similarity to list, from 0.5 to 1."""
    value = _one(query, "threshold", 10)
    if value is None or value == "":
        return embeddings.DEFAULT_THRESHOLD
    if not re.fullmatch(r"(0\.\d{1,4}|1(\.0{1,4})?)", value) or not 0.5 <= float(value) <= 1:
        raise ValueError("threshold must be from 0.5 to 1")
    return float(value)


def _int(query: dict, name: str, default: int | None, low: int, high: int) -> int | None:
    value = _one(query, name, 20)
    if value is None or value == "":
        return default
    if not value.isdigit():
        raise ValueError(f"{name} must be a number")
    return max(low, min(int(value), high))


class Handler(BaseHTTPRequestHandler):
    server_version = "shoalscan"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 20

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    def version_string(self) -> str:
        return self.server_version

    # The log never carries query strings, cookies or bodies.
    def _log(self, status: str) -> None:
        path = urlsplit(getattr(self, "path", "") or "").path[:200] or "-"
        sys.stderr.write(
            f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {self.client_address[0]} {getattr(self, 'command', None) or '-'} "
            f"{path} {status}\n"
        )

    def log_request(self, code="-", size="-") -> None:
        self._log(str(code))

    def log_error(self, format, *args) -> None:  # noqa: A002 - the base class names it so
        self._log("error")

    def log_message(self, format, *args) -> None:  # noqa: A002
        self._log("")

    # ------------------------------------------------------------ responses

    def send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(status)
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra or {}).items():
            # A list sends the header once per value (two Set-Cookie headers, say).
            for one in value if isinstance(value, list) else [value]:
                self.send_header(name, one)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, status: int, value) -> None:
        self.send(status, json.dumps(value, separators=(",", ":")).encode("utf-8"), "application/json; charset=utf-8")

    def send_error_json(self, status: int, message: str) -> None:
        self.send_json(status, {"error": message})

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        # http.server calls this for requests it cannot parse (400, 414, 431,
        # 501, 505). Its own error page carries none of the security headers.
        self.close_connection = True
        # For a line it cannot parse, http.server assumes HTTP/0.9 and would
        # send a bare body with no status line or headers. The dashboard never
        # speaks HTTP/0.9, so the answer is always a full HTTP/1.1 response.
        self.request_version = "HTTP/1.1"
        try:
            self.send_json(code, {"error": GENERIC_ERRORS.get(code, "request refused")})
        except OSError:
            pass

    def _session(self) -> tuple[str | None, auth.Session | None]:
        sid = auth.cookie_value(self.headers.get("Cookie"))
        return sid, self.app.sessions.get(sid)

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self.app.allowed_hosts

    # ------------------------------------------------------------ methods

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        if len(self.path) > MAX_URL:
            return self.send_error_json(414, "request URL too long")
        if not self._host_ok():
            return self.send_error_json(421, "this dashboard does not answer to that host name")
        url = urlsplit(self.path)
        route = ROUTES.get(url.path)
        if self.app.oidc is None:
            # Setup mode: the wizard and what it needs, and nothing else.
            if route and route[2] and url.path not in ("/", "/login"):
                return self.send(200, self.app.static[url.path], route[1])
            if url.path.startswith("/api/"):
                return self.send_error_json(503, "sign-in is not set up yet; open /setup")
            return self.send(303, b"", "text/plain", {"Location": "/setup"})
        if url.path in SETUP_PATHS:
            return self.send(303, b"", "text/plain", {"Location": "/login"})
        if route and route[2]:
            return self.send(200, self.app.static[url.path], route[1])
        if url.path == "/oidc/start":
            return self.oidc_start()
        if url.path == "/oidc/callback":
            return self.oidc_callback(parse_qs(url.query, max_num_fields=10))
        _, session = self._session()
        if session is None:
            if url.path == "/":
                return self.send(303, b"", "text/plain", {"Location": "/login"})
            return self.send_error_json(401, "log in first")
        if route:
            return self.send(200, self.app.static[url.path], route[1])
        if url.path.startswith("/api/"):
            try:
                return self.api(url.path, parse_qs(url.query, max_num_fields=20), session)
            except ValueError:
                return self.send_error_json(400, "invalid query parameter")
            except SetupError as exc:
                return self.send_error_json(503, str(exc)[:300])
        return self.send_error_json(404, "not found")

    def do_POST(self) -> None:
        if len(self.path) > MAX_URL:
            return self.send_error_json(414, "request URL too long")
        if not self._host_ok():
            return self.send_error_json(421, "this dashboard does not answer to that host name")
        if "Transfer-Encoding" in self.headers:
            # Bodies must carry a Content-Length; an unread chunked body would
            # otherwise be read as the next request on this connection.
            self.close_connection = True
            return self.send(
                400,
                b'{"error":"chunked request bodies are not accepted"}',
                "application/json; charset=utf-8",
                {"Connection": "close"},
            )
        length = self.headers.get("Content-Length", "0")
        post_path = urlsplit(self.path).path
        limit = (
            MAX_CONFIG_BODY
            if post_path in CONFIG_POSTS
            else (MAX_REVIEW_BODY if post_path == "/api/review" else MAX_BODY)
        )
        if not length.isdigit() or int(length) > limit:
            self.close_connection = True
            return self.send_error_json(413, "request body too large")
        body = self.rfile.read(int(length))
        if not auth.same_origin(
            self.headers.get("Host"), self.headers.get("Origin"), self.headers.get("Referer"), self.app.allowed_hosts
        ):
            return self.send_error_json(403, "cross-origin request refused")
        path = urlsplit(self.path).path
        if path in SETUP_POSTS:
            return self.setup_sign_in(path, body) if self.app.oidc is None else self.send_error_json(404, "not found")
        if self.app.oidc is None:
            return self.send_error_json(503, "sign-in is not set up yet; open /setup")
        sid, session = self._session()
        if session is None:
            return self.send_error_json(401, "log in first")
        if not auth.csrf_matches(session, self.headers.get("X-CSRF-Token")):
            return self.send_error_json(403, "missing or wrong CSRF token")
        if path == "/logout":
            self.app.sessions.end(sid)
            return self.send(204, b"", "text/plain", {"Set-Cookie": auth.clear_cookie()})
        if path in ("/api/scan", *CONFIG_POSTS, *USER_POSTS) and session.role != "admin":
            return self.send_error_json(403, "this needs an admin")
        if path == "/api/scan":
            return self.start_scan(body, session)
        if path in CONFIG_POSTS:
            return self.change_config(path, body, session)
        if path in USER_POSTS:
            return self.change_users(path, body, session)
        if path == "/api/review":
            return self.review(body, session)
        return self.send_error_json(404, "not found")

    def review(self, body: bytes, session: auth.Session) -> None:
        """POST /api/review: {repo, finding_key | finding_keys, status, description[, run_id]}.
        The change is written on a short-lived connection; the serving connection stays read-only."""
        request = self._json_body(body)
        if request is None:
            return None
        single, bulk = "finding_key" in request, "finding_keys" in request
        allowed = {"repo", "status", "description", "run_id", "finding_key", "finding_keys"}
        if single == bulk or not set(request) <= allowed or not {"repo", "status", "description"} <= set(request):
            return self.send_error_json(400, "send repo, status, description and finding_key (or finding_keys)")
        keys = [request["finding_key"]] if single else request["finding_keys"]
        if not isinstance(keys, list) or len(keys) > history.MAX_BULK_REVIEWS:
            return self.send_error_json(400, f"review at most {history.MAX_BULK_REVIEWS} findings at a time")
        repo, run_id = request["repo"], request.get("run_id")
        if not scanning.valid_name(repo):
            return self.send_error_json(400, "invalid repository name")
        if run_id is not None:
            if isinstance(run_id, bool) or not isinstance(run_id, int) or not 0 < run_id < 2**62:
                return self.send_error_json(400, "run_id must be a run number")
            data = self.app.data()
            try:
                repo_id = data.repo_id(repo)
                if repo_id is None or data.run(repo_id, run_id) is None:
                    return self.send_error_json(404, "this repository has no such run")
            finally:
                data.conn.close()
        try:
            count = history.set_reviews(
                self.app.config.db,
                repo,
                keys,
                request["status"],
                request["description"],
                session.who,
                run_id,
            )
        except LookupError:
            return self.send_error_json(404, "no such finding in this repository")
        except SetupError as exc:
            return self.send_error_json(400, str(exc)[:300])
        return self.send_json(200, {"reviewed": count, "status": request["status"]})

    def change_config(self, path: str, body: bytes, session: auth.Session) -> None:
        if not self.app.config_enabled():
            return self.send_error_json(404, "not found")
        request = self._json_body(body)
        if request is None:
            return None
        editor = self.app.config_editor
        who = session.who
        try:
            if path == "/api/config/target":
                status, result = editor.save_target(request, who)
            elif path == "/api/config/enable":
                status, result = editor.set_enabled(request, who)
            else:
                status, result = editor.remove(request, who)
        except SetupError as exc:
            status, result = 400, {"error": str(exc)[:300]}
        return self.send_json(status, result)

    def change_users(self, path: str, body: bytes, session: auth.Session) -> None:
        """POST /api/users/allow {email}, or /api/users/change {email, action}: disallow, disable or enable.
        Admins come from the provider's admin claim; here an admin lets members in and out."""
        request = self._json_body(body)
        if request is None:
            return None
        conn = self.app.users()
        try:
            if path == "/api/users/allow":
                if set(request) != {"email"}:
                    return self.send_error_json(400, "send exactly {email}")
                users.allow(conn, request["email"], session.who)
                return self.send_json(200, {"email": users.normalise_email(request["email"]), "done": "allow"})
            action = request.get("action")
            if set(request) != {"email", "action"} or action not in ("disallow", "disable", "enable"):
                return self.send_error_json(400, "send {email, action}: disallow, disable or enable")
            if action == "disallow":
                users.disallow(conn, request["email"], session.who)
            else:
                users.set_disabled(conn, request["email"], action == "disable", session.who)
            return self.send_json(200, {"email": users.normalise_email(request["email"]), "done": action})
        except SetupError as exc:
            return self.send_error_json(400, str(exc)[:300])
        finally:
            conn.close()

    def setup_sign_in(self, path: str, body: bytes) -> None:
        """POST /setup/test or /setup/save: check (and save) the provider settings from the wizard.
        Both need the one-time setup code printed on the server's console."""
        address = self.client_address[0]
        if not self.app.limiter.allowed(address):
            return self.send_error_json(429, "too many wrong setup codes; wait 15 minutes")
        request = self._json_body(body)
        if request is None:
            return None
        code = request.pop("setup_code", None)
        if not isinstance(code, str) or not hmac.compare_digest(code.strip(), self.app.setup_code or "\0"):
            self.app.limiter.failed(address)
            return self.send_error_json(403, "that is not the setup code printed on the server's console")
        request["redirect_uri"] = f"https://{self.headers.get('Host')}/oidc/callback"
        try:
            config = oidc.validate(request)
            provider = oidc.discover(config)
            checks = [*provider.checks, oidc.check_client(provider, config)]
        except SetupError as exc:
            return self.send_json(400, {"ok": False, "error": str(exc)[:500]})
        except oidc.OidcError as exc:
            return self.send_json(400, {"ok": False, "error": str(exc)[:500]})
        if path == "/setup/test":
            return self.send_json(200, {"ok": True, "checks": checks, "redirect_uri": config.redirect_uri})
        oidc.save(self.app.auth_dir, config)
        with self.app._provider_lock:
            self.app.provider = provider
        self.app.oidc, self.app.setup_code = config, None
        self.app.limiter.succeeded(address)
        return self.send_json(200, {"ok": True, "checks": checks, "redirect": "/login"})

    def _json_body(self, body: bytes) -> dict | None:
        """Actions take a JSON object, from a page of this dashboard (an exact Origin header)."""
        if self.headers.get("Origin") != f"https://{self.headers.get('Host')}":
            self.send_error_json(403, "this action needs the dashboard's own Origin header")
            return None
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            self.send_error_json(415, "expected application/json")
            return None
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            self.send_error_json(400, "bad JSON")
            return None
        if not isinstance(value, dict):
            self.send_error_json(400, "expected a JSON object")
            return None
        return value

    def start_scan(self, body: bytes, session: auth.Session) -> None:
        scans = self.app.scans
        if scans is None or scans.targets() is None:
            return self.send_error_json(404, "not found")
        request = self._json_body(body)
        if request is None:
            return None
        # {"target": name} scans the tip of the branch; {"target": name, "rescan": true} does the
        # same from a Rescan button; {"target": name, "run_id": n} scans that run's commit again.
        if (
            "target" not in request
            or not set(request) <= {"target", "rescan", "run_id"}
            or ("rescan" in request and "run_id" in request)
        ):
            return self.send_error_json(400, 'send {"target": name}, optionally with "rescan": true or "run_id": n')
        if "rescan" in request and request["rescan"] is not True:
            return self.send_error_json(400, "rescan must be true")
        run_id = request.get("run_id")
        if "run_id" in request and (isinstance(run_id, bool) or not isinstance(run_id, int) or not 0 < run_id < 2**62):
            return self.send_error_json(400, "run_id must be a run number")
        if not scanning.valid_name(request["target"]):
            return self.send_error_json(400, "invalid target name")
        data = self.app.data()
        try:
            if run_id is not None:
                repo_id = data.repo_id(request["target"])
                run = data.run(repo_id, run_id) if repo_id is not None else None
                if run is None:
                    return self.send_error_json(404, "this repository has no such run")
                if run["kind"] != "scheduled":
                    return self.send_error_json(409, "only scheduled runs can be rescanned by commit")
            trigger = "rescan-commit" if run_id is not None else ("rescan" if request.get("rescan") else "dashboard")
            status, result = scans.start(request["target"], data.scan_triggers, trigger, run_id, session.who)
        finally:
            data.conn.close()
        return self.send_json(status, result)

    def _not_allowed(self) -> None:
        self.send_error_json(405, "method not allowed")

    # The names http.server looks up for each method.
    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = _not_allowed  # noqa: N815

    # ------------------------------------------------------------ routes

    def _to_login(self, error: str, extra: dict | None = None) -> None:
        self.send(303, b"", "text/plain", {"Location": f"/login?error={error}", **(extra or {})})

    def oidc_start(self) -> None:
        """GET /oidc/start: send the browser to the provider, with a fresh state, nonce and PKCE challenge."""
        try:
            provider = self.app.provider_now()
        except oidc.OidcError:
            return self._to_login("provider")
        state, pending = self.app.logins.start()
        cookie = f"{LOGIN_COOKIE}={state}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={oidc.LOGIN_SECONDS}"
        location = oidc.authorization_url(provider, self.app.oidc, state, pending)
        return self.send(303, b"", "text/plain", {"Location": location, "Set-Cookie": cookie})

    def oidc_callback(self, query: dict) -> None:
        """GET /oidc/callback: check the state, swap the code for an ID token, check it, and decide."""
        address = self.client_address[0]
        clear = {"Set-Cookie": f"{LOGIN_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"}
        if not self.app.limiter.allowed(address):
            return self._to_login("limit", clear)
        state = _one(query, "state", 100)
        cookie = None
        for part in (self.headers.get("Cookie") or "")[:8192].split(";"):
            name, _, value = part.strip().partition("=")
            if name == LOGIN_COOKIE:
                cookie = value
        # The state must come back to the browser that started the login, and be used once.
        if not state or not cookie or not hmac.compare_digest(state, cookie):
            self.app.limiter.failed(address)
            return self._to_login("state", clear)
        pending = self.app.logins.finish(state)
        if pending is None:
            return self._to_login("state", clear)
        if _one(query, "error", 100):
            return self._to_login("denied", clear)
        try:
            provider = self.app.provider_now()
            claims = oidc.exchange(provider, self.app.oidc, _one(query, "code", 2000) or "", pending)
        except oidc.OidcError:
            self.app.limiter.failed(address)
            return self._to_login("provider", clear)
        conn = self.app.users()
        try:
            user = users.sign_in(conn, claims, oidc.is_admin(self.app.oidc, claims))
        except users.SignInRefusedError as exc:
            return self._to_login(exc.code, clear)
        finally:
            conn.close()
        self.app.limiter.succeeded(address)
        sid = self.app.sessions.create(user.email, user.role, user.version)
        return self.send(200, SIGNED_IN_PAGE, HTML, {"Set-Cookie": [auth.session_cookie(sid), clear["Set-Cookie"]]})

    def api(self, path: str, query: dict, session: auth.Session) -> None:
        if path not in API_PATHS:
            return self.send_error_json(404, "not found")
        if path == "/api/session":
            return self.send_json(200, {"csrf": session.csrf, "user": session.user, "role": session.role})
        if path in ADMIN_GETS and session.role != "admin":
            return self.send_error_json(403, "this needs an admin")
        if path == "/api/users":
            conn = self.app.users()
            try:
                return self.send_json(
                    200,
                    {
                        "users": users.list_users(conn),
                        "events": users.events(conn),
                        "provider": {
                            "name": self.app.oidc.display_name,
                            "issuer": self.app.oidc.issuer,
                            "admin_claim": self.app.oidc.admin_claim,
                            "admin_value": self.app.oidc.admin_value,
                        },
                    },
                )
            finally:
                conn.close()
        if path in ("/api/config", "/api/config/baseline"):
            if not self.app.config_enabled():
                return self.send_error_json(404, "not found")
            data = self.app.data()
            try:
                if path == "/api/config/baseline":
                    status, result = self.app.config_editor.baseline(_one(query, "target", 200))
                    return self.send_json(status, result)
                return self.send_json(200, self.app.config_editor.page(data.latest_run_of, data.config_changes()))
            except SetupError as exc:
                return self.send_error_json(503, str(exc)[:300])
            finally:
                data.conn.close()
        if path == "/api/scan/status":
            scans = self.app.scans
            if scans is None or scans.targets() is None:
                return self.send_error_json(404, "not found")
            data = self.app.data()
            try:
                return self.send_json(200, scans.status(data.scan_triggers))
            finally:
                data.conn.close()
        if path == "/api/about":
            data = self.app.data()
            try:
                return self.send_json(200, {**self.app.about, "scanners_in_use": data.latest_scanners()})
            finally:
                data.conn.close()
        data = self.app.data()
        try:
            if path == "/api/repos":
                return self.send_json(200, {"repos": data.repos()})
            repo = _one(query, "repo", 200)
            if not repo:
                return self.send_error_json(400, "repo is required")
            repo_id = data.repo_id(repo)
            if repo_id is None:
                return self.send_error_json(404, "unknown repository")
            if path == "/api/overview":
                return self.send_json(200, {"repo": repo, **self.app.overview(data, repo_id)})
            if path == "/api/runs":
                runs = data.runs(repo_id, _int(query, "limit", 100, 1, 500), _int(query, "offset", 0, 0, 10**9))
                return self.send_json(200, {"repo": repo, **runs, "deletions": data.deletions(repo)})
            if path == "/api/similar":
                threshold = _threshold(query)
                return self.send_json(
                    200,
                    {"repo": repo, **data.similar(repo_id, _finding_key(query), threshold, _flag(query, "all_repos"))},
                )
            if path == "/api/review/history":
                return self.send_json(200, {"repo": repo, "history": data.review_history(repo, _finding_key(query))})
            if path == "/api/changes":
                week = _one(query, "week", 10)
                change = _one(query, "change", 5)
                if not week or not _WEEK.match(week) or change not in ("new", "fixed"):
                    raise ValueError("week and change")
                picked = self.app.change_keys(data, repo_id, week, change)
                page = data.changes(
                    repo_id,
                    week,
                    change,
                    _int(query, "limit", 200, 1, 500),
                    _int(query, "offset", 0, 0, 10**9),
                    picked=picked,
                )
                return self.send_json(200, {"repo": repo, **page})
            run_id = data.resolve_run(repo_id, _int(query, "run", None, 0, 2**62))
            if run_id is None:
                return self.send_error_json(404, "no such run for this repository")
            limit, offset = _int(query, "limit", 200, 1, 500), _int(query, "offset", 0, 0, 10**9)
            if path == "/api/finding":
                found = data.finding(repo_id, run_id, _finding_key(query))
                if found is None:
                    return self.send_error_json(404, "no such finding in this run")
                return self.send_json(
                    200,
                    {"repo": repo, "run": run_id, "finding": found, "history": data.review_history(repo, found["key"])},
                )
            if path == "/api/run":
                return self.send_json(200, {"repo": repo, "run": data.run(repo_id, run_id)})
            if path == "/api/stale":
                return self.send_json(200, {"repo": repo, **data.stale(run_id, limit, offset)})
            if path == "/api/suppressions":
                return self.send_json(200, {"repo": repo, **data.suppressions(run_id, limit, offset)})
            if path == "/api/files":
                kind = _one(query, "kind", 30)
                if kind and kind not in FILE_KINDS:
                    raise ValueError("kind")
                return self.send_json(200, {"repo": repo, **data.files(run_id, kind or None, limit, offset)})
            if path in ("/api/findings", "/api/rule"):
                if path == "/api/rule":
                    rule = _one(query, "rule")
                    if not rule:
                        return self.send_error_json(400, "rule is required")
                    return self.send_json(200, {"repo": repo, **data.rule(repo_id, run_id, rule)})
                severity = _one(query, "severity", 10)
                if severity and severity not in SEVERITIES:
                    return self.send_error_json(400, "severity must be ERROR, WARNING or INFO")
                age = _age(query)
                if age is not None and run_id != data.resolve_run(repo_id, None):
                    return self.send_error_json(
                        400, "age is only available for the latest trend run, the one the age chart describes"
                    )
                result = data.findings(
                    repo_id,
                    run_id,
                    severity=severity or None,
                    rule=_one(query, "rule") or None,
                    component=_one(query, "component", 200) or None,
                    path=_one(query, "path") or None,
                    new=_flag(query, "new"),
                    new_blocking=_flag(query, "new_blocking"),
                    age=age,
                    blocking=_flag(query, "blocking"),
                    baselined=_flag(query, "baselined"),
                    sort=_sort(query),
                    review=_review_filter(query),
                    limit=limit,
                    offset=offset,
                )
                return self.send_json(200, {"repo": repo, **result})
            return self.send_error_json(404, "not found")
        finally:
            data.conn.close()


def build_server(config: ServeConfig) -> DashboardServer:
    if not config.hosts:
        raise SetupError("name at least one host name or address the dashboard is reached at (--host)")
    app = App(config)
    ctx = tls_context(config.cert, config.key)
    server = DashboardServer((config.bind, config.port), app, ctx)
    # With --port 0 the system picks the port; the Host allowlist must use the real one.
    app.allowed_hosts = allowed_host_headers(config.hosts, server.server_address[1])
    return server


def serve(config: ServeConfig) -> None:
    server = build_server(config)
    port = server.server_address[1]
    hosts = ", ".join(f"https://{h}" for h in sorted(allowed_host_headers(config.hosts, port)))
    print(f"shoalscan serve: HTTPS only on {config.bind}:{port}; open {hosts}", flush=True)
    if server.app.setup_code:
        print(
            "shoalscan serve: sign-in is not set up yet. Open /setup on the dashboard and enter this one-time "
            f"setup code:\n\n    {server.app.setup_code}\n\n"
            "It works only while the dashboard runs; a restart prints a new one.",
            flush=True,
        )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
