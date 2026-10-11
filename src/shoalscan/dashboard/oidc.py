"""Sign-in through an external OpenID Connect provider, such as Dex.

The flow is the authorization code flow with PKCE (S256), a `state` bound to
a short-lived cookie, and a `nonce`. The dashboard is a confidential client:
it sends its client secret straight to the provider's token endpoint over
TLS, and checks the ID token it gets back:

- its RS256 signature, against the provider's published keys (JWKS), with
  RSA done in plain Python (RSASSA-PKCS1-v1_5 verification needs only
  modular exponentiation, which Python's integers provide); keys shorter
  than 2048 bits and every other algorithm are refused;
- its issuer, audience (and authorised party), expiry, issue time and nonce.

The provider must be reached over https, with certificates checked (against
a given CA bundle when the provider uses a private CA); plain http is
accepted only for a provider on the loopback interface. Requests ignore
proxy settings and have deadlines.

The configuration lives in `oidc.toml` in the dashboard's state directory
(mode 0600: it holds the client secret). It is written by the setup wizard,
which needs a one-time code printed on the server's console, or by hand.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import ssl
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from shoalscan.dashboard.auth import write_private_file
from shoalscan.errors import SetupError

CONFIG_FILE = "oidc.toml"
TIMEOUT_SECONDS = 15
MAX_RESPONSE_BYTES = 1024 * 1024
CLOCK_SKEW_SECONDS = 120
MIN_RSA_BITS = 2048
LOGIN_SECONDS = 600
MAX_PENDING = 1000
DEFAULT_SCOPES = ("openid", "email", "profile", "groups")
LOOPBACK = ("127.0.0.1", "::1", "localhost")
# DER prefix of a SHA-256 DigestInfo (RFC 8017, section 9.2).
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
_CLAIM = re.compile(r"^[A-Za-z0-9_.:/-]{1,100}$")


class OidcError(Exception):
    """The provider could not be used, or what it answered cannot be trusted."""


# ------------------------------------------------------------------ configuration


@dataclass(frozen=True)
class Config:
    issuer: str
    client_id: str
    client_secret: str
    # The callback URL registered at the provider: https://<dashboard host:port>/oidc/callback.
    redirect_uri: str
    ca_file: str | None = None
    # A user is an admin when this claim holds this value (in a list, as a string, or as `true`).
    admin_claim: str = "groups"
    admin_value: str = "shoal-admin"
    scopes: tuple[str, ...] = DEFAULT_SCOPES
    display_name: str = "your identity provider"


def validate_url(url: object, what: str) -> str:
    """An https URL, or http on the loopback interface, with no user name, query or fragment."""
    if not isinstance(url, str) or len(url) > 500:
        raise SetupError(f"the {what} must be a URL")
    parts = urllib.parse.urlsplit(url)
    secure = parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in LOOPBACK)
    if not secure or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise SetupError(f"the {what} must be an https:// URL (http only on this machine), with no query: {url!r}")
    return url.rstrip("/")


def validate(raw: dict) -> Config:
    """Check a configuration from the wizard or the file; anything unexpected is refused."""
    required = {"issuer", "client_id", "client_secret", "redirect_uri"}
    allowed = required | {"ca_file", "admin_claim", "admin_value", "scopes", "display_name"}
    if not isinstance(raw, dict) or set(raw) - allowed or not required <= set(raw):
        raise SetupError(
            f"the OIDC configuration needs {', '.join(sorted(required))}, and may have "
            f"{', '.join(sorted(allowed - required))}"
        )
    issuer = validate_url(raw["issuer"], "issuer")
    redirect = raw["redirect_uri"]
    parts = urllib.parse.urlsplit(redirect) if isinstance(redirect, str) else None
    if parts is None or parts.scheme != "https" or not parts.hostname or parts.path != "/oidc/callback" or parts.query:
        raise SetupError("the redirect URI must be https://<the dashboard's host and port>/oidc/callback")
    client_id, secret = raw["client_id"], raw["client_secret"]
    if not isinstance(client_id, str) or not 0 < len(client_id) <= 200 or any(c.isspace() for c in client_id):
        raise SetupError("the client id must be a single word")
    if not isinstance(secret, str) or not 8 <= len(secret) <= 500:
        raise SetupError("the client secret must be 8 to 500 characters")
    ca_file = raw.get("ca_file") or None
    if ca_file is not None:
        if not isinstance(ca_file, str) or not Path(ca_file).is_absolute() or not Path(ca_file).is_file():
            raise SetupError("the CA bundle must be the absolute path of a PEM file on this server")
    claim, value = raw.get("admin_claim", "groups"), raw.get("admin_value", "shoal-admin")
    if not isinstance(claim, str) or not _CLAIM.match(claim) or not isinstance(value, str) or not 0 < len(value) <= 200:
        raise SetupError("the admin claim must be a claim name, and its value a non-empty string")
    scopes = raw.get("scopes", list(DEFAULT_SCOPES))
    if (
        not isinstance(scopes, list)
        or "openid" not in scopes
        or not all(isinstance(s, str) and _CLAIM.match(s) for s in scopes)
    ):
        raise SetupError("the scopes must be a list of scope names that includes openid")
    name = raw.get("display_name", "your identity provider")
    if not isinstance(name, str) or not 0 < len(name) <= 60:
        raise SetupError("the display name must be up to 60 characters")
    return Config(issuer, client_id, secret, redirect, ca_file, claim, value, tuple(dict.fromkeys(scopes)), name)


def _toml(value: str) -> str:
    return json.dumps(value)


def save(state_dir: Path, config: Config) -> None:
    lines = [
        "# Written by the Shoalscan setup wizard. It holds the client secret: keep it private (mode 0600).",
        f"issuer = {_toml(config.issuer)}",
        f"client_id = {_toml(config.client_id)}",
        f"client_secret = {_toml(config.client_secret)}",
        f"redirect_uri = {_toml(config.redirect_uri)}",
        f"admin_claim = {_toml(config.admin_claim)}",
        f"admin_value = {_toml(config.admin_value)}",
        f"scopes = [{', '.join(_toml(s) for s in config.scopes)}]",
        f"display_name = {_toml(config.display_name)}",
    ]
    if config.ca_file:
        lines.append(f"ca_file = {_toml(config.ca_file)}")
    write_private_file(state_dir / CONFIG_FILE, "\n".join(lines) + "\n")


def load(state_dir: Path) -> Config | None:
    """The saved configuration, or None when there is none (the dashboard then starts the wizard)."""
    path = state_dir / CONFIG_FILE
    try:
        with open(path, "rb") as handle:
            raw = tomllib.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SetupError(f"{path} is unreadable: {exc}") from None
    if path.stat().st_mode & 0o077:
        raise SetupError(f"{path} holds the client secret and must not be readable by others (chmod 600)")
    return validate(raw)


# ------------------------------------------------------------------ talking to the provider


def _context(config_or_ca: Config | str | None) -> ssl.SSLContext:
    ca = config_or_ca.ca_file if isinstance(config_or_ca, Config) else config_or_ca
    return ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()


def _request(url: str, ca_file: str | None, data: bytes | None = None, headers: dict | None = None) -> dict:
    validate_url(url, "provider URL")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=_context(ca_file))
    )
    request = urllib.request.Request(url, data=data, headers={"Accept": "application/json", **(headers or {})})
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        with exc:
            detail = exc.read(1000).decode("utf-8", errors="replace")
        try:
            detail = json.loads(detail).get("error_description") or json.loads(detail).get("error") or detail
        except (ValueError, AttributeError):
            pass
        raise OidcError(f"{url} answered {exc.code}: {str(detail)[:200]}") from None
    except ssl.SSLError as exc:
        raise OidcError(
            f"the TLS certificate of {url} could not be verified ({exc.reason}); give the provider's CA bundle"
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, ssl.SSLError):
            raise OidcError(
                f"the TLS certificate of {url} could not be verified ({reason.reason}); give the provider's CA bundle"
            ) from None
        raise OidcError(f"{url} is not reachable: {reason}") from None
    if len(body) > MAX_RESPONSE_BYTES:
        raise OidcError(f"{url} answered with more than allowed")
    try:
        value = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise OidcError(f"{url} did not answer with JSON") from None
    if not isinstance(value, dict):
        raise OidcError(f"{url} did not answer with a JSON object")
    return value


@dataclass
class Provider:
    """What the provider's discovery document and keys say, checked."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    keys: dict[str, tuple[int, int]] = field(default_factory=dict)  # kid -> (n, e)
    fetched_at: float = 0.0
    checks: list[str] = field(default_factory=list)


def discover(config: Config) -> Provider:
    """Fetch and check the discovery document and the signing keys. Every check passed is listed."""
    doc = _request(f"{config.issuer}/.well-known/openid-configuration", config.ca_file)
    checks = [f"Discovery document read from {config.issuer}/.well-known/openid-configuration"]
    if doc.get("issuer") != config.issuer:
        raise OidcError(f"the provider says its issuer is {doc.get('issuer')!r}, not {config.issuer!r}")
    checks.append("The issuer matches")
    endpoints = {}
    for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        try:
            endpoints[name] = validate_url(doc.get(name), name)
        except SetupError as exc:
            raise OidcError(str(exc)) from None
    checks.append("The authorization, token and key endpoints are https (or on this machine)")
    if "RS256" not in (doc.get("id_token_signing_alg_values_supported") or []):
        raise OidcError("the provider does not sign ID tokens with RS256, the only algorithm Shoalscan accepts")
    if "S256" not in (doc.get("code_challenge_methods_supported") or ["S256"]):
        raise OidcError("the provider does not support PKCE with S256")
    checks.append("ID tokens are signed with RS256, and PKCE (S256) is supported")
    missing = [s for s in config.scopes if s not in (doc.get("scopes_supported") or config.scopes)]
    if missing:
        raise OidcError(f"the provider does not offer the scopes {', '.join(missing)}")
    checks.append(f"The scopes {', '.join(config.scopes)} are offered")
    provider = Provider(
        doc["issuer"],
        endpoints["authorization_endpoint"],
        endpoints["token_endpoint"],
        endpoints["jwks_uri"],
        checks=checks,
    )
    refresh_keys(provider, config)
    checks.append(
        f"{len(provider.keys)} RSA signing key(s) of {MIN_RSA_BITS} bits or more read from {provider.jwks_uri}"
    )
    return provider


def _b64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def check_client(provider: Provider, config: Config) -> str:
    """Ask the token endpoint about the client id and secret, with a code that cannot be valid.

    A provider answers `invalid_grant` (the code) when it accepted the client,
    and `invalid_client` (or 401) when it did not; nobody is signed in either way.
    """
    try:
        exchange_raw(provider, config, "shoalscan-setup-check", config.redirect_uri, "x" * 43)
    except OidcError as exc:
        text = str(exc)
        if "invalid_client" in text or " answered 401" in text or "unauthorized_client" in text:
            raise OidcError("the provider refused the client id or secret (invalid_client)") from None
        if "invalid_grant" in text or "invalid_request" in text or " answered 400" in text:
            return "The provider accepted the client id and secret"
        raise
    raise OidcError("the token endpoint accepted a made-up code; it cannot be trusted")


def refresh_keys(provider: Provider, config: Config) -> None:
    doc = _request(provider.jwks_uri, config.ca_file)
    keys = {}
    for key in doc.get("keys") or []:
        if not isinstance(key, dict) or key.get("kty") != "RSA" or key.get("use", "sig") != "sig":
            continue
        if key.get("alg", "RS256") != "RS256" or not isinstance(key.get("kid"), str):
            continue
        try:
            n, e = int.from_bytes(_b64(key["n"]), "big"), int.from_bytes(_b64(key["e"]), "big")
        except (KeyError, TypeError, ValueError):
            continue
        if n.bit_length() >= MIN_RSA_BITS and e >= 3:
            keys[key["kid"]] = (n, e)
    if not keys:
        raise OidcError(f"{provider.jwks_uri} has no usable RS256 signing key of {MIN_RSA_BITS} bits or more")
    provider.keys, provider.fetched_at = keys, time.monotonic()


def rs256_verify(n: int, e: int, message: bytes, signature: bytes) -> bool:
    """RSASSA-PKCS1-v1_5 verification with SHA-256 (RFC 8017, section 8.2.2)."""
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    encoded = pow(s, e, n).to_bytes(k, "big")
    t = _SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    if k < len(t) + 11:
        return False
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac.compare_digest(encoded, expected)


# ------------------------------------------------------------------ the login flow


@dataclass
class Pending:
    """A login on its way to the provider and back."""

    nonce: str
    verifier: str
    created: float


class Logins:
    """Logins in progress, keyed by their `state`; each is used once and expires after LOGIN_SECONDS."""

    def __init__(self):
        self._lock = threading.Lock()
        self._items: dict[str, Pending] = {}

    def start(self) -> tuple[str, Pending]:
        state = secrets.token_urlsafe(32)
        pending = Pending(secrets.token_urlsafe(32), secrets.token_urlsafe(48), time.monotonic())
        with self._lock:
            now = time.monotonic()
            self._items = {k: v for k, v in self._items.items() if now - v.created < LOGIN_SECONDS}
            if len(self._items) >= MAX_PENDING:
                self._items.pop(next(iter(self._items)))
            self._items[state] = pending
        return state, pending

    def finish(self, state: str | None) -> Pending | None:
        if not state or len(state) > 100:
            return None
        with self._lock:
            pending = self._items.pop(state, None)
        if pending is None or time.monotonic() - pending.created >= LOGIN_SECONDS:
            return None
        return pending


def authorization_url(provider: Provider, config: Config, state: str, pending: Pending) -> str:
    challenge = base64.urlsafe_b64encode(hashlib.sha256(pending.verifier.encode()).digest()).rstrip(b"=").decode()
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "scope": " ".join(config.scopes),
            "state": state,
            "nonce": pending.nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    separator = "&" if "?" in provider.authorization_endpoint else "?"
    return f"{provider.authorization_endpoint}{separator}{query}"


def exchange(provider: Provider, config: Config, code: str, pending: Pending) -> dict:
    """Swap the code for tokens at the token endpoint, and return the ID token's checked claims."""
    if not isinstance(code, str) or not 0 < len(code) <= 2000:
        raise OidcError("the provider sent back no usable code")
    tokens = exchange_raw(provider, config, code, config.redirect_uri, pending.verifier)
    id_token = tokens.get("id_token")
    if not isinstance(id_token, str):
        raise OidcError("the token endpoint returned no ID token")
    return verify_id_token(provider, config, id_token, pending.nonce)


def exchange_raw(provider: Provider, config: Config, code: str, redirect_uri: str, verifier: str) -> dict:
    """POST the authorization code to the token endpoint, authenticating with the client secret."""
    credentials = base64.b64encode(
        f"{urllib.parse.quote(config.client_id, safe='')}:{urllib.parse.quote(config.client_secret, safe='')}".encode()
    ).decode()
    body = urllib.parse.urlencode(
        {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri, "code_verifier": verifier}
    ).encode()
    return _request(
        provider.token_endpoint,
        config.ca_file,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Authorization": f"Basic {credentials}"},
    )


def verify_id_token(provider: Provider, config: Config, token: str, nonce: str, now: float | None = None) -> dict:
    """Check an ID token's signature and claims; return the claims."""
    parts = token.split(".")
    if len(parts) != 3 or len(token) > 20000:
        raise OidcError("the ID token is not a signed JWT")
    try:
        header, claims, signature = json.loads(_b64(parts[0])), json.loads(_b64(parts[1])), _b64(parts[2])
    except (ValueError, UnicodeDecodeError):
        raise OidcError("the ID token cannot be read") from None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise OidcError("the ID token cannot be read")
    if header.get("alg") != "RS256":
        raise OidcError(f"the ID token is signed with {header.get('alg')!r}; only RS256 is accepted")
    kid = header.get("kid")
    if kid not in provider.keys:
        refresh_keys(provider, config)  # the provider may have rotated its keys
    if kid not in provider.keys:
        raise OidcError("the ID token is signed with a key the provider does not publish")
    n, e = provider.keys[kid]
    if not rs256_verify(n, e, f"{parts[0]}.{parts[1]}".encode("ascii"), signature):
        raise OidcError("the ID token's signature is not valid")
    now = time.time() if now is None else now
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if claims.get("iss") != provider.issuer:
        raise OidcError("the ID token is from another issuer")
    if config.client_id not in audiences or (len(audiences) > 1 and claims.get("azp") != config.client_id):
        raise OidcError("the ID token is for another client")
    for name in ("exp", "iat"):
        if not isinstance(claims.get(name), (int, float)) or isinstance(claims.get(name), bool):
            raise OidcError(f"the ID token has no {name}")
    if claims["exp"] < now - CLOCK_SKEW_SECONDS or claims["iat"] > now + CLOCK_SKEW_SECONDS:
        raise OidcError("the ID token has expired, or is from the future")
    if isinstance(claims.get("nbf"), (int, float)) and claims["nbf"] > now + CLOCK_SKEW_SECONDS:
        raise OidcError("the ID token is not valid yet")
    if not isinstance(claims.get("nonce"), str) or not hmac.compare_digest(claims["nonce"], nonce):
        raise OidcError("the ID token's nonce does not match this login")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise OidcError("the ID token names no subject")
    return claims


def is_admin(config: Config, claims: dict) -> bool:
    """Does the admin claim hold the admin value: in a list, as the string itself, or as `true`?"""
    value = claims.get(config.admin_claim)
    if isinstance(value, list):
        return config.admin_value in value
    if isinstance(value, bool):
        return value and config.admin_value.lower() == "true"
    return isinstance(value, str) and value == config.admin_value
