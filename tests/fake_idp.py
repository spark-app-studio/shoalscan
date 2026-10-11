"""A small OpenID Connect provider for the tests: discovery, keys, authorize and token endpoints.

It runs over plain HTTP on the loopback interface (which the dashboard accepts
only there), with an RSA key made by `openssl` and ID tokens signed in plain
Python. `misbehave` makes it send tokens that must be refused.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import re
import secrets
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import helpers  # noqa: F401 - puts src/ on the import path

from shoalscan.dashboard import oidc

_KEY: tuple[int, int, int] | None = None  # (n, e, d), made once per test run


def rsa_key() -> tuple[int, int, int]:
    global _KEY
    if _KEY is None:
        with tempfile.TemporaryDirectory() as tmp:
            pem = Path(tmp) / "key.pem"
            subprocess.run(["openssl", "genrsa", "-out", str(pem), "2048"], check=True, capture_output=True, timeout=60)
            text = subprocess.run(
                ["openssl", "rsa", "-in", str(pem), "-text", "-noout"],
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            ).stdout

        def field(name: str) -> int:
            match = re.search(rf"^{name}:\s*\n((?:\s+[0-9a-f:]+\n)+)", text, re.M)
            return int(re.sub(r"[\s:]", "", match.group(1)), 16)

        _KEY = (field("modulus"), 65537, field("privateExponent"))
    return _KEY


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign_jwt(claims: dict, kid: str = "k1", alg: str = "RS256", key: tuple[int, int, int] | None = None) -> str:
    n, _, d = key or rsa_key()
    head = b64(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
    body = b64(json.dumps(claims).encode())
    k = (n.bit_length() + 7) // 8
    t = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(f"{head}.{body}".encode()).digest()
    encoded = int.from_bytes(b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t, "big")
    return f"{head}.{body}.{b64(pow(encoded, d, n).to_bytes(k, 'big'))}"


class FakeIdP:
    CLIENT_ID = "shoalscan"
    CLIENT_SECRET = "test-client-secret"

    def __init__(self):
        self.misbehave: str | None = None
        self.user = {"sub": "u-1", "email": "alice@example.com", "email_verified": True, "groups": []}
        self.codes: dict[str, dict] = {}
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, payload, headers=None):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):  # noqa: N802 - the name http.server looks up
                url = urllib.parse.urlsplit(self.path)
                if url.path == "/.well-known/openid-configuration":
                    return self.reply(200, owner.discovery())
                if url.path == "/keys":
                    n, e, _ = rsa_key()
                    return self.reply(
                        200,
                        {
                            "keys": [
                                {
                                    "kty": "RSA",
                                    "alg": "RS256",
                                    "use": "sig",
                                    "kid": "k1",
                                    "n": b64(n.to_bytes(256, "big")),
                                    "e": b64(e.to_bytes(3, "big")),
                                }
                            ]
                        },
                    )
                if url.path == "/auth":
                    q = dict(urllib.parse.parse_qsl(url.query))
                    code = secrets.token_urlsafe(16)
                    owner.codes[code] = {**q, "user": dict(owner.user)}
                    target = f"{q['redirect_uri']}?{urllib.parse.urlencode({'code': code, 'state': q['state']})}"
                    self.send_response(302)
                    self.send_header("Location", target)
                    self.end_headers()
                    return None
                return self.reply(404, {"error": "not_found"})

            def do_POST(self):  # noqa: N802 - the name http.server looks up
                form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
                expected = base64.b64encode(f"{owner.CLIENT_ID}:{owner.CLIENT_SECRET}".encode()).decode()
                if self.headers.get("Authorization") != f"Basic {expected}":
                    return self.reply(401, {"error": "invalid_client"})
                grant = owner.codes.pop(form.get("code", ""), None)
                if grant is None or form.get("redirect_uri") != grant["redirect_uri"]:
                    return self.reply(400, {"error": "invalid_grant"})
                challenge = b64(hashlib.sha256(form.get("code_verifier", "").encode()).digest())
                if challenge != grant["code_challenge"] or grant["code_challenge_method"] != "S256":
                    return self.reply(400, {"error": "invalid_grant", "error_description": "PKCE check failed"})
                return self.reply(
                    200, {"access_token": "at", "token_type": "Bearer", "id_token": owner.id_token(grant)}
                )

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.issuer = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def discovery(self) -> dict:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/auth",
            "token_endpoint": f"{self.issuer}/token",
            "jwks_uri": f"{self.issuer}/keys",
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["openid", "email", "profile", "groups"],
        }

    def id_token(self, grant: dict) -> str:
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "aud": self.CLIENT_ID,
            "iat": now,
            "exp": now + 300,
            "nonce": grant["nonce"],
            **grant["user"],
        }
        bad = self.misbehave
        if bad == "wrong_audience":
            claims["aud"] = "someone-else"
        elif bad == "expired":
            claims["exp"], claims["iat"] = now - 3600, now - 7200
        elif bad == "wrong_nonce":
            claims["nonce"] = "not-the-nonce"
        elif bad == "wrong_issuer":
            claims["iss"] = "https://evil.example"
        token = sign_jwt(claims)
        if bad == "bad_signature":
            head, body, sig = token.split(".")
            token = f"{head}.{body}.{sig[:-4]}AAAA"
        elif bad == "alg_none":
            head, body, _ = token.split(".")
            token = f"{b64(json.dumps({'alg': 'none', 'kid': 'k1'}).encode())}.{body}."
        elif bad == "unknown_key":
            token = sign_jwt(claims, kid="k9")
        return token

    def config(self, **overrides) -> oidc.Config:
        raw = {
            "issuer": self.issuer,
            "client_id": self.CLIENT_ID,
            "client_secret": self.CLIENT_SECRET,
            "redirect_uri": "https://127.0.0.1/oidc/callback",
            **overrides,
        }
        return oidc.validate(raw, ca_file=raw.get("ca_file"))

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def dashboard(port: int, ctx, method: str, path: str, headers: dict | None = None):
    """One request to a dashboard on 127.0.0.1; returns (status, every header as (name, value), body)."""
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=10)
    try:
        conn.request(method, path, headers=headers or {})
        res = conn.getresponse()
        return res.status, res.getheaders(), res.read()
    finally:
        conn.close()


def sign_in(
    port: int, ctx, idp: FakeIdP, email="alice@example.com", groups=(), verified=True, sub=None, headers_out=None
):
    """Go through the whole sign-in against a dashboard. Returns (session cookie or None, where it sent the browser)."""
    idp.user = {"sub": sub or f"sub-{email}", "email": email, "email_verified": verified, "groups": list(groups)}
    status, headers, _ = dashboard(port, ctx, "GET", "/oidc/start")
    found = dict(headers)
    if status != 303 or not found["Location"].startswith(idp.issuer):
        return None, found.get("Location")
    login_cookie = found["Set-Cookie"].split(";")[0]

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))
    try:
        opener.open(found["Location"], timeout=10)
        raise AssertionError("the provider did not redirect back")
    except urllib.error.HTTPError as exc:
        with exc:
            back = urllib.parse.urlsplit(exc.headers["Location"])
    status, headers, _ = dashboard(port, ctx, "GET", f"{back.path}?{back.query}", {"Cookie": login_cookie})
    if headers_out is not None:
        headers_out.extend(headers)
    if status != 200:
        return None, dict(headers).get("Location")
    for name, value in headers:
        if name.lower() == "set-cookie" and value.startswith("__Host-shoalscan="):
            return value.split(";")[0].split("=", 1)[1], "/"
    return None, None
