"""Fuzz targets: the parsers that read input Shoalscan does not control.

Each target takes arbitrary bytes and checks a contract: the parser either
returns a well-formed result or raises the one error it documents, never
anything else (an unexpected exception is a crash in CI, or a 500 on the
dashboard). Some targets check more, such as the Markdown escaper never
letting markup through.

The targets need only the standard library. `fuzz/run.py` drives them with
Atheris (coverage-guided, in CI); `tests/test_fuzz_targets.py` runs each over
its seeds and some random input in the ordinary test suite.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for extra in (ROOT / "src", ROOT / "tests"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from shoalscan import markdown, suppressions  # noqa: E402
from shoalscan.baseline import baseline_from_bytes  # noqa: E402
from shoalscan.config import config_from_bytes  # noqa: E402
from shoalscan.dashboard import oidc  # noqa: E402
from shoalscan.errors import SetupError  # noqa: E402


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


# ------------------------------------------------------------------ repository files


def config_file(data: bytes) -> None:
    """`.shoalscan.toml` comes from the scanned repository: valid, or a SetupError."""
    try:
        config_from_bytes(data, ".shoalscan.toml")
    except SetupError:
        pass


def baseline_file(data: bytes) -> None:
    """The baseline comes from the scanned repository: entries, or a SetupError."""
    try:
        entries = baseline_from_bytes(data, "baseline")
    except SetupError:
        return
    assert isinstance(entries, list)


def suppression_line(data: bytes) -> None:
    """A source line with Opengrep or Trivy markers: parsed, never an error."""
    line = _text(data)
    for parse in (suppressions.parse_line, suppressions.parse_trivy_line):
        for ids, issue, bare in parse(line):
            assert isinstance(ids, tuple) and all(isinstance(i, str) for i in ids)
            assert issue is None or isinstance(issue, str)
            assert not bare or (ids == () and issue is None), "a bare marker with ids or an issue"


# ------------------------------------------------------------------ Markdown


_SPECIAL = set("\\`*_[]<>|~&@$")
_BLOCK = re.compile(r"^(?:[#+=-]|\d+[.)])")


def markdown_text(data: bytes) -> None:
    """Untrusted text in a work list or report never becomes markup."""
    value = _text(data)
    out = markdown.text(value)
    assert not re.search(r"[\x00-\x1f\x7f\u0085  ]", out), "a control character or line break got through"
    assert not _BLOCK.match(out), "the text starts a block"
    i = 0
    while i < len(out):
        if out[i] == "\\":
            assert i + 1 < len(out) and out[i + 1] in _SPECIAL | set("#+=-.)"), "a stray backslash"
            i += 2
            continue
        assert out[i] not in _SPECIAL, f"an unescaped {out[i]!r}"
        i += 1
    span = markdown.code(value)
    fence = re.match(r"`+", span).group(0)
    inner = span[len(fence) : -len(fence)]
    assert span.endswith(fence) and all(len(run) < len(fence) for run in re.findall(r"`+", inner)), (
        "the code span leaks"
    )
    link = markdown.link(value, value)
    assert link == markdown.text(value) or link.endswith(">)"), "a link to something that is not plain http(s)"


# ------------------------------------------------------------------ OpenID Connect


_ISSUER = "https://idp.example"
_CONFIG = oidc.Config(_ISSUER, "shoalscan", "client-secret", "https://dash.example/oidc/callback")
_NOW = 1_800_000_000.0
_NONCE = "n0nce"


def _provider(n: int, e: int) -> oidc.Provider:
    return oidc.Provider(_ISSUER, f"{_ISSUER}/auth", f"{_ISSUER}/token", f"{_ISSUER}/keys", {"k1": (n, e)})


def _verify(provider: oidc.Provider, token: str) -> dict:
    """verify_id_token, with an unknown key id never reaching the network. Only for this call:
    the targets also run inside the test suite, where other tests need the real refresh."""
    real = oidc.refresh_keys
    oidc.refresh_keys = lambda provider, config: None
    try:
        return oidc.verify_id_token(provider, _CONFIG, token, _NONCE, now=_NOW)
    finally:
        oidc.refresh_keys = real


def id_token(data: bytes) -> None:
    """Any string as an ID token: refused with an OidcError, never another exception."""
    provider = _provider((1 << 2047) | 0x10001, 65537)
    try:
        _verify(provider, _text(data))
    except oidc.OidcError:
        return
    raise AssertionError("an unsigned token was accepted")


_KEY = None


def id_token_claims(data: bytes) -> None:
    """Any JSON as the claims of a correctly signed token: the claim checks hold, or an OidcError."""
    global _KEY
    from fake_idp import rsa_key, sign_jwt

    try:
        claims = json.loads(data)
    except (ValueError, RecursionError):
        return
    if _KEY is None:
        _KEY = rsa_key()
    n, e, _ = _KEY
    try:
        token = sign_jwt(claims, kid="k1", key=_KEY)
    except (ValueError, RecursionError):  # not JSON the signer can write back
        return
    try:
        got = _verify(_provider(n, e), token)
    except oidc.OidcError:
        return
    assert isinstance(got, dict) and got.get("iss") == _ISSUER and got.get("nonce") == _NONCE
    audience = got["aud"] if isinstance(got.get("aud"), list) else [got.get("aud")]
    assert _CONFIG.client_id in audience
    assert isinstance(got.get("sub"), str) and got["sub"]
    assert got["exp"] >= _NOW - oidc.CLOCK_SKEW_SECONDS


TARGETS = {
    "config_file": config_file,
    "baseline_file": baseline_file,
    "suppression_line": suppression_line,
    "markdown_text": markdown_text,
    "id_token": id_token,
    "id_token_claims": id_token_claims,
}

# A few inputs per target, as a start for the fuzzer and for the unit test.
SEEDS = {
    "config_file": [
        b'blocking = ["ERROR"]\nexcludes = ["vendor/**"]\n[components]\n"api/" = "api"\n',
        b'scanners = ["opengrep", "gitleaks"]\n[limits]\nscan_timeout_seconds = 600\n',
        b"a = " + b"[" * 3000,
    ],
    "baseline_file": [
        b'[[entry]]\ntool = "opengrep"\nrule = "r.a"\npath = "src/a.py"\nfingerprint = "aa:0"\n'
        b'issue = "#1"\nreason = "False positive: test"\n',
        b"[[entry]]\n",
        b"a = " + b"{x = " * 3000,
    ],
    "suppression_line": [
        b"x = eval(y)  # nosemgrep: python.lang.security.eval -- #12",
        b"# trivy:ignore:AVD-DS-0002 #34",
        b"// nosemgrep",
        b'# trivy:ignore:* nosemgrep: a, b c, "d"',
    ],
    "markdown_text": [
        b"[click](javascript:alert(1)) <img src=x> | a | ~~x~~ @me $x$ &amp;",
        b"# heading\n- item",
        b"1. ``code`` ```",
        b"https://example.com/a(b)",
    ],
    "id_token": [
        b"eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.e30.AAAA",
        b"eyJhbGciOiJub25lIn0.e30.",
        b"a.b.c",
        b"...",
    ],
    "id_token_claims": [
        json.dumps(
            {"iss": _ISSUER, "aud": "shoalscan", "exp": _NOW + 60, "iat": _NOW, "nonce": _NONCE, "sub": "u1"}
        ).encode(),
        json.dumps({"iss": _ISSUER, "aud": ["shoalscan", "x"], "exp": "soon", "iat": True, "nonce": [_NONCE]}).encode(),
        b'{"aud": {"shoalscan": 1}, "exp": 1e400, "iat": -1e400, "nbf": NaN}',
        b"[]",
    ],
}
