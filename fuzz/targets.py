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
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for extra in (ROOT / "src", ROOT / "tests"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from shoalscan import gitleaks, hadolint, markdown, suppressions, trivy, zizmor  # noqa: E402
from shoalscan.baseline import baseline_from_bytes  # noqa: E402
from shoalscan.config import config_from_bytes  # noqa: E402
from shoalscan.dashboard import oidc  # noqa: E402
from shoalscan.errors import ScanError, SetupError  # noqa: E402
from shoalscan.findings import Finding, load_findings  # noqa: E402


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
    assert not any(markdown.is_format_control(c) for c in out), "a C1 or bidirectional control got through"
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


# ------------------------------------------------------------------ scanner output


# A small repository the scanner reports point into. Reports name files by absolute path, so an input may
# write $ROOT for this directory's path, which lets the fuzzer reach the code past the path checks.
_REPO_FILES = {
    "Dockerfile": "FROM python:3.12 AS build\nRUN pip install x\nFROM scratch\nCOPY --from=build /a /a\n",
    "main.tf": 'resource "aws_s3_bucket" "logs" {\n  acl = "public-read"\n}\n',
    ".github/workflows/ci.yml": "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n",
    "src/app.py": "class Svc:\n    def run(self):\n        token = 'not-a-real-token-0123'\n",
}
_REPO: Path | None = None


def _repo() -> Path:
    global _REPO
    if _REPO is None:
        _REPO = Path(tempfile.mkdtemp(prefix="shoalscan-fuzz-")).resolve()
        for rel, text in _REPO_FILES.items():
            (_REPO / rel).parent.mkdir(parents=True, exist_ok=True)
            (_REPO / rel).write_text(text, encoding="utf-8")
    return _REPO


def _report(data: bytes) -> object:
    """The input as a scanner's JSON report, with $ROOT standing for the repository; None when not JSON."""
    try:
        return json.loads(_text(data).replace("$ROOT", json.dumps(str(_repo()))[1:-1]))
    except (ValueError, RecursionError):
        return None


def _check_findings(findings: object, tool: str) -> None:
    """Well-formed findings of one tool, each in a file of the repository."""
    assert isinstance(findings, list)
    root = _repo()
    for f in findings:
        assert isinstance(f, Finding) and f.tool == tool and f.rule.startswith(f"{tool}.")
        assert f.severity in ("ERROR", "WARNING", "INFO")
        assert isinstance(f.line, int) and not isinstance(f.line, bool) and f.line >= 1
        assert all(isinstance(v, str) for v in (f.path, f.fingerprint, f.component, f.message)) and f.fingerprint
        assert not f.path.startswith("/") and ".." not in f.path.split("/"), f"a path outside the repository: {f.path}"
        assert f.path != ".git" and not f.path.startswith(".git/")
        assert (root / f.path).resolve().is_relative_to(root)


def gitleaks_report(data: bytes) -> None:
    """Gitleaks' JSON report: findings in the repository, or a ScanError."""
    report = _report(data)
    if not isinstance(report, list):  # `execute` refuses anything else first
        return
    try:
        findings = gitleaks.normalise(report, _repo(), {"src/": "api"}, ("vendor/**",))
    except ScanError:
        return
    _check_findings(findings, gitleaks.TOOL)


def trivy_report(data: bytes) -> None:
    """Trivy's JSON report: findings and rule metadata, or a ScanError."""
    report = _report(data)
    if not isinstance(report, dict) or not isinstance(report.get("Results", []), list):
        return
    try:
        findings, meta = trivy.normalise(report, _repo(), {}, (), ("AVD-DS-0001",))
    except ScanError:
        return
    _check_findings(findings, trivy.TOOL)
    assert isinstance(meta, dict) and set(meta) >= {f.rule for f in findings}
    for m in meta.values():
        assert all(isinstance(u, str) and u.startswith("https://") for u in m["references"])


def hadolint_report(data: bytes) -> None:
    """Hadolint's JSON output: findings and parse errors for the Dockerfiles it was given, or a ScanError."""
    report = _report(data)
    if not isinstance(report, list):
        return
    try:
        findings, errors = hadolint.normalise(report, _repo(), {"Dockerfile"}, {})
    except ScanError:
        return
    _check_findings(findings, hadolint.TOOL)
    assert all(f.path == "Dockerfile" for f in findings)
    assert all(isinstance(e, dict) and e["path"] == "Dockerfile" for e in errors)


def zizmor_report(data: bytes) -> None:
    """zizmor's JSON output: findings in the workflows it was given, or a ScanError."""
    report = _report(data)
    if not isinstance(report, list):
        return
    try:
        findings = zizmor.normalise(report, _repo(), {".github/workflows/ci.yml"}, {}, ("unpinned-uses",))
    except ScanError:
        return
    _check_findings(findings, zizmor.TOOL)
    assert all(f.path == ".github/workflows/ci.yml" for f in findings)


def findings_file(data: bytes) -> None:
    """`findings.json`, which `check` and `record` read back: findings and metadata, or a SetupError or
    ScanError."""
    fd, name = tempfile.mkstemp(prefix="shoalscan-fuzz-", suffix=".json")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        try:
            findings, meta = load_findings(Path(name))
        except (SetupError, ScanError):
            return
    finally:
        os.unlink(name)
    assert isinstance(meta, dict) and "findings" not in meta
    for f in findings:
        assert isinstance(f, Finding)
        assert all(isinstance(v, str) for v in (f.tool, f.rule, f.severity, f.path, f.fingerprint, f.component))
        assert isinstance(f.message, str) and isinstance(f.line, int) and not isinstance(f.line, bool)


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
    "gitleaks_report": gitleaks_report,
    "trivy_report": trivy_report,
    "hadolint_report": hadolint_report,
    "zizmor_report": zizmor_report,
    "findings_file": findings_file,
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
    "gitleaks_report": [
        b'[{"RuleID": "aws-access-token", "Description": "AWS key", "StartLine": 3, "EndLine": 3, '
        b'"StartColumn": 17, "File": "$ROOT/src/app.py", "Secret": "not-a-real-token-0123"}]',
        b'[{"RuleID": "generic-api-key", "StartLine": 0, "EndLine": 9, "StartColumn": 0, "File": "$ROOT/../x"}]',
        b'[{"RuleID": "x", "StartLine": 1, "EndLine": 1, "StartColumn": 1, "File": "$ROOT/.git/config"}]',
        b"[]",
    ],
    "trivy_report": [
        b'{"Results": [{"Target": "main.tf", "Misconfigurations": [{"ID": "AVD-AWS-0086", "Status": "FAIL", '
        b'"Severity": "HIGH", "Title": "Public ACL", "Message": "Bucket is public", "PrimaryURL": '
        b'"https://avd.aquasec.com/x", "References": ["https://a.example", "javascript:x"], "Resolution": "Fix", '
        b'"CauseMetadata": {"Resource": "aws_s3_bucket.logs", "StartLine": 2, "Code": {"Lines": '
        b'[{"Content": "acl = 1", "IsCause": true}]}}}]}]}',
        b'{"Results": [{"Target": "../etc/passwd", "Misconfigurations": [{"ID": "AVD-DS-0002", "Status": "FAIL", '
        b'"Severity": "LOW"}]}]}',
        b'{"Results": [{"Target": "Dockerfile", "Misconfigurations": [{"ID": "AVD-DS-0005", "Status": "FAIL", '
        b'"Severity": "UNKNOWN", "CauseMetadata": {"Code": {"Lines": 5}}, "References": 7}]}]}',
        b'{"Results": [{"Target": "main.tf", "Misconfigurations": [{"ID": "AVD-AWS-0086", "Status": "FAIL", '
        b'"Severity": ["HIGH"]}]}]}',
        b"{}",
    ],
    "hadolint_report": [
        b'[{"code": "DL3008", "level": "warning", "line": 2, "column": 1, "file": "$ROOT/Dockerfile", '
        b'"message": "Pin versions"}]',
        b'[{"code": "DL1000", "level": "error", "line": 1, "file": "$ROOT/Dockerfile", "message": "parse error"}, '
        b'{"code": "SC2086", "level": "info", "line": 99, "file": "$ROOT/Dockerfile"}]',
        b'[{"code": "DL3000", "level": "style", "line": 0, "file": "$ROOT/../Dockerfile"}]',
        b'[{"code": "DL3008", "level": ["error"], "line": 2, "file": "$ROOT/Dockerfile"}]',
    ],
    "zizmor_report": [
        b'[{"ident": "template-injection", "desc": "code injection", "determinations": {"severity": "High"}, '
        b'"locations": [{"symbolic": {"kind": "Primary", "annotation": "here", "key": {"Local": {"verbatim_path": '
        b'"$ROOT/.github/workflows/ci.yml"}}, "route": {"route": [{"Key": "jobs"}, {"Index": 0}]}}, '
        b'"concrete": {"location": {"start_point": {"row": 5, "column": 8}}, "feature": "run: echo"}}]}]',
        b'[{"ident": "artipacked", "determinations": {"severity": "Low"}, "locations": [{"symbolic": {"kind": '
        b'"Primary", "key": {"Local": {"verbatim_path": "$ROOT/main.tf"}}}, "concrete": {}}]}]',
        b'[{"ident": "excessive-permissions", "determinations": {"severity": "Medium"}, "locations": [{"symbolic": '
        b'{"kind": "Primary", "key": {"Local": {"verbatim_path": "$ROOT/.github/workflows/ci.yml"}}, "route": '
        b'{"route": 3}}, "concrete": {"location": {"start_point": [1]}}}]}]',
        b'[{"ident": "artipacked", "determinations": {"severity": {"High": 1}}, "locations": []}]',
    ],
    "findings_file": [
        b'{"format": 1, "complete": true, "findings": [{"tool": "opengrep", "rule": "r.a", "severity": "ERROR", '
        b'"path": "src/a.py", "line": 3, "fingerprint": "aa:0", "component": "api", "message": "m"}]}',
        b'{"format": 1, "complete": true, "findings": [{"tool": 1, "rule": [], "severity": null, "path": {}, '
        b'"line": "3", "fingerprint": true, "component": 0, "message": 2}]}',
        b'{"format": 1, "complete": false}',
        b"[" * 5000,
    ],
}
