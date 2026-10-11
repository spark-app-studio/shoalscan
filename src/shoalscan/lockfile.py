"""Load and validate `tools.lock`, and verify files against it."""

from __future__ import annotations

import hashlib
import platform
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from shoalscan.errors import SetupError, VerificationError

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PLATFORMS = ("darwin-x86_64", "darwin-arm64", "linux-x86_64", "linux-arm64")


@dataclass(frozen=True)
class Asset:
    url: str
    sha256: str


@dataclass(frozen=True)
class OpengrepSignature:
    certificate_identity: str
    certificate_oidc_issuer: str
    github_workflow_repository: str
    github_workflow_sha: str


@dataclass(frozen=True)
class OpengrepPlatform:
    binary: Asset
    signature: Asset
    certificate: Asset


@dataclass(frozen=True)
class RulesSnapshot:
    name: str
    repository: str
    commit: str
    archive: Asset
    license: str
    languages: tuple[str, ...]
    files_sha256: str


@dataclass(frozen=True)
class Lock:
    opengrep_version: str
    opengrep_signature: OpengrepSignature
    opengrep: dict[str, OpengrepPlatform]
    cosign_version: str
    cosign: dict[str, Asset]
    rules: RulesSnapshot


def current_platform() -> str:
    """Return this machine's platform key, such as `linux-x86_64`."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {"x86_64": "x86_64", "amd64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    if system not in ("darwin", "linux") or arch is None:
        raise SetupError(f"unsupported platform: {platform.system()} {platform.machine()}")
    return f"{system}-{arch}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sha256(path: Path, expected: str) -> None:
    """Raise VerificationError unless the file's SHA-256 equals `expected`."""
    actual = sha256_file(path)
    if actual != expected:
        raise VerificationError(
            f"SHA-256 mismatch for {path.name}: expected {expected}, got {actual}"
        )


def _table(data: object, where: str, keys: set[str]) -> dict:
    if not isinstance(data, dict):
        raise SetupError(f"tools.lock: {where} must be a table")
    unknown = set(data) - keys
    if unknown:
        raise SetupError(f"tools.lock: unknown keys in {where}: {', '.join(sorted(unknown))}")
    missing = keys - set(data)
    if missing:
        raise SetupError(f"tools.lock: missing keys in {where}: {', '.join(sorted(missing))}")
    return data


def _str(data: dict, key: str, where: str) -> str:
    value = data[key]
    if not isinstance(value, str) or not value:
        raise SetupError(f"tools.lock: {where}.{key} must be a non-empty string")
    return value


def _url(data: dict, key: str, where: str) -> str:
    value = _str(data, key, where)
    if not value.startswith("https://"):
        raise SetupError(f"tools.lock: {where}.{key} must be an https:// URL")
    return value


def _sha(data: dict, key: str, where: str) -> str:
    value = _str(data, key, where)
    if not SHA256_RE.match(value):
        raise SetupError(f"tools.lock: {where}.{key} must be a lowercase hex SHA-256")
    return value


def _platforms(data: object, where: str) -> dict:
    if not isinstance(data, dict) or not data:
        raise SetupError(f"tools.lock: {where} must be a non-empty table")
    unknown = set(data) - set(PLATFORMS)
    if unknown:
        raise SetupError(f"tools.lock: unknown platforms in {where}: {', '.join(sorted(unknown))}")
    return data


def parse_lock(data: dict) -> Lock:
    top = _table(data, "the top level", {"lock_version", "opengrep", "cosign", "rules"})
    if top["lock_version"] != 1:
        raise SetupError("tools.lock: unsupported lock_version (expected 1)")

    og = _table(top["opengrep"], "[opengrep]", {"version", "source", "license", "signature", "platforms"})
    sig = _table(
        og["signature"],
        "[opengrep.signature]",
        {"certificate_identity", "certificate_oidc_issuer", "github_workflow_repository", "github_workflow_sha"},
    )
    signature = OpengrepSignature(
        certificate_identity=_url(sig, "certificate_identity", "opengrep.signature"),
        certificate_oidc_issuer=_url(sig, "certificate_oidc_issuer", "opengrep.signature"),
        github_workflow_repository=_str(sig, "github_workflow_repository", "opengrep.signature"),
        github_workflow_sha=_str(sig, "github_workflow_sha", "opengrep.signature"),
    )
    if not COMMIT_RE.match(signature.github_workflow_sha):
        raise SetupError("tools.lock: opengrep.signature.github_workflow_sha must be a 40-character commit")
    opengrep = {}
    for name, entry in _platforms(og["platforms"], "[opengrep.platforms]").items():
        where = f"opengrep.platforms.{name}"
        entry = _table(
            entry,
            f"[{where}]",
            {"url", "sha256", "signature_url", "signature_sha256", "certificate_url", "certificate_sha256"},
        )
        opengrep[name] = OpengrepPlatform(
            binary=Asset(_url(entry, "url", where), _sha(entry, "sha256", where)),
            signature=Asset(_url(entry, "signature_url", where), _sha(entry, "signature_sha256", where)),
            certificate=Asset(_url(entry, "certificate_url", where), _sha(entry, "certificate_sha256", where)),
        )

    co = _table(top["cosign"], "[cosign]", {"version", "source", "checksums_url", "license", "platforms"})
    cosign = {}
    for name, entry in _platforms(co["platforms"], "[cosign.platforms]").items():
        where = f"cosign.platforms.{name}"
        entry = _table(entry, f"[{where}]", {"url", "sha256"})
        cosign[name] = Asset(_url(entry, "url", where), _sha(entry, "sha256", where))

    ru = _table(
        top["rules"],
        "[rules]",
        {"name", "repository", "commit", "url", "sha256", "license", "languages", "files_sha256"},
    )
    languages = ru["languages"]
    if (
        not isinstance(languages, list)
        or not languages
        or not all(isinstance(x, str) and re.fullmatch(r"[a-z0-9_-]+", x) for x in languages)
    ):
        raise SetupError("tools.lock: rules.languages must be a list of directory names")
    commit = _str(ru, "commit", "rules")
    if not COMMIT_RE.match(commit):
        raise SetupError("tools.lock: rules.commit must be a 40-character commit")
    rules = RulesSnapshot(
        name=_str(ru, "name", "rules"),
        repository=_url(ru, "repository", "rules"),
        commit=commit,
        archive=Asset(_url(ru, "url", "rules"), _sha(ru, "sha256", "rules")),
        license=_str(ru, "license", "rules"),
        languages=tuple(languages),
        files_sha256=_sha(ru, "files_sha256", "rules"),
    )
    return Lock(
        opengrep_version=_str(og, "version", "opengrep"),
        opengrep_signature=signature,
        opengrep=opengrep,
        cosign_version=_str(co, "version", "cosign"),
        cosign=cosign,
        rules=rules,
    )


def load_lock(path: Path) -> Lock:
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        raise SetupError(f"tools.lock not found: {path}") from None
    except tomllib.TOMLDecodeError as exc:
        raise SetupError(f"tools.lock is not valid TOML: {exc}") from None
    return parse_lock(data)
