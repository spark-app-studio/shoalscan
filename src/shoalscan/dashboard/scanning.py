"""Scan targets: what the dashboard may scan, how they are validated and stored.

`scan_targets.toml` in the dashboard's state directory is the single source
of truth. The dashboard starts a scan by naming a target and nothing else;
the worker (`shoalscan.scanjob`) reads this file again for itself. The
Configuration page may change it, but only through `validate_*` below, and
only the fields a browser may set: name, an https source on an allowlisted
host or a pre-registered local mirror chosen by name, branch, enabled,
nightly and the policy text. Clone, configuration and baseline paths are
derived by the server; `clone`, `config`, `baseline` and `python` can only be
written into the file by hand, and are kept as they are when the dashboard
rewrites it.

Single flight across processes comes from an flock on a lock file, held for
as long as the scan runs; the kernel releases it when the process ends.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import time
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import urlsplit

from shoalscan.config import KNOWN_SCANNERS, config_from_bytes
from shoalscan.errors import SetupError

TARGETS_FILE = "scan_targets.toml"
SOURCES_FILE = "local_sources.toml"
HOSTS_FILE = "allowed_hosts.toml"
LOCK_FILE = "scan.lock"
STATUS_FILE = "scan_status.json"
REQUESTS_FILE = "scan_requests.json"
LOG_FILE = "scan.log"
MAX_LOG_BYTES = 256 * 1024
MAX_TARGETS = 200
MAX_POLICY_BYTES = 32 * 1024
DEFAULT_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")

# Git, whenever the worker or its children run it on a scanned repository.
#
# A repository's own .gitattributes can name a filter driver (filter=lfs, or
# any name) that some git configuration defines; a checkout would then run
# that driver, and git-lfs would download from a URL the repository chose.
# So attributes are read from the empty tree (GIT_ATTR_SOURCE) instead of the
# repository, no global or system configuration is read, LFS never smudges,
# and hooks, fsmonitor, submodules, symlinks, redirects and file transports
# are off. The settings go both on the command line and into the environment
# (GIT_CONFIG_COUNT), so git commands that Shoalscan itself runs in the
# worktree get them too.
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
GIT_HARDENED = (
    ("core.hooksPath", "/dev/null"),
    ("core.fsmonitor", "false"),
    ("submodule.recurse", "false"),
    ("protocol.file.allow", "never"),
    ("http.followRedirects", "false"),
    ("core.symlinks", "false"),
    ("core.attributesFile", "/dev/null"),
    ("filter.lfs.smudge", ""),
    ("filter.lfs.process", ""),
    ("filter.lfs.required", "false"),
)
# For sources a browser named (https URLs): no transport but https, and no credential helpers.
GIT_URL_ONLY = (("protocol.allow", "never"), ("protocol.https.allow", "always"), ("credential.helper", ""))
# Fetching a clone registered by hand keeps the administrator's own git
# configuration (it may hold credentials for a private origin), but never
# runs hooks, submodules or LFS downloads.
GIT_ADMIN_FETCH = (
    ("core.hooksPath", "/dev/null"),
    ("core.fsmonitor", "false"),
    ("submodule.recurse", "false"),
    ("filter.lfs.smudge", ""),
    ("filter.lfs.process", ""),
    ("filter.lfs.required", "false"),
)
GIT_NO_PROMPT_ENV = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "/bin/echo",
    "SSH_ASKPASS": "/bin/echo",
    "GIT_LFS_SKIP_SMUDGE": "1",
}
GIT_HARDENED_ENV = {
    **GIT_NO_PROMPT_ENV,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_ATTR_SOURCE": EMPTY_TREE,
}


GIT_TOO_OLD = "git 2.40 or later is required: it must honour GIT_ATTR_SOURCE"
_probe_cache: dict[tuple, bool] = {}


def git_attr_probe(path_env: str | None = None) -> bool:
    """Does this git honour GIT_ATTR_SOURCE? Older git (before 2.40) silently
    ignores it, and the protection against filter drivers would be gone.

    A functional test, not a version check: a throwaway repository commits
    `.gitattributes` with `probe filter=shoalscanprobe`; under the hardened
    environment `git check-attr filter probe` must answer `unspecified`.
    The answer is cached per git binary and its modification time.
    """
    import shutil
    import tempfile

    path_env = path_env if path_env is not None else os.environ.get("PATH", "/usr/bin:/bin")
    git = shutil.which("git", path=path_env)
    if git is None:
        return False
    try:
        key = (os.path.realpath(git), os.stat(git).st_mtime_ns)
    except OSError:
        return False
    if key in _probe_cache:
        return _probe_cache[key]
    env = git_env({"PATH": path_env, "HOME": "/nonexistent", "LC_ALL": "C"}, GIT_HARDENED)
    ok = False
    try:
        with tempfile.TemporaryDirectory(prefix="shoalscan-git-probe-") as tmp:
            repo = Path(tmp) / "repo"
            ident = ["-c", "user.name=probe", "-c", "user.email=probe@localhost", "-c", "commit.gpgsign=false"]

            def run(*args: str) -> subprocess.CompletedProcess:
                return subprocess.run(
                    [git, *git_args(GIT_HARDENED), *ident, *args],
                    cwd=tmp,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    stdin=subprocess.DEVNULL,
                    check=False,
                )

            if run("init", "-q", str(repo)).returncode == 0:
                (repo / ".gitattributes").write_text("probe filter=shoalscanprobe\n", encoding="utf-8")
                (repo / "probe").write_text("probe\n", encoding="utf-8")
                if (
                    run("-C", str(repo), "add", ".gitattributes", "probe").returncode == 0
                    and run("-C", str(repo), "commit", "-q", "-m", "probe").returncode == 0
                ):
                    answer = run("-C", str(repo), "check-attr", "filter", "probe")
                    ok = answer.returncode == 0 and answer.stdout.strip() == "probe: filter: unspecified"
    except (OSError, subprocess.SubprocessError):
        ok = False
    _probe_cache[key] = ok
    return ok


def git_args(pairs) -> list[str]:
    return [arg for key, value in pairs for arg in ("-c", f"{key}={value}")]


def git_env(base: dict, pairs, hardened: bool = True) -> dict:
    """An environment for git: the hardened variables (or, for an administrator's
    fetch, only the no-prompt ones) and the configuration pairs as GIT_CONFIG_*."""
    env = {k: v for k, v in base.items() if not k.startswith("GIT_")}
    env.update(GIT_HARDENED_ENV if hardened else GIT_NO_PROMPT_ENV)
    env["GIT_CONFIG_COUNT"] = str(len(pairs))
    for n, (key, value) in enumerate(pairs):
        env[f"GIT_CONFIG_KEY_{n}"] = key
        env[f"GIT_CONFIG_VALUE_{n}"] = value
    return env


# A target name is a repository name on the dashboard. It must also not look
# like a path or an option anywhere it is used.
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,199}$")
_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
_URL_SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$")
_MIRROR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def valid_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(_NAME.fullmatch(value))
        and ".." not in value
        and "//" not in value
        and not value.endswith("/")
    )


def slug(name: str) -> str:
    """A directory name for a target: readable, and unique through a hash of the name."""
    readable = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:60].strip(".") or "target"
    return f"{readable}-{hashlib.sha256(name.encode('utf-8')).hexdigest()[:10]}"


@dataclass(frozen=True)
class Target:
    name: str
    branch: str
    kind: str  # "url", "mirror" or "clone"
    source: str | None = None  # the https URL, for kind "url"
    mirror: str | None = None  # the mirror's name, for kind "mirror"
    clone: Path | None = None  # set by hand, for kind "clone"
    enabled: bool = True
    nightly: bool = False
    config: Path | None = None  # set by hand only
    baseline: Path | None = None  # set by hand only
    python: Path | None = None  # set by hand only
    max_clone_mb: int | None = None  # set by hand only

    def public_source(self) -> dict:
        if self.kind == "url":
            return {"kind": "url", "url": self.source}
        if self.kind == "mirror":
            return {"kind": "mirror", "mirror": self.mirror}
        return {"kind": "clone", "clone": self.clone.name if self.clone else None}


@dataclass(frozen=True)
class Targets:
    targets: dict[str, Target]
    history_db: Path | None = None
    tools_dir: Path | None = None
    cooldown_seconds: int = 600
    timeout_seconds: int = 1800
    max_scans_per_hour: int = 6
    min_free_mb: int = 2048
    max_clone_mb: int = 2048
    mirrors: dict[str, Path] = field(default_factory=dict)
    allowed_hosts: tuple[str, ...] = DEFAULT_HOSTS
    state_dir: Path = Path(".")

    # Paths the server derives; never from a request.
    def clone_dir(self, t: Target) -> Path:
        if t.kind == "clone":
            return t.clone
        if t.kind == "mirror":
            return self.mirrors[t.mirror]
        return self.state_dir / "clones" / slug(t.name)

    def managed_dir(self, t: Target) -> Path:
        return self.state_dir / "targets" / slug(t.name)

    def policy_path(self, t: Target) -> Path | None:
        """The configuration the scan uses: set by hand, or the managed policy when there is one."""
        if t.config is not None:
            return t.config
        managed = self.managed_dir(t) / "shoalscan.toml"
        return managed if managed.is_file() else None

    def baseline_path(self, t: Target) -> Path:
        return t.baseline if t.baseline is not None else self.managed_dir(t) / "baseline.toml"


# ---------------------------------------------------------------- validation of what a browser may set


def validate_name(value: object) -> str:
    if not valid_name(value):
        raise SetupError(
            "the name must look like owner/project: letters, digits and . _ / @ : + -, up to 200 characters"
        )
    return value


def validate_url(value: object, allowed_hosts: tuple[str, ...]) -> str:
    """An https URL of a repository on an allowlisted host; anything else is refused, never cleaned up."""
    if not isinstance(value, str) or not value or len(value) > 300:
        raise SetupError("the source must be an https URL of up to 300 characters")
    if not value.isascii() or any(c <= " " or c == "\x7f" for c in value):
        raise SetupError("the source URL may contain only plain ASCII characters, with no spaces or control characters")
    parts = urlsplit(value)
    if parts.scheme != "https" or not value.startswith("https://"):
        raise SetupError("the source must be an https:// URL")
    if "@" in parts.netloc or parts.username or parts.password:
        raise SetupError("the source URL must not carry a user name or credentials")
    if parts.query or parts.fragment or "?" in value or "#" in value:
        raise SetupError("the source URL must not have a query or a fragment")
    host = parts.netloc
    if parts.port is not None or ":" in host or host != (parts.hostname or "") or not _HOST.fullmatch(host):
        raise SetupError("the source URL must name a plain host name, without a port")
    if host not in allowed_hosts:
        raise SetupError(f"the host {host} is not on this dashboard's allowlist ({', '.join(allowed_hosts)})")
    segments = parts.path.strip("/").split("/")
    if not 2 <= len(segments) <= 5 or parts.path.startswith("//") or "//" in parts.path:
        raise SetupError("the source URL must name a repository, such as https://github.com/owner/project.git")
    for segment in segments:
        if not _URL_SEGMENT.fullmatch(segment) or segment in (".", "..") or segment.startswith("-"):
            raise SetupError("the source URL has a part that is not a plain name")
    return value


def validate_branch(value: object) -> str:
    """A branch name by git's own rules (`git check-ref-format --branch`), never starting with -."""
    if not isinstance(value, str) or not value or len(value) > 200 or value.startswith("-"):
        raise SetupError("the branch must be a branch name, not starting with -")
    if not value.isascii() or any(c <= " " or c == "\x7f" for c in value) or any(c in value for c in "~^:?*[\\@{"):
        raise SetupError("the branch name has a character git does not allow")
    try:
        proc = subprocess.run(
            ["git", "check-ref-format", "--branch", value],
            capture_output=True,
            text=True,
            timeout=10,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise SetupError("git is not available to check the branch name") from None
    if proc.returncode != 0 or proc.stdout.strip() != value:
        raise SetupError(f"{value!r} is not a valid branch name")
    return value


def validate_policy(text: object) -> str:
    """A .shoalscan.toml body: parsed with the strict configuration parser; `baseline` is managed and refused."""
    if text is None or text == "":
        return ""
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_POLICY_BYTES:
        raise SetupError(f"the policy must be text of up to {MAX_POLICY_BYTES} bytes")
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise SetupError(f"the policy is not valid TOML: {exc}") from None
    if "baseline" in data:
        raise SetupError(
            "the policy may not set baseline: the dashboard manages the baseline's path, and baselines change only "
            "from the command line"
        )
    config_from_bytes(text.encode("utf-8"), "the policy")
    return text


# The managed policy starts with this header and one `scanners` line when the
# scanners were chosen on the Configuration page; the rest is the policy text
# the page shows and edits.
SCANNERS_HEADER = "# Scanners chosen on the dashboard's Configuration page.\n"


def validate_scanners(value: object) -> tuple[str, ...] | None:
    """None (the policy decides), or a non-empty choice of known scanners, in their usual order."""
    if value is None:
        return None
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(v, str) for v in value)
        or len(set(value)) != len(value)
    ):
        raise SetupError("choose at least one scanner, each once")
    unknown = sorted(set(value) - set(KNOWN_SCANNERS))
    if unknown:
        raise SetupError(f"unknown scanner: {unknown[0]!r} (known: {', '.join(KNOWN_SCANNERS)})")
    return tuple(s for s in KNOWN_SCANNERS if s in value)


def compose_policy(body: str, scanners: tuple[str, ...] | None) -> str:
    """The managed policy file: the scanners line the page chose, if any, then the policy text."""
    if scanners is None:
        return body
    line = "scanners = [" + ", ".join(_toml_string(s) for s in scanners) + "]\n"
    return SCANNERS_HEADER + line + ("\n" + body if body else "")


def split_policy(text: str) -> tuple[str, tuple[str, ...] | None]:
    """The policy text and the chosen scanners. A file without the header is all policy text."""
    if not text.startswith(SCANNERS_HEADER):
        return text, None
    line, _, body = text[len(SCANNERS_HEADER) :].partition("\n")
    try:
        data = tomllib.loads(line)
    except (tomllib.TOMLDecodeError, RecursionError):
        return text, None
    chosen = data.get("scanners")
    if set(data) != {"scanners"} or not isinstance(chosen, list) or not all(isinstance(c, str) for c in chosen):
        return text, None
    return body[1:] if body.startswith("\n") else body, tuple(chosen)


def policy_sha256(text: str | None) -> str | None:
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text else None


# ---------------------------------------------------------------- reading the files


def _abs_path(value: object, where: str) -> Path:
    if not isinstance(value, str) or not value or "\0" in value or "\n" in value:
        raise SetupError(f"{TARGETS_FILE}: {where} must be a path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise SetupError(f"{TARGETS_FILE}: {where} must be an absolute path without ..: {value!r}")
    return path


def _int(value: object, where: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise SetupError(f"{TARGETS_FILE}: {where} must be a whole number from {low} to {high}")
    return value


def _bool(value: object, where: str) -> bool:
    if not isinstance(value, bool):
        raise SetupError(f"{TARGETS_FILE}: {where} must be true or false")
    return value


def check_private(path: Path) -> None:
    """Refuse a file that someone other than its owner could change."""
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise SetupError(f"{path} must be a regular file")
    if info.st_mode & 0o022:
        raise SetupError(f"{path} is writable by group or others; run chmod 600 on it")
    if info.st_uid != os.getuid():
        raise SetupError(f"{path} must be owned by the user that runs Shoalscan")


def _read_toml(path: Path) -> dict:
    check_private(path)
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError) as exc:
        raise SetupError(f"{path} is not valid TOML: {exc}") from None


def load_mirrors(state_dir: Path) -> dict[str, Path]:
    path = state_dir / SOURCES_FILE
    if not path.exists():
        return {}
    data = _read_toml(path)
    if set(data) - {"mirror"}:
        raise SetupError(f"{SOURCES_FILE}: unknown keys: {', '.join(sorted(set(data) - {'mirror'}))}")
    mirrors: dict[str, Path] = {}
    for entry in data.get("mirror", []):
        if not isinstance(entry, dict) or set(entry) != {"name", "path"}:
            raise SetupError(f"{SOURCES_FILE}: each [[mirror]] has exactly a name and a path")
        if not isinstance(entry["name"], str) or not _MIRROR.fullmatch(entry["name"]) or entry["name"] in mirrors:
            raise SetupError(f"{SOURCES_FILE}: mirror names are short plain names, each used once")
        mirrors[entry["name"]] = _abs_path(entry["path"], f"mirror {entry['name']} path")
    return mirrors


def load_hosts(state_dir: Path) -> tuple[str, ...]:
    path = state_dir / HOSTS_FILE
    if not path.exists():
        return DEFAULT_HOSTS
    data = _read_toml(path)
    hosts = data.get("hosts")
    if (
        set(data) != {"hosts"}
        or not isinstance(hosts, list)
        or not all(isinstance(h, str) and _HOST.fullmatch(h) for h in hosts)
    ):
        raise SetupError(f'{HOSTS_FILE}: write hosts = ["github.com", ...] with plain lowercase host names')
    return tuple(hosts)


def load_targets(state_dir: Path, allow_missing: bool = False) -> Targets | None:
    """Read and strictly validate scan_targets.toml. None when there is no such file
    (scans are off), or an empty set with `allow_missing` (the Configuration page may create it)."""
    path = state_dir / TARGETS_FILE
    mirrors = load_mirrors(state_dir)
    hosts = load_hosts(state_dir)
    if not path.exists():
        return Targets({}, mirrors=mirrors, allowed_hosts=hosts, state_dir=state_dir) if allow_missing else None
    data = _read_toml(path)
    top = {
        "target",
        "history_db",
        "tools_dir",
        "cooldown_minutes",
        "timeout_minutes",
        "max_scans_per_hour",
        "min_free_mb",
        "max_clone_mb",
    }
    unknown = set(data) - top
    if unknown:
        raise SetupError(f"{TARGETS_FILE}: unknown keys: {', '.join(sorted(unknown))}")
    entries = data.get("target", [])
    if not isinstance(entries, list) or len(entries) > MAX_TARGETS:
        raise SetupError(f"{TARGETS_FILE}: list up to {MAX_TARGETS} [[target]] tables")
    targets: dict[str, Target] = {}
    allowed = {
        "name",
        "branch",
        "source",
        "mirror",
        "clone",
        "enabled",
        "nightly",
        "config",
        "baseline",
        "python",
        "max_clone_mb",
    }
    for n, entry in enumerate(entries, 1):
        where = f"target {n}"
        if not isinstance(entry, dict):
            raise SetupError(f"{TARGETS_FILE}: {where} must be a table")
        unknown = set(entry) - allowed
        if unknown:
            raise SetupError(f"{TARGETS_FILE}: unknown keys in {where}: {', '.join(sorted(unknown))}")
        try:
            name = validate_name(entry.get("name"))
            branch = validate_branch(entry.get("branch"))
        except SetupError as exc:
            raise SetupError(f"{TARGETS_FILE}: {where}: {exc}") from None
        if name in targets:
            raise SetupError(f"{TARGETS_FILE}: the target {name} is listed twice")
        kinds = [k for k in ("source", "mirror", "clone") if k in entry]
        if len(kinds) != 1:
            raise SetupError(f"{TARGETS_FILE}: {name} needs exactly one of source, mirror or clone")
        fields: dict = {}
        if "source" in entry:
            try:
                fields = {"kind": "url", "source": validate_url(entry["source"], hosts)}
            except SetupError as exc:
                raise SetupError(f"{TARGETS_FILE}: {name}: {exc}") from None
        elif "mirror" in entry:
            if entry["mirror"] not in mirrors:
                raise SetupError(
                    f"{TARGETS_FILE}: {name} names the mirror {entry['mirror']!r}, which {SOURCES_FILE} does not list"
                )
            fields = {"kind": "mirror", "mirror": entry["mirror"]}
        else:
            fields = {"kind": "clone", "clone": _abs_path(entry["clone"], f"{name} clone")}
        for key in ("config", "baseline", "python"):
            if key in entry:
                value = _abs_path(entry[key], f"{name} {key}")
                clone = fields.get("clone") or (mirrors.get(fields.get("mirror")) if fields.get("mirror") else None)
                if key != "python" and clone is not None and (value == clone or clone in value.parents):
                    # A file inside the clone would come from the very code being scanned.
                    raise SetupError(f"{TARGETS_FILE}: {name} {key} must be outside the clone")
                fields[key] = value
        if "max_clone_mb" in entry:
            fields["max_clone_mb"] = _int(entry["max_clone_mb"], f"{name} max_clone_mb", 1, 10_000_000)
        targets[name] = Target(
            name=name,
            branch=branch,
            enabled=_bool(entry.get("enabled", True), f"{name} enabled"),
            nightly=_bool(entry.get("nightly", False), f"{name} nightly"),
            **fields,
        )
    return Targets(
        targets=targets,
        history_db=_abs_path(data["history_db"], "history_db") if "history_db" in data else None,
        tools_dir=_abs_path(data["tools_dir"], "tools_dir") if "tools_dir" in data else None,
        cooldown_seconds=60 * _int(data.get("cooldown_minutes", 10), "cooldown_minutes", 0, 1440),
        timeout_seconds=60 * _int(data.get("timeout_minutes", 30), "timeout_minutes", 1, 600),
        max_scans_per_hour=_int(data.get("max_scans_per_hour", 6), "max_scans_per_hour", 1, 60),
        min_free_mb=_int(data.get("min_free_mb", 2048), "min_free_mb", 0, 10_000_000),
        max_clone_mb=_int(data.get("max_clone_mb", 2048), "max_clone_mb", 1, 10_000_000),
        mirrors=mirrors,
        allowed_hosts=hosts,
        state_dir=state_dir,
    )


# ---------------------------------------------------------------- writing scan_targets.toml


def _toml_string(value: str) -> str:
    # JSON string escapes are valid TOML basic-string escapes.
    return json.dumps(value, ensure_ascii=True)


def dump_targets(t: Targets, raw_top: dict) -> str:
    """Write the file back: the top-level settings as they were, then every target."""
    lines = [
        "# Scan targets for the Shoalscan dashboard. The Configuration page edits this file;",
        "# clone, config, baseline and python can only be set here by hand.",
        "",
    ]
    for key in ("history_db", "tools_dir"):
        if key in raw_top:
            lines.append(f"{key} = {_toml_string(str(raw_top[key]))}")
    for key in ("cooldown_minutes", "timeout_minutes", "max_scans_per_hour", "min_free_mb", "max_clone_mb"):
        if key in raw_top:
            lines.append(f"{key} = {int(raw_top[key])}")
    for target in t.targets.values():
        lines += ["", "[[target]]", f"name = {_toml_string(target.name)}"]
        if target.kind == "url":
            lines.append(f"source = {_toml_string(target.source)}")
        elif target.kind == "mirror":
            lines.append(f"mirror = {_toml_string(target.mirror)}")
        else:
            lines.append(f"clone = {_toml_string(str(target.clone))}")
        lines.append(f"branch = {_toml_string(target.branch)}")
        lines.append(f"enabled = {'true' if target.enabled else 'false'}")
        lines.append(f"nightly = {'true' if target.nightly else 'false'}")
        for key in ("config", "baseline", "python"):
            value = getattr(target, key)
            if value is not None:
                lines.append(f"{key} = {_toml_string(str(value))}")
        if target.max_clone_mb is not None:
            lines.append(f"max_clone_mb = {int(target.max_clone_mb)}")
    return "\n".join(lines) + "\n"


def write_private(path: Path, text: str) -> None:
    """Write atomically: a 0600 temporary file in the same directory, fsync, rename, fsync the directory."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def save_targets(state_dir: Path, targets: Targets) -> None:
    path = state_dir / TARGETS_FILE
    raw_top = {}
    if path.exists():
        raw_top = {k: v for k, v in _read_toml(path).items() if k != "target"}
    text = dump_targets(targets, raw_top)
    # What we write must read back to the same targets, or nothing is written.
    check = tomllib.loads(text)
    if [e["name"] for e in check.get("target", [])] != list(targets.targets):
        raise SetupError("the targets file could not be written consistently")
    write_private(path, text)


def read_policy(targets: Targets, target: Target) -> str:
    path = targets.managed_dir(target) / "shoalscan.toml"
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def write_policy(targets: Targets, target: Target, text: str) -> None:
    path = targets.managed_dir(target) / "shoalscan.toml"
    if text:
        write_private(path, text)
    else:
        path.unlink(missing_ok=True)


def with_target(targets: Targets, target: Target, old_name: str | None = None) -> Targets:
    """A copy with `target` added or replacing `old_name`, keeping the order."""
    items = list(targets.targets.items())
    if old_name is None:
        items.append((target.name, target))
    else:
        items = [(target.name, target) if n == old_name else (n, t) for n, t in items]
    return replace(targets, targets=dict(items))


# ---------------------------------------------------------------- small JSON files in the state directory


def read_json(path: Path) -> dict:
    try:
        if path.stat().st_size > 1024 * 1024:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


# ---------------------------------------------------------------- the lock
#
# An exclusive flock on scan.lock, held on an open file descriptor for as long
# as the scan runs. The kernel releases it when the process ends, however it
# ends, so a crash never leaves a stale lock and nothing has to be unlinked.
# The file's content (pid, start time, target) is only for the status page.

_held: dict[str, int] = {}


def process_start(pid: int) -> str | None:
    """When a process started, as `ps` reports it; None if there is no such process."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        pass
    try:
        out = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=10,
            stdin=subprocess.DEVNULL,
            env={"PATH": "/bin:/usr/bin", "LC_ALL": "C"},
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip() or None


def _open_lock(state_dir: Path) -> int:
    return os.open(state_dir / LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)


def lock_holder(state_dir: Path) -> dict | None:
    """Who holds the scan lock, or None when nobody does."""
    if not (state_dir / LOCK_FILE).exists():
        return None
    fd = os.open(state_dir / LOCK_FILE, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            info = read_json(state_dir / LOCK_FILE)
            return info or {"pid": None}
        fcntl.flock(fd, fcntl.LOCK_UN)
        return None
    finally:
        os.close(fd)


def acquire_lock(state_dir: Path, target: str, attempts: int = 10) -> bool:
    """Take the scan lock for this process. A status probe holds a shared lock
    for an instant, so a few quick retries tell a probe from a running scan."""
    key = str(state_dir.resolve())
    if key in _held:
        return False
    fd = _open_lock(state_dir)
    for attempt in range(attempts):
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if attempt == attempts - 1:
                os.close(fd)
                return False
            time.sleep(0.05)
    me = {"pid": os.getpid(), "started": process_start(os.getpid()), "target": target, "since": time.time()}
    os.ftruncate(fd, 0)
    os.pwrite(fd, json.dumps(me).encode("utf-8"), 0)
    os.fsync(fd)
    _held[key] = fd
    return True


def release_lock(state_dir: Path) -> None:
    fd = _held.pop(str(state_dir.resolve()), None)
    if fd is None:
        return
    try:
        os.ftruncate(fd, 0)
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# ---------------------------------------------------------------- the log, for the status endpoint


_ABS_PATH = re.compile(r"(?<![\w.>])/(?:[^\s:'\"]+)")


def sanitise_log(lines: list[str], clone: Path | None) -> list[str]:
    """Log lines for the browser: control characters dropped, the clone shown by
    its name, every other absolute path replaced with <path>."""
    out = []
    for line in lines:
        line = "".join(c for c in line if c >= " " and c != "\x7f")[:300]
        if clone is not None:
            line = line.replace(str(clone), f"<clone {clone.name}>")
        out.append(_ABS_PATH.sub("<path>", line))
    return out


def log_tail(state_dir: Path, clone: Path | None, lines: int = 15) -> list[str]:
    path = state_dir / LOG_FILE
    try:
        with open(path, "rb") as handle:
            handle.seek(max(0, path.stat().st_size - 16384))
            text = handle.read().decode("utf-8", "replace")
    except OSError:
        return []
    return sanitise_log(text.splitlines()[-lines:], clone)
