"""The baseline: known findings, each with an issue and a reason."""

from __future__ import annotations

import os
import re
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

from shoalscan.errors import SetupError
from shoalscan.findings import Finding

BASELINE_VERSION = 1
ISSUE_RE = re.compile(r"^(#\d+|https?://\S+)$")
ENTRY_KEYS = ("tool", "rule", "path", "fingerprint", "issue", "reason")


@dataclass(frozen=True)
class Entry:
    tool: str
    rule: str
    path: str
    fingerprint: str
    issue: str
    reason: str

    def key(self) -> tuple[str, str, str, str]:
        return (self.tool, self.rule, self.path, self.fingerprint)


def validate_issue(value: str) -> str:
    if not isinstance(value, str) or not ISSUE_RE.match(value.strip()):
        raise SetupError(f"an issue must be `#123` or an http(s) URL, not {value!r}")
    return value.strip()


def parse_baseline(data: dict, source: str = "baseline") -> list[Entry]:
    unknown = set(data) - {"version", "finding"}
    if unknown:
        raise SetupError(f"{source}: unknown keys: {', '.join(sorted(unknown))}")
    if data.get("version", BASELINE_VERSION) != BASELINE_VERSION:
        raise SetupError(f"{source}: unsupported version (expected {BASELINE_VERSION})")
    raw = data.get("finding", [])
    if not isinstance(raw, list):
        raise SetupError(f"{source}: `finding` must be an array of tables ([[finding]])")
    entries: list[Entry] = []
    seen: set[tuple[str, str, str, str]] = set()
    for n, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise SetupError(f"{source}: finding {n} is not a table")
        keys = set(item)
        if keys != set(ENTRY_KEYS):
            extra, missing = keys - set(ENTRY_KEYS), set(ENTRY_KEYS) - keys
            raise SetupError(f"{source}: finding {n} has unknown keys {sorted(extra)} or is missing {sorted(missing)}")
        for k in ENTRY_KEYS:
            if not isinstance(item[k], str) or not item[k].strip():
                raise SetupError(f"{source}: finding {n}: {k} must be a non-empty string")
        try:
            validate_issue(item["issue"])
        except SetupError as exc:
            raise SetupError(f"{source}: finding {n}: {exc}") from None
        entry = Entry(**{k: item[k] for k in ENTRY_KEYS})
        if entry.key() in seen:
            raise SetupError(f"{source}: finding {n} is a duplicate of an earlier entry")
        seen.add(entry.key())
        entries.append(entry)
    return entries


def load_baseline(path: Path) -> list[Entry] | None:
    """Load the baseline. Returns None when the file does not exist."""
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        return None
    except tomllib.TOMLDecodeError as exc:
        raise SetupError(f"{path}: not valid TOML: {exc}") from None
    return parse_baseline(data, str(path))


def baseline_from_bytes(data: bytes, source: str) -> list[Entry]:
    try:
        parsed = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SetupError(f"{source}: not valid TOML: {exc}") from None
    return parse_baseline(parsed, source)


def toml_string(value: str) -> str:
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def render_baseline(entries: list[Entry]) -> str:
    lines = [
        "# Shoalscan baseline: known findings that do not fail `shoalscan check`.",
        "# Each entry names an issue and a reason. Remove an entry when its finding is fixed;",
        "# an entry that no longer matches a finding fails the check.",
        "",
        f"version = {BASELINE_VERSION}",
    ]
    for e in sorted(entries, key=lambda e: (e.path, e.rule, e.fingerprint, e.tool)):
        lines.append("")
        lines.append("[[finding]]")
        for k in ENTRY_KEYS:
            lines.append(f"{k} = {toml_string(getattr(e, k))}")
    return "\n".join(lines) + "\n"


def entries_from_findings(findings: list[Finding], issue: str, reason: str) -> list[Entry]:
    issue = validate_issue(issue)
    if not reason.strip():
        raise SetupError("--reason must not be empty")
    unique = {f.key(): f for f in findings}
    return [Entry(f.tool, f.rule, f.path, f.fingerprint, issue, reason.strip()) for f in unique.values()]


def write_baseline(path: Path, entries: list[Entry], force: bool) -> None:
    if path.exists() and not force:
        raise SetupError(f"baseline already exists: {path} (pass --force to overwrite it)")
    path.parent.mkdir(parents=True, exist_ok=True)
    text = render_baseline(entries)
    parse_baseline(tomllib.loads(text), str(path))  # never write a file we cannot read back
    fd, tmp = tempfile.mkstemp(prefix=".baseline.", dir=path.parent)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def rename_path(entries: list[Entry], old: str, new: str) -> tuple[list[Entry], int]:
    """Point entries for `old` (a file, or a directory and everything under it) at `new`.

    Fingerprints do not contain the path, so they stay valid after a move.
    Returns the new entries and the number changed.
    """
    from dataclasses import replace

    from shoalscan.config import relative_repo_path

    old = relative_repo_path(old, "OLD").rstrip("/")
    new = relative_repo_path(new, "NEW").rstrip("/")
    changed = 0
    out = []
    for e in entries:
        if e.path == old:
            out.append(replace(e, path=new))
            changed += 1
        elif e.path.startswith(old + "/"):
            out.append(replace(e, path=new + e.path[len(old) :]))
            changed += 1
        else:
            out.append(e)
    if len({e.key() for e in out}) != len(out):
        raise SetupError(f"renaming {old} to {new} would create duplicate baseline entries")
    return out, changed
