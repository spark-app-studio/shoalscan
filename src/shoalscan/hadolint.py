"""Find the Dockerfiles in a repository, run Hadolint on them and turn its output into findings.

Hadolint reads things a repository (or the machine) controls: a
`.hadolint.yaml` in the working directory or the home directory, `HADOLINT_*`
environment variables, and `# hadolint ignore=DLxxxx` pragmas. None of them
may silence a finding, so the scan passes its own configuration with
`--config`, passes `--disable-ignore-pragma`, and runs Hadolint with the
scanners' allowlisted environment. Rules are left out only through
`[hadolint] ignore` in `.shoalscan.toml`, which is policy: on a pull request
it comes from the base branch.

Hadolint takes file paths, so Shoalscan finds the Dockerfiles itself:
regular files (not links) named like `Dockerfile`, `Dockerfile.*`,
`*.dockerfile` or `Containerfile`, outside `.git` and the excludes. A file
over `max_target_bytes` is skipped and reported as unscanned; a file
Hadolint cannot parse (DL1000) is reported as an unscanned error, not as a
finding, so a changed Dockerfile that was not linted fails a pull request.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from shoalscan import process
from shoalscan.config import Limits, component_for
from shoalscan.errors import ScanError, SetupError
from shoalscan.excludes import ExcludeMatcher
from shoalscan.findings import Finding, assign_fingerprints, split_lines
from shoalscan.lockfile import verify_sha256

TOOL = "hadolint"
PARSE_ERROR = "DL1000"
MAX_FILES = 10_000
BATCH = 100
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
_SEVERITY = {"error": "ERROR", "warning": "WARNING", "info": "INFO", "style": "INFO"}
_CODE = re.compile(r"^(?:DL|SC)\d{4}$")
# Hadolint's own configuration: empty. Everything is set on the command line.
CONFIG_TEXT = "{}\n"


# `Dockerfile.<x>` names that are not Dockerfiles: documentation, BuildKit's
# per-Dockerfile ignore files, editor leftovers, and templates that Hadolint
# could not parse until they are rendered.
NOT_DOCKERFILE_SUFFIXES = (
    ".md", ".txt", ".rst", ".adoc", ".dockerignore", ".orig", ".bak", ".swp", ".rej",
    ".j2", ".jinja", ".jinja2", ".tmpl", ".tpl", ".template", ".erb", ".mustache",
)  # fmt: skip


def is_dockerfile(name: str) -> bool:
    lower = name.lower()
    if lower.endswith(NOT_DOCKERFILE_SUFFIXES):
        return False
    return (
        lower in ("dockerfile", "containerfile")
        or lower.startswith(("dockerfile.", "containerfile."))
        or lower.endswith((".dockerfile", ".containerfile"))
    )


def discover(root: Path, excludes: tuple[str, ...], max_bytes: int) -> tuple[list[str], list[dict]]:
    """The Dockerfiles to lint, and those skipped for their size, as repository-relative paths."""
    matcher = ExcludeMatcher(list(excludes))
    found: list[str] = []
    skipped: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = sorted(
            d for d in dirnames if d != ".git" and not matcher.excluded(f"{rel_dir}/{d}" if rel_dir else d)
        )
        for name in sorted(filenames):
            if not is_dockerfile(name):
                continue
            rel = f"{rel_dir}/{name}" if rel_dir else name
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file() or matcher.excluded(rel):
                continue
            if path.stat().st_size > max_bytes:
                skipped.append({"path": rel, "reason": "exceeded_size_limit"})
                continue
            found.append(rel)
            if len(found) > MAX_FILES:
                raise ScanError(f"more than {MAX_FILES} Dockerfiles; exclude some")
    return found, skipped


def build_command(binary: Path, config: Path, ignore: tuple[str, ...], files: list[Path]) -> list[str]:
    cmd = [
        str(binary),
        # Shoalscan's empty configuration, never a .hadolint.yaml.
        "--config", str(config),
        "--disable-ignore-pragma",
        "--no-fail", "--no-color",
        "--format", "json",
    ]  # fmt: skip
    for code in ignore:
        cmd += ["--ignore", code]
    return cmd + [str(f) for f in files]


def execute(cmd: list[str], cwd: Path, timeout: int) -> list:
    """Run Hadolint and return its parsed JSON output, or raise ScanError. With --no-fail, only 0 is success."""
    returncode, stdout, tail = process.run_scanner(TOOL, cmd, cwd, timeout)
    if returncode != 0:
        raise ScanError(f"hadolint failed with exit code {returncode}\n{tail}")
    if len(stdout) > MAX_OUTPUT_BYTES:
        raise ScanError("hadolint output is larger than allowed")
    try:
        doc = json.loads(stdout)
    except (ValueError, UnicodeDecodeError):
        raise ScanError(f"hadolint output is not valid JSON\n{tail}") from None
    if not isinstance(doc, list):
        raise ScanError("hadolint output is not a list of results")
    return doc


def stage_context(lines: list[str], line: int) -> str:
    """The build stage a line belongs to: the alias of the nearest FROM above it, else its image."""
    for n in range(min(line, len(lines)) - 1, -1, -1):
        words = [w for w in lines[n].split() if not w.startswith("--")]
        if len(words) >= 2 and words[0].upper() == "FROM":
            alias = words[3] if len(words) >= 4 and words[2].upper() == "AS" else None
            return f"stage:{alias or words[1]}"
    return ""


def normalise(results: list, root: Path, scanned: set[str], components: dict[str, str]) -> tuple[list[Finding], list[dict]]:
    """Findings, and an unscanned error for each file Hadolint could not parse."""
    lines_cache: dict[str, list[str]] = {}
    items, errors = [], {}
    for r in results:
        if not isinstance(r, dict):
            raise ScanError("hadolint output has a result that is not an object")
        code, level, line, path = r.get("code"), r.get("level"), r.get("line"), r.get("file")
        if not isinstance(code, str) or not _CODE.match(code) or level not in _SEVERITY:
            raise ScanError(f"hadolint output has a malformed result: {str(r)[:300]}")
        if not isinstance(line, int) or isinstance(line, bool) or line < 0:
            raise ScanError("hadolint output has a malformed line number")
        if not isinstance(path, str) or not Path(path).is_absolute():
            raise ScanError(f"hadolint reported a path that is not absolute: {str(path)[:300]}")
        try:
            rel = Path(path).relative_to(root).as_posix()
        except ValueError:
            raise ScanError(f"hadolint reported a path outside the target: {path[:300]}") from None
        if rel not in scanned:
            raise ScanError(f"hadolint reported a file it was not given: {rel[:300]}")
        if code == PARSE_ERROR:
            errors[rel] = {"path": rel, "type": f"hadolint {PARSE_ERROR}", "message": str(r.get("message", ""))[:400]}
            continue
        if rel not in lines_cache:
            try:
                lines_cache[rel] = split_lines((root / rel).read_bytes().decode("utf-8", errors="replace"))
            except OSError:
                lines_cache[rel] = []
        lines = lines_cache[rel]
        line = max(line, 1)
        items.append(
            {
                "tool": TOOL,
                "rule": f"{TOOL}.{code}",
                "path": rel,
                "line": line,
                "col": r.get("column") if isinstance(r.get("column"), int) else 0,
                "code": lines[line - 1] if line <= len(lines) else "",
                "context": stage_context(lines, line),
                "severity": _SEVERITY[level],
                "message": " ".join(str(r.get("message", "")).split())[:1000],
            }
        )
    prints = assign_fingerprints(items)
    findings = [
        Finding(tool=TOOL, rule=it["rule"], severity=it["severity"], path=it["path"], line=it["line"], fingerprint=fp,
                component=component_for(it["path"], components), message=it["message"])  # fmt: skip
        for it, fp in zip(items, prints)
    ]
    # A file that did not parse has no other results worth keeping.
    findings = [f for f in findings if f.path not in errors]
    return findings, sorted(errors.values(), key=lambda e: e["path"])


def rule_metadata(findings: list[Finding]) -> dict[str, dict]:
    """The same shape as `opengrep.rule_metadata`, with a link to each rule's page."""
    out = {}
    for f in findings:
        code = f.rule.split(".", 1)[1]
        url = (f"https://github.com/hadolint/hadolint/wiki/{code}" if code.startswith("DL")
               else f"https://www.shellcheck.net/wiki/{code}")  # fmt: skip
        out[f.rule] = {"file": None, "cwe": [], "owasp": [], "fix": None, "references": [url], "confidence": None, "likelihood": None, "impact": None}
    return out


def run(binary: Path, binary_sha256: str, root: Path, stage: Path, limits: Limits, components: dict[str, str],
        excludes: tuple[str, ...], ignore: tuple[str, ...]) -> tuple[list[Finding], dict, int]:  # fmt: skip
    """Lint the repository's Dockerfiles. Returns the findings, the unscanned files and how many files were linted."""
    if not binary.is_file():
        raise SetupError(f"hadolint is not installed: {binary} (run `shoalscan install`)")
    verify_sha256(binary, binary_sha256)
    files, skipped = discover(root, excludes, limits.max_target_bytes)
    if not files:
        return [], {"skipped": skipped, "errors": []}, 0
    work = stage / "hadolint"
    work.mkdir(parents=True)
    config = work / "config.yaml"
    config.write_text(CONFIG_TEXT, encoding="utf-8")
    results: list = []
    # One deadline for all batches, so many Dockerfiles cannot stretch the scan's time limit.
    deadline = time.monotonic() + limits.scan_timeout_seconds
    for start in range(0, len(files), BATCH):
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            raise ScanError(f"hadolint timed out after {limits.scan_timeout_seconds}s")
        batch = [root / f for f in files[start : start + BATCH]]
        results += execute(build_command(binary, config, ignore, batch), work, remaining)
    findings, errors = normalise(results, root, set(files), components)
    return findings, {"skipped": skipped, "errors": errors}, len(files)
