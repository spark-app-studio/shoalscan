"""Run Gitleaks over the working tree and turn its report into findings.

Gitleaks reads three things a repository controls: a `.gitleaks.toml` that
can replace the rules, a `.gitleaksignore` that can drop findings, and
`gitleaks:allow` comments. None of them may silence a finding here, so the
scan passes the pinned default configuration with `--config`, points
`--gitleaks-ignore-path` at an empty directory, and passes
`--ignore-gitleaks-allow`. A false positive goes into the baseline, with an
issue and a reason, like any other finding.

`--gitleaks-ignore-path` is not enough on its own: Gitleaks 8.30.1 also
reads `<source>/.gitleaksignore` whatever the flag says (cmd/root.go), and
in `dir` mode its fingerprints are `<path as scanned>:<rule>:<line>`, which
a repository can predict. That top-level file is the only other one it
reads (it never looks deeper). So when the repository has one, Gitleaks
scans a staging view of the tree, under a random private directory, that
holds every other file it would scan but not the top-level `.gitleaksignore`,
and the top-level file itself is scanned on its own, as a file, which reads
no ignore file. Without one, the tree is scanned in place, and Gitleaks has
nothing to read. Either way no ignore file a repository writes is ever
read, by construction rather than by trusting a flag.

Gitleaks skips files over `--max-target-megabytes` without a word, so they
are listed here as skipped (not fully scanned), like Hadolint's.

Gitleaks writes each secret into its report. The report goes to the scan's
private staging directory, which is deleted when the scan ends, and the
secret is used only to mask it out of the line before the line is hashed
into the fingerprint. No secret, and no hash of one, reaches the findings.

Exit codes: 0 means no leaks, LEAKS_EXIT means leaks were found (set with
`--exit-code`), anything else is an error and fails the scan.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import time
import tomllib
from pathlib import Path

from shoalscan import process
from shoalscan.config import Limits, component_for
from shoalscan.errors import ScanError, SetupError
from shoalscan.excludes import ExcludeMatcher
from shoalscan.findings import Finding, assign_fingerprints, enclosing_context, split_lines
from shoalscan.lockfile import verify_sha256

TOOL = "gitleaks"
LEAKS_EXIT = 3
MAX_REPORT_BYTES = 256 * 1024 * 1024
MAX_FINDINGS = 100_000
SEVERITY = "ERROR"
CWE = "CWE-798: Use of Hard-coded Credentials"
FIX = (
    "Treat the secret as compromised: revoke and rotate it, since it is in the repository's history. "
    "Then remove it from the code and read it from a secret store or the environment."
)
_RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,199}$")
_MASK = "\0secret\0"
IGNORE_FILE = ".gitleaksignore"


def rule_name(rule_id: str) -> str:
    return f"{TOOL}.{rule_id}"


def rule_ids(config: Path) -> list[str]:
    """The ids of the rules in the pinned configuration, as finding rule names."""
    try:
        with open(config, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError, RecursionError) as exc:
        raise SetupError(f"the gitleaks configuration is unreadable: {exc}") from None
    rules = data.get("rules")
    ids = [r.get("id") for r in rules] if isinstance(rules, list) and all(isinstance(r, dict) for r in rules) else []
    if not ids or not all(isinstance(i, str) and _RULE_ID.match(i) for i in ids):
        raise SetupError("the gitleaks configuration has no rules, or a rule id that is not plain")
    return sorted(rule_name(i) for i in ids)


def max_megabytes(limits: Limits) -> int:
    return max(1, math.ceil(limits.max_target_bytes / 1_000_000))


def walk(root: Path, excludes: tuple[str, ...], max_bytes: int, view: Path | None = None) -> list[dict]:
    """The files Gitleaks skips for their size, as unscanned entries; with `view`, also stage the rest.

    Gitleaks never follows links and skips files over `max_bytes`; `.git` and
    excluded paths are left out (their findings are dropped anyway). With
    `view`, every other regular file is hard-linked (or copied) into it at the
    same relative path, except the top-level `.gitleaksignore` (deeper ones are ordinary files to Gitleaks).
    """
    matcher = ExcludeMatcher(list(excludes))
    skipped = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d != ".git"
            and not matcher.excluded(f"{rel_dir}/{d}" if rel_dir else d)
            and not os.path.islink(os.path.join(dirpath, d))
        )
        if view is not None:
            (view / rel_dir).mkdir(parents=True, exist_ok=True)
        for name in sorted(filenames):
            rel = f"{rel_dir}/{name}" if rel_dir else name
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if not os.path.isfile(full) or os.path.islink(full) or matcher.excluded(rel):
                continue
            if st.st_size > max_bytes:
                skipped.append({"path": rel, "reason": "exceeded_size_limit"})
                continue
            if view is None or rel == IGNORE_FILE or st.st_size == 0:
                continue
            target = view / rel
            try:
                os.link(full, target)
            except OSError:
                shutil.copyfile(full, target, follow_symlinks=False)
    return skipped


def build_command(
    binary: Path, target: Path, config: Path, ignore_dir: Path, report: Path, limits: Limits
) -> list[str]:
    return [
        str(binary),
        "dir",
        str(target),
        # The pinned rules, never the repository's own .gitleaks.toml.
        "--config",
        str(config),
        # An empty directory: the repository's .gitleaksignore is never read.
        "--gitleaks-ignore-path",
        str(ignore_dir),
        # gitleaks:allow comments do not silence findings.
        "--ignore-gitleaks-allow",
        "--report-format",
        "json",
        "--report-path",
        str(report),
        "--exit-code",
        str(LEAKS_EXIT),
        "--max-target-megabytes",
        str(max_megabytes(limits)),
        "--no-banner",
        "--no-color",
        "--log-level",
        "error",
    ]


def execute(cmd: list[str], cwd: Path, report: Path, timeout: int) -> list:
    """Run Gitleaks and return its parsed report, or raise ScanError."""
    returncode, _, stderr = process.run_scanner(TOOL, cmd, cwd, timeout, max_stdout=1024 * 1024)
    if returncode not in (0, LEAKS_EXIT):
        raise ScanError(f"gitleaks failed with exit code {returncode}\n{process.error_summary(stderr)}")
    try:
        size = report.stat().st_size
    except OSError:
        raise ScanError("gitleaks did not write its report") from None
    if size > MAX_REPORT_BYTES:
        raise ScanError("the gitleaks report is larger than allowed")
    try:
        doc = json.loads(report.read_bytes())
    except (ValueError, UnicodeDecodeError):
        raise ScanError("the gitleaks report is not valid JSON") from None
    if not isinstance(doc, list):
        raise ScanError("the gitleaks report is not a list of findings")
    if (returncode == LEAKS_EXIT) != bool(doc):
        raise ScanError(f"gitleaks exited with {returncode} but its report lists {len(doc)} findings")
    if len(doc) > MAX_FINDINGS:
        raise ScanError(f"gitleaks reported more than {MAX_FINDINGS} findings")
    return doc


def _relative(path: object, root: Path, scanned: Path | None = None) -> str:
    """The repository-relative path of a reported file, under `root` or the staging view `scanned`."""
    if not isinstance(path, str) or not Path(path).is_absolute():
        raise ScanError(f"gitleaks reported a path that is not absolute: {str(path)[:300]}")
    if ".." in Path(path).parts:  # relative_to is lexical: root/../x would otherwise pass as "../x"
        raise ScanError(f"gitleaks reported a path outside the target: {path[:300]}")
    for base in (scanned, root) if scanned is not None else (root,):
        try:
            return Path(path).relative_to(base).as_posix()
        except ValueError:
            continue
    raise ScanError(f"gitleaks reported a path outside the target: {path[:300]}")


def masked_code(lines: list[str], start: int, end: int, secret: str) -> str:
    """The matched lines with every copy of the secret replaced, or "" when the
    secret does not appear in them as written (it was found decoded, say)."""
    if not secret or not 1 <= start <= end <= len(lines):
        return ""
    text = "\n".join(lines[start - 1 : end])
    return text.replace(secret, _MASK) if secret in text else ""


def normalise(
    report: list, root: Path, components: dict[str, str], excludes: tuple[str, ...], scanned: Path | None = None
) -> list[Finding]:
    """Turn a Gitleaks report into findings. Excluded paths and anything under .git are dropped.

    `scanned` is the staging view Gitleaks scanned in place of `root`, if any;
    the lines are always read from `root`."""
    matcher = ExcludeMatcher(list(excludes))
    lines_cache: dict[str, list[str]] = {}
    items = []
    for entry in report:
        if not isinstance(entry, dict):
            raise ScanError("the gitleaks report has an entry that is not an object")
        rule_id, start, end, col = (
            entry.get("RuleID"),
            entry.get("StartLine"),
            entry.get("EndLine"),
            entry.get("StartColumn"),
        )
        if not isinstance(rule_id, str) or not _RULE_ID.match(rule_id):
            raise ScanError(f"the gitleaks report has a malformed rule id: {str(rule_id)[:100]!r}")
        if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in (start, end, col)):
            raise ScanError("the gitleaks report has a malformed location")
        rel = _relative(entry.get("File"), root, scanned)
        if rel == ".git" or rel.startswith(".git/") or matcher.excluded(rel):
            continue
        if rel not in lines_cache:
            try:
                data = (root / rel).read_bytes()
            except OSError:
                data = b""
            lines_cache[rel] = split_lines(data.decode("utf-8", errors="replace"))
        lines = lines_cache[rel]
        line = max(start, 1)
        secret = entry.get("Secret") if isinstance(entry.get("Secret"), str) else ""
        description = entry.get("Description") if isinstance(entry.get("Description"), str) else ""
        items.append(
            {
                "tool": TOOL,
                "rule": rule_name(rule_id),
                "path": rel,
                "line": line,
                "col": col,
                "code": masked_code(lines, line, max(end, line), secret),
                "context": enclosing_context(lines, line),
                # The description comes from the pinned configuration, never from the scanned file.
                "message": " ".join(description.split())[:1000] or "A secret was found.",
            }
        )
    prints = assign_fingerprints(items)
    return [
        Finding(
            tool=TOOL,
            rule=it["rule"],
            severity=SEVERITY,
            path=it["path"],
            line=it["line"],
            fingerprint=fp,
            component=component_for(it["path"], components),
            message=it["message"],
        )
        for it, fp in zip(items, prints, strict=True)
    ]


def rule_metadata(findings: list[Finding]) -> dict[str, dict]:
    """The same shape as `opengrep.rule_metadata`, for the work list."""
    return {
        f.rule: {
            "file": None,
            "cwe": [CWE],
            "owasp": [],
            "fix": FIX,
            "references": [],
            "confidence": None,
            "likelihood": None,
            "impact": None,
        }
        for f in findings
    }


def run(
    binary: Path,
    binary_sha256: str,
    config: Path,
    config_sha256: str,
    root: Path,
    stage: Path,
    limits: Limits,
    components: dict[str, str],
    excludes: tuple[str, ...],
) -> tuple[list[Finding], list[str], dict]:
    """Scan `root`. Returns the findings, the rule names that ran and the unscanned files."""
    if not binary.is_file():
        raise SetupError(f"gitleaks is not installed: {binary} (run `shoalscan install`)")
    verify_sha256(binary, binary_sha256)
    if not config.is_file():
        raise SetupError(f"the gitleaks configuration is not installed: {config} (run `shoalscan install`)")
    verify_sha256(config, config_sha256)
    rules = rule_ids(config)
    work = stage / "gitleaks"
    ignore_dir = work / "ignore"
    ignore_dir.mkdir(parents=True)
    max_bytes = max_megabytes(limits) * 1_000_000
    ignore_file = root / IGNORE_FILE
    # The targets: (what Gitleaks scans, the view it stands for). See the module docstring.
    if os.path.lexists(ignore_file):
        view = work / "view"
        skipped = walk(root, excludes, max_bytes, view)
        targets: list[tuple[Path, Path | None]] = [(view, view)]
        if ignore_file.is_file() and not ignore_file.is_symlink() and 0 < ignore_file.stat().st_size <= max_bytes:
            # A file as the source: Gitleaks looks for "<file>/.gitleaksignore", which cannot exist.
            targets.append((ignore_file, None))
    else:
        skipped = walk(root, excludes, max_bytes)
        targets = [(root, None)]
    deadline = time.monotonic() + limits.scan_timeout_seconds
    findings: list[Finding] = []
    for number, (target, scanned) in enumerate(targets):
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            raise ScanError(f"gitleaks timed out after {limits.scan_timeout_seconds}s")
        report_path = work / f"report-{number}.json"
        cmd = build_command(binary, target, config, ignore_dir, report_path, limits)
        report = execute(cmd, work, report_path, remaining)
        try:
            findings += normalise(report, root, components, excludes, scanned)
        finally:
            report.clear()
            report_path.unlink(missing_ok=True)
    # Fingerprints are numbered per file, and no file is in two runs, so they stay unique.
    return findings, rules, {"skipped": skipped, "errors": []}
