"""Find GitHub Actions files, audit them with zizmor and turn its output into findings.

zizmor reads things a repository controls: a `zizmor.yml` (or
`.github/zizmor.yml`) that can turn audits off, `# zizmor: ignore[...]`
comments, and `.gitignore` files that decide which inputs are collected. It
can also reach the GitHub API. The scan passes `--offline`, `--no-config`
and `--no-ignores`, and gives zizmor the files explicitly, so none of that
applies; `ZIZMOR_*` and token variables never pass the scanners'
allowlisted environment. Audits are left out only through `[zizmor] ignore`
in `.shoalscan.toml`, which is policy.

Inputs are the workflows directly in `.github/workflows`, every
`action.yml` or `action.yaml` (composite and other action definitions), and
`.github/dependabot.yml`, outside `.git` and the excludes, not links, not
over the size limit. They are audited together with `--strict-collection`;
if that fails, each file is audited alone, and the ones zizmor cannot read
are listed as unscanned errors while the others still count.
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
from shoalscan.findings import Finding, assign_fingerprints, normalise_code
from shoalscan.lockfile import verify_sha256

TOOL = "zizmor"
MAX_FILES = 5_000
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
_SEVERITY = {"High": "ERROR", "Medium": "WARNING", "Low": "INFO", "Informational": "INFO"}
_AUDIT = re.compile(r"^[a-z0-9][a-z0-9-]{0,99}$")
_DOCS = "https://docs.zizmor.sh/"


def is_input(rel: str) -> bool:
    parts = rel.split("/")
    name = parts[-1]
    if not name.endswith((".yml", ".yaml")):
        return False
    if len(parts) == 3 and parts[:2] == [".github", "workflows"]:
        return True
    if name in ("action.yml", "action.yaml"):
        return True
    return len(parts) == 2 and parts[0] == ".github" and name in ("dependabot.yml", "dependabot.yaml")


def discover(root: Path, excludes: tuple[str, ...], max_bytes: int) -> tuple[list[str], list[dict]]:
    """The files to audit, and those skipped for their size, as repository-relative paths."""
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
            rel = f"{rel_dir}/{name}" if rel_dir else name
            path = Path(dirpath) / name
            if not is_input(rel) or path.is_symlink() or not path.is_file() or matcher.excluded(rel):
                continue
            if path.stat().st_size > max_bytes:
                skipped.append({"path": rel, "reason": "exceeded_size_limit"})
                continue
            found.append(rel)
            if len(found) > MAX_FILES:
                raise ScanError(f"more than {MAX_FILES} GitHub Actions files; exclude some")
    return found, skipped


def build_command(binary: Path, files: list[Path]) -> list[str]:
    return [
        str(binary),
        # No network, no repository configuration, no ignore comments.
        "--offline",
        "--no-config",
        "--no-ignores",
        "--strict-collection",
        "--persona",
        "regular",
        "--no-exit-codes",
        "--no-progress",
        "--color",
        "never",
        "--format",
        "json",
        *[str(f) for f in files],
    ]


def execute(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, list | None, str]:
    """Run zizmor. Returns its exit code, its parsed results (None unless it exited 0) and its error tail."""
    returncode, stdout, tail = process.run_scanner(TOOL, cmd, cwd, timeout)
    if returncode != 0:
        return returncode, None, tail
    if len(stdout) > MAX_OUTPUT_BYTES:
        raise ScanError("zizmor output is larger than allowed")
    try:
        doc = json.loads(stdout)
    except (ValueError, UnicodeDecodeError):
        raise ScanError(f"zizmor output is not valid JSON\n{tail}") from None
    if not isinstance(doc, list):
        raise ScanError("zizmor output is not a list of findings")
    return 0, doc, tail


def _primary(result: dict) -> dict:
    locations = result.get("locations")
    if isinstance(locations, list):
        for loc in locations:
            if (
                isinstance(loc, dict)
                and isinstance(loc.get("symbolic"), dict)
                and loc["symbolic"].get("kind") == "Primary"
            ):
                return loc
    raise ScanError(f"a zizmor finding has no primary location: {str(result)[:300]}")


def normalise(
    results: list, root: Path, scanned: set[str], components: dict[str, str], ignore: tuple[str, ...]
) -> list[Finding]:
    items = []
    for r in results:
        if not isinstance(r, dict):
            raise ScanError("zizmor output has a finding that is not an object")
        ident = r.get("ident")
        det = r.get("determinations") if isinstance(r.get("determinations"), dict) else {}
        severity = _SEVERITY.get(det.get("severity"))
        if not isinstance(ident, str) or not _AUDIT.match(ident) or severity is None:
            raise ScanError(f"zizmor output has a malformed finding: {str(r)[:300]}")
        if ident in ignore:
            continue
        loc = _primary(r)
        key = loc["symbolic"].get("key")
        path = (
            key.get("Local", {}).get("verbatim_path")
            if isinstance(key, dict) and isinstance(key.get("Local"), dict)
            else None
        )
        if not isinstance(path, str) or not Path(path).is_absolute():
            raise ScanError(f"zizmor reported a location that is not a local absolute path: {str(key)[:300]}")
        try:
            rel = Path(path).relative_to(root).as_posix()
        except ValueError:
            raise ScanError(f"zizmor reported a path outside the target: {path[:300]}") from None
        if rel not in scanned:
            raise ScanError(f"zizmor reported a file it was not given: {rel[:300]}")
        concrete = loc.get("concrete") if isinstance(loc.get("concrete"), dict) else {}
        start = (
            concrete.get("location", {}).get("start_point", {}) if isinstance(concrete.get("location"), dict) else {}
        )
        row, col = start.get("row"), start.get("column")
        if not isinstance(row, int) or isinstance(row, bool) or row < 0:
            raise ScanError("zizmor output has a malformed location")
        route = loc["symbolic"].get("route", {}).get("route") if isinstance(loc["symbolic"].get("route"), dict) else []
        # Keys only: a step index changes when a step is added above it.
        keys = [str(step["Key"]) for step in route or [] if isinstance(step, dict) and "Key" in step]
        desc = " ".join(str(r.get("desc", "")).split())
        note = " ".join(str(loc["symbolic"].get("annotation", "")).split())
        items.append(
            {
                "tool": TOOL,
                "rule": f"{TOOL}.{ident}",
                "path": rel,
                "line": row + 1,
                "col": col if isinstance(col, int) else 0,
                "code": normalise_code(str(concrete.get("feature", ""))),
                "context": "/".join(keys)[:500],
                "severity": severity,
                "message": (f"{desc}: {note}" if note else desc)[:1000] or ident,
            }
        )
    prints = assign_fingerprints(items)
    return [
        Finding(
            tool=TOOL,
            rule=it["rule"],
            severity=it["severity"],
            path=it["path"],
            line=it["line"],
            fingerprint=fp,
            component=component_for(it["path"], components),
            message=it["message"],
        )
        for it, fp in zip(items, prints)
    ]


def rule_metadata(findings: list[Finding], results: list) -> dict[str, dict]:
    """The same shape as `opengrep.rule_metadata`, with each audit's documentation link."""
    urls = {f"{TOOL}.{r.get('ident')}": r.get("url") for r in results if isinstance(r, dict)}
    out = {}
    for f in findings:
        url = urls.get(f.rule)
        refs = [url] if isinstance(url, str) and url.startswith(_DOCS) and " " not in url else []
        out[f.rule] = {
            "file": None,
            "cwe": [],
            "owasp": [],
            "fix": None,
            "references": refs,
            "confidence": None,
            "likelihood": None,
            "impact": None,
        }
    return out


def run(
    binary: Path,
    binary_sha256: str,
    root: Path,
    stage: Path,
    limits: Limits,
    components: dict[str, str],
    excludes: tuple[str, ...],
    ignore: tuple[str, ...],
) -> tuple[list[Finding], dict, int, dict]:
    """Audit the repository's GitHub Actions files.

    Returns the findings, the unscanned files, how many files were audited
    and the rule metadata.
    """
    if not binary.is_file():
        raise SetupError(f"zizmor is not installed: {binary} (run `shoalscan install`)")
    verify_sha256(binary, binary_sha256)
    files, skipped = discover(root, excludes, limits.max_target_bytes)
    if not files:
        return [], {"skipped": skipped, "errors": []}, 0, {}
    work = stage / "zizmor"
    work.mkdir(parents=True)
    deadline = time.monotonic() + limits.scan_timeout_seconds

    def audit(paths: list[str]) -> tuple[int, list | None, str]:
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            raise ScanError(f"zizmor timed out after {limits.scan_timeout_seconds}s")
        return execute(build_command(binary, [root / p for p in paths]), work, remaining)

    errors: list[dict] = []
    code, results, tail = audit(files)
    if results is None:
        # Something could not be read: audit each file alone to find out which.
        results = []
        for path in files:
            one_code, found, one_tail = audit([path])
            if found is None:
                # Keep the message repository-relative: the runner's paths mean nothing in the history.
                message = one_tail.replace(f"{root}/", "").replace(str(work), "")
                errors.append({"path": path, "type": "zizmor input error", "message": message[-400:]})
            else:
                results += found
        if not errors:
            raise ScanError(f"zizmor failed with exit code {code}, but every file passes alone\n{tail}")
    scanned = set(files) - {e["path"] for e in errors}
    findings = normalise(results, root, scanned, components, ignore)
    return findings, {"skipped": skipped, "errors": errors}, len(scanned), rule_metadata(findings, results)
