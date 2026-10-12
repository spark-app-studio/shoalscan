"""Run `trivy config` over the repository and turn its misconfigurations into findings.

Trivy reads things the repository or the machine controls: a `trivy.yaml`
in the working directory, `.trivyignore` files, `TRIVY_*` environment
variables, WebAssembly modules in `~/.trivy/modules`, a cached checks
bundle downloaded from a registry, and inline ignore comments. The scan
passes empty files for `--config` and `--ignorefile`, an empty
`--module-dir`, an empty `--cache-dir` with `--skip-check-update` (so the
checks embedded in the pinned binary are used, and nothing is downloaded),
`--skip-version-check` and `--disable-telemetry`, and runs Trivy with the
scanners' allowlisted environment.

Inline ignore comments cannot be turned off in Trivy, so Shoalscan lints
them (see `shoalscan.suppressions`): each must name one check and an issue,
or it is a blocking finding, and every one is counted. Checks are left out
only through `[trivy] ignore` in `.shoalscan.toml`, which is policy.

Trivy finds the configuration files itself. Files it could not parse are
listed as unscanned errors when Trivy logs them (it does for Terraform); a
YAML or JSON file it cannot parse is not recognised as configuration at all,
and so is not reported.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from shoalscan import process
from shoalscan.config import Limits, component_for
from shoalscan.errors import ScanError, SetupError
from shoalscan.excludes import ExcludeMatcher
from shoalscan.findings import Finding, assign_fingerprints, normalise_code
from shoalscan.hadolint import is_dockerfile
from shoalscan.lockfile import verify_sha256
from shoalscan.suppressions import Suppression, find_trivy_suppressions

TOOL = "trivy"
MAX_OUTPUT_BYTES = 256 * 1024 * 1024
MAX_STDERR_CHARS = 4 * 1024 * 1024
_SEVERITY = {"CRITICAL": "ERROR", "HIGH": "ERROR", "MEDIUM": "WARNING", "LOW": "INFO", "UNKNOWN": "INFO"}
_CHECK = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{3,5}$")
# A log line of a file Trivy could not parse: `<time>\tERROR\t[...] Error parsing file\t... file_path="..."`.
_PARSE_ERROR = re.compile(r'\tERROR\t[^\n]*?[Ee]rror parsing[^\n]*?file_path="((?:[^"\\\n]|\\.)*)"')
# Files whose Trivy markers are linted: the kinds of files Trivy reads.
_CONFIG_SUFFIXES = (".tf", ".tf.json", ".tfvars", ".hcl", ".yaml", ".yml", ".json", ".template", ".bicep")


def build_command(binary: Path, target: Path, work: Path) -> list[str]:
    return [
        str(binary),
        "config",
        # The checks embedded in the pinned binary; no downloads, no cache from earlier runs.
        "--cache-dir",
        str(work / "cache"),
        "--skip-check-update",
        "--skip-version-check",
        "--disable-telemetry",
        # Empty files and directories, never the repository's or the machine's.
        "--config",
        str(work / "trivy.yaml"),
        "--ignorefile",
        str(work / "trivyignore"),
        "--module-dir",
        str(work / "modules"),
        "--format",
        "json",
        "--exit-code",
        "0",
        str(target),
    ]


def execute(cmd: list[str], cwd: Path, timeout: int) -> tuple[dict, str]:
    """Run Trivy and return its parsed report and its log, or raise ScanError."""
    returncode, stdout, log = process.run_scanner(TOOL, cmd, cwd, timeout, stderr_chars=MAX_STDERR_CHARS)
    if returncode != 0:
        raise ScanError(f"trivy failed with exit code {returncode}\n{log[-2000:]}")
    if len(stdout) > MAX_OUTPUT_BYTES:
        raise ScanError("trivy output is larger than allowed")
    try:
        doc = json.loads(stdout)
    except (ValueError, UnicodeDecodeError):
        raise ScanError(f"trivy output is not valid JSON\n{log[-2000:]}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("Results", []), list):
        raise ScanError("trivy output has no list of results")
    return doc, log


def _inside(root: Path, rel: object) -> str | None:
    """A repository-relative file path Trivy reported, if it is one."""
    if not isinstance(rel, str) or not rel or rel.startswith("/") or "\\" in rel or ".." in rel.split("/"):
        return None
    path = root / rel
    try:
        return rel if path.is_file() and not path.is_symlink() else None
    except OSError:  # a name the file system refuses (too long, for example) is not a file of the repository
        return None


def parse_errors(log: str, root: Path, excludes: tuple[str, ...]) -> list[dict]:
    matcher = ExcludeMatcher(list(excludes))
    errors = {}
    for match in _PARSE_ERROR.finditer(log):
        rel = _inside(root, match.group(1).replace('\\"', '"'))
        if rel and not matcher.excluded(rel):
            errors[rel] = {"path": rel, "type": "trivy parse error"}
    return sorted(errors.values(), key=lambda e: e["path"])


def normalise(
    doc: dict, root: Path, components: dict[str, str], excludes: tuple[str, ...], ignore: tuple[str, ...]
) -> tuple[list[Finding], dict]:
    """Findings, and the rule metadata for the work list."""
    matcher = ExcludeMatcher(list(excludes))
    items, meta = [], {}
    for result in doc.get("Results") or []:
        if not isinstance(result, dict):
            raise ScanError("trivy output has a result that is not an object")
        misconfigs = result.get("Misconfigurations") or []
        if not isinstance(misconfigs, list):
            raise ScanError("trivy output has a malformed list of misconfigurations")
        failures = [m for m in misconfigs if isinstance(m, dict) and m.get("Status") == "FAIL"]
        if not failures:
            continue
        rel = _inside(root, result.get("Target"))
        if rel is None:
            raise ScanError(
                "trivy reported a finding in something that is not a file of the repository: "
                f"{str(result.get('Target'))[:300]}"
            )
        if rel == ".git" or rel.startswith(".git/") or matcher.excluded(rel):
            continue
        for m in failures:
            check, severity = m.get("ID"), _SEVERITY.get(str(m.get("Severity")))
            if not isinstance(check, str) or not _CHECK.match(check) or severity is None:
                raise ScanError(f"trivy output has a malformed misconfiguration: {str(m)[:300]}")
            if check in ignore:
                continue
            cause = m.get("CauseMetadata") if isinstance(m.get("CauseMetadata"), dict) else {}
            start = cause.get("StartLine")
            line = start if isinstance(start, int) and not isinstance(start, bool) and start > 0 else 1
            code = cause.get("Code") if isinstance(cause.get("Code"), dict) else {}
            listed = code.get("Lines") if isinstance(code.get("Lines"), list) else []
            lines = [c.get("Content", "") for c in listed if isinstance(c, dict) and c.get("IsCause")]
            title = " ".join(str(m.get("Title", "")).split())
            message = " ".join(str(m.get("Message", "")).split())
            rule = f"{TOOL}.{check}"
            items.append(
                {
                    "tool": TOOL,
                    "rule": rule,
                    "path": rel,
                    "line": line,
                    "code": normalise_code("\n".join(str(x) for x in lines)),
                    # The resource (aws_s3_bucket.logs) follows the finding when blocks move.
                    "context": str(cause.get("Resource") or "")[:300],
                    "severity": severity,
                    "message": (f"{title}: {message}" if message and message != title else title)[:1000] or check,
                }
            )
            refs = [
                u
                for u in [m.get("PrimaryURL"), *(m.get("References") if isinstance(m.get("References"), list) else [])]
                if isinstance(u, str) and u.startswith("https://") and " " not in u
            ]
            resolution = " ".join(str(m.get("Resolution", "")).split())[:500] or None
            meta[rule] = {
                "file": None,
                "cwe": [],
                "owasp": [],
                "fix": resolution,
                "references": list(dict.fromkeys(refs))[:5],
                "confidence": None,
                "likelihood": None,
                "impact": None,
            }
    prints = assign_fingerprints(items)
    findings = [
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
        for it, fp in zip(items, prints, strict=True)
    ]
    return findings, meta


def config_files(root: Path, excludes: tuple[str, ...], max_bytes: int) -> list[str]:
    """The files whose Trivy markers are linted: every file of a kind Trivy reads, outside .git and the excludes."""
    matcher = ExcludeMatcher(list(excludes))
    found = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = sorted(
            d for d in dirnames if d != ".git" and not matcher.excluded(f"{rel_dir}/{d}" if rel_dir else d)
        )
        for name in filenames:
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if (name.lower().endswith(_CONFIG_SUFFIXES) or is_dockerfile(name)) and not matcher.excluded(rel):
                found.append(rel)
    return sorted(found)


def run(
    binary: Path,
    binary_sha256: str,
    root: Path,
    stage: Path,
    limits: Limits,
    components: dict[str, str],
    excludes: tuple[str, ...],
    ignore: tuple[str, ...],
) -> tuple[list[Finding], dict, list[Suppression], int, dict]:
    """Check the repository's infrastructure as code.

    Returns the findings, the unscanned files, the Trivy markers found, how
    many findings those markers silenced (from Trivy's log) and the rule metadata.
    """
    if not binary.is_file():
        raise SetupError(f"trivy is not installed: {binary} (run `shoalscan install`)")
    verify_sha256(binary, binary_sha256)
    work = stage / "trivy"
    for d in ("cache", "modules"):
        (work / d).mkdir(parents=True)
    (work / "trivy.yaml").write_text("{}\n", encoding="utf-8")
    (work / "trivyignore").write_text("", encoding="utf-8")
    doc, log = execute(build_command(binary, root, work), work, limits.scan_timeout_seconds)
    findings, meta = normalise(doc, root, components, excludes, ignore)
    markers = find_trivy_suppressions(
        root, config_files(root, excludes, limits.max_target_bytes), limits.max_target_bytes
    )
    silenced = len(re.findall(r"\tINFO\t\[[^\]\n]*\] Ignore finding\t", log))
    return findings, {"skipped": [], "errors": parse_errors(log, root, excludes)}, markers, silenced, meta
