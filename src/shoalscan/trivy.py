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

Inline ignore comments (the current and the legacy tfsec prefix) cannot be
turned off in Trivy, so Shoalscan lints them (see `shoalscan.suppressions`):
each must name one check and an issue, or it is a blocking finding, and
every one is counted. Each finding Trivy logs as silenced must sit in a file
with a valid marker, or the scan fails. Checks are left out only through
`[trivy] ignore` in `.shoalscan.toml`, which is policy.

Trivy fetches remote Terraform modules (git, S3, GCS, HTTPS, the registry)
and 0.74.0 has no flag to stop it (`--tf-exclude-downloaded-modules` only
filters results). The scanner environment (see `shoalscan.process`) leaves
it no credentials, no transport and no route: an empty home directory, git
without configuration or allowed protocols, proxies on a closed port, and
an operating-system network sandbox where one is available.

Helm charts are not scanned (see `MISCONFIG_SCANNERS`). Trivy finds the
configuration files itself. Files it could not parse are listed as
unscanned errors when Trivy logs them (it does for Terraform); a
YAML or JSON file it cannot parse is not recognised as configuration at all,
and so is not reported.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from shoalscan import helm, process
from shoalscan.config import Limits, component_for
from shoalscan.errors import ScanError, SetupError
from shoalscan.excludes import ExcludeMatcher
from shoalscan.findings import Finding, assign_fingerprints, normalise_code
from shoalscan.hadolint import is_dockerfile
from shoalscan.helm import Rendered
from shoalscan.lockfile import verify_sha256
from shoalscan.suppressions import Suppression, find_trivy_suppressions

TOOL = "trivy"
MAX_OUTPUT_BYTES = 256 * 1024 * 1024
MAX_STDERR_BYTES = 16 * 1024 * 1024
_SEVERITY = {"CRITICAL": "ERROR", "HIGH": "ERROR", "MEDIUM": "WARNING", "LOW": "INFO", "UNKNOWN": "INFO"}
_CHECK = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{3,5}$")
# A log line of a file Trivy could not parse: `<time>\tERROR\t[...] Error parsing file\t... file_path="..."`.
_PARSE_ERROR = re.compile(
    r'\tERROR\t[^\n]*?(?:[Ee]rror parsing|[Ff]ailed to parse)[^\n]*?file_path="((?:[^"\\\n]|\\.)*)"'
)
MISCONFIG_SCANNERS = (
    "azure-arm",
    "cloudformation",
    "dockerfile",
    "kubernetes",
    "terraform",
    "terraformplan-json",
    "terraformplan-snapshot",
    "ansible",
)
# A log line of a finding an inline comment silenced: `<time>\tINFO\t[...] Ignore finding\trule="..." range="..."`.
_IGNORED = re.compile(r"\tINFO\t\[[^\]\n]*\] Ignore finding\t([^\n]*)")
# Its range is `path:start-end`, or `path:line` for one line.
_RANGE = re.compile(r'\brange="((?:[^"\\\n]|\\.)*):(\d+)(?:-(\d+))?"')
# Files whose Trivy markers are linted: the kinds of files Trivy reads, packaged Helm charts included.
_CONFIG_SUFFIXES = (
    ".tf",
    ".tf.json",
    ".tofu",
    ".tofu.json",
    ".tfvars",
    ".hcl",
    ".yaml",
    ".yml",
    ".json",
    ".template",
    ".tpl",
    ".bicep",
    ".tgz",
    ".tar.gz",
    ".tar",
)


def build_command(binary: Path, target: Path, work: Path, scanners: tuple[str, ...] = MISCONFIG_SCANNERS) -> list[str]:
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
        # Every scanner but Helm's: Trivy reads ignore comments from the rendered chart, which a
        # template can produce at render time where no lint of the source can see them.
        "--misconfig-scanners",
        ",".join(scanners),
        "--format",
        "json",
        "--exit-code",
        "0",
        str(target),
    ]


def execute(cmd: list[str], cwd: Path, timeout: int) -> tuple[dict, str]:
    """Run Trivy and return its parsed report and its log, or raise ScanError."""
    # The whole log is kept: the findings inline comments silenced are read from it, so a log
    # too long to keep fails the scan rather than hiding them.
    returncode, stdout, log = process.run_scanner(
        TOOL, cmd, cwd, timeout, max_stdout=MAX_OUTPUT_BYTES, max_stderr=MAX_STDERR_BYTES
    )
    if returncode != 0:
        raise ScanError(f"trivy failed with exit code {returncode}\n{process.error_summary(log)}")
    try:
        doc = json.loads(stdout)
    except (ValueError, UnicodeDecodeError):
        raise ScanError(f"trivy output is not valid JSON\n{process.error_summary(log)}") from None
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
    doc: dict,
    root: Path,
    components: dict[str, str],
    excludes: tuple[str, ...],
    ignore: tuple[str, ...],
    rendered: dict[str, Rendered] | None = None,
) -> tuple[list[Finding], dict]:
    """Findings, and the rule metadata for the work list.

    With `rendered`, the report is of rendered Helm charts: each target is a
    rendered document, reported at its template (see `shoalscan.helm`).
    """
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
        origin = rendered.get(str(result.get("Target"))) if rendered is not None else None
        rel = (
            origin.path if origin is not None else None if rendered is not None else _inside(root, result.get("Target"))
        )
        if rel is None:
            raise ScanError(
                "trivy reported a finding in something that is not a file of the repository: "
                f"{str(result.get('Target'))[:300]}"
            )
        # A rendered finding is never dropped: its path was chosen (and kept out of the excludes) by helm.render.
        if origin is None and (rel == ".git" or rel.startswith(".git/") or matcher.excluded(rel)):
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
            item = {
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
            if origin is not None:
                # Rendered output has no stable lines: the template, the resource and the rule identify it.
                where = f" (in {origin.resource})" if origin.resource else ""
                item.update(
                    line=1,
                    code="",
                    # The template path too, so no resource name chosen in one template matches another's.
                    context=f"helm:{origin.path}:{origin.resource}"[:300],
                    message=(
                        f"{item['message']}{where}; found in the chart as Helm renders it, so the line is the "
                        "template's first"
                    )[:1000],
                )
            items.append(item)
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


def silenced_findings(log: str, markers: list[Suppression], excludes: tuple[str, ...]) -> int:
    """How many findings Trivy says inline comments silenced, each checked against the linted markers.

    Trivy logs these for Terraform and CloudFormation. Each must be in a file
    that holds a valid marker (one check and an issue) at or above its first
    line; anything else means
    a comment the lint did not see silenced a finding, and the scan fails.
    Findings in excluded files and under .git are dropped anyway, and not counted.
    """
    matcher = ExcludeMatcher(list(excludes))
    valid: dict[str, list[int]] = {}
    for s in markers:
        if s.valid:
            valid.setdefault(s.path, []).append(s.line)
    count = 0
    for match in _IGNORED.finditer(log):
        where = _RANGE.search(match.group(1))
        path = where.group(1).replace('\\"', '"') if where else None
        if path is not None and (path == ".git" or path.startswith(".git/") or matcher.excluded(path)):
            continue
        start = int(where.group(2)) if where else 0
        # Trivy applies a marker to a block that starts on its line or the next, and to everything
        # inside that block, so a valid marker must sit at or above the silenced finding.
        if path not in valid or not any(line <= start for line in valid[path]):
            raise ScanError(
                "trivy reports a finding silenced by an inline comment that is not a valid, linted marker "
                f"({str(path)[:300] if path else 'in an unknown place'}); nothing in the repository may silence a "
                "check except a marker that names it and an issue"
            )
        count += 1
    return count


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


def _remaining(deadline: float, timeout: int) -> int:
    left = int(deadline - time.monotonic())
    if left <= 0:
        raise ScanError(f"trivy timed out after {timeout}s")
    return left


def _scan_charts(
    binary: Path,
    root: Path,
    stage: Path,
    components: dict[str, str],
    excludes: tuple[str, ...],
    ignore: tuple[str, ...],
    helm_pin: tuple[Path, str] | None,
    helm_values: dict[str, tuple[str, ...]],
    deadline: float,
) -> tuple[list[Finding], list[dict], dict]:
    """Render the Helm charts and check the manifests with Trivy's Kubernetes checks."""
    charts = helm.find_charts(root, excludes)
    if not charts:
        return [], [], {}
    if helm_pin is None:
        raise SetupError("the repository has Helm charts, but tools.lock pins no helm (run `shoalscan install`)")
    timeout = int(deadline - time.monotonic())
    work = stage / "trivy-helm"
    rendered, mapping, errors = helm.render(
        helm_pin[0], helm_pin[1], root, work / "helm", charts, helm_values, _remaining(deadline, timeout), excludes
    )
    if not mapping:
        return [], errors, {}
    for d in ("cache", "modules"):
        (work / d).mkdir(parents=True)
    (work / "trivy.yaml").write_text("{}\n", encoding="utf-8")
    (work / "trivyignore").write_text("", encoding="utf-8")
    cmd = build_command(binary, rendered, work, ("kubernetes",))
    doc, log = execute(cmd, work, _remaining(deadline, timeout))
    # Nothing in a rendered chart may silence a check: its comments were removed and its markers defused.
    if _IGNORED.search(log):
        raise ScanError("trivy reports a finding silenced in a rendered Helm chart; nothing there may silence a check")
    findings, meta = normalise(doc, root, components, excludes, ignore, rendered=mapping)
    for match in _PARSE_ERROR.finditer(log):
        origin = mapping.get(match.group(1).replace('\\"', '"'))
        if origin is not None:
            errors.append({"path": origin.path, "type": "trivy parse error (rendered by helm)"})
    return findings, errors, meta


def run(
    binary: Path,
    binary_sha256: str,
    root: Path,
    stage: Path,
    limits: Limits,
    components: dict[str, str],
    excludes: tuple[str, ...],
    ignore: tuple[str, ...],
    helm_pin: tuple[Path, str] | None = None,
    helm_values: dict[str, tuple[str, ...]] | None = None,
) -> tuple[list[Finding], dict, list[Suppression], int, dict]:
    """Check the repository's infrastructure as code, Helm charts rendered by the pinned Helm.

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
    deadline = time.monotonic() + limits.scan_timeout_seconds
    doc, log = execute(build_command(binary, root, work), work, limits.scan_timeout_seconds)
    findings, meta = normalise(doc, root, components, excludes, ignore)
    chart_findings, chart_errors, chart_meta = _scan_charts(
        binary, root, stage, components, excludes, ignore, helm_pin, helm_values or {}, deadline
    )
    findings += chart_findings
    meta.update(chart_meta)
    markers = find_trivy_suppressions(
        root, config_files(root, excludes, limits.max_target_bytes), limits.max_target_bytes
    )
    silenced = silenced_findings(log, markers, excludes)
    unscanned = {"skipped": [], "errors": [*parse_errors(log, root, excludes), *chart_errors]}
    return findings, unscanned, markers, silenced, meta
