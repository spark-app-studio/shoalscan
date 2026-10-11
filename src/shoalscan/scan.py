"""`shoalscan scan`: run the configured scanners and write normalised findings."""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from shoalscan import __version__, gitleaks, hadolint, opengrep, trivy, zizmor
from shoalscan.check import CHECK_JSON
from shoalscan.config import Config
from shoalscan.errors import ScanError, SetupError
from shoalscan.excludes import ExcludeMatcher
from shoalscan.findings import Finding, findings_to_json
from shoalscan.lockfile import verify_sha256
from shoalscan.gitref import baseline_binding_path, worktree_state
from shoalscan.rulesets import RuleIdFilter
from shoalscan.sarif import build_sarif
from shoalscan.suppressions import find_suppressions, lint_findings

FINDINGS_JSON = "findings.json"
FINDINGS_SARIF = "findings.sarif"


@dataclass(frozen=True)
class Tools:
    """The scanner binary and rule snapshot a scan uses.

    `opengrep_sha256` is the pinned hash the binary must match before it runs.
    `community_rules` is the verified snapshot directory, or None when the
    configuration turns community rules off.
    """

    opengrep: Path
    opengrep_sha256: str | None
    opengrep_version: str
    community_rules: Path | None
    community_commit: str | None
    shoalscan_rules: Path | None
    signature_verified: bool = True
    # Scanners pinned by SHA-256 in their own tools.lock table, by name.
    pinned: dict[str, "PinnedBinary"] = field(default_factory=dict)


@dataclass(frozen=True)
class PinnedBinary:
    """An installed scanner and its extra files, each with the SHA-256 it must have."""

    version: str
    path: Path
    sha256: str
    files: dict[str, tuple[Path, str]] = field(default_factory=dict)


@dataclass
class ScanResult:
    findings: list[Finding]
    meta: dict


def _repo_rule_dir(root: Path, rel: str) -> Path:
    path = (root / rel).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        raise SetupError(f"rule directory leaves the repository: {rel}") from None
    if not path.is_dir():
        raise SetupError(f"rule directory not found: {rel}")
    return path


MAX_SUPPRESSION_LIST = 10_000


def write_atomic(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def run_scan(
    repo: Path,
    config: Config,
    tools: Tools,
    out_dir: Path,
    rule_root: Path | None = None,
    policy: dict | None = None,
    baseline: Path | None = None,
) -> ScanResult:
    """Scan `repo`. Repository rule dirs are read under `rule_root` (default: the repo).

    With a policy ref, `rule_root` holds the rule dirs extracted from that ref
    and `policy` records which ref and configuration were used.

    `baseline` is the baseline file `check` will read, given only without a
    policy ref: the tree binding then also records the working tree's state
    with that file left out (see `gitref.worktree_state`).
    """
    started = time.monotonic()
    root = repo.resolve()
    if not root.is_dir():
        raise SetupError(f"repository directory not found: {repo}")
    out_dir.mkdir(parents=True, exist_ok=True)
    # A failed scan must never leave an older findings file behind for `check`.
    for name in (FINDINGS_JSON, FINDINGS_SARIF, CHECK_JSON):
        (out_dir / name).unlink(missing_ok=True)

    excludes = list(config.excludes)
    ExcludeMatcher(excludes)  # validate the patterns before running anything

    suppressions = []
    own_findings: list[Finding] = []
    findings: list[Finding] = []
    meta: dict = {
        "shoalscan_version": __version__,
        "scanners": {},
        "policy": policy or {"ref": None},
        "worktree": worktree_state(root, baseline_binding_path(repo, baseline) if baseline is not None else None),
    }
    unscanned: dict = {"skipped": [], "errors": []}
    sarif_index: dict = {}
    sarif_source: Path | None = None
    suppressed_by_scanner = 0
    stage = Path(tempfile.mkdtemp(prefix="shoalscan-rules-"))
    try:
        if "opengrep" in config.scanners:
            if tools.opengrep_sha256 is not None:
                if not tools.opengrep.is_file():
                    raise SetupError(f"opengrep is not installed: {tools.opengrep} (run `shoalscan install`)")
                verify_sha256(tools.opengrep, tools.opengrep_sha256)
            sources: list[opengrep.RuleSource] = []
            if config.opengrep.community_rules:
                if tools.community_rules is None:
                    raise SetupError("community rules are enabled but not installed (run `shoalscan install`)")
                sources.append(
                    opengrep.RuleSource("community", tools.community_rules, frozenset(config.opengrep.categories))
                )
            if config.opengrep.shoalscan_rules:
                if tools.shoalscan_rules is None:
                    raise SetupError("Shoalscan's own rules were not found")
                sources.append(opengrep.RuleSource("shoalscan", tools.shoalscan_rules))
            for rel in config.opengrep.rule_dirs:
                sources.append(opengrep.RuleSource(f"repo/{rel}", _repo_rule_dir((rule_root or root).resolve(), rel)))
            rules_stage = stage / "rules"
            rules_stage.mkdir()
            excluded = RuleIdFilter(config.opengrep.exclude_rules)
            stats = opengrep.stage_rules(rules_stage, sources, excluded)
            namespaces = [s.namespace for s in sources]
            sarif_source = stage / "opengrep.sarif"
            cmd = opengrep.build_command(tools.opengrep, namespaces, root, config.limits, excludes, sarif_source)
            doc = opengrep.execute(cmd, rules_stage, config.limits.scan_timeout_seconds)
            warnings = opengrep.check_errors(doc)
            rules_ran = opengrep.check_rules_ran(doc, stats.rule_ids)
            scanned_paths = opengrep.scanned_paths(doc, root)
            scanned = len(scanned_paths)
            if scanned == 0:
                raise ScanError("opengrep scanned no files; check the target and the excludes")
            # The lint covers exactly the files Opengrep scanned, prose included:
            # Opengrep honours a marker in any file it scans.
            suppressions = find_suppressions(root, scanned_paths, config.limits.max_target_bytes)
            own_findings = lint_findings(suppressions, config.components)
            findings += own_findings
            unscanned = opengrep.unscanned(doc, root)
            og_findings, sarif_index = opengrep.normalise(doc, root, config.components)
            # Defence in depth: the staging filter already left these rules out.
            og_findings = [f for f in og_findings if not excluded.matches(f.rule)]
            findings += og_findings
            if not sarif_source.is_file():
                raise ScanError("opengrep did not write its SARIF output")
            # Which rules this run applied: a finding missing from a run proves a fix only if its rule ran.
            meta["rule_ids"] = sorted(stats.rule_ids)
            # What the rules behind the findings say about themselves, for `shoalscan triage`.
            meta["rules"] = opengrep.rule_metadata(doc, stats.rule_files)
            meta["scanners"]["opengrep"] = {
                "version": tools.opengrep_version,
                "signature_verified": tools.signature_verified,
                "rule_files": stats.files,
                "rules_staged": len(stats.rule_ids),
                "rules_ran": rules_ran,
                "rules_selected_from_filtered_files": stats.rules_kept,
                "rules_left_out": stats.rules_dropped,
                "community_categories": list(config.opengrep.categories) if config.opengrep.community_rules else [],
                "exclude_rules": list(config.opengrep.exclude_rules),
                "rule_sources": [s.namespace for s in sources],
                "community_rules_commit": tools.community_commit if config.opengrep.community_rules else None,
                "files_scanned": scanned,
                "warnings": len(warnings),
                "skipped_rules": len(doc.get("skipped_rules") or []),
                "suppressed_findings": opengrep.ignored_count(doc),
            }
            suppressed_by_scanner += opengrep.ignored_count(doc)
        extra_runs = []
        if "gitleaks" in config.scanners:
            pin = tools.pinned.get("gitleaks")
            if pin is None:
                raise SetupError("gitleaks is enabled but tools.lock pins no gitleaks")
            config_file, config_sha256 = pin.files["config"]
            leaks, leak_rules = gitleaks.run(
                pin.path, pin.sha256, config_file, config_sha256, root, stage, config.limits, config.components, config.excludes
            )
            findings += leaks
            extra_runs.append((gitleaks.TOOL, pin.version, leaks))
            meta["rule_ids"] = sorted({*meta.get("rule_ids", []), *leak_rules})
            meta.setdefault("rules", {}).update(gitleaks.rule_metadata(leaks))
            meta["scanners"]["gitleaks"] = {
                "version": pin.version,
                "verification": "sha256",
                "config_sha256": config_sha256,
                "rules": len(leak_rules),
                "findings": len(leaks),
            }
        if "hadolint" in config.scanners:
            pin = tools.pinned.get("hadolint")
            if pin is None:
                raise SetupError("hadolint is enabled but tools.lock pins no hadolint")
            lints, missed, linted = hadolint.run(
                pin.path, pin.sha256, root, stage, config.limits, config.components, config.excludes, config.hadolint.ignore
            )
            findings += lints
            extra_runs.append((hadolint.TOOL, pin.version, lints))
            unscanned = {kind: [*unscanned.get(kind, []), *missed[kind]] for kind in ("skipped", "errors")}
            meta.setdefault("rules", {}).update(hadolint.rule_metadata(lints))
            meta["scanners"]["hadolint"] = {
                "version": pin.version,
                "verification": "sha256",
                "files_scanned": linted,
                "ignore": list(config.hadolint.ignore),
                "findings": len(lints),
            }
        if "zizmor" in config.scanners:
            pin = tools.pinned.get("zizmor")
            if pin is None:
                raise SetupError("zizmor is enabled but tools.lock pins no zizmor")
            audits, missed, audited, audit_rules = zizmor.run(
                pin.path, pin.sha256, root, stage, config.limits, config.components, config.excludes, config.zizmor.ignore
            )
            findings += audits
            extra_runs.append((zizmor.TOOL, pin.version, audits))
            unscanned = {kind: [*unscanned.get(kind, []), *missed[kind]] for kind in ("skipped", "errors")}
            meta.setdefault("rules", {}).update(audit_rules)
            meta["scanners"]["zizmor"] = {
                "version": pin.version,
                "verification": "sha256",
                "files_scanned": audited,
                "ignore": list(config.zizmor.ignore),
                "findings": len(audits),
            }
        if "trivy" in config.scanners:
            pin = tools.pinned.get("trivy")
            if pin is None:
                raise SetupError("trivy is enabled but tools.lock pins no trivy")
            misconfigs, missed, markers, silenced, misconfig_rules = trivy.run(
                pin.path, pin.sha256, root, stage, config.limits, config.components, config.excludes, config.trivy.ignore
            )
            findings += misconfigs
            extra_runs.append((trivy.TOOL, pin.version, misconfigs))
            unscanned = {kind: [*unscanned.get(kind, []), *missed[kind]] for kind in ("skipped", "errors")}
            # Trivy's inline markers are held to the same rule as Opengrep's, and counted with them.
            suppressions = [*suppressions, *markers]
            marker_findings = lint_findings(markers, config.components)
            own_findings = [*own_findings, *marker_findings]
            findings += marker_findings
            suppressed_by_scanner += silenced
            meta.setdefault("rules", {}).update(misconfig_rules)
            meta["scanners"]["trivy"] = {
                "version": pin.version,
                "verification": "sha256 and cosign",
                "ignore": list(config.trivy.ignore),
                "findings": len(misconfigs),
                "inline_suppressions": len(markers),
                "suppressed_findings": silenced,
            }
        sarif_text = build_sarif(sarif_source, root, sarif_index, own_findings, extra_runs)
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    sev = Counter(f.severity for f in findings)
    meta.update(
        {
            "excludes": excludes,
            "unscanned": unscanned,
            "suppressions": {
                "total": len(suppressions),
                "invalid": sum(1 for s in suppressions if not s.valid),
                "suppressed_findings": suppressed_by_scanner,
            },
            # Kept apart from the counts above, which go into the check summary line.
            "suppression_list": [
                {
                    "path": s.path,
                    "line": s.line,
                    "rules": list(s.rule_ids),
                    "issue": s.issue,
                    "valid": s.valid,
                    "problem": None if s.valid else s.problem(),
                }
                for s in sorted(suppressions, key=lambda s: (s.path, s.line))[:MAX_SUPPRESSION_LIST]
            ],
            "counts": {k: sev.get(k, 0) for k in ("ERROR", "WARNING", "INFO")},
            "duration_seconds": round(time.monotonic() - started, 1),
        }
    )
    write_atomic(out_dir / FINDINGS_SARIF, sarif_text)
    write_atomic(out_dir / FINDINGS_JSON, findings_to_json(findings, meta))
    return ScanResult(findings, meta)

