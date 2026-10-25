"""`shoalscan scan`: run the configured scanners and write normalised findings."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path

from shoalscan import __version__, gitleaks, hadolint, opengrep, process, testscope, trivy, zizmor
from shoalscan.check import CHECK_JSON
from shoalscan.config import Config
from shoalscan.errors import ScanError, SetupError
from shoalscan.excludes import ExcludeMatcher
from shoalscan.findings import Finding, findings_to_json
from shoalscan.gitref import baseline_binding_path, worktree_state
from shoalscan.lockfile import verify_sha256
from shoalscan.resources import scope_rules_file
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
    # None when tools.lock pins no signature for it; else whether `install` recorded a cosign check.
    signature_verified: bool | None = None

    def verification(self) -> str:
        if self.signature_verified is None:
            return "sha256"
        return "sha256 and cosign" if self.signature_verified else "sha256 (signature not verified)"


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


def check_network_sandbox(required: bool) -> str:
    """The network sandbox scanners will run in; a SetupError when one is required and none works."""
    network = process.network_sandbox()[1]
    if required and network == process.NO_SANDBOX:
        raise SetupError(
            "a network sandbox is required (--require-network-sandbox, or require_network_sandbox in "
            "scan_targets.toml) but neither sandbox-exec nor unshare --net works here; nothing was scanned"
        )
    return network


def run_scan(
    repo: Path,
    config: Config,
    tools: Tools,
    out_dir: Path,
    rule_root: Path | None = None,
    policy: dict | None = None,
    baseline: Path | None = None,
    require_network_sandbox: bool = False,
) -> ScanResult:
    """Scan `repo`. Repository rule dirs are read under `rule_root` (default: the repo).

    With a policy ref, `rule_root` holds the rule dirs extracted from that ref
    and `policy` records which ref and configuration were used.

    `baseline` is the baseline file `check` will read, given only without a
    policy ref: the tree binding then also records the working tree's state
    with that file left out (see `gitref.worktree_state`).
    """
    started = time.monotonic()
    network = check_network_sandbox(require_network_sandbox)
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
        # How the scanners were kept apart from this machine (see `shoalscan.process`).
        "isolation": {
            "home": "empty, one per scanner run",
            "network": network,
            "network_sandbox_required": require_network_sandbox,
        },
        "worktree": worktree_state(root, baseline_binding_path(repo, baseline) if baseline is not None else None),
    }
    unscanned: dict = {"skipped": [], "errors": []}
    sarif_index: dict = {}
    scoped: dict = {}
    sarif_source: Path | None = None
    suppressed_by_scanner = 0
    silenced_spans: list[dict] = []  # where a scanner silenced a finding because of an inline comment
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
            # Test code labels: the scope rules run in the same scan, staged apart so that no policy
            # setting (exclude_rules) can leave them out. Off unless the policy lists a rule. Labels are
            # triage help: they never change whether a finding blocks.
            labels_on = bool(config.test_code.rules)
            scope_ids: set[str] = set()
            if labels_on:
                repository = testscope.read_repository(root)
                meta["test_code"] = {
                    "rules": list(config.test_code.rules),
                    # Why the labels may be unreliable (a note for reviewers; never affects blocking).
                    "unreliable": repository.unreliable,
                    "module_names": len(repository.module_names),
                    "module_names_dropped": repository.names_dropped,
                    "findings": 0,
                }
                testscope.stage(rules_stage / testscope.NAMESPACE, scope_rules_file(), repository.module_names)
                scope_ids = testscope.rule_ids(repository.module_names)
                namespaces.append(testscope.NAMESPACE)
            sarif_source = stage / "opengrep.sarif"
            cmd = opengrep.build_command(tools.opengrep, namespaces, root, config.limits, excludes, sarif_source)
            og_env = opengrep.scanner_env_extra(config.limits)
            doc = opengrep.execute(cmd, rules_stage, config.limits.scan_timeout_seconds, extra_env=og_env)
            # The scope rules' matches are never findings: taken out before anything reads the results.
            scope_results = testscope.split_results(doc)
            warnings = opengrep.check_errors(doc)
            rules_ran = opengrep.check_rules_ran(doc, stats.rule_ids | scope_ids)
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
            if labels_on:
                errored = frozenset(e["path"] for e in unscanned["errors"]) | frozenset(
                    e["path"] for e in unscanned["skipped"]
                )
                scopes = testscope.build(root, scope_results, errored)
                listed = RuleIdFilter(config.test_code.rules)
                spans = opengrep.result_spans(doc, root)
                by_print = {(k[0], k[1], fp): spans.get(k) for k, fp in sarif_index.items()}
                og_findings = [
                    replace(f, test_code=scopes.scope_for(f.path, *(by_print.get(f.key()[1:]) or (None, None))))
                    if testscope.eligible(f.tool, f.rule, f.path, listed)
                    else f
                    for f in og_findings
                ]
                scoped = {(f.rule, f.path, f.fingerprint): f.test_code for f in og_findings if f.test_code}
                meta["test_code"].update(
                    {"findings": len(scoped), "items": scopes.counts(), "unrecognised_spelling": scopes.unrecognised}
                )
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
                "jobs": config.limits.jobs,
                "python_cpu_count": int(og_env["PYTHON_CPU_COUNT"]),
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
            silenced_spans += opengrep.ignored_spans(doc, root)
        extra_runs = []
        if "gitleaks" in config.scanners:
            pin = tools.pinned.get("gitleaks")
            if pin is None:
                raise SetupError("gitleaks is enabled but tools.lock pins no gitleaks")
            config_file, config_sha256 = pin.files["config"]
            leaks, leak_rules, missed = gitleaks.run(
                pin.path,
                pin.sha256,
                config_file,
                config_sha256,
                root,
                stage,
                config.limits,
                config.components,
                config.excludes,
            )
            findings += leaks
            extra_runs.append((gitleaks.TOOL, pin.version, leaks))
            unscanned = {kind: [*unscanned.get(kind, []), *missed[kind]] for kind in ("skipped", "errors")}
            meta["rule_ids"] = sorted({*meta.get("rule_ids", []), *leak_rules})
            meta.setdefault("rules", {}).update(gitleaks.rule_metadata(leaks))
            meta["scanners"]["gitleaks"] = {
                "version": pin.version,
                "verification": pin.verification(),
                "config_sha256": config_sha256,
                "rules": len(leak_rules),
                "findings": len(leaks),
                "files_skipped": len(missed["skipped"]),
            }
        if "hadolint" in config.scanners:
            pin = tools.pinned.get("hadolint")
            if pin is None:
                raise SetupError("hadolint is enabled but tools.lock pins no hadolint")
            lints, missed, linted = hadolint.run(
                pin.path,
                pin.sha256,
                root,
                stage,
                config.limits,
                config.components,
                config.excludes,
                config.hadolint.ignore,
            )
            findings += lints
            extra_runs.append((hadolint.TOOL, pin.version, lints))
            unscanned = {kind: [*unscanned.get(kind, []), *missed[kind]] for kind in ("skipped", "errors")}
            meta.setdefault("rules", {}).update(hadolint.rule_metadata(lints))
            meta["scanners"]["hadolint"] = {
                "version": pin.version,
                "verification": pin.verification(),
                "files_scanned": linted,
                "ignore": list(config.hadolint.ignore),
                "findings": len(lints),
            }
        if "zizmor" in config.scanners:
            pin = tools.pinned.get("zizmor")
            if pin is None:
                raise SetupError("zizmor is enabled but tools.lock pins no zizmor")
            audits, missed, audited, audit_rules = zizmor.run(
                pin.path,
                pin.sha256,
                root,
                stage,
                config.limits,
                config.components,
                config.excludes,
                config.zizmor.ignore,
            )
            findings += audits
            extra_runs.append((zizmor.TOOL, pin.version, audits))
            unscanned = {kind: [*unscanned.get(kind, []), *missed[kind]] for kind in ("skipped", "errors")}
            meta.setdefault("rules", {}).update(audit_rules)
            meta["scanners"]["zizmor"] = {
                "version": pin.version,
                "verification": pin.verification(),
                "files_scanned": audited,
                "ignore": list(config.zizmor.ignore),
                "findings": len(audits),
            }
        if "trivy" in config.scanners:
            pin = tools.pinned.get("trivy")
            if pin is None:
                raise SetupError("trivy is enabled but tools.lock pins no trivy")
            misconfigs, missed, markers, silenced, misconfig_rules, spans = trivy.run(
                pin.path,
                pin.sha256,
                root,
                stage,
                config.limits,
                config.components,
                config.excludes,
                config.trivy.ignore,
                helm_pin=(tools.pinned["helm"].path, tools.pinned["helm"].sha256) if "helm" in tools.pinned else None,
                helm_values=config.trivy.helm_values_map(),
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
            silenced_spans += spans
            meta.setdefault("rules", {}).update(misconfig_rules)
            meta["scanners"]["trivy"] = {
                "version": pin.version,
                "verification": pin.verification(),
                "signature_verified": bool(pin.signature_verified),
                "ignore": list(config.trivy.ignore),
                "findings": len(misconfigs),
                "inline_suppressions": len(markers),
                "suppressed_findings": silenced,
                "helm": {"version": tools.pinned["helm"].version, "verification": tools.pinned["helm"].verification()}
                if "helm" in tools.pinned
                else None,
            }
        sarif_text = build_sarif(sarif_source, root, sarif_index, own_findings, extra_runs, scoped)
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    sev = Counter(f.severity for f in findings)
    # Two scanners can skip the same file for the same reason: list it once.
    unscanned = {
        kind: list({json.dumps(e, sort_keys=True): e for e in entries}.values()) for kind, entries in unscanned.items()
    }
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
                    # For a marker inside a packaged chart: the member, whose line the archive's diff cannot show.
                    **({"member": s.member} if s.member else {}),
                }
                for s in sorted(suppressions, key=lambda s: (s.path, s.line))[:MAX_SUPPRESSION_LIST]
            ],
            # Every finding a scanner silenced because of an inline comment, with its lines: `check
            # --changed-since` fails a change whose added lines one of them overlaps, even under an old marker.
            "silenced_total": len(silenced_spans),
            "silenced_list": sorted(silenced_spans, key=lambda s: (s["path"], s["start"], s["tool"], s["rule"]))[
                :MAX_SUPPRESSION_LIST
            ],
            "counts": {k: sev.get(k, 0) for k in ("ERROR", "WARNING", "INFO")},
            "duration_seconds": round(time.monotonic() - started, 1),
        }
    )
    write_atomic(out_dir / FINDINGS_SARIF, sarif_text)
    write_atomic(out_dir / FINDINGS_JSON, findings_to_json(findings, meta))
    return ScanResult(findings, meta)
