"""The `shoalscan` command line."""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from shoalscan import __version__, gitref
from shoalscan import markdown as md
from shoalscan.baseline import (
    Entry,
    baseline_from_bytes,
    entries_from_findings,
    load_baseline,
    rename_path,
    validate_issue,
    write_baseline,
)
from shoalscan.check import CHECK_JSON, compare, details, render_report, summary_line
from shoalscan.config import CONFIG_NAME, Config, config_from_bytes, load_config
from shoalscan.dashboard.commands import add_commands as add_dashboard_commands
from shoalscan.errors import ScanError, SetupError, ShoalscanError
from shoalscan.findings import load_findings
from shoalscan.install import (
    community_rules_path,
    install,
    opengrep_path,
    signature_verified,
    tool_file_path,
    tool_path,
    tool_signature_verified,
    verify_rules_dir,
)
from shoalscan.locations import default_out_dir, default_tools_dir, refuse_inside_repo
from shoalscan.lockfile import Lock, current_platform, load_lock
from shoalscan.resources import default_lock_path, shoalscan_rules_dir
from shoalscan.scan import FINDINGS_JSON, PinnedBinary, Tools, check_network_sandbox, run_scan, write_atomic

TOOLS_HELP = "installed tools (default: $XDG_CACHE_HOME/shoalscan/tools or ~/.cache/shoalscan/tools)"
OUT_HELP = "output directory, outside the repository (default: a private directory under the system temp directory)"


def _tools_dir(args: argparse.Namespace) -> Path:
    path = Path(args.tools_dir) if args.tools_dir else default_tools_dir()
    if getattr(args, "repo", None) is not None:
        refuse_inside_repo(path, Path(args.repo), "tools directory", "--tools-dir")
    return path


def _out_dir(args: argparse.Namespace) -> Path:
    path = Path(args.out) if args.out else default_out_dir(Path(args.repo))
    refuse_inside_repo(path, Path(args.repo), "output directory", "--out")
    return path


def _lock(args: argparse.Namespace) -> Lock:
    return load_lock(Path(args.lock) if args.lock else default_lock_path())


def _config(args: argparse.Namespace) -> Config:
    path = Path(args.config) if args.config else Path(args.repo) / CONFIG_NAME
    if args.config and not path.is_file():
        raise SetupError(f"configuration file not found: {path}")
    return load_config(path)


@dataclass
class Policy:
    """Where the configuration came from: the working tree, or a git ref."""

    config: Config
    ref: str | None
    commit: str | None
    config_sha256: str
    adoption: bool = False

    def record(self) -> dict:
        return {
            "ref": self.ref,
            "commit": self.commit,
            "config_sha256": self.config_sha256,
            "adoption": self.adoption,
        }


def _require_attr_source() -> None:
    """Refuse a git that ignores GIT_ATTR_SOURCE (older than 2.40), as the scan worker does: with such a git the
    change's own .gitattributes (a clean filter, say) would shape the diffs that decide what the change touched."""
    from shoalscan.dashboard.scanning import GIT_TOO_OLD, git_attr_probe

    if not git_attr_probe():
        raise SetupError(GIT_TOO_OLD)


def _policy(args: argparse.Namespace) -> Policy:
    ref = getattr(args, "policy_ref", None)
    path = Path(args.config) if args.config else Path(args.repo) / CONFIG_NAME
    if not ref:
        data = path.read_bytes() if path.is_file() else b""
        return Policy(_config(args), None, None, hashlib.sha256(data).hexdigest())
    if args.config:
        raise SetupError(
            "--config and --policy-ref cannot be used together: with a policy ref the configuration comes from the ref"
        )
    _require_attr_source()
    repo = Path(args.repo)
    commit = gitref.resolve_commit(repo, ref)
    data = gitref.show_file(repo, commit, CONFIG_NAME)
    config = config_from_bytes(data, f"{ref}:{CONFIG_NAME}") if data is not None else Config()
    base_baseline = gitref.show_file(repo, commit, config.baseline)
    if data is None and base_baseline is None:
        # First-time adoption: the base has neither file, so the change's own
        # configuration and baseline are used, and reported loudly.
        local = path.read_bytes() if path.is_file() else b""
        if not local:
            raise SetupError(f"adoption: the base ref has no {CONFIG_NAME}, and neither does this change")
        return Policy(_config(args), ref, commit, hashlib.sha256(local).hexdigest(), adoption=True)
    if data is None or base_baseline is None:
        missing = CONFIG_NAME if data is None else config.baseline
        raise SetupError(
            f"the policy ref has a configuration or a baseline but not both ({missing} is missing at {ref}). "
            "Commit both on the base branch; an empty baseline is written by `shoalscan baseline init`."
        )
    return Policy(config, ref, commit, hashlib.sha256(data).hexdigest())


def _tools(args: argparse.Namespace, config: Config, lock: Lock) -> Tools:
    tools_dir = _tools_dir(args)
    plat = current_platform()
    entry = lock.opengrep.get(plat)
    if entry is None:
        raise SetupError(f"tools.lock pins no Opengrep binary for {plat}")
    community = None
    if config.opengrep.community_rules:
        community = community_rules_path(tools_dir)
        verify_rules_dir(community, lock)
    own = None
    if config.opengrep.shoalscan_rules:
        own = shoalscan_rules_dir()
    pinned = {}
    # Helm is no scanner of its own: Trivy renders charts with it.
    wanted = [*config.scanners, *(["helm"] if "trivy" in config.scanners and "helm" in lock.tools else [])]
    for name in wanted:
        tool = lock.tools.get(name)
        if name == "opengrep" or tool is None:
            continue
        platform_pin = tool.platforms.get(plat)
        if platform_pin is None:
            raise SetupError(f"tools.lock pins no {name} binary for {plat}")
        pinned[name] = PinnedBinary(
            version=tool.version,
            path=tool_path(tools_dir, name).absolute(),
            sha256=platform_pin.binary_sha256,
            files={
                extra: (tool_file_path(tools_dir, name, extra).absolute(), asset.sha256)
                for extra, asset in tool.files.items()
            },
            signature_verified=tool_signature_verified(tools_dir, tool, plat),
        )
    return Tools(
        pinned=pinned,
        signature_verified=signature_verified(tools_dir, lock, plat),
        opengrep=opengrep_path(tools_dir).absolute(),
        opengrep_sha256=entry.binary.sha256,
        opengrep_version=lock.opengrep_version,
        community_rules=community.absolute() if community else None,
        community_commit=lock.rules.commit,
        shoalscan_rules=own,
    )


def _baseline_path(args: argparse.Namespace, config: Config) -> Path:
    """The baseline file `check` and `baseline init` read: --baseline, or the configured one."""
    baseline = getattr(args, "baseline", None)
    return Path(baseline) if baseline else Path(args.repo) / config.baseline


def _do_scan(args: argparse.Namespace):
    # Checked first: a required sandbox that is missing must stop the scan before anything else runs.
    check_network_sandbox(getattr(args, "require_network_sandbox", False))
    out = _out_dir(args)
    _tools_dir(args)
    policy = _policy(args)
    lock = _lock(args)
    tools = _tools(args, policy.config, lock)
    if policy.commit is None or policy.adoption:
        if policy.adoption:
            _print_adoption(policy)
        # Without a policy ref, `check` may accept an edit to the baseline it reads.
        baseline = _baseline_path(args, policy.config) if policy.ref is None else None
        rules_commit = getattr(args, "rules_commit", None)
        if rules_commit is None:
            result = run_scan(
                Path(args.repo),
                policy.config,
                tools,
                out,
                policy=policy.record(),
                baseline=baseline,
                require_network_sandbox=getattr(args, "require_network_sandbox", False),
            )
            return result, policy.config
        # An explicit configuration whose repository rule dirs come from another commit (the base branch's head,
        # when the scan worker scans a pull request), never from the tree being scanned.
        if policy.ref is not None or not args.config:
            raise SetupError("--rules-commit needs --config and cannot be used with --policy-ref")
        commit = gitref.resolve_commit(Path(args.repo), rules_commit)
        with tempfile.TemporaryDirectory(prefix="shoalscan-policy-rules-") as tmp:
            gitref.archive_dirs(Path(args.repo), commit, list(policy.config.opengrep.rule_dirs), Path(tmp))
            result = run_scan(
                Path(args.repo),
                policy.config,
                tools,
                out,
                rule_root=Path(tmp),
                policy={**policy.record(), "rules_commit": commit},
                baseline=baseline,
                require_network_sandbox=getattr(args, "require_network_sandbox", False),
            )
        return result, policy.config
    # The repository's own rules also come from the policy ref.
    with tempfile.TemporaryDirectory(prefix="shoalscan-policy-rules-") as tmp:
        gitref.archive_dirs(Path(args.repo), policy.commit, list(policy.config.opengrep.rule_dirs), Path(tmp))
        result = run_scan(
            Path(args.repo),
            policy.config,
            tools,
            out,
            rule_root=Path(tmp),
            policy=policy.record(),
            require_network_sandbox=getattr(args, "require_network_sandbox", False),
        )
    return result, policy.config


def cmd_install(args: argparse.Namespace) -> int:
    install(
        Path(args.dir) if args.dir else default_tools_dir(),
        _lock(args),
        skip_signature_check=args.skip_signature_check,
        with_rules=not args.no_community_rules,
    )
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    result, _ = _do_scan(args)
    for name, info in sorted(result.meta["scanners"].items()):
        if isinstance(info, dict) and info.get("signature_verified") is False:
            bar = "!" * 78
            print(
                f"{bar}\nshoalscan: WARNING: there is no record that the installed {name}'s cosign signature was\n"
                "verified (installed with --skip-signature-check, or copied in by hand). Its SHA-256 matches\n"
                f"tools.lock. Run `shoalscan install` with cosign available to verify it.\n{bar}",
                file=sys.stderr,
            )
    labels = result.meta.get("test_code")
    if isinstance(labels, dict):
        print(
            f"shoalscan scan: {labels.get('findings', 0)} findings labelled as test code (triage help only; "
            "they block like any other finding until a person accepts them)"
        )
        if labels.get("unreliable"):
            print(f"shoalscan scan: the test code labels may be unreliable: {md.one_line(labels['unreliable'])}")
        if labels.get("module_names_dropped"):
            print(
                f"shoalscan: WARNING: {labels['module_names_dropped']} #[cfg(test)] module names were left out "
                f"(the limit is {labels['module_names']}); findings in those modules get no label.",
                file=sys.stderr,
            )
    counts = result.meta["counts"]
    print(
        f"shoalscan scan: {len(result.findings)} findings "
        f"(ERROR {counts['ERROR']}, WARNING {counts['WARNING']}, INFO {counts['INFO']}) "
        f"in {result.meta['duration_seconds']}s; wrote {_out_dir(args) / FINDINGS_JSON}"
    )
    return 0


def _print_adoption(policy: Policy) -> None:
    bar = "!" * 78
    print(bar)
    print(f"ADOPTION: {policy.ref} has no Shoalscan configuration or baseline, so this change's own")
    print("configuration and baseline are used. Review them with care: they set the policy from now on.")
    print("ERROR findings still block.")
    if policy.config.test_code.rules:
        print(
            f"ADOPTION: [test_code] from this change: rules = {md.one_line(str(list(policy.config.test_code.rules)))}"
        )
    print(bar)


def _print_policy_diff(repo: Path, policy: Policy) -> None:
    paths = {CONFIG_NAME, policy.config.baseline, *policy.config.opengrep.rule_dirs}
    try:
        local = load_config(repo / CONFIG_NAME)
        paths |= {local.baseline, *local.opengrep.rule_dirs}
    except SetupError:
        pass
    diff = gitref.diff_against(repo, policy.commit, sorted(paths))
    if diff.strip():
        bar = "!" * 78
        print(bar)
        print("POLICY CHANGES: this change edits the configuration, baseline or rule directories.")
        print(f"They are NOT applied here: the policy comes from {policy.ref}. Review them carefully.")
        print(bar)
        print(md.lines(diff))  # the diff is the change's own text: no escape sequences reach the terminal
        print(bar)
        print()


def _same_tree(meta: dict, state: dict | None, findings: list, leave_out: str | None) -> bool:
    """Do the findings describe the current tree?

    The whole working tree must match the scan's. The one exception is the
    baseline file `check` reads (`leave_out`): an edit to it is accepted when
    the scan recorded the same file left out, the scan reported nothing in
    that file, and everything else (HEAD, other changes, untracked files)
    matches exactly. If the scan found something in the baseline file it is a
    scanned file like any other, and the strict comparison applies.
    """
    recorded = meta.get("worktree")
    if state is None or recorded is None:
        return recorded == state
    if not isinstance(recorded, dict):
        return False
    strict = {k: v for k, v in state.items() if k != "without_baseline"}
    if {k: v for k, v in recorded.items() if k != "without_baseline"} == strict:
        return True
    if leave_out is None:
        return False
    if recorded.get("commit") != state.get("commit") or recorded.get("tree") != state.get("tree"):
        return False
    without = recorded.get("without_baseline")
    if not isinstance(without, dict) or without.get("path") != leave_out or without != state.get("without_baseline"):
        return False
    return not _reported_in(meta, findings, leave_out)


def _reported_in(meta: dict, findings: list, path: str) -> bool:
    """Did the scan report a finding, an unscanned entry or a suppression in `path`?"""
    if any(f.path == path for f in findings):
        return True
    unscanned = meta.get("unscanned") or {}
    for kind in ("skipped", "errors"):
        if any(isinstance(e, dict) and e.get("path") == path for e in unscanned.get(kind) or []):
            return True
    return any(isinstance(s, dict) and s.get("path") == path for s in meta.get("suppression_list") or [])


def _new_suppressions(meta: dict, changed: set[str], added) -> list[dict]:
    """The inline suppressions whose marker is on a line the change added. The scan lists at most
    MAX_SUPPRESSION_LIST of them; when it left some out, which are new cannot be told, and the check stops."""
    listed = meta.get("suppression_list")
    total = (meta.get("suppressions") or {}).get("total", 0)
    if not isinstance(listed, list) or (isinstance(total, int) and total > len(listed)):
        raise SetupError(
            "the scan did not list every inline suppression, so the check cannot tell which ones the change added"
        )
    lines: dict[str, set[int]] = {}
    out = []
    for entry in listed:
        path = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(path, str) or path not in changed:
            continue
        if entry.get("member"):
            # A marker inside a changed chart archive: its line is a member's, which the archive's diff cannot
            # show, so it counts as new.
            out.append(entry)
            continue
        if path not in lines:
            lines[path] = added(path)
        if entry.get("line") in lines[path]:
            out.append(entry)
    return out


def _new_silenced(meta: dict, changed: set[str], added, markers: list[dict]) -> list[dict]:
    """The findings a scanner silenced because of an inline comment whose lines overlap lines the change added,
    whether the comment is new or was already there (a marker silences the line below it, and a match or block that
    starts there): a change must not hide new code under an old marker. One that a new marker of the same file
    already explains (the marker on its first line or the line above) is not listed twice."""
    listed = meta.get("silenced_list")
    total = meta.get("silenced_total")
    if not isinstance(listed, list) or not isinstance(total, int) or total > len(listed):
        raise SetupError(
            "the scan did not list every finding an inline comment silenced, so the check cannot tell which ones "
            "the change hides"
        )
    lines: dict[str, list[int]] = {}  # each changed file's added lines, sorted, for a binary search per span
    out = []
    for span in listed:
        path = span.get("path") if isinstance(span, dict) else None
        start, end = (span.get("start"), span.get("end")) if isinstance(span, dict) else (None, None)
        if not isinstance(path, str) or path not in changed or not isinstance(start, int) or not isinstance(end, int):
            continue
        if path not in lines:
            lines[path] = sorted(added(path))
        first = bisect.bisect_left(lines[path], start)
        if first == len(lines[path]) or lines[path][first] > end:
            continue
        if any(m.get("path") == path and m.get("line") in (start - 1, start) for m in markers):
            continue
        out.append({"path": path, "line": start, "rules": [span.get("rule")], "silenced": span.get("tool")})
    return out


def cmd_check(args: argparse.Namespace) -> int:
    if getattr(args, "changed_since", None):
        _require_attr_source()  # before anything else is read (--policy-ref checks it in _policy)
    out = _out_dir(args)
    policy = _policy(args)
    config = policy.config
    repo = Path(args.repo)
    # A check that stops early must not leave an older details file behind.
    (out / CHECK_JSON).unlink(missing_ok=True)
    if gitref.worktree_state(repo.resolve()) is not None:
        # A path the scanners cannot report faithfully (not UTF-8, a control character) would pass unscanned.
        gitref.check_path_names(repo)
    findings_sha256 = (
        hashlib.sha256((out / FINDINGS_JSON).read_bytes()).hexdigest() if (out / FINDINGS_JSON).is_file() else ""
    )
    findings, meta = load_findings(out / FINDINGS_JSON)
    recorded = meta.get("policy") or {}
    if recorded.get("commit") != policy.commit or recorded.get("config_sha256") != policy.config_sha256:
        raise SetupError(
            "the findings were produced with a different policy than this check uses; "
            "run `shoalscan scan` with the same --policy-ref (or the same configuration) as `shoalscan check`"
        )
    baseline_path = _baseline_path(args, config)
    # Without a policy ref, the baseline this check reads may be left out of
    # the tree binding: editing it cannot change what was scanned.
    leave_out = gitref.baseline_binding_path(repo, baseline_path) if policy.ref is None else None
    state = gitref.worktree_state(repo.resolve(), leave_out)
    if state is None and not args.no_git:
        raise SetupError(
            f"{repo} is not inside a git work tree, so check cannot tie the findings to a commit. "
            "Pass --no-git to check a directory without git."
        )
    if not _same_tree(meta, state, findings, leave_out):
        raise SetupError(
            "the findings do not match the current tree: the repository changed after `shoalscan scan` "
            "(or the findings come from another checkout); run the scan again"
        )
    baseline = load_baseline(baseline_path)
    base_baseline = None
    changed = None
    new_suppressions = None
    added = None
    moved = None
    if policy.commit is not None:
        if args.baseline:
            raise SetupError("--baseline and --policy-ref cannot be used together")
        if policy.adoption:
            _print_adoption(policy)
        _print_policy_diff(repo, policy)
        if not policy.adoption:
            data = gitref.show_file(repo, policy.commit, config.baseline)
            base_baseline = baseline_from_bytes(data, f"{policy.ref}:{config.baseline}") if data is not None else []
            moved = gitref.renames(repo, policy.commit)
        changed = gitref.changed_files(repo, policy.commit)
        commit = policy.commit

        def added(path: str) -> set[int]:
            return gitref.added_lines(repo, commit, path)

    elif getattr(args, "changed_since", None):
        # An explicit configuration and baseline, with the changed files listed against the merge base with
        # another commit (the base branch's head, when the scan worker scans a pull request).
        since = gitref.resolve_commit(repo, args.changed_since)
        changed = gitref.changed_files(repo, since)
        print(f"Changed files: compared with the merge base of HEAD and {since[:12]}.")

        def added(path: str) -> set[int]:
            return gitref.added_lines(repo, since, path)

        new_suppressions = _new_suppressions(meta, set(changed), added)
        new_suppressions += _new_silenced(meta, set(changed), added, new_suppressions)

    result = compare(
        findings,
        baseline,
        config.blocking,
        meta.get("suppressions"),
        config.non_blocking_paths,
        unscanned=meta.get("unscanned"),
        changed_files=changed,
        excludes=config.excludes,
        base_baseline=base_baseline,
        policy_ref=policy.ref,
        added_lines=added,
        renames=moved,
        components=config.components,
        adoption=policy.adoption,
        parse_warn_only=config.parse_warn_only,
        test_code_rules=config.test_code.rules,
        new_suppressions=new_suppressions,
        # A change checked against an outside baseline cannot remove its stale entries: they are reported only.
        stale_blocks=not getattr(args, "changed_since", None),
    )
    write_atomic(out / CHECK_JSON, json.dumps(details(result, findings_sha256), sort_keys=True) + "\n")
    print(render_report(result))
    print(summary_line(result))
    return 0 if result.passed else 1


def cmd_baseline_init(args: argparse.Namespace) -> int:
    config = _config(args)
    baseline_path = Path(args.baseline) if args.baseline else Path(args.repo) / config.baseline
    if baseline_path.exists() and not args.force:
        raise SetupError(f"baseline already exists: {baseline_path} (pass --force to overwrite it)")
    entries = entries_from_findings([], args.issue, args.reason)  # validate the inputs before scanning
    result, _ = _do_scan(args)
    entries = entries_from_findings(result.findings, args.issue, args.reason)
    write_baseline(baseline_path, entries, force=args.force)
    print(f"shoalscan baseline init: wrote {len(entries)} entries to {baseline_path}")
    return 0


def cmd_baseline_rename_path(args: argparse.Namespace) -> int:
    config = _config(args)
    baseline_path = Path(args.baseline) if args.baseline else Path(args.repo) / config.baseline
    entries = load_baseline(baseline_path)
    if entries is None:
        raise SetupError(f"baseline not found: {baseline_path}")
    renamed, changed = rename_path(entries, args.old, args.new)
    if changed == 0:
        raise SetupError(f"no baseline entries have the path {args.old}")
    write_baseline(baseline_path, renamed, force=True)
    print(f"shoalscan baseline rename-path: moved {changed} entries from {args.old} to {args.new} in {baseline_path}")
    return 0


def cmd_baseline_accept(args: argparse.Namespace) -> int:
    """A person accepts findings labelled as test code into the baseline: who, when and why are recorded."""
    if not args.test_code:
        raise SetupError("say what to accept: --test-code is the only kind for now")
    who = (args.by or "").strip()
    if not who or any(c < " " or md.is_format_control(c) for c in who) or len(who) > 200:
        raise SetupError("--by must name the person who accepts the findings")
    if not args.issue:
        raise SetupError("--issue must name the issue that tracks the decision: #123 or a URL")
    validate_issue(args.issue)
    if not args.fingerprint and not args.all:
        raise SetupError("name the findings to accept with --fingerprint (repeatable), or pass --all")
    config = _config(args)
    if not config.test_code.rules:
        raise SetupError(f"{CONFIG_NAME} has no [test_code] rules, so no finding carries a test code label")
    repo = Path(args.repo)
    out = _out_dir(args)
    baseline_path = _baseline_path(args, config)
    entries = load_baseline(baseline_path)
    if entries is None:
        raise SetupError(f"baseline not found: {baseline_path}")
    findings, meta = load_findings(out / FINDINGS_JSON)
    policy = _policy(args)
    recorded = meta.get("policy") or {}
    if recorded.get("commit") is not None or recorded.get("config_sha256") != policy.config_sha256:
        raise SetupError(
            "the findings were produced with another configuration; run `shoalscan scan` (without --policy-ref) "
            "with this configuration first"
        )
    leave_out = gitref.baseline_binding_path(repo, baseline_path)
    state = gitref.worktree_state(repo.resolve(), leave_out)
    if state is None and not args.no_git:
        raise SetupError(f"{repo} is not inside a git work tree; pass --no-git to accept without one")
    if not _same_tree(meta, state, findings, leave_out):
        raise SetupError("the findings do not match the current tree; run the scan again")
    result = compare(findings, entries, config.blocking, test_code_rules=config.test_code.rules)
    known = {e.key() for e in entries}
    labelled = [f for f in result.test_code if f.key() not in known]
    if args.fingerprint:
        wanted = set(args.fingerprint)
        chosen = [f for f in labelled if f.fingerprint in wanted]
        missing = wanted - {f.fingerprint for f in chosen}
        if missing:
            raise SetupError(
                "these fingerprints are not findings labelled as test code that the baseline lacks: "
                + ", ".join(sorted(md.one_line(m) for m in missing))
            )
    else:
        chosen = labelled
    if not chosen:
        print("shoalscan baseline accept: no findings labelled as test code are missing from the baseline")
        return 0
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    added = [
        Entry(
            f.tool,
            f.rule,
            f.path,
            f.fingerprint,
            validate_issue(args.issue),
            f"Accepted: test code ({f.test_code.kind} at {f.test_code.path}:{f.test_code.line}); accepted by "
            f"{who} on {when}",
        )
        for f in chosen
    ]
    write_baseline(baseline_path, [*entries, *added], force=True)
    print(
        f"shoalscan baseline accept: added {len(added)} entries to {baseline_path}, accepted by {md.one_line(who)}. "
        "Commit them through a reviewed change on the base branch; a pull request cannot add baseline entries."
    )
    for f in chosen:
        print(f"  {md.one_line(f.path)}:{f.line}  {md.one_line(f.rule)}  ({md.one_line(f.test_code.description())})")
    return 0


def _policy_option(p: argparse._ActionsContainer) -> None:
    p.add_argument(
        "--policy-ref",
        help=(
            "read the configuration, baseline and repository rule dirs from this git ref (use the base branch on pull "
            "requests)"
        ),
    )


def _scan_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--repo", default=".", help="repository to scan (default: the current directory)")
    p.add_argument("--config", help=f"configuration file (default: <repo>/{CONFIG_NAME})")
    p.add_argument("--tools-dir", help=TOOLS_HELP)
    p.add_argument("--out", help=OUT_HELP)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shoalscan", description="Run pinned security scanners and check findings against a baseline."
    )
    parser.add_argument("--version", action="version", version=f"shoalscan {__version__}")
    parser.add_argument("--lock", help="tools lock file (default: the one shipped with Shoalscan)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("install", help="download, verify and install the pinned tools")
    p.add_argument("--dir", help=TOOLS_HELP.replace("installed tools", "tools directory"))
    p.add_argument(
        "--skip-signature-check", action="store_true", help="install without cosign signature checks (SHA-256 only)"
    )
    p.add_argument("--no-community-rules", action="store_true", help="do not install the community rules snapshot")
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("scan", help="run the scanners and write findings.json and findings.sarif")
    _scan_options(p)
    p.add_argument(
        "--require-network-sandbox",
        action="store_true",
        help="fail unless the scanners can run in an operating-system network sandbox (sandbox-exec or unshare --net)",
    )
    group = p.add_mutually_exclusive_group()
    _policy_option(group)
    group.add_argument(
        "--rules-commit",
        metavar="COMMIT",
        help=(
            "with --config: read the repository rule dirs from this commit instead of the tree being scanned (a full "
            "SHA or a refs/heads/ or refs/remotes/ ref)"
        ),
    )
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("check", help="compare findings with the baseline")
    p.add_argument("--repo", default=".", help="repository root (default: the current directory)")
    p.add_argument("--config", help=f"configuration file (default: <repo>/{CONFIG_NAME})")
    p.add_argument("--out", help="directory with findings.json (default: the same default as `scan`)")
    p.add_argument("--baseline", help="baseline file (default: from the configuration)")
    p.add_argument(
        "--no-git",
        action="store_true",
        help="allow a repository directory that is not a git work tree (the findings are then not tied to a commit)",
    )
    group = p.add_mutually_exclusive_group()
    _policy_option(group)
    group.add_argument(
        "--changed-since",
        metavar="COMMIT",
        help=(
            "with an explicit configuration and baseline: also fail on changed files that were not fully scanned, "
            "comparing HEAD with its merge base with this commit (a full SHA or a refs/heads/ or refs/remotes/ ref)"
        ),
    )
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("baseline", help="manage the baseline")
    bsub = p.add_subparsers(dest="baseline_command", required=True)
    b = bsub.add_parser("init", help="write the baseline from a full scan")
    _scan_options(b)
    b.add_argument("--baseline", help="baseline file (default: from the configuration)")
    b.add_argument("--issue", required=True, help="triage issue for every entry: #123 or a URL")
    b.add_argument("--reason", required=True, help="why these findings are accepted for now")
    b.add_argument("--force", action="store_true", help="overwrite an existing baseline")
    b.set_defaults(func=cmd_baseline_init)
    r = bsub.add_parser("rename-path", help="point baseline entries for a moved file or directory at its new path")
    r.add_argument("old", help="the old path, relative to the repository")
    r.add_argument("new", help="the new path, relative to the repository")
    r.add_argument("--repo", default=".", help="repository root (default: the current directory)")
    r.add_argument("--config", help=f"configuration file (default: <repo>/{CONFIG_NAME})")
    r.add_argument("--baseline", help="baseline file (default: from the configuration)")
    r.set_defaults(func=cmd_baseline_rename_path)
    ac = bsub.add_parser(
        "accept", help="accept findings labelled as test code into the baseline, recording who and why"
    )
    ac.add_argument("--test-code", action="store_true", help="accept findings labelled as test code")
    ac.add_argument("--fingerprint", action="append", default=[], help="a finding to accept (repeatable)")
    ac.add_argument("--all", action="store_true", help="accept every labelled finding the baseline lacks")
    ac.add_argument("--by", help="who accepts them, recorded in each entry's reason (required)")
    ac.add_argument("--issue", help="the issue that tracks the decision: #123 or a URL (required)")
    ac.add_argument("--repo", default=".", help="repository root (default: the current directory)")
    ac.add_argument("--config", help=f"configuration file (default: <repo>/{CONFIG_NAME})")
    ac.add_argument("--out", help="directory with findings.json (default: the same default as `scan`)")
    ac.add_argument("--baseline", help="baseline file (default: from the configuration)")
    ac.add_argument("--no-git", action="store_true", help="allow a repository directory that is not a git work tree")
    ac.set_defaults(func=cmd_baseline_accept)

    add_dashboard_commands(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ScanError as exc:
        print(f"shoalscan: scan failed: {exc}", file=sys.stderr)
        return exc.exit_code
    except ShoalscanError as exc:
        print(f"shoalscan: error: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 - an unexpected error is a broken run, never a pass or a plain fail
        print(f"shoalscan: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
