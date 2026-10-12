"""The `shoalscan` command line."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from shoalscan import __version__, gitref
from shoalscan import markdown as md
from shoalscan.baseline import baseline_from_bytes, entries_from_findings, load_baseline, rename_path, write_baseline
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
    verify_rules_dir,
)
from shoalscan.locations import default_out_dir, default_tools_dir, refuse_inside_repo
from shoalscan.lockfile import Lock, current_platform, load_lock
from shoalscan.resources import default_lock_path, shoalscan_rules_dir
from shoalscan.scan import FINDINGS_JSON, PinnedBinary, Tools, run_scan, write_atomic

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
    for name in config.scanners:
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
        result = run_scan(Path(args.repo), policy.config, tools, out, policy=policy.record(), baseline=baseline)
        return result, policy.config
    # The repository's own rules also come from the policy ref.
    with tempfile.TemporaryDirectory(prefix="shoalscan-policy-rules-") as tmp:
        gitref.archive_dirs(Path(args.repo), policy.commit, list(policy.config.opengrep.rule_dirs), Path(tmp))
        result = run_scan(Path(args.repo), policy.config, tools, out, rule_root=Path(tmp), policy=policy.record())
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
    opengrep_meta = result.meta["scanners"].get("opengrep")
    if opengrep_meta is not None and not opengrep_meta.get("signature_verified", False):
        bar = "!" * 78
        print(
            f"{bar}\nshoalscan: WARNING: there is no record that the installed Opengrep's cosign signature was\n"
            "verified (installed with --skip-signature-check, or copied in by hand). Its SHA-256 matches\n"
            f"tools.lock. Run `shoalscan install` with cosign available to verify it.\n{bar}",
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


def cmd_check(args: argparse.Namespace) -> int:
    out = _out_dir(args)
    policy = _policy(args)
    config = policy.config
    repo = Path(args.repo)
    # A check that stops early must not leave an older details file behind.
    (out / CHECK_JSON).unlink(missing_ok=True)
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


def _policy_option(p: argparse.ArgumentParser) -> None:
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
    _policy_option(p)
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
    _policy_option(p)
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
