"""The `record` and `serve` commands."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from pathlib import Path

from shoalscan import embeddings, history
from shoalscan.check import CHECK_JSON
from shoalscan.errors import SetupError
from shoalscan.locations import default_out_dir
from shoalscan.scan import FINDINGS_JSON

DEFAULT_PORT = 8443


def config_home() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME", "")
    if xdg and os.path.isabs(xdg):
        return Path(xdg)
    return Path.home() / ".config"


def default_state_dir() -> Path:
    """`$XDG_CONFIG_HOME/shoalscan/dashboard`: the token hash and the TLS files."""
    return config_home() / "shoalscan" / "dashboard"


def _db(args: argparse.Namespace) -> Path:
    return Path(args.db) if args.db else history.default_db_path()


def _state(args: argparse.Namespace) -> Path:
    return Path(args.state_dir) if args.state_dir else default_state_dir()


def _read_check_output(name: str) -> str:
    if name == "-":
        return sys.stdin.read(history.MAX_CHECK_OUTPUT_BYTES + 1)
    try:
        with open(name, encoding="utf-8") as handle:
            return handle.read(history.MAX_CHECK_OUTPUT_BYTES + 1)
    except OSError as exc:
        raise SetupError(f"cannot read the check output {name}: {exc.strerror}") from None


def cmd_record(args: argparse.Namespace) -> int:
    if args.embed:
        # Checked before anything is recorded, so a bad setting never leaves half the work done.
        embeddings.validate_host(args.ollama_host)
        embeddings.validate_model(args.model)
    if args.findings:
        findings_path = Path(args.findings)
    else:
        findings_path = (Path(args.out) if args.out else default_out_dir(Path(args.repo))) / FINDINGS_JSON
    info = history.RunInfo(
        repo=args.repo_name,
        ref=args.ref,
        commit=args.commit.lower(),
        kind=args.kind,
        scanned_at=history.parse_timestamp(args.scanned_at),
    )
    details = None
    note = ""
    if args.check_exit == 2:
        # The check could not run: there are no results to store, only the fact.
        findings, meta, summary = [], {}, {}
    else:
        if not args.check_output:
            raise SetupError("--check-output is required unless --check-exit is 2")
        findings, meta, summary = history.read_inputs(findings_path, _read_check_output(args.check_output))
        history.check_commit(meta, info.commit, args.allow_no_git)
        details_path = Path(args.check_details) if args.check_details else findings_path.parent / CHECK_JSON
        if args.check_details or details_path.is_file():
            details = history.read_details(details_path, findings_path, summary, findings)
        else:
            note = (
                f"; no {CHECK_JSON} next to the findings, so the dashboard cannot list new or stale entries for this "
                "run"
            )
    db = _db(args)
    conn = history.open_for_write(db)
    try:
        result = history.record_run(
            conn,
            info,
            findings,
            meta,
            summary,
            details=details,
            check_exit=args.check_exit,
            review_transitions=not args.commit_rescan,
            max_runs=args.max_runs,
            keep_pr_days=args.keep_pr_days,
        )
    finally:
        conn.close()
    what = {"recorded": "recorded", "replaced": "replaced the earlier record of", "unchanged": "already had"}[
        result.status
    ]
    pruned = f"; pruned {result.pruned} old runs" if result.pruned else ""
    outcome = "a scan error" if args.check_exit == 2 else f"{len(findings)} findings"
    print(
        f"shoalscan record: {what} {info.kind} run {result.run_id} for {info.repo} at {info.commit[:12]} ({outcome}) "
        f"in {db}{pruned}{note}"
    )
    if args.embed:
        _embed(db, info.repo, args, warn_only=True)
    return 0


def _embed(db: Path, repo: str, args: argparse.Namespace, warn_only: bool) -> int:
    """Embed a repository's findings. When Ollama cannot, warn (record) or fail (triage embed); never a traceback."""
    conn = history.open_for_write(db)
    try:
        result = embeddings.embed_repository(
            conn, repo, args.model, args.ollama_host, now=history.parse_timestamp(None)
        )
    except embeddings.OllamaError as exc:
        print(f"shoalscan: warning: no embeddings were made: {exc}", file=sys.stderr)
        return 0 if warn_only else 2
    finally:
        conn.close()
    print(
        f"shoalscan: embedded {result.embedded} findings of {repo} with {args.model}; "
        f"{result.up_to_date} were up to date",
        file=sys.stderr,
    )
    return 0


def cmd_triage_embed(args: argparse.Namespace) -> int:
    embeddings.validate_host(args.ollama_host)
    embeddings.validate_model(args.model)
    db = _db(args)
    if not db.is_file():
        raise SetupError(f"history database not found: {db}")
    return _embed(db, args.repo_name, args, warn_only=False)


def cmd_triage_suggest_similar(args: argparse.Namespace) -> int:
    """Print the findings most like one finding, with what was decided about each."""
    embeddings.validate_model(args.model)
    if not 0 < args.threshold <= 1:
        raise SetupError("--threshold must be above 0 and at most 1")
    if not 1 <= args.limit <= 50:
        raise SetupError("--limit must be from 1 to 50")
    db = _db(args)
    if not db.is_file():
        raise SetupError(f"history database not found: {db}")
    conn = history.open_read_only(db)
    try:
        keys = embeddings.find_keys(conn, args.repo_name, args.fingerprint)
        if not keys:
            raise SetupError(f"{args.repo_name} has no finding with the fingerprint {args.fingerprint}")
        if len(keys) > 1:
            listing = "\n".join(f"  {k[3]}  {k[1]}  {k[2]}" for _, k in keys[:20])
            raise SetupError(f"{len(keys)} findings match {args.fingerprint}; give more of the fingerprint:\n{listing}")
        key_id, key = keys[0]
        found = embeddings.similar(conn, key_id, args.model, args.threshold, args.limit, args.all_repos)
    finally:
        conn.close()
    if found is None:
        raise SetupError(
            f"this finding has no {args.model} embedding yet; run `shoalscan triage embed --repo-name "
            f"{args.repo_name}` "
            "with Ollama running"
        )
    if args.format == "json":
        print(
            json.dumps({"finding": key, "model": args.model, "threshold": args.threshold, "similar": found}, indent=2)
        )
        return 0
    print(f"Findings like {key[1]} in {key[2]} ({key[3][:12]}), similarity at least {args.threshold}:")
    if not found:
        print("  none")
    for f in found:
        where = f"{f['key'][2]}:{f['line']}" if f["line"] else f["key"][2]
        repo = "" if f["repo"] == args.repo_name else f" [{f['repo']}]"
        print(f"  {f['score']:.3f}  {f['severity'] or '-':<7} {where}  {f['key'][1]}{repo}")
        d = f["decision"]
        if d is None:
            print("         no decision yet")
        elif d["source"] == "review":
            print(
                f"         reviewed {d['status']} by {d['by']} on {d['at'][:10]}: "
                f"{' '.join(d['description'].split())[:200]}"
            )
        else:
            print(f"         baselined ({d['issue']}): {' '.join(d['description'].split())[:200]}")
    return 0


def _embedding_options(p: argparse.ArgumentParser, host: bool = True) -> None:
    p.add_argument(
        "--model",
        default=embeddings.DEFAULT_MODEL,
        help=f"Ollama embedding model (default: {embeddings.DEFAULT_MODEL})",
    )
    if host:
        p.add_argument(
            "--ollama-host",
            default=embeddings.DEFAULT_HOST,
            help=f"Ollama on this machine's loopback interface (default: {embeddings.DEFAULT_HOST})",
        )


def _describe(run: dict) -> str:
    return (
        f"run {run['id']}: {run['kind']} {run['ref']} at {run['commit'][:12]}, scanned {run['scanned_at']}, "
        f"{run['outcome']}, {run['findings']} findings"
    )


EXPORT_LABELS = {"false_positive": "False positive", "accepted_risk": "Accepted", "wont_fix": "Won't fix"}


def cmd_triage_export(args: argparse.Namespace) -> int:
    """Print baseline entries for findings reviewed on the dashboard as false
    positives, accepted risks or won't-fix. Nothing is written: the output is
    for a reviewed change to the repository's baseline."""
    from shoalscan.baseline import Entry, render_baseline, validate_issue

    if not args.issue:
        raise SetupError("--issue is required: every baseline entry names the issue that tracks it")
    issue = validate_issue(args.issue)
    conn = history.open_read_only(_db(args))
    try:
        rows = conn.execute(
            "SELECT fr.tool, fr.rule, fr.path, fr.fingerprint, fr.status, fr.description, fr.updated_by, "
            "fr.resolved_at, "
            "(SELECT rf.line FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id JOIN runs r ON r.id = "
            "rf.run_id "
            " JOIN repos rp ON rp.id = r.repo_id WHERE rp.name = fr.repo_name AND fk.tool = fr.tool AND fk.rule = "
            "fr.rule "
            " AND fk.path = fr.path AND fk.fingerprint = fr.fingerprint ORDER BY r.scanned_at DESC LIMIT 1) "
            "FROM finding_reviews fr WHERE fr.repo_name = ? AND fr.status IN ('false_positive', 'accepted_risk', "
            "'wont_fix') "
            "ORDER BY fr.path, fr.rule, fr.fingerprint",
            (args.repo,),
        ).fetchall()
    finally:
        conn.close()
    entries = []
    suppressions = []
    for tool, rule, path, fingerprint, status, description, who, resolved_at, line in rows:
        summary = " ".join(description.split())
        reason = f"{EXPORT_LABELS[status]}: {summary} (reviewed in dashboard by {who} on {resolved_at})"
        entries.append(Entry(tool, rule, path, fingerprint, issue, reason))
        # The path is quoted, so no character in a file name (a newline, say) can end the comment.
        suppressions.append(f"# {json.dumps(path)} line {line or '?'}:  # nosemgrep: {rule} {issue} {summary[:80]}")
    print(render_baseline(entries), end="")
    if args.suppressions and suppressions:
        print(
            "\n# Or, instead of baseline entries, inline suppressions on the lines below (each line of code it applies "
            "to):"
        )
        for line in suppressions:
            print(line)
    print(
        f"shoalscan triage export: {len(entries)} reviewed findings of {args.repo}. Nothing was written; add them to "
        "the baseline "
        "through a reviewed change. Dashboard reviews alone never change what blocks CI.",
        file=sys.stderr,
    )
    return 0


def cmd_history_list_runs(args: argparse.Namespace) -> int:
    db = _db(args)
    conn = history.open_read_only(db)
    try:
        runs = history.list_runs(conn, args.repo_name)
    finally:
        conn.close()
    if not runs:
        raise SetupError(f"{db} has no runs for {args.repo_name}")
    print(f"{'ID':>6}  {'SCANNED':<20}  {'KIND':<9}  {'COMMIT':<12}  {'OUTCOME':<10}  {'FINDINGS':>8}  REF")
    for r in runs:
        print(
            f"{r['id']:>6}  {r['scanned_at']:<20}  {r['kind']:<9}  {r['commit'][:12]:<12}  {r['outcome'] or '-':<10}  "
            f"{r['findings']:>8}  {r['ref']}"
        )
    return 0


def cmd_history_delete_run(args: argparse.Namespace) -> int:
    db = _db(args)
    if not args.yes:
        conn = history.open_read_only(db)
        try:
            run = next((r for r in history.list_runs(conn, args.repo_name) if r["id"] == args.run), None)
        finally:
            conn.close()
        if run is None:
            raise SetupError(
                f"{args.repo_name} has no run {args.run} (`shoalscan history list-runs --repo-name {args.repo_name}` "
                "lists them)"
            )
        raise SetupError(
            f"this would delete {args.repo_name} {_describe(run)}; nothing was deleted. Pass --yes to delete it."
        )
    conn = history.open_for_write(db)
    try:
        run = history.delete_run(conn, args.repo_name, args.run)
    finally:
        conn.close()
    print(f"shoalscan history: deleted {args.repo_name} {_describe(run)}, with its findings and lists, from {db}")
    if run["runs_left"] == 0:
        print(
            f"shoalscan history: that was the last run of {args.repo_name}, so the repository is gone from the "
            "dashboard too"
        )
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from shoalscan.dashboard.server import ServeConfig, serve

    state = _state(args)
    hosts = list(args.host or [])
    if not hosts:
        try:
            wildcard = ipaddress.ip_address(args.bind).is_unspecified
        except ValueError:
            wildcard = False
        if wildcard:
            raise SetupError("with a wildcard --bind, name the addresses or host names clients use with --host")
        hosts = [args.bind]
    if not 0 <= args.port <= 65535:
        raise SetupError("--port must be between 0 and 65535")
    serve(
        ServeConfig(
            db=_db(args),
            cert=Path(args.cert) if args.cert else state / "tls" / "server.pem",
            key=Path(args.key) if args.key else state / "tls" / "server.key",
            token_hash=state / "token.sha256",
            bind=args.bind,
            port=args.port,
            hosts=tuple(hosts),
            state_dir=state,
            allow_config=args.allow_config,
        )
    )
    return 0


def cmd_serve_token(args: argparse.Namespace) -> int:
    from shoalscan.dashboard.auth import create_token

    path = _state(args) / "token.sha256"
    token = create_token(path)
    print("A new dashboard login token (shown once; only its SHA-256 is stored):")
    print(token)
    print(f"Its hash is in {path}. Any earlier token and its sessions stop working.")
    return 0


def _cli_who() -> str:
    return f"{history._who()} (command line)"


def _print_invite(name: str, code: str, expires: str, url: str | None) -> None:
    path = f"/invite#{code}"
    link = f"{url.rstrip('/')}{path}" if url else f"https://<the dashboard's address>{path}"
    print(f"An invite for {name} (shown once; it works once, until {expires}):")
    print(link)
    print("Send it over a channel you trust. Opening it gives them their own token, which you never see.")


def _dashboard_url(value: str | None) -> str | None:
    if value is None:
        return None
    from urllib.parse import urlsplit

    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname or parts.path not in ("", "/") or parts.query or parts.fragment:
        raise SetupError(
            f"--url must be the dashboard's https:// address, such as https://dash.example.com:8443: {value!r}"
        )
    return value


def cmd_serve_user(args: argparse.Namespace) -> int:
    from shoalscan.dashboard import users

    url = _dashboard_url(getattr(args, "url", None))
    conn = users.open_users(_state(args))
    try:
        if args.user_command == "add":
            code, expires = users.add_user(conn, args.name, "admin" if args.admin else "member", _cli_who())
            _print_invite(args.name, code, expires, url)
        elif args.user_command == "reset":
            code, expires = users.reinvite(conn, args.name, _cli_who())
            print(f"{args.name}'s token and sessions no longer work.")
            _print_invite(args.name, code, expires, url)
        elif args.user_command in ("disable", "enable"):
            users.set_disabled(conn, args.name, args.user_command == "disable", _cli_who())
            print(
                f"{args.name} is {args.user_command}d"
                + ("; their sessions have ended." if args.user_command == "disable" else ".")
            )
        elif args.user_command == "role":
            users.set_role(conn, args.name, args.role, _cli_who())
            print(f"{args.name} is now {'an admin' if args.role == 'admin' else 'a member'}.")
        else:
            listed = users.list_users(conn)
            if not listed:
                print("No users yet. Add the first admin with `shoalscan serve user add NAME --admin`.")
            for u in listed:
                until = f" until {u['invite_expires_at']}" if u["invite_expires_at"] else ""
                print(f"{u['name']:<24} {u['role']:<7} {u['status']}{until}")
    finally:
        conn.close()
    return 0


def cmd_serve_init_tls(args: argparse.Namespace) -> int:
    from shoalscan.dashboard.tlsgen import generate

    out = Path(args.out_dir) if args.out_dir else _state(args) / "tls"
    made = generate(out, args.ip or [], args.dns or [], force=args.force)
    print(f"shoalscan serve init-tls: wrote {made['cert']} and {made['key']} for {', '.join(made['names'])}")
    print(f"CA certificate: {made['ca']}")
    print(f"CA SHA-256 fingerprint: {made['ca_sha256']}")
    print("The CA's private key has been deleted: it signed this one certificate and can sign nothing else.")
    print(
        "Its name constraints allow only these names, for both DNS names and IP addresses, and it may vouch only for "
        "TLS servers."
    )
    print(
        'Trust the CA certificate on the machines that open the dashboard (see docs/dashboard.md, "Trusting the '
        'certificate").'
    )
    return 0


def add_commands(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("record", help="store a run's findings and check result in the history database")
    p.add_argument("--findings", help="findings.json from `shoalscan scan` (default: findings.json in --out)")
    p.add_argument("--out", help="directory with findings.json (default: the same default as `scan`)")
    p.add_argument(
        "--repo", default=".", help="repository the default --out belongs to (default: the current directory)"
    )
    p.add_argument(
        "--check-output",
        help="a file with the output of `shoalscan check`, or - for standard input (required unless --check-exit is 2)",
    )
    p.add_argument(
        "--allow-no-git",
        action="store_true",
        help="record findings that do not name the commit they were scanned at (a --no-git scan)",
    )
    p.add_argument(
        "--commit-rescan",
        action="store_true",
        help=(
            "this run rescans an earlier commit: pass that run's time with --scanned-at; it never changes finding "
            "reviews"
        ),
    )
    p.add_argument(
        "--check-exit",
        type=int,
        choices=(0, 1, 2),
        help="the exit status of `shoalscan check`; 2 records a scan error with no results",
    )
    p.add_argument(
        "--check-details",
        help=f"the {CHECK_JSON} that check wrote (default: {CHECK_JSON} next to the findings, when it is there)",
    )
    p.add_argument("--repo-name", required=True, help="the repository's name on the dashboard, such as owner/project")
    p.add_argument(
        "--ref", required=True, help="the branch or ref that was scanned, such as main or refs/pull/12/merge"
    )
    p.add_argument("--commit", required=True, help="the commit SHA that was scanned")
    p.add_argument(
        "--kind",
        required=True,
        choices=history.KINDS,
        help="pr for a pull-request run, scheduled for a scan of the default branch",
    )
    p.add_argument("--scanned-at", help="when the scan ran, ISO 8601 with a time zone (default: now)")
    p.add_argument(
        "--db",
        help=(
            "history database (default: $XDG_DATA_HOME/shoalscan/history.sqlite3 or "
            "~/.local/share/shoalscan/history.sqlite3)"
        ),
    )
    p.add_argument(
        "--max-runs",
        type=int,
        default=history.DEFAULT_MAX_RUNS,
        help=f"runs kept per repository (default: {history.DEFAULT_MAX_RUNS})",
    )
    p.add_argument(
        "--keep-pr-days",
        type=int,
        default=history.DEFAULT_KEEP_PR_DAYS,
        help=f"days of pull-request runs kept (default: {history.DEFAULT_KEEP_PR_DAYS})",
    )
    p.add_argument(
        "--embed",
        action="store_true",
        help="also embed the repository's new findings with a local Ollama, for similar-finding suggestions "
        "(a warning, never a failure, when Ollama is not available)",
    )
    _embedding_options(p)
    p.set_defaults(func=cmd_record)

    from shoalscan import triage

    p = sub.add_parser(
        "triage",
        help="list the findings of the last scan as a prioritised work list, or export dashboard reviews",
        description=(
            "Without a subcommand: print a prioritised work list of the last scan's findings, grouped by rule "
            "family and component. `triage export` turns dashboard reviews into baseline entries."
        ),
    )
    triage.add_arguments(p)
    p.set_defaults(func=triage.run)
    tsub = p.add_subparsers(dest="triage_command")
    t = tsub.add_parser(
        "export", help="print baseline entries for findings reviewed as false positive, accepted risk or won't fix"
    )
    t.add_argument("--repo", required=True, help="the repository's name on the dashboard, such as owner/project")
    t.add_argument("--issue", help="the issue every printed entry names: #123 or a URL (required)")
    t.add_argument(
        "--suppressions", action="store_true", help="also print matching inline suppression lines, as comments"
    )
    t.add_argument("--db", help="history database (default: the same default as `record`)")
    t.set_defaults(func=cmd_triage_export)
    t = tsub.add_parser(
        "embed", help="embed a repository's findings with a local Ollama model, for similar-finding suggestions"
    )
    t.add_argument("--repo-name", required=True, help="the repository's name in the history, such as owner/project")
    t.add_argument("--db", help="history database (default: the same default as `record`)")
    _embedding_options(t)
    t.set_defaults(func=cmd_triage_embed)
    t = tsub.add_parser(
        "suggest-similar",
        help="list the findings most like one finding, with the review or baseline decision made about each",
    )
    t.add_argument("fingerprint", help="the finding's fingerprint, or at least its first 8 characters")
    t.add_argument("--repo-name", required=True, help="the repository's name in the history, such as owner/project")
    t.add_argument(
        "--threshold",
        type=float,
        default=embeddings.DEFAULT_THRESHOLD,
        help=f"lowest cosine similarity to list (default: {embeddings.DEFAULT_THRESHOLD})",
    )
    t.add_argument("--limit", type=int, default=embeddings.DEFAULT_LIMIT, help="how many to list (default: 3)")
    t.add_argument(
        "--all-repos", action="store_true", help="compare with the findings of every repository in the history"
    )
    t.add_argument("--format", choices=("text", "json"), default="text", help="output format (default: text)")
    t.add_argument("--db", help="history database (default: the same default as `record`)")
    _embedding_options(t, host=False)
    t.set_defaults(func=cmd_triage_suggest_similar)

    from shoalscan import report

    p = sub.add_parser(
        "report",
        help="write a dated security report on one repository from the history database",
        description=(
            "Write a dated Markdown (or JSON) security report on one repository for a period of whole UTC days: "
            "the posture at the end, the trend, what was found and fixed, what the baseline accepts, reviews "
            "and coverage."
        ),
    )
    report.add_arguments(p)
    p.set_defaults(func=report.run)

    p = sub.add_parser("history", help="look at or correct the history database")
    hsub = p.add_subparsers(dest="history_command", required=True)
    h = hsub.add_parser("list-runs", help="list a repository's runs, newest first, with their ids")
    h.add_argument("--repo-name", required=True, help="the repository's name on the dashboard")
    h.add_argument("--db", help="history database (default: the same default as `record`)")
    h.set_defaults(func=cmd_history_list_runs)
    h = hsub.add_parser("delete-run", help="delete one run and everything recorded for it")
    h.add_argument("--repo-name", required=True, help="the repository's name on the dashboard")
    h.add_argument("--run", required=True, type=int, help="the run id, from `history list-runs`")
    h.add_argument("--db", help="history database (default: the same default as `record`)")
    h.add_argument("--yes", action="store_true", help="really delete it; without this nothing is deleted")
    h.set_defaults(func=cmd_history_delete_run)

    from shoalscan import scanjob

    p = sub.add_parser("scanjob", help="scan a target registered in scan_targets.toml, or all nightly targets")
    scanjob.add_arguments(p)
    p.set_defaults(func=scanjob.run)

    state_help = (
        "where the token hash and TLS files live (default: $XDG_CONFIG_HOME/shoalscan/dashboard or "
        "~/.config/shoalscan/dashboard)"
    )
    p = sub.add_parser("serve", help="serve the dashboard over HTTPS")
    p.add_argument("--db", help="history database (default: the same default as `record`)")
    p.add_argument("--bind", default="127.0.0.1", help="address to listen on (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port to listen on (default: {DEFAULT_PORT})")
    p.add_argument(
        "--host", action="append", help="a host name or address clients use; repeat for several (default: --bind)"
    )
    p.add_argument("--cert", help="TLS certificate chain, PEM (default: tls/server.pem in the state directory)")
    p.add_argument("--key", help="TLS private key, PEM (default: tls/server.key in the state directory)")
    p.add_argument("--state-dir", help=state_help)
    p.add_argument(
        "--allow-config",
        action="store_true",
        help=(
            "show the Configuration page even before scan_targets.toml exists, so targets can be added from the "
            "dashboard"
        ),
    )
    p.set_defaults(func=cmd_serve)
    serve_sub = p.add_subparsers(dest="serve_command")
    t = serve_sub.add_parser("token", help="make the shared login token of earlier versions (until a user joins)")
    t.add_argument("--state-dir", help=state_help)
    t.set_defaults(func=cmd_serve_token)
    u = serve_sub.add_parser("user", help="add, invite again, disable, enable or list the dashboard's users")
    usub = u.add_subparsers(dest="user_command", required=True)
    url_help = "the dashboard's https:// address, to print the whole invite link"
    for name, text in (
        ("add", "add a user and print their single-use invite link"),
        ("reset", "invite a user again: their token and sessions stop working at once"),
    ):
        x = usub.add_parser(name, help=text)
        x.add_argument("name", help="the user name: lowercase letters, digits, dots, dashes or underscores")
        if name == "add":
            x.add_argument("--admin", action="store_true", help="an admin: manages users, the configuration and scans")
        x.add_argument("--url", help=url_help)
        x.add_argument("--state-dir", help=state_help)
        x.set_defaults(func=cmd_serve_user)
    for name, text in (
        ("disable", "stop a user from signing in, and end their sessions"),
        ("enable", "let a disabled user sign in again"),
    ):
        x = usub.add_parser(name, help=text)
        x.add_argument("name", help="the user name")
        x.add_argument("--state-dir", help=state_help)
        x.set_defaults(func=cmd_serve_user)
    x = usub.add_parser("role", help="make a user an admin or a member")
    x.add_argument("name", help="the user name")
    x.add_argument("role", choices=("admin", "member"))
    x.add_argument("--state-dir", help=state_help)
    x.set_defaults(func=cmd_serve_user)
    x = usub.add_parser("list", help="list the users and their status")
    x.add_argument("--state-dir", help=state_help)
    x.set_defaults(func=cmd_serve_user)
    t = serve_sub.add_parser(
        "init-tls", help="make a name-constrained, single-use CA and a server certificate with openssl"
    )
    t.add_argument("--ip", action="append", help="an IP address clients use to reach the dashboard; repeat for several")
    t.add_argument("--dns", action="append", help="a DNS name clients use to reach the dashboard; repeat for several")
    t.add_argument(
        "--out-dir", help="where to write ca.pem, server.pem and server.key (default: tls/ in the state directory)"
    )
    t.add_argument("--state-dir", help=state_help)
    t.add_argument("--force", action="store_true", help="replace existing files")
    t.set_defaults(func=cmd_serve_init_tls)
