"""Run Opengrep and turn its JSON output into findings.

Opengrep exit codes: 0 means the scan ran (with or without findings), 1 means
findings were reported with `--error`, and 2 or more means an error. Anything
else, a timeout, a crash, unreadable output, or an `errors` entry of level
`error` fails the scan.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from shoalscan import process
from shoalscan.config import Limits, component_for
from shoalscan.errors import ScanError, SetupError
from shoalscan.findings import Finding, assign_fingerprints, enclosing_context, normalise_severity, split_lines
from shoalscan.rulesets import RuleIdFilter, select, split_rules

TOOL = "opengrep"
MAX_STDOUT_BYTES = 1024 * 1024 * 1024
MAX_SNIPPET_BYTES = 64 * 1024
_RULE_SUFFIXES = (".yaml", ".yml")


@dataclass(frozen=True)
class RuleSource:
    """A rule directory and the namespace its rule ids get, such as `community`.

    `categories` limits the rules to those categories (None keeps them all).
    """

    namespace: str
    path: Path
    categories: frozenset[str] | None = None


@dataclass
class StageStats:
    files: int = 0
    rules_kept: int = 0
    rules_dropped: int = 0
    rule_ids: set[str] = field(default_factory=set)
    # Each staged rule id's file, as `<namespace>/<path in the source>`.
    rule_files: dict[str, str] = field(default_factory=dict)


def is_rule_file(name: str) -> bool:
    return name.endswith(_RULE_SUFFIXES) and ".test." not in name and ".fixed." not in name


def stage_rules(stage: Path, sources: list[RuleSource], excluded: RuleIdFilter | None = None) -> StageStats:
    """Write the selected rules into `stage/<namespace>/...`.

    Opengrep prefixes each rule id with the config directory path relative to
    its working directory. Running it inside the stage therefore gives stable
    ids such as `community.python.lang.security.audit.eval-detected`, whatever
    the machine's paths are. Rules outside the source's categories, and rules
    whose id `excluded` matches, are left out; the source directory is never
    changed. Every source must keep at least one rule.
    """
    excluded = excluded or RuleIdFilter([])
    stats = StageStats()
    for source in sources:
        if not source.path.is_dir():
            raise SetupError(f"rule directory not found: {source.path}")
        kept_before = stats.rules_kept + stats.files
        filtering = source.categories is not None or excluded.exact or excluded.prefixes
        for dirpath, dirnames, filenames in os.walk(source.path, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
            for name in sorted(filenames):
                src = Path(dirpath) / name
                if not is_rule_file(name) or src.is_symlink():
                    continue
                rel = src.relative_to(source.path)
                dest = stage / source.namespace / rel
                id_prefix = ".".join(PurePosixPath(source.namespace).parts + rel.parent.parts)
                where = f"{source.namespace}/{rel.as_posix()}"
                if filtering:
                    text, kept, dropped = select(
                        src.read_text(encoding="utf-8"), where, id_prefix, source.categories, excluded
                    )
                    stats.rules_dropped += dropped
                    if text is None:
                        continue
                    stats.rules_kept += kept
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_text(text, encoding="utf-8")
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(src, dest)
                # Record the ids Opengrep will load from the staged file, so the
                # run can be checked against them.
                for rule in split_rules(dest.read_text(encoding="utf-8"), where):
                    stats.rule_ids.add(f"{id_prefix}.{rule.rule_id}")
                    stats.rule_files[f"{id_prefix}.{rule.rule_id}"] = where
                stats.files += 1
        if stats.rules_kept + stats.files == kept_before:
            raise SetupError(f"no rules selected from {source.path} ({source.namespace})")
    return stats


def build_command(
    binary: Path,
    namespaces: list[str],
    target: Path,
    limits: Limits,
    excludes: list[str],
    sarif_path: Path,
) -> list[str]:
    cmd = [str(binary), "scan"]
    for ns in namespaces:
        cmd += ["--config", ns]
    cmd += [
        "--json",
        # --time lists the rules that ran; the scan checks them against the stage.
        "--time",
        f"--sarif-output={sarif_path}",
        "--disable-version-check",
        # A pull request must not be able to hide files with its own ignore file.
        "--x-ignore-semgrepignore-files",
        "--jobs",
        str(limits.jobs),
        "--timeout",
        str(limits.rule_timeout_seconds),
        "--max-target-bytes",
        str(limits.max_target_bytes),
        # --verbose adds paths.skipped (with reasons) to the JSON output.
        "--verbose",
    ]
    for pattern in excludes:
        cmd.append(f"--exclude={pattern}")
    cmd.append(str(target))
    return cmd


# Kept under its old name for callers and tests.
_scanner_env = process.scanner_env


def execute(cmd: list[str], cwd: Path, timeout: int) -> dict:
    """Run Opengrep and return its parsed JSON output, or raise ScanError."""
    returncode, stdout, tail = process.run_scanner("opengrep", cmd, cwd, timeout)
    if returncode not in (0, 1):
        detail = tail
        try:
            reported = json.loads(stdout).get("errors") or []
            detail = "\n".join(f"- {str(e.get('message', e)).strip()[:400]}" for e in reported[:5]) or tail
        except (ValueError, AttributeError, UnicodeDecodeError):
            pass
        raise ScanError(f"opengrep failed with exit code {returncode}\n{detail}")
    if len(stdout) > MAX_STDOUT_BYTES:
        raise ScanError("opengrep output is larger than allowed")
    try:
        doc = json.loads(stdout)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ScanError(f"opengrep output is not valid JSON (exit code {returncode})\n{tail}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), list) or not isinstance(doc.get("errors"), list):
        raise ScanError("opengrep output has no results or errors list")
    return doc


def check_errors(doc: dict) -> list[dict]:
    """Raise ScanError for any error-level entry. Return the other entries as warnings."""
    fatal, warnings = [], []
    for entry in doc["errors"]:
        if not isinstance(entry, dict):
            raise ScanError(f"opengrep reported a malformed error entry: {entry!r}"[:300])
        level = str(entry.get("level", "error")).lower()
        (warnings if level in ("warn", "warning", "info") else fatal).append(entry)
    if fatal:
        lines = []
        for entry in fatal[:5]:
            message = str(entry.get("message") or entry.get("type") or entry)
            lines.append(f"- {entry.get('type', 'error')}: {message.strip()[:400]}")
        more = f"\n(and {len(fatal) - 5} more)" if len(fatal) > 5 else ""
        raise ScanError("opengrep reported errors:\n" + "\n".join(lines) + more)
    return warnings


def relative_path(path: str, root: Path) -> str:
    p = Path(path)
    if not p.is_absolute():
        raise ScanError(f"opengrep reported a relative path: {path}")
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        raise ScanError(f"opengrep reported a path outside the target: {path}") from None


def _file_bytes(abs_path: Path, cache: dict) -> bytes | None:
    if abs_path not in cache:
        try:
            cache[abs_path] = abs_path.read_bytes()
        except OSError:
            cache[abs_path] = None
    return cache[abs_path]


def _matched_code(abs_path: Path, start: dict, end: dict, fallback: str, cache: dict) -> str:
    s, e = start.get("offset"), end.get("offset")
    if isinstance(s, int) and isinstance(e, int) and 0 <= s <= e:
        data = _file_bytes(abs_path, cache)
        if data is not None and e <= len(data):
            return data[s : min(e, s + MAX_SNIPPET_BYTES)].decode("utf-8", errors="replace")
    return fallback


def _context(abs_path: Path, line: int, cache: dict, lines_cache: dict) -> str:
    if abs_path not in lines_cache:
        data = _file_bytes(abs_path, cache)
        lines_cache[abs_path] = split_lines(data.decode("utf-8", errors="replace")) if data is not None else []
    return enclosing_context(lines_cache[abs_path], line)


def normalise(doc: dict, root: Path, components: dict[str, str]) -> tuple[list[Finding], dict]:
    """Turn Opengrep results into findings.

    Returns the findings and a map from (rule, path, line, column) to
    fingerprint, used to annotate the SARIF file.
    """
    items = []
    cache: dict = {}
    lines_cache: dict = {}
    for r in doc["results"]:
        # With --sarif-output, Opengrep also lists results silenced by an
        # inline suppression comment, marked is_ignored. They are not findings;
        # the suppression lint and counts cover them.
        if isinstance(r, dict) and isinstance(r.get("extra"), dict) and r["extra"].get("is_ignored") is True:
            continue
        try:
            rule = r["check_id"]
            path = r["path"]
            start, end, extra = r["start"], r["end"], r["extra"]
            line = start["line"]
        except (KeyError, TypeError):
            raise ScanError(f"opengrep result is malformed: {str(r)[:300]}") from None
        if not isinstance(rule, str) or not isinstance(path, str) or not isinstance(line, int):
            raise ScanError(f"opengrep result is malformed: {str(r)[:300]}")
        rel = relative_path(path, root)
        fallback = extra.get("lines") if isinstance(extra.get("lines"), str) else ""
        items.append(
            {
                "tool": TOOL,
                "rule": rule,
                "path": rel,
                "line": line,
                "col": start.get("col", 0) if isinstance(start.get("col"), int) else 0,
                "code": _matched_code(Path(path), start, end, fallback, cache),
                "context": _context(Path(path), line, cache, lines_cache),
                "severity": normalise_severity(extra.get("severity")),
                "message": str(extra.get("message", "")).strip(),
            }
        )
    prints = assign_fingerprints(items)
    findings, index = [], {}
    for it, fp in zip(items, prints, strict=True):
        findings.append(
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
        )
        index[(it["rule"], it["path"], it["line"], it["col"])] = fp
    return findings, index


# Rule metadata kept for the work list and reports. Rule files can come from
# the scanned repository, so every value is checked and bounded, and only
# http(s) links are kept.
MAX_META_TEXT = 500
MAX_META_ITEMS = 5
_META_LEVELS = ("confidence", "likelihood", "impact")


def _meta_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    return text[:MAX_META_TEXT] or None


def _meta_list(value: object) -> list[str]:
    items = value if isinstance(value, list) else [value]
    out = []
    for item in items:
        text = _meta_text(item)
        if text and text not in out:
            out.append(text)
    return out[:MAX_META_ITEMS]


def rule_metadata(doc: dict, rule_files: dict[str, str]) -> dict[str, dict]:
    """What each rule that reported a finding says about itself.

    For every rule with a result: its CWE and OWASP labels, confidence,
    likelihood and impact, fix hint and reference links from the rule's
    `metadata`, and the staged file it came from (`<namespace>/<path>`).
    """
    out: dict[str, dict] = {}
    for r in doc["results"]:
        if not isinstance(r, dict) or not isinstance(r.get("extra"), dict) or r["extra"].get("is_ignored") is True:
            continue
        rule = r.get("check_id")
        if not isinstance(rule, str) or rule in out:
            continue
        meta = r["extra"].get("metadata")
        meta = meta if isinstance(meta, dict) else {}
        info: dict = {
            "file": rule_files.get(rule),
            "cwe": _meta_list(meta.get("cwe")),
            "owasp": _meta_list(meta.get("owasp")),
            "fix": _meta_text(meta.get("fix")),
            "references": [
                u for u in _meta_list(meta.get("references")) if u.startswith(("https://", "http://")) and " " not in u
            ],
        }
        for level in _META_LEVELS:
            text = _meta_text(meta.get(level))
            info[level] = text.upper()[:20] if text else None
        out[rule] = info
    return out


def ignored_count(doc: dict) -> int:
    return sum(
        1
        for r in doc["results"]
        if isinstance(r, dict) and isinstance(r.get("extra"), dict) and r["extra"].get("is_ignored") is True
    )


def check_rules_ran(doc: dict, staged: set[str]) -> int:
    """Fail if Opengrep ran a rule that was not staged. Returns the number of rules that ran."""
    timing = doc.get("time")
    rules = timing.get("rules") if isinstance(timing, dict) else None
    if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
        raise ScanError("opengrep output has no list of the rules that ran (--time)")
    unexpected = sorted(set(rules) - staged)
    if unexpected:
        raise ScanError(f"opengrep ran rules that were not selected: {', '.join(unexpected[:5])}")
    return len(rules)


# Skip reasons that come from the configuration or from git, not from a
# limit or an error: such files were never meant to be scanned.
_INTENDED_SKIPS = ("exclude", "ignore", "always_skipped", "dotfile", "include")


def _span_lines(entry: dict) -> list[list[int]]:
    spans = []
    for span in entry.get("spans") or []:
        try:
            start, end = int(span["start"]["line"]), int(span["end"]["line"])
        except (KeyError, TypeError, ValueError):
            continue
        spans.append([min(start, end), max(start, end)])
    return spans


def _count_lines(path: Path) -> int:
    try:
        return len(split_lines(path.read_bytes().decode("utf-8", errors="replace")))
    except OSError:
        return 0


def unscanned(doc: dict, root: Path) -> dict:
    """Files Opengrep skipped for a limit, and files it reported errors for.

    A PartialParsing error carries the unparsed line spans and the file's
    line count, so `check` can tell a small parse gap from a large one. A
    file skipped because its analysis failed is described by its error
    entries when there are any.
    """
    errors: dict[tuple[str, str], dict] = {}
    for entry in doc.get("errors", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            continue
        try:
            rel = relative_path(entry["path"], root)
        except ScanError:
            continue
        kind = entry.get("type", "error")
        # Some types are lists such as ["PartialParsing", [locations]]; keep the name.
        if isinstance(kind, list) and kind:
            kind = kind[0]
        kind = str(kind)[:80]
        record = errors.setdefault((rel, kind), {"path": rel, "type": kind})
        if kind == "PartialParsing":
            record.setdefault("spans", []).extend(_span_lines(entry))
            record["file_lines"] = _count_lines(root / rel)
    errored_paths = {path for path, _ in errors}
    skipped = {}
    paths = doc.get("paths")
    for entry in (paths.get("skipped") or []) if isinstance(paths, dict) else []:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            continue
        reason = str(entry.get("reason", "unknown"))
        if any(word in reason for word in _INTENDED_SKIPS):
            continue
        try:
            rel = relative_path(entry["path"], root)
        except ScanError:
            continue
        if reason == "analysis_failed_parser_or_internal_error" and rel in errored_paths:
            continue
        skipped[(rel, reason)] = {"path": rel, "reason": reason}
    for record in errors.values():
        if "spans" in record:
            record["spans"] = sorted({tuple(s) for s in record["spans"]})
            record["spans"] = [list(s) for s in record["spans"]]
    return {
        "skipped": [skipped[k] for k in sorted(skipped)],
        "errors": [errors[k] for k in sorted(errors)],
    }


def scanned_paths(doc: dict, root: Path) -> list[str]:
    paths = doc.get("paths")
    scanned = paths.get("scanned") if isinstance(paths, dict) else None
    if not isinstance(scanned, list) or not all(isinstance(p, str) for p in scanned):
        raise ScanError("opengrep output does not list the scanned files")
    return [relative_path(p, root) for p in scanned]
