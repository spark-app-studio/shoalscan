"""The common finding format, and fingerprints that survive line shifts."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from shoalscan.errors import ScanError, SetupError

FINDINGS_FORMAT = 1
_WS = re.compile(r"\s+")

# Opengrep accepts both the classic and the newer severity names.
_SEVERITY_MAP = {
    "ERROR": "ERROR",
    "CRITICAL": "ERROR",
    "HIGH": "ERROR",
    "WARNING": "WARNING",
    "WARN": "WARNING",
    "MEDIUM": "WARNING",
    "INFO": "INFO",
    "LOW": "INFO",
    "INVENTORY": "INFO",
    "EXPERIMENT": "INFO",
}


@dataclass(frozen=True)
class Finding:
    tool: str
    rule: str
    severity: str
    path: str
    line: int
    fingerprint: str
    component: str
    message: str

    def key(self) -> tuple[str, str, str, str]:
        return (self.tool, self.rule, self.path, self.fingerprint)


def normalise_severity(value: object) -> str:
    """Map a scanner severity to ERROR, WARNING or INFO. Unknown values count as ERROR."""
    if isinstance(value, str):
        return _SEVERITY_MAP.get(value.upper(), "ERROR")
    return "ERROR"


def normalise_code(text: str) -> str:
    return _WS.sub(" ", text).strip()


_DEFINITION = re.compile(
    r"^(?P<indent>[ \t]*)(?:(?:pub(?:\([^)]*\))?|export|default|async|static|public|private|protected|unsafe)\s+)*"
    r"(?P<kind>def|fn|function\*?|class|struct|enum|impl|trait|interface|mod)\s+(?P<name>[A-Za-z_$][\w$]*)"
)


def enclosing_context(lines: list[str], line: int) -> str:
    """Name the enclosing definitions of a 1-based line, outermost first.

    Walking up from the line, each `def`/`fn`/`function`/`class`/... line
    that is indented less than everything seen so far encloses it, giving a
    qualified name such as `class:Svc/def:run`. Code at the left margin has
    no context. This is a heuristic: it reads lines, not syntax.
    """
    if not 1 <= line <= len(lines):
        return ""
    target = lines[line - 1]
    indent = len(target) - len(target.lstrip(" \t"))
    names: list[str] = []
    for n in range(line - 2, -1, -1):
        if indent == 0:
            break
        candidate = lines[n]
        if not candidate.strip():
            continue
        match = _DEFINITION.match(candidate)
        cand_indent = len(candidate) - len(candidate.lstrip(" \t"))
        if match and cand_indent < indent:
            names.append(f"{match.group('kind').rstrip('*')}:{match.group('name')}")
            indent = cand_indent
    return "/".join(reversed(names))


def split_lines(text: str) -> list[str]:
    """Split on newline only, as Opengrep numbers lines. (str.splitlines also
    breaks on form feeds, U+2028 and other separators, which shifts numbers.)"""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def base_fingerprint(tool: str, rule: str, context: str, code: str) -> str:
    material = "\0".join((tool, rule, context, normalise_code(code)))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def assign_fingerprints(items: list[dict]) -> list[str]:
    """Return one fingerprint per item.

    The fingerprint is a hash of the tool, the rule, the enclosing context
    (function or class name, when known) and the normalised matched code. It
    holds neither the line number nor the path, so moving code within a file
    keeps it, and `shoalscan baseline rename-path` can follow a moved file.
    Identical matches in one file and context get an occurrence suffix
    (`:0`, `:1`, ...) in line order. Each item needs the keys tool, rule,
    path, code and line, and may have context and col.
    """
    order = sorted(range(len(items)), key=lambda i: (items[i]["line"], items[i].get("col", 0)))
    seen: dict[tuple[str, str], int] = defaultdict(int)
    result = [""] * len(items)
    for i in order:
        it = items[i]
        base = base_fingerprint(it["tool"], it["rule"], it.get("context", ""), it["code"])
        key = (it["path"], base)
        result[i] = f"{base}:{seen[key]}"
        seen[key] += 1
    return result


def findings_to_json(findings: list[Finding], meta: dict) -> str:
    doc = {
        "format": FINDINGS_FORMAT,
        "complete": True,
        **meta,
        "findings": [asdict(f) for f in sort_findings(findings)],
    }
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.path, f.line, f.rule, f.fingerprint, f.tool))


def load_findings(path: Path) -> tuple[list[Finding], dict]:
    """Read findings.json written by `shoalscan scan`. Incomplete files are refused."""
    try:
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
    except FileNotFoundError:
        raise SetupError(f"findings file not found: {path} (run `shoalscan scan` first)") from None
    except (OSError, json.JSONDecodeError) as exc:
        raise SetupError(f"findings file is unreadable: {path}: {exc}") from None
    if not isinstance(doc, dict) or doc.get("format") != FINDINGS_FORMAT or doc.get("complete") is not True:
        raise ScanError(f"findings file is incomplete or has an unknown format: {path}")
    raw = doc.get("findings")
    if not isinstance(raw, list):
        raise ScanError(f"findings file has no findings list: {path}")
    fields = set(Finding.__dataclass_fields__)
    findings = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != fields:
            raise ScanError(f"findings file has a malformed entry: {item!r}"[:300])
        findings.append(Finding(**item))
    meta = {k: v for k, v in doc.items() if k != "findings"}
    return findings, meta
