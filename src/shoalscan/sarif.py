"""Post-process Opengrep's SARIF file and add Shoalscan's own findings.

Locations become repository-relative, each result gets Shoalscan's
fingerprint in `partialFingerprints`, so code scanning tools can track
findings across line shifts, and code snippets are removed, so the file
never carries a copy of a secret a rule matched.
"""

from __future__ import annotations

import json
from pathlib import Path

from shoalscan import __version__
from shoalscan.errors import ScanError
from shoalscan.findings import Finding

FINGERPRINT_KEY = "shoalscan/v1"
_LEVEL = {"ERROR": "error", "WARNING": "warning", "INFO": "note"}


def _relativise(uri: str, root: Path) -> str | None:
    path = uri[len("file://") :] if uri.startswith("file://") else uri
    p = Path(path)
    if not p.is_absolute():
        return path
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        return None


def _drop_snippets(node: object) -> None:
    """Remove every `snippet` (the matched source text) inside a SARIF result.

    A snippet copies the scanned line, and with it any secret a rule found
    there, into a file that CI often uploads or keeps as an artifact.
    Locations stay, so code scanning tools still show the line from the
    repository itself.
    """
    if isinstance(node, dict):
        node.pop("snippet", None)
        for value in node.values():
            _drop_snippets(value)
    elif isinstance(node, list):
        for value in node:
            _drop_snippets(value)


def rewrite_opengrep_sarif(doc: dict, root: Path, index: dict) -> dict:
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise ScanError("opengrep SARIF output has no runs")
    for run in doc["runs"]:
        for result in run.get("results", []) or []:
            _drop_snippets(result)
            rel = None
            line = col = None
            for loc in result.get("locations", []) or []:
                phys = loc.get("physicalLocation", {})
                art = phys.get("artifactLocation", {})
                uri = art.get("uri")
                if isinstance(uri, str):
                    new = _relativise(uri, root)
                    if new is None:
                        raise ScanError(f"SARIF location outside the target: {uri}")
                    art["uri"] = new
                    art["uriBaseId"] = "%SRCROOT%"
                    if rel is None:
                        rel = new
                        region = phys.get("region", {})
                        line, col = region.get("startLine"), region.get("startColumn")
            fp = index.get((result.get("ruleId"), rel, line, col))
            if fp:
                result.setdefault("partialFingerprints", {})[FINGERPRINT_KEY] = fp
        # The command line holds local temporary paths; it adds nothing.
        for inv in run.get("invocations", []) or []:
            inv.pop("commandLine", None)
            inv.pop("arguments", None)
    return doc


def shoalscan_run(findings: list[Finding]) -> dict:
    rules = sorted({f.rule for f in findings})
    return {
        "tool": {
            "driver": {
                "name": "shoalscan",
                "version": __version__,
                "rules": [{"id": r, "shortDescription": {"text": r}} for r in rules],
            }
        },
        "results": [
            {
                "ruleId": f.rule,
                "level": _LEVEL[f.severity],
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": f.line},
                        }
                    }
                ],
                "partialFingerprints": {FINGERPRINT_KEY: f.fingerprint},
            }
            for f in findings
        ],
    }


def build_sarif(opengrep_sarif: Path | None, root: Path, index: dict, own: list[Finding]) -> str:
    if opengrep_sarif is not None:
        try:
            with open(opengrep_sarif, encoding="utf-8") as handle:
                doc = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise ScanError(f"opengrep SARIF output is unreadable: {exc}") from None
        doc = rewrite_opengrep_sarif(doc, root, index)
    else:
        doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [],
        }
    doc["runs"].append(shoalscan_run(own))
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"
