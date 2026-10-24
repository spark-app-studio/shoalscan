"""The Configuration page's changes to scan_targets.toml.

A browser may set only a target's name, its source (an https URL on an
allowlisted host, or a registered local mirror chosen by name), its branch,
whether it is enabled and scanned nightly, and its policy text. Everything
is validated strictly and refused when it does not fit; nothing is cleaned up
and accepted. Paths are derived by the server. Baselines are never written
here: they change only from the command line.

Each change is written atomically (temporary file, fsync, rename, mode 0600)
and audited in `config_changes` with a field-level diff and the SHA-256 of
the policy text before and after.
"""

from __future__ import annotations

import difflib
import threading
import tomllib
from dataclasses import replace
from pathlib import Path

from shoalscan import history
from shoalscan.baseline import load_baseline
from shoalscan.config import KNOWN_SCANNERS, config_from_bytes
from shoalscan.dashboard import scanning
from shoalscan.errors import SetupError
from shoalscan.install import opengrep_path, tool_path
from shoalscan.locations import default_tools_dir
from shoalscan.lockfile import load_lock
from shoalscan.resources import default_lock_path

TARGET_KEYS = {"original", "name", "source", "branch", "enabled", "nightly", "policy", "scanners"}
MAX_BASELINE_ENTRIES = 500
_write_lock = threading.Lock()


def _source(value: object, targets: scanning.Targets, current: scanning.Target | None) -> dict:
    if not isinstance(value, dict) or value.get("kind") not in ("url", "mirror", "clone"):
        raise SetupError("the source must be an https URL or a registered mirror")
    kind = value["kind"]
    if kind == "url":
        if set(value) != {"kind", "url"}:
            raise SetupError("a URL source has only a url")
        return {
            "kind": "url",
            "source": scanning.validate_url(value["url"], targets.allowed_hosts),
            "mirror": None,
            "clone": None,
        }
    if kind == "mirror":
        if (
            set(value) != {"kind", "mirror"}
            or not isinstance(value["mirror"], str)
            or value["mirror"] not in targets.mirrors
        ):
            raise SetupError("choose one of the registered mirrors")
        return {"kind": "mirror", "mirror": value["mirror"], "source": None, "clone": None}
    # A clone path is set only by hand in the file; the page may keep it, never set or change it.
    if current is None or current.kind != "clone" or set(value) != {"kind"}:
        raise SetupError("a local clone can only be registered by editing scan_targets.toml by hand")
    return {"kind": "clone", "clone": current.clone, "source": None, "mirror": None}


def _flag(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise SetupError(f"{name} must be true or false")
    return value


def _fields(t: scanning.Target, policy: str) -> dict:
    chosen = scanning.split_policy(policy)[1]
    return {
        "name": t.name,
        "source": t.public_source(),
        "branch": t.branch,
        "enabled": t.enabled,
        "nightly": t.nightly,
        "scanners": list(chosen) if chosen is not None else None,
        "policy_sha256": scanning.policy_sha256(policy),
    }


def _diff(before: dict | None, after: dict | None) -> dict:
    keys = sorted(set(before or {}) | set(after or {}))
    return {
        k: [(before or {}).get(k), (after or {}).get(k)] for k in keys if (before or {}).get(k) != (after or {}).get(k)
    }


def _policy_scanners(text: str) -> list[str] | None:
    """The scanners a managed policy runs, or None when there is none (the repository's own file decides)."""
    if not text:
        return None
    try:
        return list(config_from_bytes(text.encode("utf-8"), "the policy").scanners)
    except SetupError:
        return None


def available_scanners(tools_dir: Path | None) -> list[dict]:
    """Every scanner a policy can choose, its pinned version, and whether this server has it installed."""
    lock = load_lock(default_lock_path())
    tools = tools_dir or default_tools_dir()
    out = []
    for name in KNOWN_SCANNERS:
        if name == "opengrep":
            version, installed = lock.opengrep_version, opengrep_path(tools).is_file()
        elif name in lock.tools:
            version, installed = lock.tools[name].version, tool_path(tools, name).is_file()
        else:
            version, installed = None, False
        out.append({"name": name, "version": version, "installed": installed})
    return out


class ConfigEditor:
    def __init__(self, state_dir: Path, db: Path):
        self.state_dir = state_dir
        self.db = db

    def load(self) -> scanning.Targets:
        return scanning.load_targets(self.state_dir, allow_missing=True)

    def _save(self, targets: scanning.Targets) -> None:
        path = self.state_dir / scanning.TARGETS_FILE
        if not path.exists():
            # A new file records into the database this dashboard serves.
            scanning.write_private(path, f"history_db = {scanning._toml_string(str(self.db))}\n")
        scanning.save_targets(self.state_dir, targets)

    def _audit(
        self,
        who: str,
        target: str,
        action: str,
        before: dict | None,
        after: dict | None,
        policy_before: str = "",
        policy_after: str = "",
    ) -> int:
        text_diff = "\n".join(
            difflib.unified_diff(
                policy_before.splitlines(), policy_after.splitlines(), "before", "after", lineterm="", n=1
            )
        )
        return history.append_config_change(
            self.db,
            who,
            target,
            action,
            _diff(before, after),
            (before or {}).get("policy_sha256"),
            (after or {}).get("policy_sha256"),
            text_diff or None,
        )

    # ------------------------------------------------------------ changes

    def save_target(self, request: dict, who: str) -> tuple[int, dict]:
        """Create a target (original is null) or update one (original names it)."""
        if set(request) != TARGET_KEYS:
            return 400, {"error": "send exactly: original, name, source, branch, enabled, nightly, policy, scanners"}
        try:
            with _write_lock:
                targets = self.load()
                original = request["original"]
                current = None
                if original is not None:
                    if not scanning.valid_name(original) or original not in targets.targets:
                        return 404, {"error": "no such target"}
                    current = targets.targets[original]
                    if request["name"] != original:
                        raise SetupError("a target's name cannot change; remove it and add a new one")
                name = scanning.validate_name(request["name"])
                if current is None and name in targets.targets:
                    raise SetupError("a target with this name exists already")
                if current is None and len(targets.targets) >= scanning.MAX_TARGETS:
                    raise SetupError(f"at most {scanning.MAX_TARGETS} targets")
                source = _source(request["source"], targets, current)
                branch = scanning.validate_branch(request["branch"])
                enabled = _flag(request["enabled"], "enabled")
                nightly = _flag(request["nightly"], "nightly")
                body = scanning.validate_policy(request["policy"])
                scanners = scanning.validate_scanners(request["scanners"])
                if current is not None and current.config is not None and (body != "" or scanners is not None):
                    raise SetupError(
                        "this target's configuration file is set by hand in scan_targets.toml; edit it there"
                    )
                if scanners is not None and body and "scanners" in tomllib.loads(body):
                    raise SetupError(
                        "the policy text sets scanners too: remove that line, or let the policy decide the scanners"
                    )
                policy = scanning.validate_policy(scanning.compose_policy(body, scanners))
                kept = (
                    {k: getattr(current, k) for k in ("config", "baseline", "python", "max_clone_mb", "pull_requests")}
                    if current
                    else {}
                )
                if kept.get("pull_requests") and source["kind"] != "url":
                    raise SetupError(
                        "this target scans pull requests (pull_requests = true in scan_targets.toml), which needs an "
                        "https source; remove that line there first"
                    )
                target = scanning.Target(
                    name=name,
                    branch=branch,
                    enabled=enabled,
                    nightly=nightly,
                    kind=source["kind"],
                    source=source["source"],
                    mirror=source["mirror"],
                    clone=source["clone"],
                    **kept,
                )
                old_policy = scanning.read_policy(targets, current) if current else ""
                before = _fields(current, old_policy) if current else None
                updated = scanning.with_target(targets, target, original)
                after = _fields(target, policy)
                audit_id = self._audit(who, name, "update" if current else "create", before, after, old_policy, policy)

                def write() -> None:
                    # The policy first, then the targets file that refers to it: a crash in
                    # between leaves either an unreferenced policy or the new pair.
                    scanning.write_policy(updated, target, policy)
                    self._save(updated)

                def undo() -> None:
                    scanning.write_policy(updated, target, old_policy)

                self._commit(audit_id, write, undo)
        except SetupError as exc:
            return 400, {"error": str(exc)}
        except OSError:
            return 500, {"error": "the change could not be saved; nothing was changed"}
        return 200, {"saved": name}

    def _commit(self, audit_id: int, write, undo=None) -> None:
        """The audit row is written first; if the files cannot be written, it is taken back."""
        try:
            write()
        except BaseException:
            if undo is not None:
                try:
                    undo()
                except OSError:
                    pass
            history.delete_config_change(self.db, audit_id)
            raise

    def set_enabled(self, request: dict, who: str) -> tuple[int, dict]:
        if set(request) != {"name", "enabled"} or not isinstance(request["enabled"], bool):
            return 400, {"error": 'send exactly {"name": name, "enabled": true or false}'}
        with _write_lock:
            targets = self.load()
            name = request["name"]
            if not scanning.valid_name(name) or name not in targets.targets:
                return 404, {"error": "no such target"}
            current = targets.targets[name]
            target = replace(current, enabled=request["enabled"])
            policy = scanning.read_policy(targets, current)
            audit_id = self._audit(
                who,
                name,
                "enable" if request["enabled"] else "disable",
                _fields(current, policy),
                _fields(target, policy),
            )
            try:
                self._commit(audit_id, lambda: self._save(scanning.with_target(targets, target, name)))
            except OSError:
                return 500, {"error": "the change could not be saved; nothing was changed"}
        return 200, {"saved": name}

    def remove(self, request: dict, who: str) -> tuple[int, dict]:
        """Remove a target from the file. Its runs, findings and baseline stay."""
        if set(request) != {"name", "confirm"}:
            return 400, {"error": 'send exactly {"name": name, "confirm": name}'}
        with _write_lock:
            targets = self.load()
            name = request["name"]
            if not scanning.valid_name(name) or name not in targets.targets:
                return 404, {"error": "no such target"}
            if request["confirm"] != name:
                return 400, {"error": "to remove a target, confirm by typing its name"}
            current = targets.targets[name]
            policy = scanning.read_policy(targets, current)
            remaining = replace(targets, targets={n: t for n, t in targets.targets.items() if n != name})
            audit_id = self._audit(who, name, "remove", _fields(current, policy), None)
            try:
                self._commit(audit_id, lambda: self._save(remaining))
            except OSError:
                return 500, {"error": "the change could not be saved; nothing was changed"}
        return 200, {"removed": name}

    # ------------------------------------------------------------ reading

    def page(self, latest_run, changes: list[dict]) -> dict:
        targets = self.load()
        out = []
        for t in targets.targets.values():
            baseline = self.baseline_entries(targets, t)
            full = scanning.read_policy(targets, t) if t.config is None else ""
            body, chosen = scanning.split_policy(full)
            out.append(
                {
                    **_fields(t, ""),
                    "scanners": list(chosen) if chosen is not None else None,
                    "policy_scanners": _policy_scanners(full),
                    "policy": body if t.config is None else None,
                    "policy_editable": t.config is None,
                    "set_by_hand": [k for k in ("clone", "config", "baseline", "python") if getattr(t, k) is not None]
                    + (["pull_requests"] if t.pull_requests else []),
                    "last_run": latest_run(t.name),
                    "baseline": {"size": baseline["size"], "found": baseline["found"]},
                }
            )
        return {
            "targets": out,
            "scanners": available_scanners(targets.tools_dir),
            "mirrors": sorted(targets.mirrors),
            "allowed_hosts": list(targets.allowed_hosts),
            "changes": changes,
        }

    def baseline_entries(self, targets: scanning.Targets, t: scanning.Target) -> dict:
        path = targets.baseline_path(t)
        try:
            entries = load_baseline(path) if t.kind != "clone" or t.baseline is not None else None
        except SetupError:
            entries = None
        state_relative = (
            f"<state dir>/targets/{scanning.slug(t.name)}/baseline.toml"
            if t.baseline is None
            else "the baseline set in scan_targets.toml"
        )
        return {
            "found": entries is not None,
            "size": len(entries) if entries is not None else 0,
            "location": state_relative
            if t.kind != "clone" or t.baseline is not None
            else "the repository's own baseline",
            "entries": [
                {
                    "tool": e.tool,
                    "rule": e.rule,
                    "path": e.path,
                    "fingerprint": e.fingerprint,
                    "issue": e.issue,
                    "reason": e.reason,
                }
                for e in (entries or [])[:MAX_BASELINE_ENTRIES]
            ],
            "command": (
                f"shoalscan baseline init --repo <a checkout of {t.name}> --config <state "
                f"dir>/targets/{scanning.slug(t.name)}/shoalscan.toml "
                f'--baseline {state_relative} --issue "#123" --reason "accepted at adoption"'
            ),
        }

    def baseline(self, name: object) -> tuple[int, dict]:
        targets = self.load()
        if not scanning.valid_name(name) or name not in targets.targets:
            return 404, {"error": "no such target"}
        return 200, {"name": name, **self.baseline_entries(targets, targets.targets[name])}
