"""Locate the files that ship with Shoalscan: `tools.lock`, its own rules and its scope rules."""

from __future__ import annotations

from pathlib import Path

from shoalscan.errors import SetupError

_PACKAGE_DIR = Path(__file__).resolve().parent


def data_path(name: str) -> Path:
    """Return the path of a shipped data file or directory.

    An installed wheel carries the data in `shoalscan/_data/`. A source
    checkout keeps it at the repository root.
    """
    for candidate in (_PACKAGE_DIR / "_data" / name, _PACKAGE_DIR.parents[1] / name):
        if candidate.exists():
            return candidate
    raise SetupError(f"Shoalscan data file not found: {name}")


def default_lock_path() -> Path:
    return data_path("tools.lock")


def shoalscan_rules_dir() -> Path:
    return data_path("rules")


def scope_rules_file() -> Path:
    """The internal rule pack that finds `#[cfg(test)]` items for test code labels (see `shoalscan.testscope`)."""
    return data_path("scope") / "rust-test-scope.yaml"
