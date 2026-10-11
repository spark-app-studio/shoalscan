"""Default locations for tools and output, and the rule that keeps both out of the repository.

A tools or output directory inside the scanned repository could be planted
by a pull request (a forged tool, a forged findings file), so Shoalscan
refuses one.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from pathlib import Path

from shoalscan.errors import SetupError


def cache_home() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME", "")
    if xdg and os.path.isabs(xdg):
        return Path(xdg)
    return Path.home() / ".cache"


def default_tools_dir() -> Path:
    """`$XDG_CACHE_HOME/shoalscan/tools`, or `~/.cache/shoalscan/tools`."""
    return cache_home() / "shoalscan" / "tools"


def default_out_dir(repo: Path) -> Path:
    """A per-user, per-repository directory under the system temp directory.

    It is created with mode 0700 and must be owned by the current user, so
    another user cannot prepare it in advance.
    """
    key = hashlib.sha256(str(repo.resolve()).encode("utf-8")).hexdigest()[:16]
    path = Path(tempfile.gettempdir()) / f"shoalscan-{os.getuid()}-{key}"
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise SetupError(f"refusing the output directory {path}: it must be a directory owned by you with mode 0700")
    return path


def refuse_inside_repo(path: Path, repo: Path, what: str, flag: str) -> None:
    """Refuse a tools or output directory that is inside the repository."""
    resolved = path.resolve()
    root = repo.resolve()
    if resolved == root or root in resolved.parents:
        raise SetupError(
            f"the {what} {path} is inside the repository {repo}. A pull request could plant files there, "
            f"so Shoalscan refuses it. Pass {flag} with a directory outside the repository, "
            "or leave it out to use the default."
        )
