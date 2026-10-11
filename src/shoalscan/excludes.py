"""A small gitignore-style matcher for exclude patterns.

Opengrep receives the same patterns as `--exclude`. Shoalscan uses this
matcher for the files it reads itself (the suppression lint), so both see the
same tree. Supported: `*`, `?`, `**`, a leading `/` to anchor at the root, a
trailing `/` for directories, and patterns with a `/` anchored at the root.
Negation (`!`) is not supported and is rejected.
"""

from __future__ import annotations

import re

from shoalscan.errors import SetupError


def _glob_to_regex(glob: str) -> str:
    out = []
    i = 0
    while i < len(glob):
        ch = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("/**", i) and i + 3 == len(glob):
            out.append("/.*")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif ch == "*":
            out.append("[^/]*")
            i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(ch))
            i += 1
    return "".join(out)


class FileGlobMatcher:
    """Globs that name files, for `parse_warn_only`.

    A glob without `/` matches the file's own name only, never a directory
    on its path. A glob with `/` matches the whole repository-relative path.
    """

    def __init__(self, patterns: tuple[str, ...] | list[str]):
        self._names = [re.compile(f"^{_glob_to_regex(p)}$") for p in patterns if "/" not in p]
        self._paths = [re.compile(f"^{_glob_to_regex(p)}$") for p in patterns if "/" in p]

    def matches(self, rel_path: str) -> bool:
        name = rel_path.rsplit("/", 1)[-1]
        return any(r.match(name) for r in self._names) or any(r.match(rel_path) for r in self._paths)


class ExcludeMatcher:
    def __init__(self, patterns: tuple[str, ...] | list[str]):
        self._anchored: list[re.Pattern[str]] = []
        self._names: list[re.Pattern[str]] = []
        for raw in patterns:
            pattern = raw.strip()
            if pattern.startswith("!"):
                raise SetupError(f"negated exclude patterns are not supported: {raw!r}")
            pattern = pattern.rstrip("/")
            if not pattern:
                continue
            if "/" in pattern:
                regex = _glob_to_regex(pattern.lstrip("/"))
                self._anchored.append(re.compile(f"^{regex}(?:/.*)?$"))
            else:
                self._names.append(re.compile(f"^{_glob_to_regex(pattern)}$"))

    def excluded(self, rel_path: str) -> bool:
        """True if a repository-relative POSIX path, or one of its parent directories, matches."""
        if any(r.match(rel_path) for r in self._anchored):
            return True
        return any(r.match(part) for part in rel_path.split("/") for r in self._names)
