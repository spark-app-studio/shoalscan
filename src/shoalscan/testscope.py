"""Rust test scope: prove that a finding sits in an item that is compiled only for tests.

Opengrep's own Rust parser does the proving. Shoalscan ships a small rule pack
(`scope/rust-test-scope.yaml`) that runs in the same scan as the security
rules; its matches give the exact line ranges of:

- `#[cfg(test)]` and `#[cfg(all(test, ...))]` modules (`cfg_test_module`);
- such functions, `impl` blocks, constants and statics (`cfg_test_item`).

Only items count, never whole files: code inside a `#[cfg(test)]` item is
removed from every build without `cfg(test)`, wherever its file is included.

Shoalscan trusts only what it can prove, and turns the feature off otherwise:

- nothing in the repository may be able to set `cfg(test)` in a build that is
  not a test (see `shoalscan.cargotrust`);
- a finding counts only when its whole byte range lies inside the item;
- every match is checked to be spelled exactly as recognised;
- a file Opengrep reported an error for gets no scope at all.
"""

from __future__ import annotations

import json
import os
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from shoalscan.cargotrust import CargoCheck

NAMESPACE = "test-scope"
RULES_FILE = "rust-test-scope.yaml"
MODULE_RULES_FILE = "rust-test-scope-modules.yaml"
ITEM_RULE = f"{NAMESPACE}.rust-cfg-test-item"
MODULE_RULE = f"{NAMESPACE}.rust-cfg-test-module"

KINDS = ("cfg_test_module", "cfg_test_item")
# Who an automatic test-scope review is recorded under. It is not an email
# address, so it can never be a person signed in to the dashboard.
AUTO_REVIEWER = "shoalscan (test scope)"
ELIGIBLE_TOOL = "opengrep"
ELIGIBLE_SUFFIX = ".rs"

# Module names written into the generated rule; Watchlight-sized monorepos need a few hundred.
MAX_MODULE_NAMES = 2_000
MAX_FILE_BYTES = 16 * 1024 * 1024

_RUST_KEYWORDS = frozenset(
    "as async await break const continue crate dyn else enum extern false fn for gen if impl in let loop match mod "
    "move mut pub ref return self Self static struct super trait true try type union unsafe use where while abstract "
    "become box do final macro override priv typeof unsized virtual yield".split()
)
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,99}$")

# Rules whose findings are secrets: a secret in test code is still a leaked secret.
_SECRET_RULE = re.compile(r"secret|(^|[.-])detected-[a-z0-9-]*-token|api-key|private-key|jwt", re.IGNORECASE)


def secret_rule(rule: str) -> bool:
    return bool(_SECRET_RULE.search(rule))


@dataclass(frozen=True)
class TestScope:
    """Why a finding is in test-only code: the kind of item and the file and line of its attribute."""

    __test__ = False  # not a unittest class

    kind: str
    path: str
    line: int

    def as_json(self) -> dict:
        return {"kind": self.kind, "path": self.path, "line": self.line}

    def description(self) -> str:
        return f"test-only code: {self.kind} at {self.path}:{self.line}"


def scope_from_json(value: object) -> TestScope | None:
    """A finding's `test_scope` from findings.json; None for a malformed one."""
    if not isinstance(value, dict) or set(value) != {"kind", "path", "line"}:
        return None
    kind, path, line = value["kind"], value["path"], value["line"]
    if kind not in KINDS or not isinstance(path, str) or not path or len(path) > 1024:
        return None
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        return None
    return TestScope(kind, path, line)


def eligible(tool: str, rule: str, path: str, matcher) -> bool:
    """Only Opengrep findings in Rust files, for a listed rule that is not about secrets, can be test-scoped."""
    return tool == ELIGIBLE_TOOL and path.endswith(ELIGIBLE_SUFFIX) and matcher.matches(rule) and not secret_rule(rule)


def never_test_scope(path: str) -> bool:
    """Code under `examples/`, in `build.rs` or under `src/bin/` is never test scope."""
    parts = path.split("/")
    if "examples" in parts[:-1] or parts[-1] == "build.rs":
        return True
    return any(parts[i] == "src" and parts[i + 1] == "bin" for i in range(len(parts) - 2))


# ---------------------------------------------------------------- reading Rust text


def strip_code(text: str) -> str:
    """The text with comments, string literals and character literals blanked out (newlines kept).

    Handles nested block comments, escapes and raw strings (`r#"..."#`, also
    `b` and `c` prefixed). Lifetimes (`'a`) are kept.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            out.append(" " * (end - i))
            i = end
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            out.append(_blank(text[i:j]))
            i = j
        elif (m := _RAW_STRING.match(text, i)) and (i == 0 or not _word(text[i - 1])):
            close = '"' + m.group(1)
            end = text.find(close, m.end())
            end = n if end < 0 else end + len(close)
            out.append(_blank(text[i:end]))
            i = end
        elif c == '"' or (c in "bc" and text.startswith('"', i + 1) and (i == 0 or not _word(text[i - 1]))):
            j = i + (1 if c == '"' else 2)
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(_blank(text[i : j + 1]))
            i = j + 1
        elif c == "'" and (m := _CHAR.match(text, i)):
            out.append(" " * (m.end() - i))
            i = m.end()
        else:
            out.append(c)
            i += 1
    return "".join(out)


_RAW_STRING = re.compile(r'[bc]?r(#*)"')
_CHAR = re.compile(r"'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f]{1,6}\}|.)|[^\\'\n])'")


def _word(c: str) -> bool:
    return c.isalnum() or c == "_"


def _blank(s: str) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in s)


# `#[cfg(test)]` or `#[cfg(all(...))]` (the arguments are checked on each match, see `_spelled`).
_CFG_TEST = re.compile(r"#\s*\[\s*cfg\s*\(\s*(?:test|all\s*\([^\]]*\))\s*\)\s*\]")
_ATTRIBUTE = re.compile(r"\s*#\s*\[")
_VISIBILITY = re.compile(r"\s*pub\s*(\(\s*(crate|self|super|in\s+[\w:\s]+)\s*\))?")
_MODULE = re.compile(r"\s*mod\s+([A-Za-z_][A-Za-z0-9_]*)(?![#\w])")


def _skip_attribute(text: str, i: int) -> int:
    """The index after the attribute that starts at `i` (`#[`), brackets balanced."""
    depth, j = 0, text.index("[", i)
    while j < len(text):
        if text[j] == "[":
            depth += 1
        elif text[j] == "]":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return len(text)


def cfg_test_module_names(code: str) -> set[str]:
    """Names of modules after a `#[cfg(test)]` or `#[cfg(all(...))]` attribute in comment- and string-free code."""
    names = set()
    for m in _CFG_TEST.finditer(code):
        i = m.end()
        while a := _ATTRIBUTE.match(code, i):
            i = _skip_attribute(code, a.start())
        if v := _VISIBILITY.match(code, i):
            i = v.end()
        if (mod := _MODULE.match(code, i)) and _IDENT.match(mod.group(1)) and mod.group(1) not in _RUST_KEYWORDS:
            names.add(mod.group(1))
    return names


# ---------------------------------------------------------------- the repository


@dataclass
class Repository:
    """What the scope needs from the repository's files, read once."""

    module_names: list[str] = field(default_factory=list)
    names_dropped: int = 0
    off: str | None = None  # why test scope is off for the whole tree


def _inside(root: Path, target: Path) -> str | None:
    try:
        return target.relative_to(root).as_posix()
    except ValueError:
        return None


# Names Cargo and rustup read. A file system may treat other spellings as the same name: in another letter
# case, with a character that folds to these (the long s, `ſ`, folds to `s`), or in another Unicode form.
_SPECIAL_NAMES = ("Cargo.toml", "build.rs", "rust-toolchain", "rust-toolchain.toml")
_CARGO_DIR = ".cargo"
_CONFIG_FILES = ("config", "config.toml")


def fold(name: str) -> str:
    """A name as a case-insensitive, normalising file system may compare it."""
    return unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", name).casefold())


_FOLDED_SPECIAL = {fold(n): n for n in _SPECIAL_NAMES}
_FOLDED_CARGO_DIR = fold(_CARGO_DIR)
_FOLDED_CONFIG = {fold(n): n for n in _CONFIG_FILES}


def special_name(name: str, in_cargo_dir: bool = False) -> str | None:
    """The special name this file name could stand for, or None."""
    folded = fold(name)
    return _FOLDED_SPECIAL.get(folded) or (_FOLDED_CONFIG.get(folded) if in_cargo_dir else None)


def read_repository(root: Path, allowed_wrappers: tuple[str, ...] = ()) -> Repository:
    """Read the whole tree under `root` (only `.git` is skipped, `target/` and `node_modules/` included): Rust
    files for module names, and the Cargo and toolchain files that could change how Rust is compiled. Anything
    Shoalscan cannot read or does not recognise turns test scope off."""
    repo = Repository()
    root = root.resolve()
    cargo = CargoCheck(root, allowed_wrappers)
    names: set[str] = set()

    def walk_error(error: OSError) -> None:
        cargo.fail(f"{_inside(root, Path(error.filename)) if error.filename else root} could not be listed")

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=walk_error):
        here = Path(dirpath)
        keep = []
        for d in sorted(dirnames):
            if d == ".git":
                continue
            full = here / d
            rel_dir = _inside(root, full)
            if full.is_symlink():
                # A linked directory may hold build settings or code Shoalscan does not walk.
                cargo.fail(f"{rel_dir} is a symbolic link to a directory")
                continue
            if fold(d) == _FOLDED_CARGO_DIR and d != _CARGO_DIR:
                cargo.fail(f"{rel_dir} could stand for {_CARGO_DIR} on a case-insensitive file system")
            keep.append(d)
        dirnames[:] = keep
        in_cargo_dir = fold(here.name) == _FOLDED_CARGO_DIR
        for name in filenames:
            full = here / name
            rel = _inside(root, full) or name
            special = special_name(name, in_cargo_dir)
            if special and (name != special or (in_cargo_dir and here.name != _CARGO_DIR)):
                cargo.fail(f"{rel} could stand for {special} on a case-insensitive file system")
                continue
            if full.is_symlink():
                # A link into the tree is read where it points; anything else is unknown.
                if special or name.endswith(".rs") or _inside(root, full.resolve()) is None:
                    cargo.fail(f"{rel} is a symbolic link")
                continue
            if name == "build.rs":
                cargo.fail(f"{rel} is a build script; test scope is off wherever a build script runs")
            elif name == "Cargo.toml":
                cargo.add_manifest(full, rel)
            elif in_cargo_dir and name in _CONFIG_FILES:
                cargo.add_config(full, rel)
            elif name in ("rust-toolchain", "rust-toolchain.toml"):
                cargo.add_toolchain(full, rel)
            elif name.endswith(".rs"):
                try:
                    if full.stat().st_size > MAX_FILE_BYTES:
                        continue  # its module names are not proposed: no scope there
                    text = full.read_bytes().decode("utf-8", errors="replace")
                except OSError:
                    cargo.fail(f"{rel} could not be read")
                    continue
                names |= cfg_test_module_names(strip_code(text))
    repo.off = cargo.result()
    ordered = sorted(names)
    repo.module_names = ordered[:MAX_MODULE_NAMES]
    repo.names_dropped = max(0, len(ordered) - MAX_MODULE_NAMES)
    return repo


# ---------------------------------------------------------------- what a change touches

_UNTRUSTED_DIRS = ("target", "node_modules")


def change_problem(entries: list[tuple[str, str, str, str]]) -> str | None:
    """Why a change keeps test scope off, or None when it changes Rust source only.

    `entries` are (status, old mode, new mode, path) from `gitref.changed_entries`.
    Every changed path must be a regular `.rs` file, added or modified, that is
    not a special name in any spelling and not under `target/` or `node_modules/`.
    """
    for status, old_mode, new_mode, path in sorted(entries, key=lambda e: e[3]):
        parts = path.split("/")
        name = parts[-1]
        if not name.endswith(".rs"):
            return f"the change touches {path}, which is not Rust source"
        if special_name(name) or any(special_name(p) or fold(p) == _FOLDED_CARGO_DIR for p in parts[:-1]):
            return f"the change touches {path}, which Cargo or rustup reads"
        if any(fold(p) in _UNTRUSTED_DIRS for p in parts[:-1]):
            return f"the change touches {path}, under a build or package directory"
        if status == "D":
            return f"the change deletes {path}"
        if status not in ("A", "M", "?"):
            return f"the change {status!r} on {path} is not an addition or a modification"
        if new_mode not in ("100644", "100755") or (old_mode not in ("000000", new_mode)):
            return f"the change gives {path} the mode {new_mode} (a link, a submodule or a mode change)"
    return None


# ---------------------------------------------------------------- the rule pack


def module_rules(names: list[str]) -> dict:
    """The `#[cfg(test)] mod NAME` rule (and `cfg(all(..., test, ...))`), one pattern per module name.

    Opengrep binds no metavariable to a module's name (`mod $M { ... }` never
    matches), so each name is written out. A name only proposes a pattern:
    Opengrep still has to find a module of that name with exactly the
    attribute `#[cfg(test)]` in the parsed code.
    """
    return {
        "rules": [
            {
                "id": MODULE_RULE.split(".", 1)[1],
                "message": "A module compiled only for tests (#[cfg(test)]).",
                "severity": "INFO",
                "languages": ["rust"],
                "metadata": {"category": "test-scope"},
                "pattern-either": [
                    {"pattern": f"{attr}\nmod {n} {{ ... }}\n"}
                    for n in names
                    for attr in ("#[cfg(test)]", "#[cfg(all(..., test, ...))]")
                ],
            }
        ]
    }


def stage(dest: Path, pack: Path, names: list[str]) -> None:
    """Write the scope rules into `dest` (a directory of the rule stage)."""
    dest.mkdir(parents=True, exist_ok=True)
    (dest / RULES_FILE).write_text(pack.read_text(encoding="utf-8"), encoding="utf-8")
    if names:
        # JSON is YAML, and needs no YAML writer.
        (dest / MODULE_RULES_FILE).write_text(json.dumps(module_rules(names), indent=1), encoding="utf-8")


def rule_ids(names: list[str]) -> set[str]:
    ids = {ITEM_RULE}
    if names:
        ids.add(MODULE_RULE)
    return ids


def split_results(doc: dict) -> list[dict]:
    """Take the scope rules' matches out of Opengrep's output and return them.

    They are never findings: they are removed before the results are read,
    counted or written. A match silenced by an inline suppression comment does
    not count (fail closed).
    """
    scope, others = [], []
    for r in doc["results"]:
        rule = r.get("check_id") if isinstance(r, dict) else None
        if isinstance(rule, str) and rule.startswith(NAMESPACE + "."):
            extra = r.get("extra") if isinstance(r.get("extra"), dict) else {}
            if extra.get("is_ignored") is not True:
                scope.append(r)
        else:
            others.append(r)
    doc["results"] = others
    return scope


# ---------------------------------------------------------------- the scope map


@dataclass
class ScopeMap:
    """Byte ranges that are test-only, per repository path."""

    ranges: dict[str, list[tuple[int, int, TestScope]]] = field(default_factory=dict)
    unrecognised: int = 0

    def scope_for(self, path: str, start: int | None, end: int | None) -> TestScope | None:
        """The scope whose byte range holds all of [start, end), the finding's own range; None without one."""
        if never_test_scope(path) or not isinstance(start, int) or not isinstance(end, int) or not 0 <= start <= end:
            return None
        inside = [r for r in self.ranges.get(path, []) if r[0] <= start and end <= r[1]]
        if not inside:
            return None
        # The outermost range names the scope.
        return min(inside, key=lambda r: (r[0], -r[1]))[2]

    def counts(self) -> dict:
        kinds: dict[str, int] = {}
        for items in self.ranges.values():
            for _, _, scope in items:
                kinds[scope.kind] = kinds.get(scope.kind, 0) + 1
        return dict(sorted(kinds.items()))


def _rel(path: object, root: Path) -> str | None:
    if not isinstance(path, str):
        return None
    p = Path(path)
    return _inside(root, p if p.is_absolute() else root / p)


def _leading_attributes(code: str) -> list[str]:
    """The attributes at the start of comment-free code, each with its white space removed."""
    attrs, i = [], 0
    while a := _ATTRIBUTE.match(code, i):
        end = _skip_attribute(code, a.start())
        attrs.append("".join(code[a.end() - 1 : end].split()))
        i = end
    return attrs


def _top_level_args(text: str) -> list[str]:
    args, depth, current = [], 0, ""
    for ch in text:
        if ch == "," and depth == 0:
            args.append(current)
            current = ""
            continue
        depth += ch == "("
        depth -= ch == ")"
        current += ch
    return [*args, current] if current or args else []


def _cfg_test_spelling(attr: str) -> bool:
    """`[cfg(test)]`, or `[cfg(all(...))]` with `test` as one of its own arguments."""
    if attr == "[cfg(test)]":
        return True
    if attr.startswith("[cfg(all(") and attr.endswith("))]"):
        return "test" in _top_level_args(attr[len("[cfg(all(") : -len("))]")])
    return False


def spelled_as_recognised(match_text: str) -> bool:
    """Is the item's own attribute spelled exactly as Shoalscan recognises it?

    A second check on every match, after Opengrep's: any spelling Shoalscan
    does not recognise (`cfg(r#test)`, a macro, a parser surprise) is not
    test scope.
    """
    return any(_cfg_test_spelling(a) for a in _leading_attributes(strip_code(match_text)))


def build(root: Path, results: list[dict], unparsed: frozenset[str] = frozenset()) -> ScopeMap:
    """Turn the scope rules' matches into byte ranges.

    Matches in a file Opengrep reported an error for (`unparsed`) are not
    used: a parser that recovered from an error could place an item's end
    wrongly. Each match's attribute must be spelled as recognised.
    """
    root = root.resolve()
    scopes = ScopeMap()
    sources: dict[str, bytes | None] = {}
    for r in results:
        rule = r.get("check_id")
        rel = _rel(r.get("path"), root)
        start = r.get("start") if isinstance(r.get("start"), dict) else {}
        end = r.get("end") if isinstance(r.get("end"), dict) else {}
        line, a, b = start.get("line"), start.get("offset"), end.get("offset")
        if rel is None or rel in unparsed or not isinstance(line, int) or line < 1:
            continue
        if rule == ITEM_RULE:
            kind = "cfg_test_item"
        elif rule == MODULE_RULE:
            kind = "cfg_test_module"
        else:
            continue
        if rel not in sources:
            try:
                sources[rel] = (root / rel).read_bytes()
            except OSError:
                sources[rel] = None
        data = sources[rel]
        if data is None or not isinstance(a, int) or not isinstance(b, int) or not 0 <= a < b <= len(data):
            continue
        if not spelled_as_recognised(data[a:b].decode("utf-8", errors="replace")):
            scopes.unrecognised += 1
            continue
        scopes.ranges.setdefault(rel, []).append((a, b, TestScope(kind, rel, line)))
    return scopes
