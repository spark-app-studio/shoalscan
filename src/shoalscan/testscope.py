"""Rust test scope: prove that a finding sits in an item that is compiled only for tests.

Opengrep's own Rust parser does the proving. Shoalscan ships a small rule pack
(`scope/rust-test-scope.yaml`) that runs in the same scan as the security
rules; its matches give the exact line ranges of:

- `#[cfg(test)]` and `#[cfg(all(test, ...))]` modules (`cfg_test_module`);
- such functions, `impl` blocks, constants and statics (`cfg_test_item`);
- functions with the built-in `#[test]` attribute (`test_fn`).

Only items count, never whole files: code inside a `#[cfg(test)]` item is
removed from every build without `cfg(test)`, wherever its file is included.

Shoalscan trusts only what it can prove, and turns the feature off otherwise:

- the repository's Cargo files and build scripts must not be able to set
  `cfg(test)` (see `shoalscan.cargotrust`);
- `#[test]` is a name a file can rebind (`use test_log::test;`), so a file that
  binds `test` gets no `test_fn` scope, and no file does when any `extern crate`
  exists; `cfg(test)` cannot be rebound;
- every match is checked to be spelled exactly as recognised;
- a file Opengrep reported an error for gets no scope at all.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from shoalscan.cargotrust import CargoCheck

NAMESPACE = "test-scope"
RULES_FILE = "rust-test-scope.yaml"
MODULE_RULES_FILE = "rust-test-scope-modules.yaml"
ITEM_RULE = f"{NAMESPACE}.rust-cfg-test-item"
TEST_FN_RULE = f"{NAMESPACE}.rust-test-fn"
MODULE_RULE = f"{NAMESPACE}.rust-cfg-test-module"

KINDS = ("cfg_test_module", "cfg_test_item", "test_fn")
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


# Binding `test` in a file can shadow the built-in `#[test]` attribute.
_SHADOW_ITEM = re.compile(
    r"\b(?:as|fn|mod|struct|enum|const|static|type|trait|union|macro_rules\s*!|macro)\s*(?:r#)?test\b"
)
_USE = re.compile(r"\buse\s+([^;]*);")
_USE_LEAF = re.compile(r"(?:^|::|\{|,)\s*(?:r#)?test\s*(?=$|,|\})")
_EXTERN_CRATE = re.compile(r"\bextern\s+crate\b")


def shadows_test_attributes(code: str) -> bool:
    """Could `#[test]` mean something other than the built-in attribute in this (comment-free) file?

    True when the file binds `test` itself: `... as test`, an item or macro
    named `test`, or a `use` that imports a `test` (any crate's, `tokio::test`
    included). A glob import that brings in a `test` attribute is rejected by
    rustc as ambiguous with the built-in one (E0659).
    """
    if _SHADOW_ITEM.search(code):
        return True
    return any(_USE_LEAF.search(u.group(1)) for u in _USE.finditer(code))


# ---------------------------------------------------------------- the repository


@dataclass
class Repository:
    """What the scope needs from the repository's files, read once."""

    module_names: list[str] = field(default_factory=list)
    names_dropped: int = 0
    shadowed: set[str] = field(default_factory=set)  # files where #[test] may be shadowed
    shadowed_everywhere: str | None = None  # why no file can have test_fn scope
    off: str | None = None  # why test scope is off for the whole repository
    build_scripts: list[str] = field(default_factory=list)


def _inside(root: Path, target: Path) -> str | None:
    try:
        return target.relative_to(root).as_posix()
    except ValueError:
        return None


def read_repository(root: Path, trusted_build_scripts: dict[str, str] | None = None) -> Repository:
    """Read every Rust file, Cargo.toml and Cargo configuration under `root` (only `.git` is skipped)."""
    repo = Repository()
    root = root.resolve()
    cargo = CargoCheck(root, trusted_build_scripts or {})
    names: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        keep = []
        for d in sorted(dirnames):
            if d == ".git":
                continue
            full = here / d
            if full.is_symlink():
                # A linked directory may hold Cargo files or code Shoalscan does not walk.
                repo.off = repo.off or f"{_inside(root, full)} is a symbolic link to a directory"
                continue
            keep.append(d)
        dirnames[:] = keep
        in_cargo_dir = here.name == ".cargo"
        for name in filenames:
            full = here / name
            rel = _inside(root, full) or name
            if name == "Cargo.toml":
                cargo.add_manifest(full, rel)
                continue
            if in_cargo_dir and name in ("config", "config.toml"):
                cargo.add_config(full, rel)
                continue
            if not name.endswith(".rs"):
                continue
            if name == "build.rs":
                cargo.add_build_rs(rel)
            if full.is_symlink():
                repo.off = repo.off or f"{rel} is a symbolic link"
                continue
            try:
                if full.stat().st_size > MAX_FILE_BYTES:
                    repo.off = repo.off or f"{rel} is larger than {MAX_FILE_BYTES} bytes"
                    continue
                text = full.read_bytes().decode("utf-8", errors="replace")
            except OSError:
                repo.off = repo.off or f"{rel} could not be read"
                continue
            code = strip_code(text)
            names |= cfg_test_module_names(code)
            if shadows_test_attributes(code):
                repo.shadowed.add(rel)
            if _EXTERN_CRATE.search(code):
                repo.shadowed_everywhere = repo.shadowed_everywhere or f"{rel} has an extern crate"
    repo.off = repo.off or cargo.result()
    repo.build_scripts = sorted(cargo.build_scripts)
    ordered = sorted(names)
    repo.module_names = ordered[:MAX_MODULE_NAMES]
    repo.names_dropped = max(0, len(ordered) - MAX_MODULE_NAMES)
    return repo


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
    ids = {ITEM_RULE, TEST_FN_RULE}
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
    """Line ranges that are test-only, per repository path."""

    ranges: dict[str, list[tuple[int, int, TestScope]]] = field(default_factory=dict)
    test_fn_dropped: int = 0
    unrecognised: int = 0

    def scope_for(self, path: str, line: int) -> TestScope | None:
        if never_test_scope(path):
            return None
        inside = [r for r in self.ranges.get(path, []) if r[0] <= line <= r[1]]
        if not inside:
            return None
        # The outermost range names the scope: the module rather than a test inside it.
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


def spelled_as_recognised(match_text: str, kind: str) -> bool:
    """Is the item's own attribute spelled exactly as Shoalscan recognises it?

    A second check on every match, after Opengrep's: any spelling Shoalscan
    does not recognise (`cfg(r#test)`, a macro, a parser surprise) is not
    test scope.
    """
    attrs = _leading_attributes(strip_code(match_text))
    if kind == "test_fn":
        return "[test]" in attrs
    return any(_cfg_test_spelling(a) for a in attrs)


def build(root: Path, results: list[dict], repo: Repository, unparsed: frozenset[str] = frozenset()) -> ScopeMap:
    """Turn the scope rules' matches into a scope map.

    Matches in a file Opengrep reported an error for (`unparsed`) are not
    used: a parser that recovered from an error could place an item's end
    wrongly. Each match's attribute must be spelled as recognised. `test_fn`
    matches are not used in a file that may shadow `#[test]`, nor anywhere
    when the repository may (see `Repository`).
    """
    root = root.resolve()
    scopes = ScopeMap()
    sources: dict[str, bytes | None] = {}
    for r in results:
        rule = r.get("check_id")
        rel = _rel(r.get("path"), root)
        start = r.get("start") if isinstance(r.get("start"), dict) else {}
        end = r.get("end") if isinstance(r.get("end"), dict) else {}
        first, last = start.get("line"), end.get("line")
        if rel is None or rel in unparsed or not isinstance(first, int) or not isinstance(last, int):
            continue
        if first < 1 or last < first:
            continue
        if rule == ITEM_RULE:
            kind = "cfg_test_item"
        elif rule == MODULE_RULE:
            kind = "cfg_test_module"
        elif rule == TEST_FN_RULE:
            if repo.shadowed_everywhere or rel in repo.shadowed:
                scopes.test_fn_dropped += 1
                continue
            kind = "test_fn"
        else:
            continue
        if rel not in sources:
            try:
                sources[rel] = (root / rel).read_bytes()
            except OSError:
                sources[rel] = None
        data, a, b = sources[rel], start.get("offset"), end.get("offset")
        if data is None or not isinstance(a, int) or not isinstance(b, int) or not 0 <= a < b <= len(data):
            continue
        if not spelled_as_recognised(data[a:b].decode("utf-8", errors="replace"), kind):
            scopes.unrecognised += 1
            continue
        scopes.ranges.setdefault(rel, []).append((first, last, TestScope(kind, rel, first)))
    return scopes
