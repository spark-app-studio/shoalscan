"""Rust test scope: prove that a finding sits in code that is compiled only for tests.

Opengrep's own Rust parser does the proving. Shoalscan ships a small rule pack
(`scope/rust-test-scope.yaml`) that runs in the same scan as the security
rules; its matches give the exact line ranges of:

- `#[cfg(test)] mod NAME { ... }` blocks, and `#[cfg(test)] mod NAME;`
  declarations, whose whole file is then test-only (`cfg_test_module`,
  `cfg_test_file`);
- `#[cfg(test)]` functions, `impl` blocks, constants and statics
  (`cfg_test_item`);
- `#[test]`, `#[tokio::test]` and `#[rstest]` functions (`test_fn`).

Cargo's integration tests and benchmarks (files under a crate's `tests/` and
`benches/`) are test-only too (`test_target`).

The rule is one-sided: only Opengrep's parser, or Cargo's layout, can put code
in test scope. A plain text search over every `.rs` file can only take scope
away: a file-level scope (`test_target`, `cfg_test_file`) is dropped when any
code that is not test-only could compile that file (`mod NAME;`, `#[path]`,
`include!`, a symbolic link or a Cargo target path pointing at it). Comments
and strings can only make that search drop more, never less. Whenever
something cannot be resolved for certain, the code is not test scope.
"""

from __future__ import annotations

import bisect
import json
import os
import posixpath
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

NAMESPACE = "test-scope"
RULES_FILE = "rust-test-scope.yaml"
MODULE_RULES_FILE = "rust-test-scope-modules.yaml"
ITEM_RULE = f"{NAMESPACE}.rust-cfg-test-item"
FN_RULE = f"{NAMESPACE}.rust-test-fn"
MODULE_RULE = f"{NAMESPACE}.rust-cfg-test-module"
MODULE_PATH_RULE = f"{NAMESPACE}.rust-cfg-test-module-path"

KINDS = ("cfg_test_module", "cfg_test_item", "test_fn", "test_target", "cfg_test_file")
# Who an automatic test-scope review is recorded under. It is not an email
# address, so it can never be a person signed in to the dashboard.
AUTO_REVIEWER = "shoalscan (test scope)"
ELIGIBLE_TOOL = "opengrep"
ELIGIBLE_SUFFIX = ".rs"

MAX_MODULE_NAMES = 5_000
MAX_RS_FILES = 200_000
MAX_RS_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024

_RUST_KEYWORDS = frozenset(
    "as async await break const continue crate dyn else enum extern false fn for gen if impl in let loop match mod "
    "move mut pub ref return self Self static struct super trait true try type union unsafe use where while abstract "
    "become box do final macro override priv typeof unsized virtual yield".split()
)
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,99}$")
_MOD_NAME = re.compile(r"\bmod\s+([A-Za-z_][A-Za-z0-9_]*)(?![#\w])")
_MOD_FORM = re.compile(r"(?<![\w#])mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*([;{])")
_MOD_DECL = re.compile(r"(?<![\w#])mod\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*;")
# `path = ` inside any attribute, `#[path = ...]` and `#[cfg_attr(..., path = ...)]` alike.
_PATH_ATTR = re.compile(r"#\s*\[[^\]]*?\bpath\s*=")
_PATH_LITERAL = re.compile(r"\s*\"([^\"\\\n]*)\"")
_INCLUDE = re.compile(r"\binclude\s*!")
_INCLUDE_LITERAL = re.compile(r"\s*[(\[{]\s*\"([^\"\\\n]*)\"\s*,?\s*[)\]}]")
# Build output: a `target` directory next to a Cargo.toml.
_BUILD_DIR = "target"


@dataclass(frozen=True)
class TestScope:
    """Why a finding is in test-only code: the kind of scope and where it is proved.

    For `test_target` the path is the crate's `tests` or `benches` directory and
    the line is 0; otherwise it is the file and line of the attribute (for
    `cfg_test_file`, of the `#[cfg(test)] mod NAME;` declaration).
    """

    __test__ = False  # not a unittest class

    kind: str
    path: str
    line: int

    def as_json(self) -> dict:
        return {"kind": self.kind, "path": self.path, "line": self.line}

    def where(self) -> str:
        return f"{self.path}:{self.line}" if self.line else self.path

    def description(self) -> str:
        return f"test-only code: {self.kind} at {self.where()}"


def scope_from_json(value: object) -> TestScope | None:
    """A finding's `test_scope` from findings.json; None for a malformed one."""
    if not isinstance(value, dict) or set(value) != {"kind", "path", "line"}:
        return None
    kind, path, line = value["kind"], value["path"], value["line"]
    if kind not in KINDS or not isinstance(path, str) or not path or len(path) > 1024:
        return None
    if not isinstance(line, int) or isinstance(line, bool) or line < 0:
        return None
    return TestScope(kind, path, line)


def eligible(tool: str, rule: str, path: str, matcher) -> bool:
    """Only Opengrep findings in Rust files, for a rule the policy lists, can be test-scoped."""
    return tool == ELIGIBLE_TOOL and path.endswith(ELIGIBLE_SUFFIX) and matcher.matches(rule)


def never_test_scope(path: str) -> bool:
    """Code under `examples/`, in `build.rs` or under `src/bin/` is never test scope."""
    parts = path.split("/")
    if "examples" in parts[:-1] or parts[-1] == "build.rs":
        return True
    return any(parts[i] == "src" and parts[i + 1] == "bin" for i in range(len(parts) - 2))


# ---------------------------------------------------------------- the rule pack


def module_rules(names: list[str]) -> dict:
    """The `#[cfg(test)] mod NAME` rules, one pattern per module name.

    Opengrep binds no metavariable to a module's name (`mod $M { ... }` never
    matches), so each name is written out. A name only proposes a pattern:
    Opengrep still has to find a module of that name with exactly the
    attribute `#[cfg(test)]` in the parsed code. A `mod NAME;` declaration
    parses as an empty module, so the same pattern matches it.
    """
    common = {"severity": "INFO", "languages": ["rust"], "metadata": {"category": "test-scope"}}
    return {
        "rules": [
            {
                "id": MODULE_RULE.split(".", 1)[1],
                "message": "A module compiled only for tests (#[cfg(test)]).",
                **common,
                "pattern-either": [{"pattern": f"#[cfg(test)]\nmod {n} {{ ... }}\n"} for n in names],
            },
            {
                "id": MODULE_PATH_RULE.split(".", 1)[1],
                "message": "A test-only module with a #[path] attribute.",
                **common,
                "pattern-either": [{"pattern": f"#[cfg(test)]\n#[path = $P]\nmod {n} {{ ... }}\n"} for n in names],
            },
        ]
    }


def module_names(texts: dict[str, str]) -> list[str]:
    """Module names that could carry `#[cfg(test)]`: every `mod NAME` in a file that mentions cfg(test)."""
    names: set[str] = set()
    for text in texts.values():
        if "cfg(test)" not in "".join(text.split()):
            continue
        for match in _MOD_NAME.finditer(text):
            name = match.group(1)
            if _IDENT.match(name) and name not in _RUST_KEYWORDS:
                names.add(name)
    return sorted(names)[:MAX_MODULE_NAMES]


def stage(dest: Path, pack: Path, names: list[str]) -> None:
    """Write the scope rules into `dest` (a directory of the rule stage)."""
    dest.mkdir(parents=True, exist_ok=True)
    (dest / RULES_FILE).write_text(pack.read_text(encoding="utf-8"), encoding="utf-8")
    if names:
        # JSON is YAML, and needs no YAML writer.
        (dest / MODULE_RULES_FILE).write_text(json.dumps(module_rules(names), indent=1), encoding="utf-8")


def rule_ids(names: list[str]) -> set[str]:
    ids = {ITEM_RULE, FN_RULE}
    if names:
        ids |= {MODULE_RULE, MODULE_PATH_RULE}
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


# ---------------------------------------------------------------- the repository


@dataclass
class Tree:
    """What the scope needs to know about the repository's files."""

    rs_files: set[str] = field(default_factory=set)
    texts: dict[str, str] = field(default_factory=dict)
    manifests: dict[str, dict | None] = field(default_factory=dict)  # crate dir ("" for the root) -> Cargo.toml
    symlink_targets: list[str] = field(default_factory=list)  # repository paths links point at
    incomplete: str | None = None  # why file-level scopes cannot be trusted


def _inside(root: Path, target: Path) -> str | None:
    try:
        return target.relative_to(root).as_posix()
    except ValueError:
        return None


def read_tree(root: Path) -> Tree:
    """Every `.rs` file (with its text), every Cargo.toml, and every symbolic link under `root`.

    `.git` and `target` directories next to a Cargo.toml (build output) are
    skipped. A file that cannot be read, or too many files, makes the tree
    incomplete, and then no file-level scope is trusted.
    """
    tree = Tree()
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        rel_dir = _inside(root, here) or ""
        rel_dir = "" if rel_dir == "." else rel_dir
        keep = []
        for d in sorted(dirnames):
            full = here / d
            if d == ".git" or (d == _BUILD_DIR and "Cargo.toml" in filenames):
                continue
            if full.is_symlink():
                target = _inside(root, full.resolve())
                if target is not None:
                    tree.symlink_targets.append(target)
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in filenames:
            full = here / name
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if full.is_symlink():
                target = _inside(root, full.resolve())
                if target is not None:
                    tree.symlink_targets.append(target)
                continue
            if name == "Cargo.toml":
                tree.manifests[rel_dir] = _manifest(full)
            elif name.endswith(".rs"):
                if len(tree.rs_files) >= MAX_RS_FILES:
                    tree.incomplete = f"more than {MAX_RS_FILES} Rust files"
                    continue
                tree.rs_files.add(rel)
                try:
                    if full.stat().st_size > MAX_RS_BYTES:
                        tree.incomplete = f"{rel} is larger than {MAX_RS_BYTES} bytes"
                        continue
                    tree.texts[rel] = full.read_bytes().decode("utf-8", errors="replace")
                except OSError:
                    tree.incomplete = f"{rel} could not be read"
    return tree


def _manifest(path: Path) -> dict | None:
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            return None
        doc = tomllib.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError):
        return None
    return doc if isinstance(doc, dict) else None


def _norm(*parts: str) -> str | None:
    """A repository-relative path, or None when it leaves the repository."""
    joined = posixpath.normpath(posixpath.join(*[p for p in parts if p]))
    if joined.startswith("../") or joined == ".." or joined.startswith("/"):
        return None
    return joined


def _crate_of(path: str, manifests: dict) -> str | None:
    parts = path.split("/")[:-1]
    for n in range(len(parts), -1, -1):
        crate = "/".join(parts[:n])
        if crate in manifests:
            return crate
    return None


def _manifest_targets(crate: str, manifest: dict) -> list[str]:
    """The paths a Cargo.toml gives its library, binaries, examples and build script."""
    paths = []
    lib = manifest.get("lib")
    if isinstance(lib, dict) and isinstance(lib.get("path"), str):
        paths.append(lib["path"])
    for table in ("bin", "example"):
        items = manifest.get(table)
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict) and isinstance(item.get("path"), str):
                paths.append(item["path"])
    package = manifest.get("package")
    if isinstance(package, dict) and isinstance(package.get("build"), str):
        paths.append(package["build"])
    out = []
    for p in paths:
        resolved = _norm(crate, p)
        out.append(resolved if resolved is not None else "..")
    return out


def _under(path: str, directory: str) -> bool:
    return path == directory or path.startswith(directory + "/")


# ---------------------------------------------------------------- the scope map


@dataclass
class ScopeMap:
    """Line ranges and whole files that are test-only, per repository path."""

    ranges: dict[str, list[tuple[int, int, TestScope]]] = field(default_factory=dict)
    files: dict[str, TestScope] = field(default_factory=dict)
    module_names: int = 0
    dropped_files: int = 0
    incomplete: str | None = None

    def scope_for(self, path: str, line: int) -> TestScope | None:
        if never_test_scope(path):
            return None
        if path in self.files:
            return self.files[path]
        inside = [r for r in self.ranges.get(path, []) if r[0] <= line <= r[1]]
        if not inside:
            return None
        # The outermost range names the scope: the module rather than a test inside it.
        return min(inside, key=lambda r: (r[0], -r[1]))[2]

    def summary(self) -> dict:
        kinds: dict[str, int] = {}
        for items in self.ranges.values():
            for _, _, scope in items:
                kinds[scope.kind] = kinds.get(scope.kind, 0) + 1
        for scope in self.files.values():
            kinds[scope.kind] = kinds.get(scope.kind, 0) + 1
        return {
            "module_names": self.module_names,
            "scopes": dict(sorted(kinds.items())),
            "file_scopes_dropped": self.dropped_files,
            "file_scopes_off": self.incomplete,
        }


def _rel(path: object, root: Path) -> str | None:
    if not isinstance(path, str):
        return None
    p = Path(path)
    if not p.is_absolute():
        p = root / p
    return _inside(root, p)


def _module_form(data: bytes | None, start: object, end: object) -> tuple[str, bool] | None:
    """The module's name, and True for `mod NAME;` or False for `mod NAME { ... }`; None when unclear.

    Opengrep's match of a module ends at its last item (a declaration ends at
    its name), so the form is read from the first `mod NAME` in the match and
    the character after it.
    """
    if data is None or not isinstance(start, int) or not isinstance(end, int) or not 0 <= start < end <= len(data):
        return None
    text = data[start : min(len(data), end + 256)].decode("utf-8", errors="replace")
    m = _MOD_FORM.search(text)
    if m is None or m.start() > end - start:
        return None
    return m.group(1), m.group(2) == ";"


def _path_literal(result: dict) -> str | None:
    metavars = result.get("extra", {}).get("metavars") if isinstance(result.get("extra"), dict) else None
    value = metavars.get("$P", {}).get("abstract_content") if isinstance(metavars, dict) else None
    if not isinstance(value, str) or len(value) < 2 or not (value.startswith('"') and value.endswith('"')):
        return None
    inner = value[1:-1]
    if not inner or '"' in inner or "\\" in inner:
        return None
    return inner


def _declared_file(declaring: str, name: str, rs_files: set[str]) -> str | None:
    """The one file `mod NAME;` at the top of `declaring` can load, or None when that is not certain.

    A file named mod.rs, lib.rs or main.rs loads `NAME.rs` or `NAME/mod.rs`
    from its own directory; any other file from a directory named after it.
    Crate roots and `#[path]` files can be named anything, so both readings
    are tried, and only a single existing file across them is accepted.
    """
    directory = posixpath.dirname(declaring)
    base = posixpath.basename(declaring)
    stem = base[:-3] if base.endswith(".rs") else base
    bases = [directory] if base == "mod.rs" else [directory, _norm(directory, stem) or ""]
    found = set()
    for b in bases:
        for candidate in (_norm(b, f"{name}.rs"), _norm(b, name, "mod.rs")):
            if candidate is not None and candidate in rs_files:
                found.add(candidate)
    return found.pop() if len(found) == 1 else None


def build(
    root: Path, results: list[dict], tree: Tree, names: list[str], unparsed: frozenset[str] = frozenset()
) -> ScopeMap:
    """Turn the scope rules' matches and the repository's layout into a scope map.

    Matches in a file Opengrep reported an error for (`unparsed`) are not
    used: a parser that recovered from an error could place a module's end
    wrongly. Such a file gets no in-file scope and declares no test file.
    """
    root = root.resolve()
    scopes = ScopeMap(module_names=len(names), incomplete=tree.incomplete)
    data_cache: dict[str, bytes | None] = {}

    def data(rel: str) -> bytes | None:
        if rel not in data_cache:
            try:
                data_cache[rel] = (root / rel).read_bytes()
            except OSError:
                data_cache[rel] = None
        return data_cache[rel]

    path_attrs: dict[tuple[str, int], str | None] = {}
    for r in results:
        if r.get("check_id") == MODULE_PATH_RULE:
            rel = _rel(r.get("path"), root)
            start = r.get("start") if isinstance(r.get("start"), dict) else {}
            if rel is not None and isinstance(start.get("line"), int):
                path_attrs[(rel, start["line"])] = _path_literal(r)

    declarations: list[tuple[str, int, int, str | None]] = []
    for r in results:
        rule = r.get("check_id")
        rel = _rel(r.get("path"), root)
        start = r.get("start") if isinstance(r.get("start"), dict) else {}
        end = r.get("end") if isinstance(r.get("end"), dict) else {}
        first, last = start.get("line"), end.get("line")
        if rel is None or not isinstance(first, int) or not isinstance(last, int) or last < first:
            continue
        if rel in unparsed:
            continue
        if rule == ITEM_RULE:
            kind = "cfg_test_item"
        elif rule == FN_RULE:
            kind = "test_fn"
        elif rule == MODULE_RULE:
            kind = "cfg_test_module"
            form = _module_form(data(rel), start.get("offset"), end.get("offset"))
            if form is None:
                continue
            name, declaration = form
            if declaration and start.get("col") == 1:
                declarations.append((rel, first, last, name))
        else:
            continue
        scopes.ranges.setdefault(rel, []).append((first, last, TestScope(kind, rel, first)))

    candidates: dict[str, TestScope] = {}
    if tree.incomplete is None:
        _test_targets(tree, candidates)
        for rel, first, _last, name in declarations:
            key = (rel, first)
            if key in path_attrs:
                literal = path_attrs[key]
                target = _norm(posixpath.dirname(rel), literal) if literal is not None else None
                if target is None or target not in tree.rs_files:
                    continue
            else:
                target = _declared_file(rel, name, tree.rs_files)
            if target is not None and not never_test_scope(target):
                candidates.setdefault(target, TestScope("cfg_test_file", rel, first))
        dropped = _disproved(tree, candidates, scopes.ranges)
        scopes.dropped_files = len(dropped)
        scopes.files = {p: s for p, s in candidates.items() if p not in dropped}
    return scopes


def _test_targets(tree: Tree, candidates: dict[str, TestScope]) -> None:
    """Files under a crate's `tests/` and `benches/`, unless a Cargo target lives there."""
    if any(m is None for m in tree.manifests.values()):
        return  # a Cargo.toml that does not parse could name a target anywhere
    targets = [t for crate, m in tree.manifests.items() for t in _manifest_targets(crate, m)]
    if ".." in targets:
        return
    for path in tree.rs_files:
        crate = _crate_of(path, tree.manifests)
        if crate is None or not isinstance(tree.manifests[crate].get("package"), dict):
            continue
        rel = path[len(crate) + 1 :] if crate else path
        top = rel.split("/", 1)[0]
        if top not in ("tests", "benches") or "/" not in rel:
            continue
        directory = f"{crate}/{top}" if crate else top
        if never_test_scope(path) or any(_under(t, directory) for t in targets):
            continue
        candidates[path] = TestScope("test_target", directory, 0)


def _in_ranges(line: int, ranges: list[tuple[int, int, TestScope]]) -> bool:
    return any(a <= line <= b for a, b, _ in ranges)


def _disproved(tree: Tree, candidates: dict[str, TestScope], ranges: dict) -> set[str]:
    """The candidate files that code outside test scope could compile.

    A text search, so it can only take scope away. A file stays test-scoped
    only if no file outside test scope (and no line outside a proven test range
    of such a file) declares it with `mod NAME;`, names it in `#[path]` or
    `include!`, and no symbolic link points at it. Repeated until nothing
    changes, because a file that loses its scope may declare others.
    """
    dropped: set[str] = set()
    by_name: dict[str, list[str]] = {}
    for p in candidates:
        base = posixpath.basename(p)
        by_name.setdefault(base, []).append(p)
        if base == "mod.rs":
            by_name.setdefault(posixpath.basename(posixpath.dirname(p)) + "/mod.rs", []).append(p)
    for target in tree.symlink_targets:
        dropped |= {p for p in candidates if _under(p, target)}
    effects = {path: _effects(path, text, ranges.get(path, [])) for path, text in tree.texts.items()}
    applied: set[str] = set()
    while True:
        before = len(dropped)
        for path, (decls, literals, unknown) in effects.items():
            if path in applied or (path in candidates and path not in dropped):
                continue
            applied.add(path)
            directory = posixpath.dirname(path)
            for name in decls:
                for p in by_name.get(f"{name}.rs", []) + by_name.get(f"{name}/mod.rs", []):
                    if not directory or _under(p, directory):
                        dropped.add(p)
            for literal in literals:
                dropped |= set(by_name.get(posixpath.basename(literal), []))
            if unknown:
                # Something is loaded from a path Shoalscan cannot read: nothing in this crate is certain.
                crate = _crate_of(path, tree.manifests)
                dropped |= {p for p in candidates if not crate or _crate_of(p, tree.manifests) == crate}
        if len(dropped) == before:
            return dropped


def _effects(path: str, text: str, ranges: list) -> tuple[set[str], set[str], bool]:
    """What a file could load: declared module names, `#[path]`/`include!` literals, and whether any is unknown."""
    decls: set[str] = set()
    literals: set[str] = set()
    unknown = False
    starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line_of(offset: int) -> int:
        return bisect.bisect_right(starts, offset)

    if "mod" in text:
        for m in _MOD_DECL.finditer(text):
            if not _in_ranges(line_of(m.start()), ranges):
                decls.add(m.group(1))
    for pattern, literal in ((_PATH_ATTR, _PATH_LITERAL), (_INCLUDE, _INCLUDE_LITERAL)):
        for m in pattern.finditer(text):
            if _in_ranges(line_of(m.start()), ranges):
                continue
            exact = literal.match(text, m.end())
            if exact:
                literals.add(exact.group(1))
            else:
                unknown = True
    return decls, literals, unknown
