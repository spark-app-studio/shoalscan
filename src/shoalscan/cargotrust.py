"""Can anything in this repository make `cfg(test)` true in a build that is not a test?

Test scope rests on one fact: code inside a `#[cfg(test)]` item is compiled
only when rustc runs with `--test` (or `--cfg test`). A build script, a
compiler wrapper, extra compiler flags, a toolchain override, or a patched or
replaced dependency can change that. Rather than look for what such things
might do, Shoalscan trusts only what it can read and recognise:

- **Build scripts:** any `build.rs` (in any letter case) or `build = ...` in
  a Cargo.toml turns test scope off. A build script can read, include or run
  anything, so no hash of one file can vouch for it.
- **Cargo.toml and `.cargo/config(.toml)`** are read with tomllib, and every
  key must be on an allowlist. A file that does not parse, an unknown key,
  `[replace]`, `[source]`, `paths`, `cargo-features`, a `[patch]` that is not a
  path inside the repository, a compiler or wrapper setting (except a wrapper
  the policy allows), or a `rustflags` entry other than `-C`, `-L`, `-l` and
  the lint levels turns test scope off.
- **`rust-toolchain(.toml)`** may name a channel, components, targets and a
  profile, nothing else.
- **Every other text file** (scripts, Dockerfiles, Makefiles, CI workflows) is
  searched for compiler settings, except prose (`.md`, `.rst`, `.adoc`) and
  whole-line `#` comments in files whose comments are `#` and that have no
  heredoc. Flags built from a command or a variable turn it off, so a skipped
  file cannot be read into them. The search looks for `--cfg` followed by anything but a plain
  name other than `test`, `RUSTC_WRAPPER` (unless set to an allowed wrapper,
  alone on its line), `RUSTC_WORKSPACE_WRAPPER`, `CARGO_ENCODED_RUSTFLAGS`,
  `RUSTC=`, `cargo rustc`, a compiler set through `--config`, and `--test` in
  rustflags.
- **Special names in any letter case** that are not spelled exactly
  (`BUILD.RS`, `.Cargo/Config.Toml`, `cargo.toml`) turn it off: a
  case-insensitive file system would use them.

The answer is a reason when test scope must be off, or None.
"""

from __future__ import annotations

import posixpath
import re
import tomllib
from pathlib import Path

MAX_TOML_BYTES = 1024 * 1024

# Cargo.toml: the top-level tables and keys Shoalscan understands. Others (patch, replace,
# cargo-features, and anything new) turn test scope off.
_MANIFEST_TOP = frozenset(
    {
        "package",
        "project",
        "lib",
        "bin",
        "example",
        "test",
        "bench",
        "dependencies",
        "dev-dependencies",
        "dev_dependencies",
        "build-dependencies",
        "build_dependencies",
        "target",
        "features",
        "workspace",
        "profile",
        "badges",
        "lints",
    }
)
_PACKAGE_KEYS = frozenset(
    {
        "name",
        "version",
        "authors",
        "edition",
        "rust-version",
        "description",
        "documentation",
        "readme",
        "homepage",
        "repository",
        "license",
        "license-file",
        "keywords",
        "categories",
        "workspace",
        "build",
        "links",
        "exclude",
        "include",
        "publish",
        "metadata",
        "default-run",
        "autobins",
        "autoexamples",
        "autotests",
        "autobenches",
        "autolib",
        "resolver",
    }
)
_TARGET_KEYS = frozenset(
    {
        "name",
        "path",
        "test",
        "doctest",
        "bench",
        "doc",
        "proc-macro",
        "proc_macro",
        "harness",
        "edition",
        "crate-type",
        "crate_type",
        "required-features",
    }
)
_DEPENDENCY_TABLES = frozenset(
    {"dependencies", "dev-dependencies", "dev_dependencies", "build-dependencies", "build_dependencies"}
)
_WORKSPACE_KEYS = frozenset(
    {"members", "exclude", "default-members", "resolver", "package", "dependencies", "lints", "metadata"}
)
# Profile settings that cannot set a cfg. `rustflags` (an unstable feature) is not among them.
_PROFILE_KEYS = frozenset(
    {
        "opt-level",
        "debug",
        "split-debuginfo",
        "strip",
        "debug-assertions",
        "overflow-checks",
        "lto",
        "panic",
        "incremental",
        "codegen-units",
        "rpath",
    }
)

# .cargo/config(.toml): what Shoalscan understands. A compiler or wrapper (build.rustc,
# build.rustc-wrapper, build.rustc-workspace-wrapper), [patch], [source], paths, [env], include
# and anything else turn test scope off.
_CONFIG_BUILD_KEYS = frozenset({"target", "target-dir", "jobs", "incremental", "rustflags", "rustc-wrapper"})
_CONFIG_UNSTABLE_KEYS = frozenset({"build-std", "build-std-features"})
_CONFIG_TARGET_KEYS = frozenset({"rustflags", "linker", "runner"})
# Compiler flags that cannot set a cfg: codegen options, search paths, libraries and lint levels.
_FLAG_WITH_VALUE = frozenset({"-C", "-L", "-l", "-A", "-W", "-D", "-F"})


def _load(path: Path, rel: str) -> tuple[dict | None, str | None]:
    try:
        if path.is_symlink():
            return None, f"{rel} is a symbolic link"
        if path.stat().st_size > MAX_TOML_BYTES:
            return None, f"{rel} is larger than {MAX_TOML_BYTES} bytes"
        return tomllib.loads(path.read_bytes().decode("utf-8")), None
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError):
        return None, f"{rel} could not be read as TOML"


def rustflags_problem(value: object) -> str | None:
    """Why these rustflags could change cfg(test), or None when every flag is a safe form."""
    if isinstance(value, str):
        flags = value.split()
    elif isinstance(value, list) and all(isinstance(v, str) for v in value):
        flags = list(value)
    else:
        return "rustflags is neither a string nor a list of strings"
    i = 0
    while i < len(flags):
        flag = flags[i]
        if flag in _FLAG_WITH_VALUE:
            if i + 1 >= len(flags):
                return f"rustflags ends with {flag} and no value"
            i += 2
            continue
        if len(flag) > 2 and flag[:2] in _FLAG_WITH_VALUE and flag[2] != " ":
            i += 1
            continue
        return f"rustflags has {flag!r}; only -C, -L, -l and -A/-W/-D/-F are accepted"
    return None


def _unknown(table: object, allowed: frozenset[str], where: str) -> str | None:
    if not isinstance(table, dict):
        return f"{where} is not a table"
    extra = sorted(set(table) - allowed)
    return f"{where} has {', '.join(extra)}, which Shoalscan does not accept with test scope" if extra else None


def _patch_problem(patch: object, rel: str) -> str | None:
    """A [patch] is accepted only when every entry is a path inside the repository.

    Such a crate is part of the repository, so its Cargo.toml and build script
    are held to the same rules as every other. A patch from git or a registry,
    or a path outside the repository, is not.
    """
    if not isinstance(patch, dict):
        return f"{rel} [patch] is not a table"
    crate_dir = posixpath.dirname(rel)
    for source, entries in patch.items():
        if not isinstance(entries, dict):
            return f"{rel} [patch.{source}] is not a table"
        for name, spec in entries.items():
            path = spec.get("path") if isinstance(spec, dict) else None
            if not isinstance(path, str) or set(spec) - {"path", "version", "package"}:
                return f"{rel} [patch.{source}] {name} is not a path inside the repository"
            resolved = posixpath.normpath(posixpath.join(crate_dir, path))
            if posixpath.isabs(path) or resolved == ".." or resolved.startswith("../"):
                return f"{rel} [patch.{source}] {name} points outside the repository"
    return None


def manifest_problem(doc: dict, rel: str) -> str | None:
    """Why this Cargo.toml could change cfg(test) or the code that is built, or None."""
    for key in ("replace", "cargo-features"):
        if key in doc:
            return f"{rel} has [{key}]"
    if "patch" in doc and (problem := _patch_problem(doc["patch"], rel)):
        return problem
    problem = _unknown(doc, _MANIFEST_TOP | {"patch"}, rel)
    if problem:
        return problem
    for key in ("package", "project"):
        if key in doc and (problem := _unknown(doc[key], _PACKAGE_KEYS, f"{rel} [{key}]")):
            return problem
    for key in ("lib",):
        if key in doc and (problem := _unknown(doc[key], _TARGET_KEYS, f"{rel} [{key}]")):
            return problem
    for key in ("bin", "example", "test", "bench"):
        items = doc.get(key, [])
        if not isinstance(items, list):
            return f"{rel} [[{key}]] is not a list of tables"
        for item in items:
            if problem := _unknown(item, _TARGET_KEYS, f"{rel} [[{key}]]"):
                return problem
    target = doc.get("target", {})
    if not isinstance(target, dict):
        return f"{rel} [target] is not a table"
    for name, table in target.items():
        if problem := _unknown(table, _DEPENDENCY_TABLES, f"{rel} [target.{name}]"):
            return problem
    if "workspace" in doc and (problem := _unknown(doc["workspace"], _WORKSPACE_KEYS, f"{rel} [workspace]")):
        return problem
    profiles = doc.get("profile", {})
    if not isinstance(profiles, dict):
        return f"{rel} [profile] is not a table"
    for name, profile in profiles.items():
        where = f"{rel} [profile.{name}]"
        if problem := _unknown(profile, _PROFILE_KEYS | {"inherits", "package", "build-override"}, where):
            return problem
        for sub in ("build-override",):
            if sub in profile and (problem := _unknown(profile[sub], _PROFILE_KEYS, f"{where}.{sub}")):
                return problem
        packages = profile.get("package", {})
        if not isinstance(packages, dict):
            return f"{where}.package is not a table"
        for pkg, settings in packages.items():
            if problem := _unknown(settings, _PROFILE_KEYS, f"{where}.package.{pkg}"):
                return problem
    return None


def config_problem(doc: dict, rel: str, allowed_wrappers: tuple[str, ...] = ()) -> str | None:
    """Why this .cargo/config(.toml) could change cfg(test) or the code that is built, or None."""
    if problem := _unknown(doc, frozenset({"build", "unstable", "target"}), rel):
        return problem
    build = doc.get("build", {})
    if problem := _unknown(build, _CONFIG_BUILD_KEYS, f"{rel} [build]"):
        return problem
    if "rustc-wrapper" in build and build["rustc-wrapper"] not in allowed_wrappers:
        return f"{rel} [build] rustc-wrapper is not one of [test_scope] allowed_rustc_wrappers"
    if "rustflags" in build and (problem := rustflags_problem(build["rustflags"])):
        return f"{rel} [build] {problem}"
    if problem := _unknown(doc.get("unstable", {}), _CONFIG_UNSTABLE_KEYS, f"{rel} [unstable]"):
        return problem
    target = doc.get("target", {})
    if not isinstance(target, dict):
        return f"{rel} [target] is not a table"
    for name, table in target.items():
        where = f"{rel} [target.{name}]"
        if problem := _unknown(table, _CONFIG_TARGET_KEYS, where):
            return problem
        if "rustflags" in table and (problem := rustflags_problem(table["rustflags"])):
            return f"{where} {problem}"
    return None


def _has_build_script(manifest: dict) -> bool:
    """Does a Cargo.toml set `build` (to anything but false)?"""
    for key in ("package", "project"):
        package = manifest.get(key)
        if isinstance(package, dict) and "build" in package and package["build"] is not False:
            return True
    return False


_TOOLCHAIN_KEYS = frozenset({"channel", "components", "targets", "profile"})
_CHANNEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def toolchain_problem(text: str, rel: str) -> str | None:
    """A rust-toolchain(.toml) may name a channel, components, targets and a profile; nothing else, not a `path`."""
    stripped = text.strip()
    if "\n" not in stripped and _CHANNEL.match(stripped):
        return None  # the legacy one-line form: a channel name
    try:
        doc = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError):
        return f"{rel} could not be read as TOML"
    if set(doc) != {"toolchain"} or not isinstance(doc["toolchain"], dict):
        return f"{rel} has something other than a [toolchain] table"
    toolchain = doc["toolchain"]
    if problem := _unknown(toolchain, _TOOLCHAIN_KEYS, f"{rel} [toolchain]"):
        return problem
    if "channel" in toolchain and not (isinstance(toolchain["channel"], str) and _CHANNEL.match(toolchain["channel"])):
        return f"{rel} has a channel Shoalscan does not recognise"
    for key in ("components", "targets"):
        value = toolchain.get(key, [])
        if not isinstance(value, list) or not all(isinstance(v, str) and _CHANNEL.match(v) for v in value):
            return f"{rel} [toolchain] {key} is not a list of names"
    if "profile" in toolchain and not (isinstance(toolchain["profile"], str) and _CHANNEL.match(toolchain["profile"])):
        return f"{rel} [toolchain] profile is not a name"
    return None


# Compiler settings in any other text file. `--cfg` must be followed by white space and a plain name that is
# not `test`, then a delimiter.
_CFG_FLAG = re.compile(r"--cfg")
_CFG_ALLOWED = re.compile(r"--cfg[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?=$|[\s\"'`,\])};])")
_SETTINGS = (
    (re.compile(r"RUSTC_WORKSPACE_WRAPPER"), "sets RUSTC_WORKSPACE_WRAPPER"),
    (re.compile(r"CARGO_ENCODED_RUSTFLAGS"), "sets CARGO_ENCODED_RUSTFLAGS"),
    (re.compile(r"RUSTC\s*="), "sets RUSTC"),
    (re.compile(r"\bcargo\s+(?:\+\S+\s+)?rustc\b"), "runs cargo rustc"),
    (re.compile(r"rustc-(?:workspace-)?wrapper|build\.rustc\b", re.IGNORECASE), "sets a compiler or wrapper for Cargo"),
)
_WRAPPER = re.compile(r"RUSTC_WRAPPER")
_RUSTFLAGS_TEST = re.compile(r"rustflags", re.IGNORECASE)
_TEST_FLAG = re.compile(r"--test(?![\w-])")


# Prose: documentation, never run by a build. A flag variable built from a command or a variable (below) is
# what could read one, and that turns test scope off.
PROSE_SUFFIXES = (".md", ".rst", ".adoc")
# Files whose line comments are `#`, known from the name or the extension.
_HASH_COMMENT_SUFFIXES = (".sh", ".bash", ".zsh", ".yml", ".yaml", ".mk", ".toml", ".py", ".ini", ".cfg")
# RUSTFLAGS and friends given a value that is built at run time: from a command, a variable or a CI expression.
_DYNAMIC_FLAGS = re.compile(
    r"\b(?:CARGO_BUILD_RUSTFLAGS|CARGO_TARGET_[A-Za-z0-9_]+_RUSTFLAGS|RUSTFLAGS|RUSTDOCFLAGS)\s*\+?[=:]\s*"
    r"(?P<value>.*)$"
)
_DYNAMIC_VALUE = re.compile(r"\$\(|`|\$\{|\$[A-Za-z_]")


def hash_comments(name: str) -> bool:
    """Is `#` a line comment in this file, by its name or extension?"""
    lower = name.lower()
    return (
        lower.endswith(_HASH_COMMENT_SUFFIXES)
        or lower.startswith("dockerfile")
        or lower.endswith(".dockerfile")
        or lower in ("makefile", "gnumakefile", ".envrc")
    )


def text_problem(text: str, rel: str, allowed_wrappers: tuple[str, ...]) -> str | None:
    """A line of a non-Rust text file that could compile shipped code with cfg(test), as `path:line: why`.

    Whole-line `#` comments are skipped in files whose comments are `#` (not a
    `#!` line), unless the file has a heredoc (`<<`): a heredoc's body becomes
    another file's content, where `#` may not start a comment.
    """
    allowed = _allowed_wrapper_line(allowed_wrappers)
    skip_comments = hash_comments(rel.rsplit("/", 1)[-1]) and "<<" not in text
    for number, line in enumerate(text.split("\n"), 1):
        stripped = line.lstrip()
        if skip_comments and stripped.startswith("#") and not stripped.startswith("#!"):
            continue
        why = None
        dynamic = _DYNAMIC_FLAGS.search(line)
        if dynamic and _DYNAMIC_VALUE.search(dynamic.group("value")):
            why = "sets compiler flags from a command, a variable or an expression"
        for m in _CFG_FLAG.finditer(line) if why is None else ():
            ok = _CFG_ALLOWED.match(line, m.start())
            if ok is None or ok.group("name") == "test":
                why = "passes --cfg with something other than a plain name, or test"
                break
        if why is None:
            for pattern, what in _SETTINGS:
                if pattern.search(line):
                    why = what
                    break
        if why is None and _WRAPPER.search(line) and not (allowed and allowed.match(line)):
            why = "sets RUSTC_WRAPPER to something other than a wrapper [test_scope] allowed_rustc_wrappers names"
        if why is None and _RUSTFLAGS_TEST.search(line) and _TEST_FLAG.search(line):
            why = "passes --test in rustflags"
        if why:
            return f"{rel}:{number} {why}"
    return None


def _allowed_wrapper_line(allowed_wrappers: tuple[str, ...]) -> re.Pattern | None:
    """A line that sets RUSTC_WRAPPER to one allowed wrapper and nothing else."""
    if not allowed_wrappers:
        return None
    names = "|".join(re.escape(w) for w in allowed_wrappers)
    return re.compile(
        rf"^\s*(?:export\s+|ENV\s+|-\s+)?(?:CARGO_BUILD_)?RUSTC_WRAPPER\s*(?:=|:|\s)\s*([\"']?)(?:{names})\1\s*$"
    )


MAX_TEXT_BYTES = 2 * 1024 * 1024
_BUILD_RS = "build.rs"


class CargoCheck:
    """Collects a repository walk's build-related files and decides whether test scope can stay on."""

    def __init__(self, root: Path, allowed_wrappers: tuple[str, ...] = ()):
        self.root = root
        self.allowed_wrappers = tuple(allowed_wrappers)
        self.problem: str | None = None
        self.unchecked: list[str] = []  # files the text search skipped: binary or too large

    def fail(self, reason: str) -> None:
        self.problem = self.problem or reason

    def add_manifest(self, path: Path, rel: str) -> None:
        doc, error = _load(path, rel)
        if error:
            self.fail(error)
            return
        if problem := manifest_problem(doc, rel):
            self.fail(problem)
        elif _has_build_script(doc):
            self.fail(f"{rel} sets a build script (build = ...); test scope is off wherever a build script runs")

    def add_config(self, path: Path, rel: str) -> None:
        doc, error = _load(path, rel)
        if error:
            self.fail(error)
            return
        if problem := config_problem(doc, rel, self.allowed_wrappers):
            self.fail(problem)

    def add_toolchain(self, path: Path, rel: str) -> None:
        text = self._read(path, rel, MAX_TOML_BYTES)
        if text is not None and (problem := toolchain_problem(text, rel)):
            self.fail(problem)

    def add_text(self, path: Path, rel: str) -> None:
        """Search a non-Rust file for compiler settings; a binary or too large file is logged as unchecked."""
        try:
            if path.stat().st_size > MAX_TEXT_BYTES:
                self.unchecked.append(rel)
                return
            data = path.read_bytes()
        except OSError:
            self.fail(f"{rel} could not be read")
            return
        if b"\0" in data[:8192]:
            self.unchecked.append(rel)
            return
        if rel.lower().endswith(PROSE_SUFFIXES):
            self.unchecked.append(rel)
            return
        if problem := text_problem(data.decode("utf-8", errors="replace"), rel, self.allowed_wrappers):
            self.fail(problem)

    def _read(self, path: Path, rel: str, limit: int) -> str | None:
        try:
            if path.is_symlink() or path.stat().st_size > limit:
                self.fail(f"{rel} is a symbolic link or too large")
                return None
            return path.read_bytes().decode("utf-8", errors="replace")
        except OSError:
            self.fail(f"{rel} could not be read")
            return None

    def result(self) -> str | None:
        """Why test scope is off for the repository, or None."""
        return self.problem
