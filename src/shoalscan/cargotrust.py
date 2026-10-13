"""Can anything in this repository make `cfg(test)` true in a build that is not a test?

Test scope rests on one fact: code inside a `#[cfg(test)]` item is compiled
only when rustc runs with `--test` (or `--cfg test`). A build script, a
compiler wrapper, extra compiler flags, or a patched or replaced dependency
can change that. Rather than look for what such things might do, Shoalscan
trusts only what it can read and recognise:

- **Build scripts** (any `build.rs`, and any `build = "..."` in a Cargo.toml)
  are trusted only when the policy names each one with its SHA-256 under
  `[test_scope] trusted_build_scripts`. Any other build script turns test
  scope off.
- **Cargo.toml and `.cargo/config(.toml)`** are read with tomllib, and every
  key must be on an allowlist. A file that does not parse, an unknown key,
  `[replace]`, `[source]`, `paths`, `cargo-features`, a `[patch]` that is not a
  path inside the repository, a compiler or
  wrapper setting, or a `rustflags` entry other than `-C`, `-L`, `-l` and the
  lint levels turns test scope off.

The answer is a reason when test scope must be off, or None.
"""

from __future__ import annotations

import hashlib
import posixpath
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
_CONFIG_BUILD_KEYS = frozenset({"target", "target-dir", "jobs", "incremental", "rustflags"})
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


def config_problem(doc: dict, rel: str) -> str | None:
    """Why this .cargo/config(.toml) could change cfg(test) or the code that is built, or None."""
    if problem := _unknown(doc, frozenset({"build", "unstable", "target"}), rel):
        return problem
    build = doc.get("build", {})
    if problem := _unknown(build, _CONFIG_BUILD_KEYS, f"{rel} [build]"):
        return problem
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


def _build_script(manifest: dict, crate_dir: str) -> str | None:
    """The path a Cargo.toml's `package.build` names, or None (none, `true` or `false`)."""
    for key in ("package", "project"):
        package = manifest.get(key)
        if isinstance(package, dict) and isinstance(package.get("build"), str):
            return posixpath.normpath(posixpath.join(crate_dir, package["build"]))
    return None


def sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


class CargoCheck:
    """Collects the Cargo files of a repository walk and decides whether test scope can stay on."""

    def __init__(self, root: Path, trusted_build_scripts: dict[str, str]):
        self.root = root
        self.trusted = dict(trusted_build_scripts)
        self.build_scripts: set[str] = set()
        self.problem: str | None = None

    def _fail(self, reason: str) -> None:
        self.problem = self.problem or reason

    def add_manifest(self, path: Path, rel: str) -> None:
        doc, error = _load(path, rel)
        if error:
            self._fail(error)
            return
        if problem := manifest_problem(doc, rel):
            self._fail(problem)
            return
        crate_dir = rel.rsplit("/", 1)[0] if "/" in rel else ""
        script = _build_script(doc, crate_dir)
        if script is not None:
            self.build_scripts.add(script)

    def add_config(self, path: Path, rel: str) -> None:
        doc, error = _load(path, rel)
        if error:
            self._fail(error)
            return
        if problem := config_problem(doc, rel):
            self._fail(problem)

    def add_build_rs(self, rel: str) -> None:
        self.build_scripts.add(rel)

    def result(self) -> str | None:
        """Why test scope is off for the repository, or None."""
        if self.problem:
            return self.problem
        for script in sorted(self.build_scripts):
            expected = self.trusted.get(script)
            if expected is None:
                return f"{script} is a build script that [test_scope] trusted_build_scripts does not list"
            actual = sha256_file(self.root / script) if not (self.root / script).is_symlink() else None
            if actual != expected:
                return f"{script} does not match the SHA-256 that [test_scope] trusted_build_scripts gives it"
        return None
