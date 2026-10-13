"""Could this tree compile `#[cfg(test)]` code into a build that is not a test?

Test code labels are triage help, and these checks only add a note when a
label may be unreliable. They never decide whether a finding blocks. They read
the whole tree and recognise only what they can parse:

- **Build scripts:** any `build.rs` or `build = ...` in a Cargo.toml. A build
  script can read, include or run anything.
- **Procedural macros:** a crate with `proc-macro = true` in its `[lib]`. A
  macro can emit code whatever its input's attributes say.
- **Cargo.toml and `.cargo/config(.toml)`**, read with tomllib, with every key
  on an allowlist: a file that does not parse, an unknown key, `[replace]`,
  `[source]`, `paths`, `cargo-features`, a `[patch]` that is not a path inside
  the repository, a compiler, a linker, a wrapper, or a `rustflags` entry other
  than `-C` (not a linker or link argument), `-L`, `-l` and the lint levels.
- **`rust-toolchain(.toml)`** naming anything but a channel, components,
  targets and a profile.

Scripts, CI workflows and the build environment are not read: they can change
the build too, which is why a label is never a proof.

The answer is a reason the labels may be unreliable, or None.
"""

from __future__ import annotations

import posixpath
import re
import tomllib
from pathlib import Path

MAX_TOML_BYTES = 1024 * 1024

# Cargo.toml: the top-level tables and keys Shoalscan understands. Others (patch, replace,
# cargo-features, and anything new) make the labels unreliable.
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
# and anything else make the labels unreliable.
_CONFIG_BUILD_KEYS = frozenset({"target", "target-dir", "jobs", "incremental", "rustflags"})
_CONFIG_UNSTABLE_KEYS = frozenset({"build-std", "build-std-features"})
# No `linker`: a linker is a program the build runs, as a compiler is.
_CONFIG_TARGET_KEYS = frozenset({"rustflags", "runner"})
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
            value, step = flags[i + 1], 2
        elif len(flag) > 2 and flag[:2] in _FLAG_WITH_VALUE:
            value, step = flag[2:], 1
        else:
            value = None
        if value is not None:
            setting = value.strip().lower()
            if flag.startswith("-C") and setting.startswith(("linker", "link-arg")):
                return f"rustflags chooses a linker or passes it arguments ({flag} {value})"
            i += step
            continue
        return f"rustflags has {flag!r}; only -C, -L, -l and -A/-W/-D/-F are accepted"
    return None


def _unknown(table: object, allowed: frozenset[str], where: str) -> str | None:
    if not isinstance(table, dict):
        return f"{where} is not a table"
    extra = sorted(set(table) - allowed)
    return f"{where} has {', '.join(extra)}, which Shoalscan does not recognise" if extra else None


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


class CargoCheck:
    """Collects a tree walk's Cargo files and says why the test code labels may be unreliable."""

    def __init__(self, root: Path):
        self.root = root
        self.problem: str | None = None

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
            self.fail(f"{rel} sets a build script (build = ...), which can change how test code is compiled")
        elif isinstance(doc.get("lib"), dict) and (doc["lib"].get("proc-macro") or doc["lib"].get("proc_macro")):
            self.fail(f"{rel} is a procedural macro crate, whose macros can emit test code into any build")

    def add_config(self, path: Path, rel: str) -> None:
        doc, error = _load(path, rel)
        if error:
            self.fail(error)
            return
        if problem := config_problem(doc, rel):
            self.fail(problem)

    def add_toolchain(self, path: Path, rel: str) -> None:
        text = self._read(path, rel, MAX_TOML_BYTES)
        if text is not None and (problem := toolchain_problem(text, rel)):
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
        """Why the test code labels may be unreliable for this tree, or None."""
        return self.problem
