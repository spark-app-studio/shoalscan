"""Which files each Opengrep language reads, as Opengrep 1.30.2 decides it.

The table is generated from Opengrep's own language list, `lang.json` in
opengrep/semgrep-interfaces at commit 5e705660dc7381d4c4c247fa83c4c5860e61d555
(the submodule the v1.30.2 tag pins; sha256
46bb98582dcde32956d5879156a4d9fa9fe7c62ccabba5d07079a64fc40b6c3e), and
`reads` follows `src/targeting/Guess_lang.ml` at that tag:

- a path whose name ends with one of the language's extensions, and not with
  one of its excluded extensions (`.min.js`, `.d.ts`), is read;
- a Dockerfile language reads a file named `Dockerfile` or `dockerfile` too;
- a file with no extension, executable by someone, whose first line is a
  shebang naming one of the language's interpreters (directly, or as the
  command after `/usr/bin/env`, `env -S` included) is read.

`generic`, `aliengrep` and `regex` map to no extension or interpreter (their
rules narrow themselves with `paths:` filters), so they are not in the table.
Update the table with the Opengrep pin.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

# Languages that map to no extension or interpreter.
ANY_FILE = frozenset({"generic", "spacegrep", "aliengrep", "regex", "none"})

# Every key a rule's `languages:` may use -> (extensions, excluded extensions, shebang interpreters).
LANGUAGES: dict[str, tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = {
    "apex": ((".cls", ".trigger"), (), ()),
    "bash": ((".bash", ".sh"), (), ("bash", "sh")),
    "sh": ((".bash", ".sh"), (), ("bash", "sh")),
    "c": ((".c", ".h"), (), ()),
    "cairo": ((".cairo",), (), ()),
    "circom": ((".circom",), (), ()),
    "clojure": ((".clj", ".cljs", ".cljc", ".edn"), (), ()),
    "c++": ((".cc", ".cpp", ".cxx", ".c++", ".pcc", ".tpp", ".C", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"), (), ()),
    "cpp": ((".cc", ".cpp", ".cxx", ".c++", ".pcc", ".tpp", ".C", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"), (), ()),
    "crystal": ((".cr",), (), ("crystal",)),
    "c#": ((".cs",), (), ()),
    "csharp": ((".cs",), (), ()),
    "dart": ((".dart",), (), ()),
    "docker": ((".dockerfile", ".Dockerfile", ".Dockerfile", ".dockerfile"), (), ()),
    "dockerfile": ((".dockerfile", ".Dockerfile", ".Dockerfile", ".dockerfile"), (), ()),
    "elixir": ((".ex", ".exs"), (), ()),
    "ex": ((".ex", ".exs"), (), ()),
    "go": ((".go",), (), ()),
    "golang": ((".go",), (), ()),
    "hack": ((".hack", ".hck", ".hh"), (), ("hhvm",)),
    "html": ((".htm", ".html"), (), ()),
    "java": ((".java",), (), ()),
    "javascript": ((".cjs", ".js", ".jsx", ".mjs"), (".min.js",), ("node", "js", "nodejs")),
    "js": ((".cjs", ".js", ".jsx", ".mjs"), (".min.js",), ("node", "js", "nodejs")),
    "json": ((".json", ".ipynb"), (), ()),
    "jsonnet": ((".jsonnet", ".libsonnet"), (), ()),
    "julia": ((".jl",), (), ()),
    "kotlin": ((".kt", ".kts", ".ktm"), (), ()),
    "kt": ((".kt", ".kts", ".ktm"), (), ()),
    "lisp": ((".lisp", ".cl", ".el"), (), ()),
    "lua": ((".lua",), (), ("lua",)),
    "move_on_sui": ((".move",), (), ()),
    "move_on_aptos": ((".move",), (), ()),
    "ocaml": ((".ml", ".mli"), (), ("ocaml", "ocamlscript")),
    "php": ((".php", ".tpl", ".phtml"), (), ("php",)),
    "promql": ((".promql",), (), ()),
    "proto": ((".proto",), (), ()),
    "proto3": ((".proto",), (), ()),
    "protobuf": ((".proto",), (), ()),
    "python2": ((".py", ".pyi"), (), ("python", "python2")),
    "python3": ((".py", ".pyi"), (), ("python", "python3")),
    "py": ((".py", ".pyi"), (), ("python", "python2", "python3")),
    "python": ((".py", ".pyi"), (), ("python", "python2", "python3")),
    "ql": ((".ql", ".qll"), (), ()),
    "r": ((".r", ".R"), (), ()),
    "ruby": ((".rb",), (), ("ruby",)),
    "rust": ((".rs",), (), ("run-cargo-script",)),
    "scala": ((".scala",), (), ("scala",)),
    "scheme": ((".scm", ".ss"), (), ()),
    "sol": ((".sol",), (), ()),
    "solidity": ((".sol",), (), ()),
    "swift": ((".swift",), (), ()),
    "hcl": ((".tf", ".hcl", ".tfvars"), (), ()),
    "terraform": ((".tf", ".hcl", ".tfvars"), (), ()),
    "tf": ((".tf", ".hcl", ".tfvars"), (), ()),
    "ts": ((".ts", ".tsx"), (".d.ts",), ("ts-node",)),
    "typescript": ((".ts", ".tsx"), (".d.ts",), ("ts-node",)),
    "vb": ((".vb",), (), ()),
    "vue": ((".vue",), (), ()),
    "xml": ((".xml", ".plist"), (), ()),
    "yaml": ((".yml", ".yaml"), (), ()),
}

_DOCKERFILE_NAMES = ("Dockerfile", "dockerfile")


def _shebang_command(path: Path) -> str | None:
    """The interpreter a file's shebang line names, as Guess_lang.ml reads it, or None."""
    try:
        with open(path, "rb") as f:
            first = f.readline(4096)
    except OSError:
        return None
    line = first.decode("utf-8", "replace").rstrip("\r\n")
    if not line.startswith("#!"):
        return None
    parts = line[2:].lstrip(" \t").split(None, 1)
    if not parts:
        return None
    arg0 = parts[0]
    if arg0 == "/usr/bin/env" and len(parts) == 2:
        rest = parts[1].strip()
        if rest.startswith("-S"):
            rest = rest[2:]
        words = rest.split()
        return words[0] if words else None
    return os.path.basename(arg0)


def reads(path: Path, name: str, languages: frozenset[str]) -> bool:
    """Whether Opengrep would read the file at `path` (named `name` in the repository) for any of `languages`.

    A language Shoalscan does not know counts as reading every file, so an unknown language fails closed.
    """
    if any(lang not in LANGUAGES for lang in languages):
        return True
    base = os.path.basename(name)
    shebangs: set[str] = set()
    for lang in languages:
        exts, excluded, sheb = LANGUAGES[lang]
        if base.endswith(exts) and not base.endswith(excluded or ("\0",)):
            return True
        if ".Dockerfile" in exts and base in _DOCKERFILE_NAMES:
            return True
        shebangs.update(sheb)
    if not shebangs or os.path.splitext(base)[1]:
        return False
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    if not stat.S_ISREG(mode) or not mode & 0o111:
        return False
    return _shebang_command(path) in shebangs
