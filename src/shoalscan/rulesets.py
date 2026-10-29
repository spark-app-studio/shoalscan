"""Select rules by category and id before a scan.

The standard library has no YAML parser, so this module reads rule files at
the text level. Opengrep rule files have one shape: a top-level `rules:` key
holding a list of rule mappings. Each list item is split out as text, and its
`id` and `metadata.category` are read from the item's own lines.

The selected rules are written to a new file in the staging directory; the
installed snapshot is never changed. If a file cannot be split with
certainty, the scan stops with an error instead of guessing. Opengrep then
parses the staged files itself, so any damage would surface as a rule parse
error, which fails the scan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from shoalscan.errors import SetupError

UNCATEGORISED = "uncategorised"
_RULES_KEY = re.compile(r"^rules\s*:\s*(#.*)?$")
_ITEM = re.compile(r"^(?P<indent> *)- ")
_KEY = re.compile(r"^(?P<indent> *)(?:- )?(?P<key>[A-Za-z_][\w-]*)\s*:(?P<value>.*)$")


@dataclass(frozen=True)
class RuleText:
    rule_id: str
    category: str
    text: str


def _scalar(value: str) -> str:
    value = value.strip()
    quoted = re.match(r'^"((?:[^"\\]|\\.)*)"|^\'((?:[^\']|\'\')*)\'', value)
    if quoted:
        return (quoted.group(1) if quoted.group(1) is not None else quoted.group(2).replace("''", "'")).strip()
    return value.split(" #", 1)[0].strip()


# YAML indicators that would make a text-level read unreliable: flow
# collections, anchors, aliases, tags, merge keys and block scalars.
_UNSAFE_VALUE_STARTS = ("{", "[", "&", "*", "!", "<<", ">", "|")


def _check_value(key: str, value: str, where: str) -> None:
    v = value.strip()
    if key == "metadata":
        if v and not v.startswith("#"):
            raise SetupError(f"`metadata:` must be a block mapping in {where}")
        return
    if v.startswith(_UNSAFE_VALUE_STARTS):
        raise SetupError(f"unsupported YAML on the `{key}:` line in {where}: {v[:40]!r}")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


_DOUBLE_QUOTED = re.compile(r'^"(?:[^"\\]|\\.)*"\s*(?:#.*)?$')
_SINGLE_QUOTED = re.compile(r"^'(?:[^']|'')*'\s*(?:#.*)?$")


def _check_quotes(key: str, value: str, where: str) -> None:
    v = value.strip()
    if v.startswith(("'", '"')) and "\\" in v:
        # Escapes in quoted values are read differently by YAML and by this
        # text-level reader, so they are refused.
        raise SetupError(f"a backslash in the quoted `{key}:` value is not supported in {where}")
    if v.startswith('"') and not _DOUBLE_QUOTED.match(v):
        raise SetupError(f"the `{key}:` value's quote does not close on its line in {where}")
    if v.startswith("'") and not _SINGLE_QUOTED.match(v):
        raise SetupError(f"the `{key}:` value's quote does not close on its line in {where}")


def _describe(item_lines: list[str], item_indent: int, where: str) -> tuple[str, str]:
    """Return (id, category) of one rule item.

    Anything that a text-level read could get wrong is refused: a duplicate
    id or category, a quote that does not close on its own line, and a
    value continued on a deeper-indented line.
    """
    child = item_indent + 2
    rule_id = None
    category = None
    metadata_indent = None
    meta_child = None
    scalar_key: tuple[str, int] | None = None  # (key, indent) of the last id/category line
    for n, line in enumerate(item_lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.lstrip("- ").startswith("<<"):
            raise SetupError(f"YAML merge keys are not supported in {where}")
        match = _KEY.match(line)
        # On the first line (`- id: x`) the key sits two columns right of the dash.
        indent = child if n == 0 else _indent(line)
        if scalar_key is not None:
            if indent > scalar_key[1]:
                raise SetupError(f"the `{scalar_key[0]}:` value continues on another line in {where}")
            scalar_key = None
        if metadata_indent is not None:
            if indent <= metadata_indent:
                metadata_indent = None
            elif match:
                if meta_child is None:
                    meta_child = indent
                if indent == meta_child and match.group("key") == "category":
                    if category is not None:
                        raise SetupError(f"a rule has two `category:` keys in {where}")
                    _check_value("category", match.group("value"), where)
                    _check_quotes("category", match.group("value"), where)
                    category = _scalar(match.group("value")) or UNCATEGORISED
                    scalar_key = ("category", indent)
                continue
            else:
                continue
        if match and indent == child:
            key = match.group("key")
            if key in ("id", "metadata"):
                _check_value(key, match.group("value"), where)
            if key == "id":
                if rule_id is not None:
                    raise SetupError(f"a rule has two `id:` keys in {where}")
                _check_quotes("id", match.group("value"), where)
                rule_id = _scalar(match.group("value"))
                scalar_key = ("id", indent)
            elif key == "metadata":
                if metadata_indent is not None or meta_child is not None:
                    raise SetupError(f"a rule has two `metadata:` keys in {where}")
                metadata_indent = child
                meta_child = None
    if not rule_id:
        raise SetupError(f"cannot read the rule id of a rule in {where}")
    return rule_id, (category or UNCATEGORISED).lower()


def rule_languages(rule: RuleText) -> frozenset[str] | None:
    """The rule's `languages:` list, lower-cased, or None when it cannot be read with certainty.

    Two forms are read: a one-line flow list (`languages: [python, js]`) and a block list (indented, or at the
    key's own indent). Anything else (a
    scalar, a list over several lines, a second `languages:` key) gives None, which a caller must treat as
    "reads every file".
    """
    lines = [line.rstrip("\n") for line in rule.text.splitlines()]
    first = _ITEM.match(lines[0]) if lines else None
    if not first:
        return None
    child = len(first.group(0))
    found: frozenset[str] | None = None
    seen = False
    n = 0
    while n < len(lines):
        line = lines[n]
        body = " " * child + line[child:] if n == 0 else line
        match = _KEY.match(body)
        n += 1
        if not match or len(match.group("indent")) != child or match.group("key") != "languages":
            continue
        if seen:
            return None
        seen = True
        value = match.group("value").split(" #", 1)[0].strip()
        if value.startswith("["):
            if not value.endswith("]"):
                return None
            items = [x.strip() for x in value[1:-1].split(",")]
        elif value == "":
            items = []
            # A block list, indented under the key or at the key's own indent (YAML's compact form).
            while n < len(lines) and (
                not lines[n].strip()
                or _indent(lines[n]) > child
                or (_indent(lines[n]) == child and lines[n].strip().startswith("- "))
            ):
                stripped = lines[n].strip()
                n += 1
                if not stripped or stripped.startswith("#"):
                    continue
                if not stripped.startswith("- "):
                    return None
                items.append(stripped[2:].split(" #", 1)[0].strip())
        else:
            return None
        names = [_scalar(x).lower() for x in items]
        if not names or any(not re.fullmatch(r"[a-z0-9_+#-]+", x) for x in names):
            return None
        found = frozenset(names)
    return found


def split_rules(text: str, where: str) -> list[RuleText]:
    """Split a rule file into its rules. Raises SetupError if the shape is unexpected."""
    # Split on newline only: YAML does not break lines on form feeds or
    # Unicode separators, but str.splitlines does.
    lines = [part for part in re.split(r"(?<=\n)", text) if part]
    start = None
    for n, line in enumerate(lines):
        if _RULES_KEY.match(line.rstrip("\n")):
            start = n + 1
            break
        if line.strip() and not line.lstrip().startswith("#") and _indent(line) == 0:
            raise SetupError(f"unexpected top-level key before `rules:` in {where}")
    if start is None:
        raise SetupError(f"no top-level `rules:` list in {where}")
    item_indent = None
    items: list[tuple[int, list[str]]] = []
    preamble: list[str] = []
    for line in lines[start:]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            (items[-1][1] if items else preamble).append(line)
            continue
        indent = _indent(line)
        match = _ITEM.match(line)
        if item_indent is None:
            if not match:
                raise SetupError(f"`rules:` is not a block list in {where}")
            item_indent = indent
        if match and indent == item_indent:
            items.append((indent, [line]))
        elif indent > item_indent and items:
            items[-1][1].append(line)
        else:
            raise SetupError(f"unexpected line after the rules list in {where}: {line.strip()[:60]!r}")
    if not items:
        raise SetupError(f"empty rules list in {where}")
    # The pieces must give back the original text exactly; otherwise a line
    # was lost or misplaced and the split cannot be trusted.
    if "".join(preamble) + "".join("".join(item) for _, item in items) != "".join(lines[start:]):
        raise SetupError(f"the rules list in {where} does not split cleanly")
    result = []
    for indent, item_lines in items:
        rule_id, category = _describe(item_lines, indent, where)
        result.append(RuleText(rule_id, category, "".join(item_lines)))
    return result


class RuleIdFilter:
    """Matches rule ids against exact ids and `prefix.*` patterns."""

    def __init__(self, patterns: tuple[str, ...] | list[str]):
        self.exact = {p for p in patterns if not p.endswith(".*")}
        self.prefixes = tuple(p[:-1] for p in patterns if p.endswith(".*"))

    def matches(self, rule_id: str) -> bool:
        return rule_id in self.exact or bool(self.prefixes and rule_id.startswith(self.prefixes))


def select(
    text: str,
    where: str,
    id_prefix: str,
    categories: frozenset[str] | None,
    excluded: RuleIdFilter,
) -> tuple[str | None, int, int]:
    """Return (filtered file text or None, rules kept, rules dropped).

    `id_prefix` is the dotted prefix Opengrep gives the rules of this file,
    such as `community.python.lang.security.audit`. `categories` None keeps
    every category.
    """
    rules = split_rules(text, where)
    keep = [
        r
        for r in rules
        if (categories is None or r.category in categories) and not excluded.matches(f"{id_prefix}.{r.rule_id}")
    ]
    if not keep:
        return None, 0, len(rules)
    if len(keep) == len(rules):
        return text, len(keep), 0
    return (
        "rules:\n" + "".join(r.text if r.text.endswith("\n") else r.text + "\n" for r in keep),
        len(keep),
        len(rules) - len(keep),
    )
