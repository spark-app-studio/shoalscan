"""Write untrusted text into Markdown safely.

Paths, rule ids, messages, baseline reasons and rule metadata can come from
the scanned repository. A work list or a report is read in a terminal, an
editor, or rendered by a code host, so such text must never become markup:
no links, images, HTML, table cells or headings it did not ask for. (A code
host may still turn a bare http(s) or www address into a link, as it would
in any comment; it never does that for other schemes.)

`text` escapes every character that has a meaning inside a line of Markdown
or HTML: emphasis, code, links and images, HTML tags and entities, table
pipes, strikethrough, mentions and math. It also escapes a block marker at
the start of the value (`#`, `-`, `+`, `=`, `1.`, `1)`), because a list
item's content is parsed as blocks: `- # x` is a heading. `code` puts a value in
a code span, where nothing is interpreted, and `link` keeps only plain
http(s) URLs. All three fold line breaks and other control characters into
spaces, so a value can never start a new block. Control characters include
the C1 range (U+0080 to U+009F, where some terminals read escape sequences)
and the bidirectional formatting characters, which can make text read in a
different order than it is stored.
`text` output is also safe in a table cell; `code` output is not (a pipe in
a code span still splits a cell), so code spans go in lists only.
"""

from __future__ import annotations

import re

# DEL and C1 controls, and the bidirectional marks, embeddings, overrides and isolates.
FORMAT_CONTROLS = "\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069"
_CONTROL = re.compile(f"[\\x00-\\x1f\\u2028\\u2029{FORMAT_CONTROLS}]+")
_UNSAFE_IN_LINES = re.compile(f"[\\x00-\\x08\\x0b-\\x1f\\u2028\\u2029{FORMAT_CONTROLS}]")
_FORMAT_CONTROL = re.compile(f"[{FORMAT_CONTROLS}]")
_SPECIAL = re.compile(r"([\\`*_\[\]<>|~&@$])")
_BLOCK_START = re.compile(r"^(?:([#+=-])|(\d+)([.)]))")
_URL = re.compile(r"^https?://[A-Za-z0-9._~:/?#@!$&'*+,;=%\-]+$")
MAX_TEXT = 2000


def one_line(value: object, limit: int = MAX_TEXT) -> str:
    """The value as a single line: control characters become spaces, runs of spaces collapse, long text is cut."""
    text = " ".join(_CONTROL.sub(" ", str(value)).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def lines(value: object) -> str:
    """Text of several lines for a terminal, kept as it is except that every control character other than a
    newline or a tab, and every bidirectional formatting character, becomes U+FFFD."""
    return _UNSAFE_IN_LINES.sub("\ufffd", str(value))


def is_format_control(char: str) -> bool:
    """DEL, a C1 control or a bidirectional formatting character."""
    return _FORMAT_CONTROL.fullmatch(char) is not None


def text(value: object, limit: int = MAX_TEXT) -> str:
    """Prose that Markdown shows as written, wherever it stands in a line."""
    escaped = _SPECIAL.sub(r"\\\1", one_line(value, limit))
    return _BLOCK_START.sub(lambda m: f"\\{m.group(1)}" if m.group(1) else f"{m.group(2)}\\{m.group(3)}", escaped)


def code(value: object, limit: int = 500) -> str:
    """A code span. Its fence is longer than any run of backticks in the value."""
    body = one_line(value, limit)
    longest = max((len(run) for run in re.findall(r"`+", body)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if body.startswith("`") or body.endswith("`") or not body.strip() else ""
    return f"{fence}{pad}{body}{pad}{fence}"


def link(label: str, url: object) -> str:
    """`[label](url)` for a plain http(s) URL; otherwise the escaped label alone. The label is escaped."""
    if isinstance(url, str) and _URL.match(url) and "(" not in url and ")" not in url:
        return f"[{text(label)}](<{url}>)"
    return text(label)


def issue(value: object) -> str:
    """A baseline issue: `#123` as written (so a code host links it), a URL as a link, anything else as text.

    Only call it mid-line: a bare `#123` at the start of a line or list item would be a heading.
    """
    if isinstance(value, str) and re.fullmatch(r"#\d{1,9}", value):
        return value
    if isinstance(value, str) and _URL.match(value):
        return link(value, value)
    return text(value)
