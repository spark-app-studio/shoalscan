"""Similar findings: local embeddings from Ollama, kept in the history database.

A finding's text (its tool, rule, path, component and message, never its
code) is turned into a vector by an embedding model that runs on this
machine through Ollama, by default Google's EmbeddingGemma. Findings whose
vectors point the same way (cosine similarity) tend to be the same kind of
problem, so the decisions made about one (a dashboard review or a baseline
reason) are a good first guess for the others.

This is advice for triage only. It never runs during `shoalscan scan` or
`check`, so it cannot change what blocks CI, and when Ollama is not running
or the model is not pulled, the commands that use it say so and carry on.

Privacy: finding text goes only to Ollama on the loopback interface. The
host must be 127.0.0.1, ::1 or localhost, proxy settings are ignored, and the
host is a command-line setting, never read from the scanned repository's
`.shoalscan.toml`, so a repository cannot send its findings elsewhere.

Vectors are stored normalised to unit length as packed float32 (the standard
library's `array`), which keeps thousands of them small and quick to load;
cosine similarity is then their dot product, computed in pure Python.

A decision suggests a status for findings like it only when it comes from a
trusted place: a dashboard review (made by a signed-in person and audited),
or the baseline as a scheduled run of the default branch recorded it. A
pull-request run's baseline is the change under review, not yet the policy,
so its reasons never become suggestions.
"""

from __future__ import annotations

import hashlib
import json
import math
import operator
import sqlite3
import urllib.error
import urllib.request
from array import array
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from shoalscan.errors import SetupError

DEFAULT_MODEL = "embeddinggemma"
DEFAULT_HOST = "http://127.0.0.1:11434"
DEFAULT_THRESHOLD = 0.85
DEFAULT_LIMIT = 3
BATCH = 64
TIMEOUT_SECONDS = 120
MAX_TEXT_CHARS = 2000
MAX_DIMS = 8192
# The largest answer to one batch: BATCH vectors of MAX_DIMS numbers, each at most about 26 characters of JSON
# ("-1.2345678901234567e-05, "), twice over for headroom. About 26 MiB, below the 32 MiB ceiling.
MAX_RESPONSE_BYTES = min(2 * BATCH * MAX_DIMS * 26, 32 * 1024 * 1024)
# Untriaged findings grouped at most, highest priority first: grouping compares each with every group.
MAX_GROUPED = 500
# Suggestions compare every untriaged finding with every decided one, so both sides are bounded: the most
# recently decided findings, and the most important untriaged findings of the latest trend run.
MAX_DECIDED = 1000
MAX_SUGGESTED = 5000
LOOPBACK = ("127.0.0.1", "::1", "localhost")
# EmbeddingGemma is trained with task prompts; this is its prompt for semantic similarity.
PROMPT = "task: sentence similarity | query: "


class OllamaError(Exception):
    """Ollama could not embed: not running, model not pulled, or an answer that makes no sense."""


def validate_host(url: str) -> str:
    """An http URL of Ollama on the loopback interface, with a port and nothing else."""
    parts = urlsplit(url)
    if parts.scheme != "http" or parts.hostname not in LOOPBACK or parts.username or parts.password:
        raise SetupError(f"the Ollama host must be http:// on {', '.join(LOOPBACK)}, such as {DEFAULT_HOST}: {url!r}")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise SetupError(f"the Ollama host must not have a path, query or fragment: {url!r}")
    try:
        port = parts.port
    except ValueError:
        raise SetupError(f"the Ollama host has an invalid port: {url!r}") from None
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    return f"http://{host}:{port or 11434}"


def validate_model(name: str) -> str:
    if not isinstance(name, str) or not 0 < len(name) <= 200 or any(c.isspace() or ord(c) < 32 for c in name):
        raise SetupError(f"the model must be an Ollama model name such as {DEFAULT_MODEL}: {name!r}")
    return name


def finding_text(tool: str, rule: str, path: str, component: str, message: str) -> str:
    """What is embedded for one finding. Its code is never sent."""
    text = f"{PROMPT}{tool} {rule} in {component} file {path}: {' '.join(message.split())}"
    return text[:MAX_TEXT_CHARS]


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ Ollama

Post = Callable[[str, bytes, float], bytes]


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Ollama never redirects; an answer that does could send the finding text to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise OllamaError(f"Ollama answered {code} with a redirect, which is never followed")


def _opener() -> urllib.request.OpenerDirector:
    """No proxies and no redirects: the request must never leave this machine."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _RefuseRedirects())


def _post(url: str, body: bytes, timeout: float) -> bytes:
    """POST JSON to Ollama on loopback. Proxies are ignored and redirects refused."""
    opener = _opener()
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with opener.open(request, timeout=timeout) as response:
            data = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        with exc:
            detail = exc.read(2000).decode("utf-8", errors="replace")
        try:
            detail = json.loads(detail).get("error", detail)
        except (ValueError, AttributeError):
            pass
        hint = "; pull it with `ollama pull <model>`" if exc.code == 404 else ""
        raise OllamaError(f"Ollama answered {exc.code}: {str(detail)[:300]}{hint}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise OllamaError(f"Ollama is not reachable at {url.rsplit('/api/', 1)[0]}: {reason}") from None
    if len(data) > MAX_RESPONSE_BYTES:
        raise OllamaError("Ollama's answer is larger than allowed")
    return data


def embed(
    texts: list[str], model: str, host: str, post: Post = _post, timeout: float = TIMEOUT_SECONDS
) -> list[list[float]]:
    """Embed texts with Ollama's /api/embed, in batches. Returns one unit vector per text."""
    host = validate_host(host)
    out: list[list[float]] = []
    for start in range(0, len(texts), BATCH):
        batch = texts[start : start + BATCH]
        body = json.dumps({"model": model, "input": batch, "truncate": True}).encode("utf-8")
        raw = post(f"{host}/api/embed", body, timeout)
        try:
            vectors = json.loads(raw)["embeddings"]
        except (ValueError, KeyError, TypeError):
            raise OllamaError("Ollama's answer has no embeddings") from None
        if not isinstance(vectors, list) or len(vectors) != len(batch):
            raise OllamaError(
                f"Ollama returned {len(vectors) if isinstance(vectors, list) else 'no'} vectors for {len(batch)} texts"
            )
        for v in vectors:
            out.append(normalise(_checked(v)))
    dims = {len(v) for v in out}
    if len(dims) > 1:
        raise OllamaError("Ollama returned vectors of different lengths")
    return out


def _checked(vector: object) -> list[float]:
    if not isinstance(vector, list) or not 0 < len(vector) <= MAX_DIMS:
        raise OllamaError("Ollama returned something that is not a vector")
    values = []
    for x in vector:
        if isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x):
            raise OllamaError("Ollama returned a vector with a value that is not a finite number")
        values.append(float(x))
    return values


# ------------------------------------------------------------------ vector maths


def norm(v: list[float]) -> float:
    return math.sqrt(sum(x * x for x in v))


def normalise(v: list[float]) -> list[float]:
    n = norm(v)
    if n == 0:
        raise OllamaError("Ollama returned a zero vector")
    return [x / n for x in v]


def dot(a: list[float], b: list[float]) -> float:
    """The cosine similarity of two unit vectors, as stored: their dot product."""
    return _sumprod(a, b)


def _sumprod_py(a: list[float], b: list[float]) -> float:
    return sum(map(operator.mul, a, b))


# math.sumprod (Python 3.12 and later) does the same in C, several times faster.
_sumprod = getattr(math, "sumprod", _sumprod_py)


def cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity: A·B / (|A| |B|). 0 when either vector is zero."""
    if len(a) != len(b):
        raise ValueError("vectors of different lengths")
    na, nb = norm(a), norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return sum(x * y for x, y in zip(a, b, strict=True)) / (na * nb)


def pack(v: list[float]) -> bytes:
    return array("f", v).tobytes()


def unpack(blob: bytes, dims: int) -> list[float]:
    values = array("f")
    values.frombytes(blob)
    if len(values) != dims:
        raise ValueError("a stored vector does not have the length it claims")
    return values.tolist()


# ------------------------------------------------------------------ the history database


def _latest_texts(conn: sqlite3.Connection, repo_id: int) -> list[tuple[int, str]]:
    """Each finding identity of the repository with the text of its most recent occurrence.

    SQLite picks each finding's newest occurrence through the run_findings key index, so only one row per
    finding reaches Python, not one per run."""
    rows = conn.execute(
        "SELECT fk.id, fk.tool, fk.rule, fk.path, rf.component, m.text FROM finding_keys fk "
        "JOIN run_findings rf ON rf.key_id = fk.id AND rf.run_id = (SELECT nrf.run_id FROM run_findings nrf "
        "JOIN runs nr ON nr.id = nrf.run_id WHERE nrf.key_id = fk.id ORDER BY nr.scanned_at DESC, nr.id DESC LIMIT 1) "
        "JOIN messages m ON m.id = rf.message_id WHERE fk.repo_id = ? ORDER BY fk.id",
        (repo_id,),
    )
    return [
        (key_id, finding_text(tool, rule, path, component, message))
        for key_id, tool, rule, path, component, message in rows
    ]


@dataclass
class EmbedResult:
    embedded: int
    up_to_date: int


def embed_repository(
    conn: sqlite3.Connection, repo: str, model: str, host: str, post: Post = _post, now: str = ""
) -> EmbedResult:
    """Embed every finding of a repository that has no vector for this model, or whose text changed."""
    row = conn.execute("SELECT id FROM repos WHERE name = ?", (repo,)).fetchone()
    if row is None:
        raise SetupError(f"the history database has no runs of {repo}")
    stored = dict(
        conn.execute(
            "SELECT e.key_id, e.text_sha256 FROM finding_embeddings e JOIN finding_keys fk ON fk.id = e.key_id "
            "WHERE fk.repo_id = ? AND e.model = ?",
            (row[0], model),
        ).fetchall()
    )
    latest = _latest_texts(conn, row[0])
    todo = [(key_id, text) for key_id, text in latest if stored.get(key_id) != text_sha256(text)]
    up_to_date = len(latest) - len(todo)
    if not todo:
        return EmbedResult(0, up_to_date)
    vectors = embed([text for _, text in todo], model, host, post)
    with conn:
        conn.executemany(
            "INSERT INTO finding_embeddings (key_id, model, text_sha256, dims, vector, created_at) VALUES (?, ?, ?, ?, "
            "?, ?) "
            "ON CONFLICT (key_id, model) DO UPDATE SET text_sha256 = excluded.text_sha256, dims = excluded.dims, "
            "vector = excluded.vector, created_at = excluded.created_at",
            [
                (key_id, model, text_sha256(text), len(v), pack(v), now)
                for (key_id, text), v in zip(todo, vectors, strict=True)
            ],
        )
    return EmbedResult(len(todo), up_to_date)


# Decisions a similar finding can suggest: those that hold for a pattern, not for one place.
# ("Fixed" is about one place in the code, so it never becomes a suggestion.)
SUGGESTIBLE = ("false_positive", "accepted_risk", "wont_fix")


def decision_status(review_status: str | None, baseline_reason: str | None) -> str | None:
    """The status a finding's decision suggests for findings like it, if any.

    A dashboard review decides; without one, a baseline reason that starts
    "False positive:" or "Accepted:" does, as on the dashboard. Callers pass
    only the reason of a scheduled run (DECISION_RUN), never a pull request's.
    """
    if review_status is not None:
        return review_status if review_status in SUGGESTIBLE else None
    if baseline_reason and baseline_reason.startswith("False positive:"):
        return "false_positive"
    if baseline_reason and baseline_reason.startswith("Accepted:"):
        return "accepted_risk"
    return None


def group(items: list[tuple[int, list[float]]], threshold: float) -> list[list[int]]:
    """Group findings by similarity, in the order given (the most important first).

    The first finding not yet in a group leads a new one, and takes every
    later finding at least `threshold` alike to it. Each group is so held
    together by its leader, never by a chain of findings that are each a
    little like the next. Every finding ends up in exactly one group; a
    group of one is a finding like no other.
    """
    groups, left = [], list(items)
    while left:
        (leader, vector), rest = left[0], left[1:]
        members, left = [leader], []
        for key_id, other in rest:
            if len(other) == len(vector) and dot(vector, other) >= threshold:
                members.append(key_id)
            else:
                left.append((key_id, other))
        groups.append(members)
    return groups


# The run whose baseline reason stands as a finding's decision: the newest scheduled run (the nightly scan of
# the default branch) that holds the finding and whose check ran. `{key}` names the finding's key id column.
# A pull-request run never counts: its baseline is the change under review, not the accepted policy.
DECISION_RUN = (
    "(SELECT drf.run_id FROM run_findings drf JOIN runs drun ON drun.id = drf.run_id WHERE drf.key_id = {key} "
    "AND drun.kind = 'scheduled' AND drun.outcome != 'scan_error' "
    "ORDER BY drun.scanned_at DESC, drun.id DESC LIMIT 1)"
)
# The decision of the finding `fk`, as columns: its dashboard review, and its baseline at DECISION_RUN.
_DECISIONS = (
    "SELECT fk.id, fr.status, fr.description, fr.updated_by, fr.updated_at, "
    "db.baseline_issue, db.baseline_reason, dr.id, dr.commit_sha, dr.scanned_at "
    "FROM finding_keys fk JOIN repos rp ON rp.id = fk.repo_id "
    "LEFT JOIN finding_reviews fr ON fr.repo_name = rp.name AND fr.tool = fk.tool AND fr.rule = fk.rule "
    "AND fr.path = fk.path AND fr.fingerprint = fk.fingerprint "
    f"LEFT JOIN run_findings db ON db.key_id = fk.id AND db.run_id = {DECISION_RUN.format(key='fk.id')} "
    "LEFT JOIN runs dr ON dr.id = db.run_id "
)


def latest_trend_run(conn: sqlite3.Connection, repo_id: int) -> int | None:
    """The run the dashboard's trends end with: the newest scheduled run whose check ran, or, for a
    repository without scheduled runs, the newest run of any kind whose check ran."""
    row = conn.execute(
        "SELECT id FROM runs WHERE repo_id = ? AND outcome != 'scan_error' "
        "ORDER BY kind = 'scheduled' DESC, scanned_at DESC, id DESC LIMIT 1",
        (repo_id,),
    ).fetchone()
    return row[0] if row else None


def decision(row: tuple) -> dict | None:
    """A finding's decision, with where it comes from, from a row of `_DECISIONS` (without the key id)."""
    status, description, by, at, issue, reason, run, commit, scanned_at = row
    if status is not None:
        return {"source": "review", "status": status, "description": description, "by": by, "at": at}
    if reason is not None:
        return {
            "source": "baseline",
            "status": "baselined",
            "issue": issue,
            "description": reason,
            "run": run,
            "commit": commit,
            "at": scanned_at,
        }
    return None


def suggest_repository(
    conn: sqlite3.Connection, repo: str, model: str, threshold: float = DEFAULT_THRESHOLD, now: str = ""
) -> int:
    """For each untriaged finding of the repository's latest trend run, store the most similar finding
    that has a decision, if it is at least `threshold` alike. Returns how many were stored.

    Untriaged means no dashboard review and no baseline entry in that run.
    Decisions come from dashboard reviews and from the baseline of scheduled
    runs (DECISION_RUN), never from a pull-request run. At most the
    MAX_DECIDED most recently decided findings are compared, with at most
    MAX_SUGGESTED untriaged findings, most important first. Earlier
    suggestions of the repository for this model are replaced.
    """
    row = conn.execute("SELECT id FROM repos WHERE name = ?", (repo,)).fetchone()
    if row is None:
        raise SetupError(f"the history database has no runs of {repo}")
    repo_id = row[0]
    run_id = latest_trend_run(conn, repo_id)
    decided_at: list[tuple[str, int]] = []
    for key_id, *rest in conn.execute(
        _DECISIONS + "JOIN finding_embeddings e ON e.key_id = fk.id AND e.model = ? WHERE fk.repo_id = ?",
        (model, repo_id),
    ):
        status, _, _, reviewed_at, _, reason, _, _, scanned_at = rest
        if decision_status(status, reason) is not None:
            decided_at.append((reviewed_at if status is not None else scanned_at, key_id))
    decided_at.sort(reverse=True)
    decided = _vectors(conn, model, [key_id for _, key_id in decided_at[:MAX_DECIDED]])
    untriaged = [
        (key_id, unpack(blob, dims))
        for key_id, blob, dims in conn.execute(
            "SELECT rf.key_id, e.vector, e.dims FROM run_findings rf JOIN finding_keys fk ON fk.id = rf.key_id "
            "JOIN repos rp ON rp.id = fk.repo_id JOIN finding_embeddings e ON e.key_id = rf.key_id AND e.model = ? "
            "LEFT JOIN finding_reviews fr ON fr.repo_name = rp.name AND fr.tool = fk.tool AND fr.rule = fk.rule "
            "AND fr.path = fk.path AND fr.fingerprint = fk.fingerprint "
            "WHERE rf.run_id = ? AND fr.status IS NULL AND rf.baseline_reason IS NULL "
            "ORDER BY CASE rf.severity WHEN 'ERROR' THEN 0 WHEN 'WARNING' THEN 1 ELSE 2 END, "
            "fk.path, rf.line, fk.rule, rf.key_id LIMIT ?",
            (model, run_id if run_id is not None else -1, MAX_SUGGESTED),
        )
    ]
    rows = []
    for key_id, vector in untriaged:
        best_id, best = None, threshold
        for other_id, other in decided:
            if len(other) == len(vector):
                score = dot(vector, other)
                if score >= best:
                    best_id, best = other_id, score
        if best_id is not None:
            rows.append((key_id, model, best_id, round(best, 4), now))
    with conn:
        conn.execute(
            "DELETE FROM finding_suggestions WHERE model = ? AND key_id IN (SELECT id FROM finding_keys WHERE repo_id "
            "= ?)",
            (model, repo_id),
        )
        conn.executemany(
            "INSERT INTO finding_suggestions (key_id, model, neighbour_id, score, computed_at) VALUES (?, ?, ?, ?, ?)",
            rows,
        )
    return len(rows)


def _vectors(conn: sqlite3.Connection, model: str, key_ids: list[int]) -> list[tuple[int, list[float]]]:
    """The stored vectors of these findings, in the order given."""
    found = {
        key_id: unpack(blob, dims)
        for key_id, blob, dims in conn.execute(
            "SELECT key_id, vector, dims FROM finding_embeddings WHERE model = ? "
            "AND key_id IN (SELECT value FROM json_each(?))",
            (model, json.dumps(key_ids)),
        )
    }
    return [(key_id, found[key_id]) for key_id in key_ids if key_id in found]


def similar(
    conn: sqlite3.Connection,
    key_id: int,
    model: str,
    threshold: float = DEFAULT_THRESHOLD,
    limit: int = DEFAULT_LIMIT,
    all_repos: bool = False,
) -> list[dict] | None:
    """The findings most like one finding, above `threshold`, best first, each with its decision.

    Returns None when the finding has no vector for this model yet. Other
    findings are those of the same repository, or of every repository with
    `all_repos`. A finding's decision is its dashboard review, else what its
    baseline entry said in its newest scheduled run (never a pull-request
    run's), with where it comes from.
    """
    target = conn.execute(
        "SELECT e.vector, e.dims, fk.repo_id FROM finding_embeddings e JOIN finding_keys fk ON fk.id = e.key_id "
        "WHERE e.key_id = ? AND e.model = ?",
        (key_id, model),
    ).fetchone()
    if target is None:
        return None
    vector = unpack(target[0], target[1])
    scored = []
    for other_id, blob, dims in conn.execute(
        "SELECT e.key_id, e.vector, e.dims FROM finding_embeddings e JOIN finding_keys fk ON fk.id = e.key_id "
        "WHERE e.model = ? AND e.key_id != ? AND e.dims = ? AND (? OR fk.repo_id = ?)",
        (model, key_id, target[1], 1 if all_repos else 0, target[2]),
    ):
        score = dot(vector, unpack(blob, dims))  # stored vectors are unit length
        if score >= threshold:
            scored.append((score, other_id))
    scored.sort(key=lambda s: (-s[0], s[1]))
    return [_describe(conn, other_id, round(score, 4)) for score, other_id in scored[: max(1, limit)]]


def _describe(conn: sqlite3.Connection, key_id: int, score: float) -> dict:
    tool, rule, path, fingerprint, repo = conn.execute(
        "SELECT fk.tool, fk.rule, fk.path, fk.fingerprint, rp.name FROM finding_keys fk JOIN repos rp ON rp.id = "
        "fk.repo_id "
        "WHERE fk.id = ?",
        (key_id,),
    ).fetchone()
    decided = conn.execute(_DECISIONS + "WHERE fk.id = ?", (key_id,)).fetchone()
    latest = conn.execute(
        "SELECT rf.severity, rf.line, m.text, r.scanned_at FROM run_findings rf "
        "JOIN runs r ON r.id = rf.run_id JOIN messages m ON m.id = rf.message_id WHERE rf.key_id = ? "
        "ORDER BY r.scanned_at DESC, r.id DESC LIMIT 1",
        (key_id,),
    ).fetchone()
    return {
        "score": score,
        "repo": repo,
        "key": [tool, rule, path, fingerprint],
        "severity": latest[0] if latest else None,
        "line": latest[1] if latest else None,
        "message": latest[2] if latest else "",
        "last_seen": latest[3] if latest else None,
        "decision": decision(tuple(decided[1:])),
    }


def find_keys(conn: sqlite3.Connection, repo: str, fingerprint: str) -> list[tuple[int, list[str]]]:
    """The finding identities of a repository with this fingerprint, or, failing that, whose fingerprint
    starts with it (a prefix needs 8 characters or more)."""
    rows = conn.execute(_KEYS_EXACT, (repo, fingerprint)).fetchall()
    if not rows:
        if len(fingerprint) < 8 or any(c in fingerprint for c in "%_\\"):
            raise SetupError("give the whole fingerprint, or at least its first 8 characters")
        rows = conn.execute(_KEYS_PREFIX, (repo, fingerprint + "%")).fetchall()
    return [(r[0], list(r[1:])) for r in rows]


_KEYS = (
    "SELECT fk.id, fk.tool, fk.rule, fk.path, fk.fingerprint FROM finding_keys fk "
    "JOIN repos rp ON rp.id = fk.repo_id WHERE rp.name = ? "
)
_KEYS_EXACT = _KEYS + "AND fk.fingerprint = ? ORDER BY fk.path, fk.rule"
_KEYS_PREFIX = _KEYS + "AND fk.fingerprint LIKE ? ESCAPE '\\' ORDER BY fk.path, fk.rule"
