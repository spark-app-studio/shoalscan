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
cosine similarity is then computed in pure Python.
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
MAX_RESPONSE_BYTES = 256 * 1024 * 1024
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


def _post(url: str, body: bytes, timeout: float) -> bytes:
    """POST JSON to Ollama on loopback. Proxies are ignored: the request must never leave this machine."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
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


def cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity: A·B / (|A| |B|). 0 when either vector is zero."""
    if len(a) != len(b):
        raise ValueError("vectors of different lengths")
    na, nb = norm(a), norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return sum(x * y for x, y in zip(a, b)) / (na * nb)


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
    """Each finding identity of the repository with the text of its most recent occurrence."""
    rows = conn.execute(
        "SELECT fk.id, fk.tool, fk.rule, fk.path, rf.component, m.text FROM finding_keys fk "
        "JOIN run_findings rf ON rf.key_id = fk.id JOIN runs r ON r.id = rf.run_id JOIN messages m ON m.id = "
        "rf.message_id "
        "WHERE fk.repo_id = ? ORDER BY fk.id, r.scanned_at DESC, r.id DESC",
        (repo_id,),
    ).fetchall()
    out, seen = [], set()
    for key_id, tool, rule, path, component, message in rows:
        if key_id not in seen:
            seen.add(key_id)
            out.append((key_id, finding_text(tool, rule, path, component, message)))
    return out


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
            [(key_id, model, text_sha256(text), len(v), pack(v), now) for (key_id, text), v in zip(todo, vectors)],
        )
    return EmbedResult(len(todo), up_to_date)


# Decisions a similar finding can suggest: those that hold for a pattern, not for one place.
# ("Fixed" is about one place in the code, so it never becomes a suggestion.)
SUGGESTIBLE = ("false_positive", "accepted_risk", "wont_fix")


def decision_status(review_status: str | None, baseline_reason: str | None) -> str | None:
    """The status a finding's decision suggests for findings like it, if any.

    A dashboard review decides; without one, a baseline reason that starts
    "False positive:" or "Accepted:" does, as on the dashboard.
    """
    if review_status is not None:
        return review_status if review_status in SUGGESTIBLE else None
    if baseline_reason and baseline_reason.startswith("False positive:"):
        return "false_positive"
    if baseline_reason and baseline_reason.startswith("Accepted:"):
        return "accepted_risk"
    return None


def dot(a: list[float], b: list[float]) -> float:
    """The cosine similarity of two unit vectors, as stored: their dot product."""
    return sum(map(operator.mul, a, b))


def suggest_repository(
    conn: sqlite3.Connection, repo: str, model: str, threshold: float = DEFAULT_THRESHOLD, now: str = ""
) -> int:
    """For each untriaged finding of the repository's latest run, store the most similar finding
    that has a decision, if it is at least `threshold` alike. Returns how many were stored.

    Untriaged means no dashboard review and no baseline entry. Earlier
    suggestions of the repository for this model are replaced.
    """
    row = conn.execute("SELECT id, name FROM repos WHERE name = ?", (repo,)).fetchone()
    if row is None:
        raise SetupError(f"the history database has no runs of {repo}")
    repo_id = row[0]
    latest = conn.execute(
        "SELECT id FROM runs WHERE repo_id = ? AND outcome IS NOT 'scan_error' ORDER BY scanned_at DESC, id DESC LIMIT "
        "1",
        (repo_id,),
    ).fetchone()
    decided: list[tuple[int, list[float]]] = []
    untriaged: list[tuple[int, list[float]]] = []
    for key_id, blob, dims, review, reason, in_latest in conn.execute(
        "SELECT fk.id, e.vector, e.dims, fr.status, "
        "(SELECT rf.baseline_reason FROM run_findings rf JOIN runs r ON r.id = rf.run_id WHERE rf.key_id = fk.id "
        " ORDER BY r.scanned_at DESC, r.id DESC LIMIT 1), "
        "EXISTS (SELECT 1 FROM run_findings WHERE run_id = ? AND key_id = fk.id) "
        "FROM finding_embeddings e JOIN finding_keys fk ON fk.id = e.key_id "
        "LEFT JOIN finding_reviews fr ON fr.repo_name = ? AND fr.tool = fk.tool AND fr.rule = fk.rule "
        "AND fr.path = fk.path AND fr.fingerprint = fk.fingerprint "
        "WHERE fk.repo_id = ? AND e.model = ?",
        (latest[0] if latest else -1, repo, repo_id, model),
    ):
        if decision_status(review, reason) is not None:
            decided.append((key_id, unpack(blob, dims)))
        elif review is None and reason is None and in_latest:
            untriaged.append((key_id, unpack(blob, dims)))
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
    newest baseline entry says.
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
        score = cosine(vector, unpack(blob, dims))
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
    review = conn.execute(
        "SELECT status, description, updated_by, updated_at FROM finding_reviews "
        "WHERE repo_name = ? AND tool = ? AND rule = ? AND path = ? AND fingerprint = ?",
        (repo, tool, rule, path, fingerprint),
    ).fetchone()
    latest = conn.execute(
        "SELECT rf.severity, rf.line, m.text, rf.baseline_issue, rf.baseline_reason, r.scanned_at FROM run_findings rf "
        "JOIN runs r ON r.id = rf.run_id JOIN messages m ON m.id = rf.message_id WHERE rf.key_id = ? "
        "ORDER BY r.scanned_at DESC, r.id DESC LIMIT 1",
        (key_id,),
    ).fetchone()
    decision = None
    if review is not None:
        decision = {"source": "review", "status": review[0], "description": review[1], "by": review[2], "at": review[3]}
    elif latest is not None and latest[4] is not None:
        decision = {"source": "baseline", "status": "baselined", "issue": latest[3], "description": latest[4]}
    return {
        "score": score,
        "repo": repo,
        "key": [tool, rule, path, fingerprint],
        "severity": latest[0] if latest else None,
        "line": latest[1] if latest else None,
        "message": latest[2] if latest else "",
        "last_seen": latest[5] if latest else None,
        "decision": decision,
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
