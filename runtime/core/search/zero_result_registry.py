"""SQLite-backed zero-result memory for premium search escalation control."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from errors import PolicyViolationError
from security.pathGuard import resolve_path

DEFAULT_DB_PATH = Path("runtime/core/state/zero_result_registry.sqlite")

_TOKEN_RE = re.compile(
    r'"[^"]*"|\(|\)|\bAND\b|\bOR\b|\bNOT\b|AROUND\(\d+\)|filetype:[^\s()]+|site:[^\s()]+|[^\s()]+',
    re.IGNORECASE,
)
_DATE_BOUND_RE = re.compile(
    r"\b(?:after|before|since|until|from|to):\S+\b|\b\d{4}-\d{2}-\d{2}\b|\b\d{4}/\d{2}/\d{2}\b",
    re.IGNORECASE,
)
_DYNAMIC_TOKEN_RE = re.compile(
    r"\b\d{5,}\b|\b[0-9a-f]{8,}\b|\b[0-9a-f]{8}-[0-9a-f-]{27,}\b|(?:%[0-9a-fA-F]{2}){6,}",
    re.IGNORECASE,
)


def compute_query_signature(normalized_query: str) -> str:
    if not isinstance(normalized_query, str) or not normalized_query.strip():
        raise PolicyViolationError("normalized_query must be a non-empty string")
    structural = _normalize_operator_structure(normalized_query)
    return hashlib.sha256(structural.encode("utf-8")).hexdigest()


def record_zero_result(
    engine: str,
    normalized_query: str,
    entropy_score: float,
    *,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> None:
    engine_norm = _normalize_engine(engine)
    signature = compute_query_signature(normalized_query)
    entropy = _clamp01(entropy_score)
    now_iso = _utc_now_iso()

    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO zero_result_registry(engine, query_signature, zero_count, last_seen, entropy_score)
            VALUES (?, ?, 1, ?, ?)
            ON CONFLICT(engine, query_signature)
            DO UPDATE SET
                zero_count = zero_result_registry.zero_count + 1,
                last_seen = excluded.last_seen,
                entropy_score = excluded.entropy_score
            """,
            (engine_norm, signature, now_iso, entropy),
        )


def should_block_premium(
    engine: str,
    normalized_query: str,
    entropy_score: float,
    *,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> bool:
    engine_norm = _normalize_engine(engine)
    signature = compute_query_signature(normalized_query)
    entropy_now = _clamp01(entropy_score)

    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT zero_count, entropy_score
            FROM zero_result_registry
            WHERE engine = ? AND query_signature = ?
            """,
            (engine_norm, signature),
        ).fetchone()

    if row is None:
        return False
    zero_count = int(row["zero_count"])
    entropy_mem = _clamp01(row["entropy_score"])
    effective_entropy = max(entropy_now, entropy_mem)
    if zero_count >= 3:
        return True
    if zero_count >= 2 and effective_entropy >= 0.85:
        return True
    return False


def decay_old_entries(
    *,
    days: int = 30,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> int:
    try:
        max_age_days = int(days)
    except (TypeError, ValueError) as exc:
        raise PolicyViolationError("days must be an integer") from exc
    if max_age_days <= 0:
        raise PolicyViolationError("days must be > 0")

    cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat().replace("+00:00", "Z")
    with _connect(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM zero_result_registry WHERE last_seen < ?",
            (cutoff,),
        )
        return int(cur.rowcount or 0)


def reset_entry(
    engine: str,
    query_signature: str,
    *,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> None:
    engine_norm = _normalize_engine(engine)
    signature = str(query_signature).strip().lower()
    if not signature:
        raise PolicyViolationError("query_signature must be non-empty")
    with _connect(db_path) as conn:
        conn.execute(
            "DELETE FROM zero_result_registry WHERE engine = ? AND query_signature = ?",
            (engine_norm, signature),
        )


def _normalize_operator_structure(query: str) -> str:
    q = _DATE_BOUND_RE.sub(" ", query.strip().lower())
    q = _DYNAMIC_TOKEN_RE.sub(" ", q)
    tokens = [tok.strip() for tok in _TOKEN_RE.findall(q) if tok.strip()]
    if not tokens:
        return "EMPTY"

    out: list[str] = []
    for token in tokens:
        upper = token.upper()
        if token in {"(", ")"}:
            out.append(token)
            continue
        if upper in {"AND", "OR", "NOT"}:
            out.append(upper)
            continue
        if re.fullmatch(r"AROUND\(\d+\)", token, flags=re.IGNORECASE):
            out.append("AROUND")
            continue
        if token.startswith("site:"):
            out.append("SITE")
            continue
        if token.startswith("filetype:"):
            out.append("FILETYPE")
            continue
        if token.startswith('"') and token.endswith('"'):
            out.append("PHRASE")
            continue
        out.append("TERM")
    return " ".join(out)


@contextmanager
def _connect(db_path: Path | str):
    resolved = resolve_path(db_path, operation="zero_result_registry", require_exists=False)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(resolved), timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS zero_result_registry(
                engine TEXT NOT NULL,
                query_signature TEXT NOT NULL,
                zero_count INTEGER NOT NULL,
                last_seen TEXT NOT NULL,
                entropy_score REAL NOT NULL,
                PRIMARY KEY(engine, query_signature)
            )
            """
        )
        yield conn
    finally:
        conn.close()


def _normalize_engine(engine: str) -> str:
    value = str(engine).strip().lower()
    if not value:
        raise PolicyViolationError("engine must be a non-empty string")
    return value


def _clamp01(value: Any) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return 0.0
    if f < 0.0:
        return 0.0
    if f > 1.0:
        return 1.0
    return round(f, 4)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
