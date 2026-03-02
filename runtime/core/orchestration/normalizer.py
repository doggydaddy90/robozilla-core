"""Deterministic normalizer for admitted research candidates.

Transforms router output + admission result into canonical RAG entry format.
No file I/O, no network calls, and no side effects.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from errors import PolicyViolationError


def normalize_candidate(
    *,
    router_json: dict[str, Any],
    admission_result: dict[str, Any],
    previous_entry: dict[str, Any] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Normalize an admitted candidate into canonical RAG entry shape.

    Determinism notes:
    - Hashes use canonical JSON serialization.
    - If `created_at` is omitted, we use router_json.created_at when present;
      otherwise a fixed epoch timestamp for deterministic output.
    """
    if not isinstance(router_json, dict):
        raise PolicyViolationError("router_json must be an object")
    if not isinstance(admission_result, dict):
        raise PolicyViolationError("admission_result must be an object")

    if not bool(admission_result.get("admit", False)):
        raise PolicyViolationError("candidate is not admitted")

    topic = _topic_from_router(router_json)
    citations = _extract_citations(router_json)
    if not citations:
        raise PolicyViolationError("at least one citation URL is required for normalization")

    resolved_created_at = _resolve_created_at(router_json, created_at)
    confidence_score = _clamp01(_to_float(admission_result.get("confidence_score", 0.0)))
    version = _next_version(previous_entry)

    topic_hash = _sha256_hex(topic.strip().lower())
    source_hash = _source_hash(citations)
    content_blocks = _extract_content_blocks(router_json, citations, confidence_score)

    document_id = _sha256_hex(
        _canonical_json(
            {
                "topic_hash": topic_hash,
                "source_hash": source_hash,
                "content_blocks": [block["fact_text"] for block in content_blocks],
                "version": version,
            }
        )
    )

    return {
        "document_id": document_id,
        "topic": topic,
        "topic_hash": topic_hash,
        "source_hash": source_hash,
        "version": version,
        "created_at": resolved_created_at,
        "confidence_score": confidence_score,
        "citations": citations,
        "content_blocks": content_blocks,
    }


def _topic_from_router(router_json: dict[str, Any]) -> str:
    query = router_json.get("query")
    if isinstance(query, str) and query.strip():
        return query.strip()

    candidate_doc = router_json.get("candidate_document")
    if isinstance(candidate_doc, dict):
        topic = candidate_doc.get("topic")
        if isinstance(topic, str) and topic.strip():
            return topic.strip()

    return "untitled-topic"


def _extract_citations(router_json: dict[str, Any]) -> list[str]:
    candidate_doc = router_json.get("candidate_document")
    if not isinstance(candidate_doc, dict):
        return []

    raw = candidate_doc.get("citations")
    if not isinstance(raw, list):
        return []

    urls: set[str] = set()
    for item in raw:
        if isinstance(item, str):
            url = item.strip()
        elif isinstance(item, dict):
            url = str(item.get("url", "")).strip()
        else:
            continue
        normalized = _normalize_url(url)
        if normalized:
            urls.add(normalized)

    return sorted(urls)


def _extract_content_blocks(
    router_json: dict[str, Any],
    citations: list[str],
    confidence_score: float,
) -> list[dict[str, Any]]:
    candidate_doc = router_json.get("candidate_document")
    if not isinstance(candidate_doc, dict):
        candidate_doc = {}

    atomic_entries: list[str] = []

    facts = candidate_doc.get("facts")
    if isinstance(facts, list):
        for item in facts:
            if isinstance(item, str) and item.strip():
                atomic_entries.append(item.strip())
            elif isinstance(item, dict):
                text = str(item.get("text") or item.get("fact") or item.get("statement") or "").strip()
                if text:
                    atomic_entries.append(text)

    if not atomic_entries:
        content_blocks = candidate_doc.get("content_blocks")
        if isinstance(content_blocks, list):
            for item in content_blocks:
                if isinstance(item, str) and item.strip():
                    atomic_entries.append(item.strip())
                elif isinstance(item, dict):
                    text = str(item.get("text") or item.get("fact_text") or "").strip()
                    if text:
                        atomic_entries.append(text)

    if not atomic_entries:
        for field in ("summary", "outline", "key_points"):
            value = candidate_doc.get(field)
            if isinstance(value, str) and value.strip():
                atomic_entries.append(value.strip())
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item.strip():
                        atomic_entries.append(item.strip())

    if not atomic_entries:
        atomic_entries.append(_canonical_json(candidate_doc))

    out: list[dict[str, Any]] = []
    for idx, fact_text in enumerate(atomic_entries):
        fact_id = _sha256_hex(
            _canonical_json({"index": idx, "fact_text": fact_text, "citations": citations})
        )
        out.append(
            {
                "fact_id": fact_id,
                "fact_text": fact_text,
                "citations": citations,
                "confidence_score": confidence_score,
            }
        )
    return out


def _next_version(previous_entry: dict[str, Any] | None) -> int:
    if not isinstance(previous_entry, dict):
        return 1
    raw = previous_entry.get("version", 0)
    try:
        current = int(raw)
    except (TypeError, ValueError):
        current = 0
    return (current if current > 0 else 0) + 1


def _resolve_created_at(router_json: dict[str, Any], created_at: str | None) -> str:
    if isinstance(created_at, str) and _is_valid_iso(created_at):
        return created_at

    from_router = router_json.get("created_at")
    if isinstance(from_router, str) and _is_valid_iso(from_router):
        return from_router

    # Deterministic fallback.
    return "1970-01-01T00:00:00Z"


def _is_valid_iso(value: str) -> bool:
    v = value.strip()
    if not v:
        return False
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return False
    return dt.tzinfo is not None


def _normalize_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    scheme = parsed.scheme.lower()
    host = parsed.netloc.lower()
    path = parsed.path or "/"
    return f"{scheme}://{host}{path}"


def _source_hash(citations: list[str]) -> str:
    return _sha256_hex(_canonical_json(sorted(citations)))


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return round(value, 4)

