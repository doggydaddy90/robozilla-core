"""RAG knowledge monitor for stale/low-confidence/conflict detection.

This module is read-only: it scans existing RAG documents and returns a report.
No disk mutation and no external API/network calls.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from errors import PolicyViolationError
from security.pathGuard import resolve_path, safeRead

_DEFAULT_FRESHNESS_DAYS = 30
_DEFAULT_REVIEW_CONFIDENCE_THRESHOLD = 0.60


def monitor_knowledge(
    *,
    rag_dir: Path | str = "rag",
    org_policy: dict[str, Any] | None = None,
    freshness_threshold_days: int | None = None,
    review_confidence_threshold: float | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Scan RAG entries and return conditions requiring review/re-research.

    Report shape:
    {
      "stale_topics": [...],
      "low_confidence_topics": [...],
      "conflict_topics": [...]
    }
    """
    now_utc = now.astimezone(timezone.utc) if now is not None else datetime.now(timezone.utc)
    freshness_days, confidence_threshold = _resolve_thresholds(
        org_policy=org_policy,
        freshness_threshold_days=freshness_threshold_days,
        review_confidence_threshold=review_confidence_threshold,
    )

    root = resolve_path(rag_dir, operation="read", require_exists=False)
    if not root.exists() or not root.is_dir():
        return {"stale_topics": [], "low_confidence_topics": [], "conflict_topics": []}

    stale_topics: list[dict[str, Any]] = []
    low_confidence_topics: list[dict[str, Any]] = []
    topic_index: dict[str, list[dict[str, Any]]] = {}

    for path in sorted(root.rglob("*.json"), key=lambda p: str(p).replace("\\", "/")):
        resolved = resolve_path(path, operation="read", require_exists=True)
        raw = safeRead(resolved, actor="runtime.core.knowledge_monitor")
        try:
            doc = json.loads(str(raw))
        except json.JSONDecodeError:
            continue
        if not isinstance(doc, dict):
            continue

        topic_hash = str(doc.get("topic_hash", "")).strip()
        source_hash = str(doc.get("source_hash", "")).strip()
        document_id = str(doc.get("document_id", "")).strip() or resolved.stem
        created_at = str(doc.get("created_at", "")).strip()
        confidence_score = _to_float(doc.get("confidence_score", 0.0))

        if not topic_hash or not source_hash:
            continue

        parsed_created = _parse_iso(created_at)
        if parsed_created is None:
            age_days = freshness_days + 1
        else:
            delta = now_utc - parsed_created
            age_days = max(0.0, delta.total_seconds() / 86400.0)

        if age_days > float(freshness_days):
            stale_topics.append(
                {
                    "topic_hash": topic_hash,
                    "document_id": document_id,
                    "age_days": round(age_days, 4),
                }
            )

        if confidence_score < confidence_threshold:
            low_confidence_topics.append(
                {
                    "topic_hash": topic_hash,
                    "document_id": document_id,
                    "confidence_score": round(confidence_score, 4),
                }
            )

        topic_index.setdefault(topic_hash, []).append(
            {
                "document_id": document_id,
                "source_hash": source_hash,
            }
        )

    conflict_topics: list[dict[str, Any]] = []
    for topic_hash, rows in topic_index.items():
        source_hashes = sorted({str(r["source_hash"]) for r in rows})
        if len(source_hashes) <= 1:
            continue
        conflict_topics.append(
            {
                "topic_hash": topic_hash,
                "source_hashes": source_hashes,
                "document_ids": sorted({str(r["document_id"]) for r in rows}),
            }
        )

    stale_topics.sort(key=lambda x: (str(x["topic_hash"]), str(x["document_id"])))
    low_confidence_topics.sort(key=lambda x: (str(x["topic_hash"]), str(x["document_id"])))
    conflict_topics.sort(key=lambda x: str(x["topic_hash"]))

    return {
        "stale_topics": stale_topics,
        "low_confidence_topics": low_confidence_topics,
        "conflict_topics": conflict_topics,
    }


def _resolve_thresholds(
    *,
    org_policy: dict[str, Any] | None,
    freshness_threshold_days: int | None,
    review_confidence_threshold: float | None,
) -> tuple[int, float]:
    if freshness_threshold_days is None:
        freshness_threshold_days = _extract_freshness_days(org_policy)
    if review_confidence_threshold is None:
        review_confidence_threshold = _extract_review_threshold(org_policy)

    if not isinstance(freshness_threshold_days, int) or freshness_threshold_days < 0:
        raise PolicyViolationError("freshness_threshold_days must be an integer >= 0")
    try:
        threshold = float(review_confidence_threshold)
    except (TypeError, ValueError) as exc:
        raise PolicyViolationError("review_confidence_threshold must be numeric") from exc
    if threshold < 0.0 or threshold > 1.0:
        raise PolicyViolationError("review_confidence_threshold must be within [0,1]")
    return freshness_threshold_days, threshold


def _extract_freshness_days(org_policy: dict[str, Any] | None) -> int:
    if not isinstance(org_policy, dict):
        return _DEFAULT_FRESHNESS_DAYS

    direct = org_policy.get("freshness_threshold_days")
    if isinstance(direct, int):
        return direct

    spec = org_policy.get("spec")
    if isinstance(spec, dict):
        knowledge = spec.get("knowledge_policy")
        if isinstance(knowledge, dict):
            value = knowledge.get("freshness_threshold_days")
            if isinstance(value, int):
                return value
    return _DEFAULT_FRESHNESS_DAYS


def _extract_review_threshold(org_policy: dict[str, Any] | None) -> float:
    if not isinstance(org_policy, dict):
        return _DEFAULT_REVIEW_CONFIDENCE_THRESHOLD

    direct = org_policy.get("review_confidence_threshold")
    if isinstance(direct, (int, float)):
        return float(direct)

    spec = org_policy.get("spec")
    if isinstance(spec, dict):
        knowledge = spec.get("knowledge_policy")
        if isinstance(knowledge, dict):
            value = knowledge.get("review_confidence_threshold")
            if isinstance(value, (int, float)):
                return float(value)
    return _DEFAULT_REVIEW_CONFIDENCE_THRESHOLD


def _parse_iso(value: str) -> datetime | None:
    if not value:
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(timezone.utc)


def _to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0

