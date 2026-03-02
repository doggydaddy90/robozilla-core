"""Deterministic admission controller for research candidates.

Evaluates whether a structured candidate document is admissible into RAG memory.
No file I/O, no side effects, no network calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AdmissionPolicy:
    min_citation_count: int = 2
    min_authority_score: float = 0.60
    min_freshness_score: float = 0.50
    require_no_unresolved_contradictions: bool = True


class AdmissionController:
    def __init__(self, *, policy: AdmissionPolicy = AdmissionPolicy()):
        self._policy = policy

    def evaluate(self, candidate: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(candidate, dict):
            return {"admit": False, "confidence_score": 0.0, "reasons": ["candidate must be an object"]}

        citation_count = _citation_count(candidate)
        authority_score = _score(candidate, "authority")
        freshness_score = _score(candidate, "freshness")
        unresolved_count = _unresolved_contradiction_count(candidate)

        reasons: list[str] = []
        if citation_count < self._policy.min_citation_count:
            reasons.append(
                f"citation count below threshold ({citation_count} < {self._policy.min_citation_count})"
            )
        if authority_score < self._policy.min_authority_score:
            reasons.append(
                f"authority score below threshold ({authority_score:.4f} < {self._policy.min_authority_score:.4f})"
            )
        if self._policy.require_no_unresolved_contradictions and unresolved_count > 0:
            reasons.append(f"unresolved contradiction flags present ({unresolved_count})")
        if freshness_score < self._policy.min_freshness_score:
            reasons.append(
                f"freshness policy not satisfied ({freshness_score:.4f} < {self._policy.min_freshness_score:.4f})"
            )

        confidence = _confidence_score(
            citation_count=citation_count,
            min_citation_count=self._policy.min_citation_count,
            authority_score=authority_score,
            freshness_score=freshness_score,
            unresolved_contradictions=unresolved_count,
            reasons_count=len(reasons),
        )

        return {"admit": len(reasons) == 0, "confidence_score": confidence, "reasons": reasons}


def _score(candidate: dict[str, Any], key: str) -> float:
    scores = candidate.get("scores")
    if not isinstance(scores, dict):
        return 0.0
    raw = scores.get(key, 0.0)
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return 0.0
    return _clamp01(value)


def _citation_count(candidate: dict[str, Any]) -> int:
    doc = candidate.get("candidate_document")
    if isinstance(doc, dict):
        for key in ("citations", "sources", "references"):
            values = doc.get(key)
            if isinstance(values, list):
                return len(values)
    return 0


def _unresolved_contradiction_count(candidate: dict[str, Any]) -> int:
    total = 0
    total += _count_from_flag(candidate.get("unresolved_contradictions"))

    doc = candidate.get("candidate_document")
    if isinstance(doc, dict):
        total += _count_from_flag(doc.get("unresolved_contradictions"))

        contradictions = doc.get("contradictions")
        if isinstance(contradictions, list):
            for item in contradictions:
                if isinstance(item, dict):
                    resolved = item.get("resolved")
                    status = str(item.get("status", "")).strip().lower()
                    if resolved is False or status == "unresolved":
                        total += 1
                elif item:
                    total += 1
    return total


def _count_from_flag(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int):
        return value if value > 0 else 0
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return 1
    return 0


def _confidence_score(
    *,
    citation_count: int,
    min_citation_count: int,
    authority_score: float,
    freshness_score: float,
    unresolved_contradictions: int,
    reasons_count: int,
) -> float:
    if min_citation_count <= 0:
        citation_component = 1.0
    else:
        citation_component = _clamp01(float(citation_count) / float(min_citation_count))

    contradiction_component = 1.0 if unresolved_contradictions == 0 else 0.0

    raw = (
        0.35 * _clamp01(authority_score)
        + 0.25 * _clamp01(freshness_score)
        + 0.25 * citation_component
        + 0.15 * contradiction_component
    )
    penalized = max(0.0, raw - 0.15 * float(reasons_count))
    return round(_clamp01(penalized), 4)


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value

