"""Risk scoring for external-content intent."""

from __future__ import annotations

import re
from typing import Any

from errors import PolicyViolationError

_PATTERNS: dict[str, tuple[re.Pattern[str], float]] = {
    "secret_extraction": (
        re.compile(
            r"(api[_\s-]?key|oauth|jwt|token|password|private[_\s-]?key|\.env|ssh key|aws secret|access key)",
            re.IGNORECASE,
        ),
        0.82,
    ),
    "scope_override": (
        re.compile(
            r"(ignore\s+previous\s+instructions|bypass|disable\s+(guard|policy|enforcer)|override\s+scope)",
            re.IGNORECASE,
        ),
        0.54,
    ),
    "system_prompt_disclosure": (
        re.compile(r"(show|reveal|dump).*(system\s+prompt|hidden\s+instructions?)", re.IGNORECASE),
        0.58,
    ),
    "file_access": (
        re.compile(r"(/etc/passwd|id_rsa|private\.pem|read\s+file|cat\s+.+\.env)", re.IGNORECASE),
        0.48,
    ),
    "tool_misuse": (
        re.compile(r"(run\s+shell|execute\s+command|curl\s+.+http|exfiltrat|rm\s+-rf)", re.IGNORECASE),
        0.45,
    ),
}


def classify_intent_risk(
    *,
    content: str,
    trust_level: str,
    strictness: float = 0.75,
) -> dict[str, Any]:
    if not isinstance(content, str):
        raise PolicyViolationError("content must be a string")
    trust = str(trust_level).strip().lower()
    if trust not in {"internal_system", "structured_external", "unstructured_external"}:
        raise PolicyViolationError("invalid trust_level")

    if trust == "internal_system":
        return {
            "risk_score": 0.0,
            "risk_category": "low",
            "matched_signals": [],
            "applied": False,
        }

    strict = _normalize_strictness(strictness)
    multiplier = 0.7 if trust == "structured_external" else 1.0
    sensitivity_boost = 1.0 + ((strict - 0.75) * 0.6)
    score = 0.0
    matched: list[str] = []

    text = content.strip()
    for name, (pattern, weight) in _PATTERNS.items():
        if pattern.search(text):
            matched.append(name)
            score += weight

    adjusted = min(1.0, max(0.0, score * multiplier * sensitivity_boost))
    category = _risk_category(adjusted)
    return {
        "risk_score": round(adjusted, 4),
        "risk_category": category,
        "matched_signals": sorted(matched),
        "applied": True,
    }


def _normalize_strictness(value: float) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        f = 0.75
    if f < 0.0:
        return 0.0
    if f > 1.0:
        return 1.0
    return round(f, 4)


def _risk_category(score: float) -> str:
    if score < 0.4:
        return "low"
    if score <= 0.7:
        return "medium"
    return "high"
