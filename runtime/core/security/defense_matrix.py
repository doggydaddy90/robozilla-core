"""Trust-level defense matrix without bypassing core enforcement."""

from __future__ import annotations

import math
from collections import Counter
from typing import Any, Callable

from errors import PolicyViolationError
from governance.strictness_adapter import derive_strictness_profile
from security.intent_classifier import classify_intent_risk
from security.prompt_injection_filter import sanitize_untrusted_content


def apply_defense_matrix(
    *,
    trust_assessment: dict[str, str],
    content: str,
    capability_check: Callable[[], None],
    strictness: float = 0.75,
    schema_validator: Callable[[str], None] | None = None,
    audit_log: Any | None = None,
) -> dict[str, Any]:
    if not callable(capability_check):
        raise PolicyViolationError("capability_check must be callable")
    capability_check()  # Mandatory for every trust level.

    trust_level = _trust_level(trust_assessment)
    profile = derive_strictness_profile(system_strictness=strictness)
    sanitized = str(content)
    intent: dict[str, Any] = {"applied": False, "risk_score": 0.0, "risk_category": "low", "matched_signals": []}
    filter_mode = "none"
    entropy_checked = False

    if trust_level == "internal_system":
        # No injection/intent preprocessing for strongly trusted typed requests.
        pass
    elif trust_level == "structured_external":
        filter_mode = "light"
        sanitized = sanitize_untrusted_content(content=sanitized, mode="light")
        intent = classify_intent_risk(content=sanitized, trust_level=trust_level, strictness=profile.system_strictness)
        if schema_validator is not None:
            schema_validator(sanitized)
    else:
        filter_mode = "full"
        sanitized = sanitize_untrusted_content(content=sanitized, mode="full")
        intent = classify_intent_risk(content=sanitized, trust_level=trust_level, strictness=profile.system_strictness)
        entropy_checked = True
        _enforce_entropy_guard(
            text=sanitized,
            tolerance=profile.entropy_tolerance,
        )
        if intent.get("risk_category") == "high":
            _log(audit_log, action="intent.risk.high", details={"trust_level": trust_level, "signals": intent.get("matched_signals", [])})

    risk_score = float(intent.get("risk_score", 0.0))
    if risk_score > 0.7:
        raise PolicyViolationError("high-risk intent denied before tool execution")
    if risk_score >= profile.risk_deny_threshold and trust_level != "internal_system":
        raise PolicyViolationError("intent risk exceeds strictness threshold")

    _log(
        audit_log,
        action="defense.matrix.applied",
        details={
            "trust_level": trust_level,
            "filter_mode": filter_mode,
            "intent_category": intent.get("risk_category"),
            "risk_score": round(risk_score, 4),
            "entropy_checked": entropy_checked,
        },
    )
    return {
        "trust_level": trust_level,
        "sanitized_content": sanitized,
        "filter_mode": filter_mode,
        "intent": intent,
    }


def _enforce_entropy_guard(*, text: str, tolerance: float) -> None:
    max_entropy = _max_token_entropy(text)
    # Higher strictness => lower tolerance (already encoded in profile.entropy_tolerance).
    threshold = max(3.2, 5.4 - (2.0 * (1.0 - tolerance)))
    if max_entropy >= threshold:
        raise PolicyViolationError("entropy guard triggered on unstructured content")


def _max_token_entropy(text: str) -> float:
    tokens = [tok for tok in text.split() if len(tok) >= 24]
    if not tokens:
        return 0.0
    entropies = [_shannon_entropy(tok) for tok in tokens]
    return max(entropies)


def _shannon_entropy(token: str) -> float:
    n = len(token)
    if n == 0:
        return 0.0
    counts = Counter(token)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return entropy


def _trust_level(assessment: dict[str, str]) -> str:
    level = str((assessment or {}).get("trust_level", "")).strip().lower()
    if level not in {"internal_system", "structured_external", "unstructured_external"}:
        raise PolicyViolationError("invalid trust assessment trust_level")
    return level


def _log(audit_log: Any | None, *, action: str, details: dict[str, Any]) -> None:
    if audit_log is None:
        return
    safe = {k: v for k, v in details.items() if k != "content"}
    audit_log.append(actor="runtime.core.security.defense_matrix", action=action, target="roland", details=safe)

