"""Bounded economic policy adjustments based on resource scarcity."""

from __future__ import annotations

from typing import Any

from errors import PolicyViolationError


def apply_economic_policy(
    *,
    scarcity_index_by_platform: dict[str, Any],
    org_policy: dict[str, Any] | None,
    base_atomic_threshold: float = 0.7,
    base_high_threshold: float = 0.8,
    base_deep_threshold: float = 0.85,
    audit_log: Any | None = None,
) -> dict[str, Any]:
    """Apply bounded deterministic threshold/tier adjustments."""
    if not isinstance(scarcity_index_by_platform, dict):
        raise PolicyViolationError("scarcity_index_by_platform must be an object")
    if round(float(base_atomic_threshold), 4) != 0.7:
        raise PolicyViolationError("Atomic threshold is immutable and must remain 0.7")

    scarcity = _effective_scarcity(scarcity_index_by_platform)
    max_writes = _base_write_budget(org_policy)

    adjusted_high = float(base_high_threshold)
    adjusted_deep = float(base_deep_threshold)
    deep_enabled = True
    minority_enabled = True
    adjusted_write_budget = max_writes

    if scarcity <= 0.3:
        low_ratio = (0.3 - scarcity) / 0.3  # 0..1
        adjusted_deep -= 0.02 * low_ratio
        minority_enabled = True
    elif scarcity < 0.75:
        moderate_ratio = (scarcity - 0.3) / 0.45  # 0..1
        adjusted_high += 0.01 * moderate_ratio
        adjusted_deep += 0.015 * moderate_ratio
    else:
        high_ratio = (scarcity - 0.75) / 0.25  # 0..1 up to 1 at 1.0
        if high_ratio < 0.0:
            high_ratio = 0.0
        if high_ratio > 1.0:
            high_ratio = 1.0
        adjusted_deep += 0.03 * high_ratio
        minority_enabled = False
        adjusted_write_budget = max(1, max_writes - 1)

    if scarcity >= 0.9:
        deep_enabled = False
        minority_enabled = False
        if audit_log is not None:
            audit_log.append(
                actor="runtime.core.economics.economic_policy_adapter",
                action="economics.deep_disabled",
                target="policy",
                details={"scarcity_index": round(scarcity, 4)},
            )

    adjusted_high = _bounded_threshold(
        value=adjusted_high,
        base=base_high_threshold,
        floor=0.75,
        cap=0.90,
    )
    adjusted_deep = _bounded_threshold(
        value=adjusted_deep,
        base=base_deep_threshold,
        floor=0.80,
        cap=0.90,
    )

    out = {
        "adjusted_high_threshold": adjusted_high,
        "adjusted_deep_threshold": adjusted_deep,
        "deep_enabled": deep_enabled,
        "minority_escalation_enabled": minority_enabled,
        "adjusted_write_budget": adjusted_write_budget,
    }
    if audit_log is not None:
        audit_log.append(
            actor="runtime.core.economics.economic_policy_adapter",
            action="economics.adjustment",
            target="policy",
            details={
                "scarcity_index": round(scarcity, 4),
                "base_atomic_threshold": round(float(base_atomic_threshold), 4),
                "base_high_threshold": round(float(base_high_threshold), 4),
                "base_deep_threshold": round(float(base_deep_threshold), 4),
                **out,
            },
        )
    return out


def _effective_scarcity(values: dict[str, Any]) -> float:
    maximum = 0.0
    for value in values.values():
        try:
            f = float(value)
        except (TypeError, ValueError):
            continue
        if f < 0.0:
            f = 0.0
        if f > 1.0:
            f = 1.0
        if f > maximum:
            maximum = f
    return maximum


def _base_write_budget(org_policy: dict[str, Any] | None) -> int:
    default = 3
    if not isinstance(org_policy, dict):
        return default
    spec = org_policy.get("spec")
    if not isinstance(spec, dict):
        return default
    knowledge = spec.get("knowledge_policy")
    if not isinstance(knowledge, dict):
        return default
    raw = knowledge.get("max_memory_writes_per_loop", default)
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        return default
    return max(1, parsed)


def _bounded_threshold(*, value: float, base: float, floor: float, cap: float) -> float:
    lower = base - 0.05
    upper = base + 0.05
    bounded = min(max(value, lower), upper)
    bounded = min(max(bounded, floor), cap)
    return round(bounded, 4)

