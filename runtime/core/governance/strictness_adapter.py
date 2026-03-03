"""Behavioral strictness tuning with invariant-preserving guardrails."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from errors import PolicyViolationError

DEFAULT_SYSTEM_STRICTNESS = 0.75


@dataclass(frozen=True)
class StrictnessProfile:
    system_strictness: float
    risk_deny_threshold: float
    deep_trigger_aggressiveness: float
    minority_escalation_sensitivity: float
    entropy_tolerance: float
    economic_throttle_aggressiveness: float
    atomic_threshold_floor: float
    pii_redaction_enabled: bool
    capability_enforcer_required: bool
    diff_only_mutation_required: bool
    endpoint_allowlist_required: bool
    credential_exposure_forbidden: bool


def derive_strictness_profile(*, system_strictness: float = DEFAULT_SYSTEM_STRICTNESS) -> StrictnessProfile:
    s = _normalize(system_strictness)
    profile = StrictnessProfile(
        system_strictness=s,
        # Higher strictness => lower deny threshold => deny sooner.
        risk_deny_threshold=round(max(0.45, 0.8 - (0.3 * s)), 4),
        # Higher strictness => more likely to escalate for caution.
        deep_trigger_aggressiveness=round(0.35 + (0.65 * s), 4),
        minority_escalation_sensitivity=round(0.25 + (0.7 * s), 4),
        # Higher strictness => lower tolerance.
        entropy_tolerance=round(max(0.2, 0.75 - (0.45 * s)), 4),
        economic_throttle_aggressiveness=round(0.35 + (0.65 * s), 4),
        atomic_threshold_floor=0.7,
        pii_redaction_enabled=True,
        capability_enforcer_required=True,
        diff_only_mutation_required=True,
        endpoint_allowlist_required=True,
        credential_exposure_forbidden=True,
    )
    assert_invariants(profile)
    return profile


def strictness_profile_dict(*, system_strictness: float = DEFAULT_SYSTEM_STRICTNESS) -> dict[str, Any]:
    return asdict(derive_strictness_profile(system_strictness=system_strictness))


def assert_invariants(profile: StrictnessProfile) -> None:
    if profile.atomic_threshold_floor < 0.7:
        raise PolicyViolationError("strictness invariant violated: atomic threshold floor below 0.7")
    if not profile.pii_redaction_enabled:
        raise PolicyViolationError("strictness invariant violated: PII redaction cannot be disabled")
    if not profile.capability_enforcer_required:
        raise PolicyViolationError("strictness invariant violated: CapabilityEnforcer cannot be disabled")
    if not profile.diff_only_mutation_required:
        raise PolicyViolationError("strictness invariant violated: diff-only mutation boundary cannot be disabled")
    if not profile.endpoint_allowlist_required:
        raise PolicyViolationError("strictness invariant violated: endpoint allowlist cannot be disabled")
    if not profile.credential_exposure_forbidden:
        raise PolicyViolationError("strictness invariant violated: credential exposure protection cannot be disabled")


def _normalize(value: float) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        f = DEFAULT_SYSTEM_STRICTNESS
    if f < 0.0:
        return 0.0
    if f > 1.0:
        return 1.0
    return round(f, 4)

