"""Job lifecycle state machine.

Canonical lifecycle:
created -> running -> waiting -> completed | failed | expired

Notes:
- Only `spec.status` is mutable on a JobContract.
- Only Evaluations can mark jobs completed/failed (enforced by the API service).
- Expiry is a system-enforced transition and does not require an Evaluation.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from errors import ConflictError, ContractViolationError
from utils import deep_get, format_rfc3339


_TERMINAL_STATES = {"completed", "failed", "expired"}

# Allowed transitions excluding no-op transitions. Expiry is handled separately.
_ALLOWED: dict[str, set[str]] = {
    "created": {"running", "waiting", "completed", "failed"},
    "running": {"waiting", "completed", "failed"},
    "waiting": {"running", "completed", "failed"},
    "completed": set(),
    "failed": set(),
    "expired": set(),
}


@dataclass(frozen=True)
class TransitionRequest:
    new_state: str
    now: datetime
    final_evaluation_ref: str | None = None
    failure_mode: str | None = None
    failure_details: str | None = None
    expiry_reason: str | None = None
    last_stop_condition: str | None = None


def is_terminal(state: str) -> bool:
    return state in _TERMINAL_STATES


def apply_transition(job: dict[str, Any], req: TransitionRequest) -> dict[str, Any]:
    """Return a new JobContract document with an updated spec.status."""
    current_state = str(deep_get(job, ["spec", "status", "state"]))
    new_state = req.new_state

    if new_state == current_state:
        return job

    if is_terminal(current_state):
        raise ConflictError(f"Job is terminal; cannot transition from {current_state} to {new_state}")

    if new_state == "expired":
        # Expiry can be applied from any non-terminal state.
        pass
    else:
        allowed = _ALLOWED.get(current_state)
        if allowed is None or new_state not in allowed:
            raise ConflictError(f"Invalid job state transition: {current_state} -> {new_state}")

    updated = deepcopy(job)
    status = deep_get(updated, ["spec", "status"])
    if not isinstance(status, dict):
        raise ContractViolationError("Invalid JobContract.spec.status shape", code="INVALID_JOB_STATUS")

    status["state"] = new_state
    status["status_updated_at"] = format_rfc3339(req.now)

    if new_state == "running":
        status.setdefault("started_at", format_rfc3339(req.now))

    if new_state in ("completed", "failed"):
        if not req.final_evaluation_ref:
            raise ContractViolationError("final_evaluation_ref is required for completed/failed jobs", code="MISSING_FINAL_EVALUATION_REF")
        status["final_evaluation_ref"] = req.final_evaluation_ref
        status["terminal_at"] = format_rfc3339(req.now)

    if new_state == "failed":
        if not req.failure_mode:
            raise ContractViolationError("failure_mode is required for failed jobs", code="MISSING_FAILURE_MODE")
        status["failure_mode"] = req.failure_mode
        if req.failure_details:
            status["failure_details"] = req.failure_details

    if new_state == "expired":
        if not req.expiry_reason:
            raise ContractViolationError("expiry_reason is required for expired jobs", code="MISSING_EXPIRY_REASON")
        status["expiry_reason"] = req.expiry_reason
        status["terminal_at"] = format_rfc3339(req.now)

    if req.last_stop_condition:
        status["last_stop_condition"] = req.last_stop_condition

    return updated

