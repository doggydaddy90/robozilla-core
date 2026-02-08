"""Evaluation submission and job progression enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from errors import ConflictError, PolicyViolationError
from executor.state_machine import TransitionRequest, apply_transition, is_terminal
from registry.registry import Registry
from registry.schema_validator import SchemaValidator
from storage.interfaces import EvaluationStore, JobStore
from utils import deep_get, parse_rfc3339, utcnow


@dataclass(frozen=True)
class EvaluationResult:
    evaluation: dict[str, Any]
    job: dict[str, Any]


def _evaluation_ref(evaluation_id: str) -> str:
    # URI-reference compatible, relative to the runtime API surface.
    return f"evaluations/{evaluation_id}"


class EvaluationService:
    def __init__(
        self,
        *,
        schema_validator: SchemaValidator,
        registry: Registry,
        evaluation_store: EvaluationStore,
        job_store: JobStore,
    ):
        self._schemas = schema_validator
        self._registry = registry
        self._evals = evaluation_store
        self._jobs = job_store

    def submit(self, evaluation: dict[str, Any]) -> EvaluationResult:
        now = utcnow()
        self._schemas.validate("Evaluation", evaluation)

        evaluation_id = str(deep_get(evaluation, ["metadata", "evaluation_id"]))
        org_id = str(deep_get(evaluation, ["metadata", "org_id"]))
        job_id = str(deep_get(evaluation, ["spec", "job_ref", "job_id"]))

        job = self._jobs.get(job_id)
        job_org_id = str(deep_get(job, ["metadata", "org_id"]))
        if job_org_id != org_id:
            raise PolicyViolationError("Evaluation.metadata.org_id must match JobContract.metadata.org_id")

        current = str(deep_get(job, ["spec", "status", "state"]))
        if is_terminal(current):
            raise ConflictError(f"Cannot apply evaluation to terminal job (state={current})")

        # Expiry is system-enforced; evaluations can't revive expired jobs.
        expires_at = parse_rfc3339(str(deep_get(job, ["spec", "timestamps", "expires_at"])))
        if expires_at <= now and not is_terminal(str(deep_get(job, ["spec", "status", "state"]))):
            expired = apply_transition(job, TransitionRequest(new_state="expired", now=now, expiry_reason="expires_at_reached"))
            self._schemas.validate("JobContract", expired)
            self._jobs.update(expired)
            self._jobs.record_event(org_id=org_id, job_id=job_id, event_type="job_expired", details={"reason": "expires_at_reached"})
            raise ConflictError("Job is expired; evaluation cannot be applied")

        # Enforce evaluator identity and authority.
        evaluator = deep_get(evaluation, ["spec", "evaluator"])
        actor_type = str(evaluator.get("actor_type"))
        actor_id = str(evaluator.get("actor_id"))
        declared_authority = str(evaluator.get("authority_level"))

        if actor_type == "agent":
            agent = self._registry.get_agent(actor_id)
            agent_authority = str(deep_get(agent.document, ["spec", "authority", "level"]))
            if agent_authority != declared_authority:
                raise PolicyViolationError("Evaluation evaluator authority_level does not match AgentDefinition authority level")

            # Enforce that the agent is included in the org manifest.
            if not self._registry.has_org(org_id):
                raise PolicyViolationError("Cannot validate evaluator membership: org_id not found in registry")
            included = self._registry.included_agent_ids_for_org(org_id)
            if actor_id not in included:
                raise PolicyViolationError("Evaluator agent is not included in OrganizationManifest.spec.agent_roles")

        # No agent may self-evaluate its own artifacts.
        if actor_type == "agent":
            decisions = deep_get(evaluation, ["spec", "artifact_decisions"])
            if isinstance(decisions, list):
                for d in decisions:
                    if not isinstance(d, dict):
                        continue
                    producing = str(d.get("producing_agent_id", ""))
                    if producing and producing == actor_id:
                        raise PolicyViolationError("Self-evaluation is prohibited (evaluator matches producing_agent_id)")

        # Apply job transition as decided by the evaluation.
        desired = str(deep_get(evaluation, ["spec", "outcome", "next_job_state"]))

        final_ref = _evaluation_ref(evaluation_id)
        if desired == "completed":
            updated = apply_transition(
                job,
                TransitionRequest(new_state="completed", now=now, final_evaluation_ref=final_ref, last_stop_condition="evaluation_passed"),
            )
        elif desired == "failed":
            updated = apply_transition(
                job,
                TransitionRequest(
                    new_state="failed",
                    now=now,
                    final_evaluation_ref=final_ref,
                    failure_mode="evaluation_failure",
                    last_stop_condition="evaluation_failed",
                ),
            )
        elif desired in ("running", "waiting"):
            updated = apply_transition(job, TransitionRequest(new_state=desired, now=now))
        else:
            raise PolicyViolationError(f"Invalid evaluation next_job_state: {desired}")

        self._schemas.validate("JobContract", updated)

        # Persist evaluation (append-only) then apply the decided job transition.
        self._evals.append(evaluation)
        self._jobs.record_event(org_id=org_id, job_id=job_id, event_type="evaluation_submitted", details={"evaluation_id": evaluation_id})

        self._jobs.update(updated)
        self._jobs.record_event(org_id=org_id, job_id=job_id, event_type="job_state_changed", details={"from": current, "to": desired})

        return EvaluationResult(evaluation=evaluation, job=updated)
