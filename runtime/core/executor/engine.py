"""Job submission and execution-request engine (build mode).

This engine:
- Validates JobContract documents against canonical schemas
- Enforces global hard limits and org policy boundaries
- Applies job lifecycle transitions via the state machine
- Records audit events

It does NOT execute agents/skills/MCPs in build mode. Execution requests are
converted into a deterministic `waiting` state with an audit event explaining
the deferral.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from config.settings import LimitsConfig
from errors import ConflictError, NotFoundError, PolicyViolationError
from executor.policy import enforce_job_contract_limits, enforce_job_contract_submission_shape, enforce_job_within_org_policy
from executor.state_machine import TransitionRequest, apply_transition
from registry.registry import Registry
from registry.schema_validator import SchemaValidator
from storage.interfaces import JobStore
from utils import deep_get, parse_rfc3339, utcnow


@dataclass(frozen=True)
class EngineResult:
    job: dict[str, Any]


class JobEngine:
    def __init__(
        self,
        *,
        schema_validator: SchemaValidator,
        registry: Registry,
        job_store: JobStore,
        limits: LimitsConfig,
        execution_deferred: bool = True,
    ):
        self._schemas = schema_validator
        self._registry = registry
        self._jobs = job_store
        self._limits = limits
        self._execution_deferred = execution_deferred

    def submit_job(self, job: dict[str, Any]) -> EngineResult:
        now = utcnow()
        self._schemas.validate("JobContract", job)
        enforce_job_contract_submission_shape(job)
        enforce_job_contract_limits(job, limits=self._limits, now=now)

        org_id = str(deep_get(job, ["metadata", "org_id"]))
        if self._limits.require_known_org and not self._registry.has_org(org_id):
            raise PolicyViolationError(f"Unknown org_id (registry.require_known_org=true): {org_id}")

        if self._registry.has_org(org_id):
            org_doc = self._registry.get_org(org_id).document
            enforce_job_within_org_policy(job, org=org_doc)

        self._jobs.create(job)
        job_id = str(deep_get(job, ["metadata", "job_id"]))
        self._jobs.record_event(org_id=org_id, job_id=job_id, event_type="job_submitted", details={"state": "created"})
        return EngineResult(job=job)

    def get_job(self, job_id: str) -> dict[str, Any]:
        return self._jobs.get(job_id)

    def run_job(self, job_id: str) -> EngineResult:
        job = self._jobs.get(job_id)
        now = utcnow()

        org_id = str(deep_get(job, ["metadata", "org_id"]))
        expires_at = parse_rfc3339(str(deep_get(job, ["spec", "timestamps", "expires_at"])))

        if expires_at <= now:
            expired = apply_transition(job, TransitionRequest(new_state="expired", now=now, expiry_reason="expires_at_reached"))
            self._schemas.validate("JobContract", expired)
            self._jobs.update(expired)
            self._jobs.record_event(org_id=org_id, job_id=job_id, event_type="job_expired", details={"reason": "expires_at_reached"})
            return EngineResult(job=expired)

        state = str(deep_get(job, ["spec", "status", "state"]))
        if state not in ("created", "waiting"):
            raise ConflictError(f"Job must be in created|waiting to run (current={state})")

        # Enforce org execution limits (concurrency + rate limit) when org is known.
        if self._registry.has_org(org_id):
            org_doc = self._registry.get_org(org_id).document
            org_exec = deep_get(org_doc, ["spec", "execution_limits"])
            max_active_jobs = int(deep_get(org_exec, ["concurrency", "max_active_jobs"]))
            if max_active_jobs <= 0:
                raise PolicyViolationError(f"Org execution is disabled (max_active_jobs={max_active_jobs})")

            active = self._jobs.count_active_by_org(org_id)
            if state == "created" and active >= max_active_jobs:
                raise PolicyViolationError("Org max_active_jobs limit reached")
            if state == "waiting" and active > max_active_jobs:
                raise PolicyViolationError("Org max_active_jobs limit reached")

            max_starts = int(deep_get(org_exec, ["rate_limits", "max_job_starts_per_minute"]))
            if max_starts <= 0:
                raise PolicyViolationError(f"Org job starts are disabled (max_job_starts_per_minute={max_starts})")

            since = now - timedelta(seconds=60)
            starts = self._jobs.count_events_since(org_id=org_id, event_type="job_started", since=since)
            if starts >= max_starts:
                raise PolicyViolationError("Org rate limit exceeded (max_job_starts_per_minute)")

        running = apply_transition(job, TransitionRequest(new_state="running", now=now))
        self._schemas.validate("JobContract", running)
        self._jobs.update(running)
        self._jobs.record_event(org_id=org_id, job_id=job_id, event_type="job_started", details={"previous_state": state})

        if self._execution_deferred:
            waiting = apply_transition(running, TransitionRequest(new_state="waiting", now=utcnow()))
            self._schemas.validate("JobContract", waiting)
            self._jobs.update(waiting)
            self._jobs.record_event(
                org_id=org_id,
                job_id=job_id,
                event_type="execution_deferred",
                details={"reason": "agent_execution_not_implemented", "build_mode": True},
            )
            return EngineResult(job=waiting)

        # Future: schedule actual execution here (intentionally deferred).
        return EngineResult(job=running)

    def stop_job(self, job_id: str) -> EngineResult:
        job = self._jobs.get(job_id)
        now = utcnow()
        org_id = str(deep_get(job, ["metadata", "org_id"]))
        state = str(deep_get(job, ["spec", "status", "state"]))

        if state in ("completed", "failed", "expired"):
            raise ConflictError(f"Cannot stop a terminal job (state={state})")
        if state == "waiting":
            return EngineResult(job=job)
        if state != "running":
            raise ConflictError(f"Job must be running to stop (current={state})")

        waiting = apply_transition(job, TransitionRequest(new_state="waiting", now=now, last_stop_condition="manual_stop"))
        self._schemas.validate("JobContract", waiting)
        self._jobs.update(waiting)
        self._jobs.record_event(org_id=org_id, job_id=job_id, event_type="job_stopped", details={"to_state": "waiting"})
        return EngineResult(job=waiting)

