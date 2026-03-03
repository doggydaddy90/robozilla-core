"""Capability deny-by-default enforcement for skill and MCP execution."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from errors import PolicyViolationError
from events.event_bus import EventBus
from events.runtime_event import RuntimeEvent
from utils import deep_get


@dataclass(frozen=True)
class CapabilityRequest:
    actor: str
    job_contract: dict[str, Any] | None
    skill_contract: dict[str, Any] | None
    skill_id: str
    requested_side_effects: bool
    requested_channel: str  # mcp|none|shell|fs
    requested_mcp_id: str | None = None
    requested_mcp_scopes: list[str] = field(default_factory=list)
    requested_scope_tags: list[str] = field(default_factory=list)


class CapabilityEnforcer:
    """Deny-by-default capability gate.

    Every skill execution request must pass through enforceCapability().
    """

    def __init__(self, *, audit_log: Any | None = None, event_bus: EventBus | None = None):
        self._audit = audit_log
        self._event_bus = event_bus

    def _log(self, *, actor: str, action: str, target: str, details: dict[str, Any] | None = None) -> None:
        if self._audit is None:
            return
        self._audit.append(actor=actor, action=action, target=target, details=details or {})

    def enforceCapability(self, request: CapabilityRequest) -> None:
        self._emit_event(
            RuntimeEvent(
                event_type="capability_request",
                job_id=self._job_id_from_contract(request.job_contract),
                module_name=request.skill_id,
                capability=request.requested_channel,
                actor_role=request.actor,
                metadata={
                    "requested_mcp_id": request.requested_mcp_id,
                    "requested_mcp_scopes": list(request.requested_mcp_scopes),
                    "requested_scope_tags": list(request.requested_scope_tags),
                    "requested_side_effects": bool(request.requested_side_effects),
                },
            )
        )
        job = request.job_contract
        if not isinstance(job, dict):
            self._deny(request, "JobContract is required")

        if not isinstance(request.skill_contract, dict):
            self._deny(request, "SkillContract is required")

        assert isinstance(job, dict)
        assert isinstance(request.skill_contract, dict)

        # Default deny: all checks must pass before we permit execution.
        self._validate_job_active(job, request)
        self._validate_intent_envelope(job, request)
        self._validate_skill_allowed(job, request)
        self._validate_channel_and_side_effects(job, request)
        self._validate_mcp_allowed(job, request)

        self._log(
            actor=request.actor,
            action="capability.allowed",
            target=request.skill_id,
            details={"channel": request.requested_channel, "mcp_id": request.requested_mcp_id},
        )

    def recordMcpCall(
        self,
        *,
        actor: str,
        job_contract: dict[str, Any] | None,
        mcp_id: str,
        target: str,
        scopes: list[str] | None = None,
    ) -> None:
        job_id = ""
        if isinstance(job_contract, dict):
            job_id = str(deep_get(job_contract, ["metadata", "job_id"]))
        self._log(
            actor=actor,
            action="mcp.call",
            target=target,
            details={"job_id": job_id, "mcp_id": mcp_id, "scopes": scopes or []},
        )

    def _deny(self, request: CapabilityRequest, reason: str) -> None:
        self._emit_event(
            RuntimeEvent(
                event_type="capability_denied",
                job_id=self._job_id_from_contract(request.job_contract),
                module_name=request.skill_id,
                capability=request.requested_channel,
                actor_role=request.actor,
                metadata={"reason": reason, "requested_mcp_id": request.requested_mcp_id},
            )
        )
        self._log(
            actor=request.actor,
            action="attempt.denied",
            target=request.skill_id,
            details={"reason": reason, "channel": request.requested_channel, "mcp_id": request.requested_mcp_id},
        )
        raise PolicyViolationError(reason)

    def _emit_event(self, event: RuntimeEvent) -> None:
        if self._event_bus is None:
            return
        self._event_bus.emit(event)

    def _job_id_from_contract(self, job_contract: dict[str, Any] | None) -> str | None:
        if not isinstance(job_contract, dict):
            return None
        job_id = str(deep_get(job_contract, ["metadata", "job_id"])).strip()
        return job_id or None

    def _validate_job_active(self, job: dict[str, Any], request: CapabilityRequest) -> None:
        state = str(deep_get(job, ["spec", "status", "state"]))
        if state in ("completed", "failed", "expired"):
            self._deny(request, f"JobContract is terminal; capability denied (state={state})")

    def _validate_skill_allowed(self, job: dict[str, Any], request: CapabilityRequest) -> None:
        snapshot = deep_get(job, ["spec", "permissions_snapshot"])
        skills = snapshot.get("skills")
        if not isinstance(skills, dict):
            self._deny(request, "JobContract.permissions_snapshot.skills is required")

        allowed_ids = {str(x) for x in (skills.get("allowed_skill_ids") or [])}
        allowed_categories = {str(x) for x in (skills.get("allowed_skill_categories") or [])}

        skill_category = ""
        classification = deep_get(request.skill_contract, ["spec", "classification"])
        if isinstance(classification, dict):
            skill_category = str(classification.get("category_id", ""))

        if request.skill_id in allowed_ids:
            return
        if skill_category and skill_category in allowed_categories:
            return
        self._deny(request, f"Skill is not allowed by JobContract permissions snapshot: {request.skill_id}")

    def _validate_intent_envelope(self, job: dict[str, Any], request: CapabilityRequest) -> None:
        envelope = deep_get(job, ["spec", "intent_envelope"])
        if not isinstance(envelope, dict):
            self._deny(request, "JobContract.spec.intent_envelope is required")

        original_prompt = envelope.get("original_prompt")
        intent_hash = envelope.get("intent_hash")
        allowed_scopes_raw = envelope.get("allowed_scopes")

        if not isinstance(original_prompt, str) or not original_prompt.strip():
            self._deny(request, "IntentEnvelope.original_prompt must be a non-empty string")
        if not isinstance(intent_hash, str) or len(intent_hash) != 64:
            self._deny(request, "IntentEnvelope.intent_hash must be a 64-char sha256 hex string")
        if not isinstance(allowed_scopes_raw, list):
            self._deny(request, "IntentEnvelope.allowed_scopes must be a list")

        computed = hashlib.sha256(original_prompt.encode("utf-8")).hexdigest()
        if computed != intent_hash:
            self._deny(request, "IntentEnvelope.intent_hash does not match original_prompt")

        is_tool_call = request.requested_mcp_id is not None or request.requested_channel.strip().lower() in (
            "mcp",
            "shell",
            "subprocess",
            "fs",
            "filesystem",
        )
        if not is_tool_call:
            return

        allowed_scopes = {str(x).strip() for x in allowed_scopes_raw if str(x).strip()}
        if not allowed_scopes:
            self._deny(request, "IntentEnvelope.allowed_scopes cannot be empty for tool calls")

        requested_scopes = request.requested_scope_tags or request.requested_mcp_scopes
        requested = {str(x).strip() for x in requested_scopes if str(x).strip()}
        if not requested:
            self._deny(request, "Tool calls must declare requested scope tags")
        if not requested.issubset(allowed_scopes):
            self._deny(request, f"Tool call scopes exceed IntentEnvelope.allowed_scopes: {sorted(requested)}")

    def _validate_channel_and_side_effects(self, job: dict[str, Any], request: CapabilityRequest) -> None:
        channel = request.requested_channel.strip().lower()
        if channel in ("fs", "filesystem"):
            self._deny(request, "Direct filesystem access from skill execution is forbidden")
        if channel in ("shell", "subprocess"):
            # Shell is only allowed indirectly through approved MCP access.
            if not request.requested_mcp_id:
                self._deny(request, "Shell access is forbidden outside approved MCP")

        if request.requested_side_effects:
            invariant = bool(deep_get(job, ["spec", "invariants", "no_side_effects_without_active_job_contract"]))
            if not invariant:
                self._deny(request, "JobContract invariant forbids side effects without active contract")

    def _validate_mcp_allowed(self, job: dict[str, Any], request: CapabilityRequest) -> None:
        if request.requested_mcp_id is None:
            if request.requested_channel == "mcp":
                self._deny(request, "MCP channel requested but no mcp_id provided")
            return

        allowed_entries = deep_get(job, ["spec", "permissions_snapshot", "mcp", "allowed"])
        if not isinstance(allowed_entries, list):
            self._deny(request, "JobContract.permissions_snapshot.mcp.allowed must be a list")

        selected: dict[str, Any] | None = None
        for item in allowed_entries:
            if not isinstance(item, dict):
                continue
            if str(item.get("mcp_id")) == request.requested_mcp_id:
                selected = item
                break
        if selected is None:
            self._deny(request, f"MCP is not allowed by JobContract: {request.requested_mcp_id}")

        allowed_scopes = {str(x) for x in (selected.get("allowed_scopes") or [])}
        requested_scopes = {str(x) for x in request.requested_mcp_scopes}
        if allowed_scopes and not requested_scopes.issubset(allowed_scopes):
            self._deny(request, f"MCP scopes exceed JobContract allowlist: {request.requested_mcp_id}")
