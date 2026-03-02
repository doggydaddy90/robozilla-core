"""Controlled autonomous loop orchestration for agents/tools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from audit.auditLog import AuditLog
from errors import PolicyViolationError
from security.capabilityEnforcer import CapabilityEnforcer, CapabilityRequest

ToolExecutor = Callable[[str, dict[str, Any]], dict[str, Any]]
REF_TOOLS_MCP_ID = "ref_tools_mcp"


@dataclass(frozen=True)
class LoopRunResult:
    status: str
    stop_reason: str
    steps_executed: int
    tool_calls: int
    history: list[dict[str, Any]]


class AutonomousLoopController:
    def __init__(
        self,
        *,
        capability_enforcer: CapabilityEnforcer,
        audit_log: AuditLog,
        tool_executor: ToolExecutor,
        registered_tools: set[str],
        actor: str = "runtime.core.autonomous_loop_controller",
        controller_skill_id: str = "autonomous_loop_controller",
        controller_skill_contract: dict[str, Any] | None = None,
        local_reasoning_tool: str = "local_reasoning_tool",
    ):
        if not callable(tool_executor):
            raise PolicyViolationError("tool_executor must be callable")
        self._capabilities = capability_enforcer
        self._audit = audit_log
        self._tool_executor = tool_executor
        self._registered_tools = set(registered_tools)
        self._actor = actor
        self._controller_skill_id = controller_skill_id
        self._controller_skill_contract = controller_skill_contract or {
            "spec": {"classification": {"category_id": "automation"}}
        }
        self._local_reasoning_tool = local_reasoning_tool

    def run(
        self,
        *,
        goal: str,
        org_id: str,
        max_steps: int,
        max_tool_calls: int,
        job_contract: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(goal, str) or not goal.strip():
            raise PolicyViolationError("goal must be a non-empty string")
        if not isinstance(org_id, str) or not org_id.strip():
            raise PolicyViolationError("org_id must be a non-empty string")
        if not isinstance(max_steps, int) or max_steps < 0:
            raise PolicyViolationError("max_steps must be an integer >= 0")
        if not isinstance(max_tool_calls, int) or max_tool_calls < 0:
            raise PolicyViolationError("max_tool_calls must be an integer >= 0")
        if not isinstance(job_contract, dict):
            raise PolicyViolationError("job_contract must be an object")

        steps = 0
        tool_calls = 0
        history: list[dict[str, Any]] = []

        if _is_kill_switch_active(job_contract):
            self._log_step(
                org_id=org_id,
                step=0,
                tool_calls=0,
                state="aborted",
                reason="kill_switch_active",
                target_tool=None,
            )
            return as_dict(
                LoopRunResult(
                    status="aborted",
                    stop_reason="kill_switch_active",
                    steps_executed=0,
                    tool_calls=0,
                    history=[],
                )
            )

        stop_reason = "done"
        status = "completed"
        while True:
            if steps >= max_steps:
                stop_reason = "max_steps_reached"
                status = "stopped"
                self._log_step(
                    org_id=org_id,
                    step=steps,
                    tool_calls=tool_calls,
                    state="stopped",
                    reason=stop_reason,
                    target_tool=None,
                )
                break
            if tool_calls >= max_tool_calls:
                stop_reason = "max_tool_calls_reached"
                status = "stopped"
                self._log_step(
                    org_id=org_id,
                    step=steps,
                    tool_calls=tool_calls,
                    state="stopped",
                    reason=stop_reason,
                    target_tool=None,
                )
                break
            if _is_kill_switch_active(job_contract):
                stop_reason = "kill_switch_active"
                status = "aborted"
                self._log_step(
                    org_id=org_id,
                    step=steps,
                    tool_calls=tool_calls,
                    state="aborted",
                    reason=stop_reason,
                    target_tool=None,
                )
                break

            step_num = steps + 1
            reasoning = self._invoke_tool(
                tool_id=self._local_reasoning_tool,
                scope_tag="planning",
                payload={
                    "goal": goal.strip(),
                    "org_id": org_id.strip(),
                    "step": step_num,
                    "max_steps": max_steps,
                    "max_tool_calls": max_tool_calls,
                    "tool_calls": tool_calls,
                    "history": history,
                },
                job_contract=job_contract,
            )
            tool_calls += 1

            state = str(reasoning.get("state", "")).strip().lower()
            action = reasoning.get("action")
            target_tool: str | None = None
            action_result: dict[str, Any] | None = None
            action_blocked = False

            if state == "done":
                steps = step_num
                history.append({"step": step_num, "reasoning": reasoning, "action_result": None})
                self._log_step(
                    org_id=org_id,
                    step=step_num,
                    tool_calls=tool_calls,
                    state="done",
                    reason="done",
                    target_tool=None,
                )
                stop_reason = "done"
                status = "completed"
                break
            if state != "continue":
                raise PolicyViolationError(f"local_reasoning_tool returned invalid state: {state}")

            if isinstance(action, dict):
                kind = str(action.get("kind", "none")).strip().lower()
                if kind in ("none", ""):
                    pass
                elif kind in ("tool", "skill"):
                    target_tool = str(action.get("tool_id") or action.get("skill_id") or "").strip()
                    if not target_tool:
                        raise PolicyViolationError(f"{kind} action requires a target id")
                    if tool_calls >= max_tool_calls:
                        action_blocked = True
                    else:
                        payload = action.get("payload")
                        if not isinstance(payload, dict):
                            payload = {}
                        action_result = self._invoke_tool(
                            tool_id=target_tool,
                            scope_tag=_action_scope_tag(action),
                            payload=payload,
                            job_contract=job_contract,
                        )
                        tool_calls += 1
                else:
                    raise PolicyViolationError(f"Unsupported action kind: {kind}")
            elif action is not None:
                raise PolicyViolationError("action must be an object when present")

            steps = step_num
            history.append({"step": step_num, "reasoning": reasoning, "action_result": action_result})

            if action_blocked:
                self._log_step(
                    org_id=org_id,
                    step=step_num,
                    tool_calls=tool_calls,
                    state="stopped",
                    reason="max_tool_calls_reached",
                    target_tool=target_tool,
                )
                stop_reason = "max_tool_calls_reached"
                status = "stopped"
                break

            self._log_step(
                org_id=org_id,
                step=step_num,
                tool_calls=tool_calls,
                state="continue",
                reason="step_completed",
                target_tool=target_tool,
            )

        return as_dict(
            LoopRunResult(
                status=status,
                stop_reason=stop_reason,
                steps_executed=steps,
                tool_calls=tool_calls,
                history=history,
            )
        )

    def _invoke_tool(
        self,
        *,
        tool_id: str,
        scope_tag: str,
        payload: dict[str, Any],
        job_contract: dict[str, Any],
    ) -> dict[str, Any]:
        if tool_id not in self._registered_tools:
            raise PolicyViolationError(f"Tool is not registered for loop execution: {tool_id}")

        is_ref_tools = tool_id == REF_TOOLS_MCP_ID
        if is_ref_tools and not _ref_tools_confirmed(payload):
            raise PolicyViolationError("ref.tools execution requires confirmation (allow_ref_tools_execution=true)")

        requested_scope_tags = ["mutation", "code_analysis"] if is_ref_tools else [scope_tag]
        self._capabilities.enforceCapability(
            CapabilityRequest(
                actor=self._actor,
                job_contract=job_contract,
                skill_contract=self._controller_skill_contract,
                skill_id=self._controller_skill_id,
                requested_side_effects=is_ref_tools,
                requested_channel="mcp",
                requested_mcp_id=tool_id,
                requested_mcp_scopes=["execute"],
                requested_scope_tags=requested_scope_tags,
            )
        )

        out = self._tool_executor(tool_id, payload)
        if not isinstance(out, dict):
            raise PolicyViolationError(f"Tool '{tool_id}' returned invalid response type (expected object)")
        return out

    def _log_step(
        self,
        *,
        org_id: str,
        step: int,
        tool_calls: int,
        state: str,
        reason: str,
        target_tool: str | None,
    ) -> None:
        self._audit.append(
            actor=self._actor,
            action="loop.step",
            target=org_id,
            details={
                "step": step,
                "tool_calls": tool_calls,
                "state": state,
                "reason": reason,
                "target_tool": target_tool,
            },
        )


def _is_kill_switch_active(job_contract: dict[str, Any]) -> bool:
    spec = job_contract.get("spec")
    if not isinstance(spec, dict):
        return False

    controls = spec.get("controls")
    if isinstance(controls, dict) and bool(controls.get("kill_switch_active")):
        return True

    flags = spec.get("runtime_flags")
    if isinstance(flags, dict) and bool(flags.get("kill_switch_active")):
        return True

    return False


def _action_scope_tag(action: dict[str, Any]) -> str:
    value = str(action.get("scope_tag", "")).strip().lower()
    if value:
        return value
    kind = str(action.get("kind", "")).strip().lower()
    if kind == "skill":
        return "runtime"
    return "research"


def as_dict(result: LoopRunResult) -> dict[str, Any]:
    return {
        "status": result.status,
        "stop_reason": result.stop_reason,
        "steps_executed": result.steps_executed,
        "tool_calls": result.tool_calls,
        "history": result.history,
    }


def _ref_tools_confirmed(payload: dict[str, Any]) -> bool:
    return bool(payload.get("allow_ref_tools_execution", False))
