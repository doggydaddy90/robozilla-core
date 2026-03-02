from __future__ import annotations

import hashlib
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from audit.auditLog import AuditLog
from errors import PolicyViolationError
from orchestration.autonomous_loop_controller import AutonomousLoopController
from security.capabilityEnforcer import CapabilityEnforcer
import security.pathGuard as path_guard


def _job_contract(*, kill_switch_active: bool = False, mcp_ids: list[str] | None = None) -> dict[str, Any]:
    allowed = []
    for mid in (mcp_ids or []):
        allowed.append({"mcp_id": mid, "ref": f"mcp://{mid}", "allowed_scopes": ["execute"]})

    prompt = "loop controller goal"
    return {
        "metadata": {"job_id": "job-loop-1"},
        "spec": {
            "status": {"state": "running"},
            "controls": {"kill_switch_active": kill_switch_active},
            "invariants": {"no_side_effects_without_active_job_contract": True},
            "intent_envelope": {
                "original_prompt": prompt,
                "intent_hash": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                "allowed_domains": ["example.org"],
                "allowed_scopes": ["planning", "research", "runtime", "execute", "mutation", "code_analysis"],
                "created_at": "2026-03-02T00:00:00Z",
            },
            "permissions_snapshot": {
                "skills": {
                    "allowed_skill_ids": ["autonomous_loop_controller"],
                    "allowed_skill_categories": ["automation"],
                },
                "mcp": {"allowed": allowed},
            },
        },
    }


class _ScriptedExecutor:
    def __init__(self, *, reasoning_script: list[dict[str, Any]], action_outputs: dict[str, dict[str, Any]] | None = None) -> None:
        self.reasoning_script = list(reasoning_script)
        self.action_outputs = action_outputs or {}
        self.calls: list[str] = []

    def __call__(self, tool_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(tool_id)
        if tool_id == "local_reasoning_tool":
            if not self.reasoning_script:
                return {"state": "done", "result": {"message": "default done"}}
            return self.reasoning_script.pop(0)
        return self.action_outputs.get(tool_id, {"tool": tool_id, "ok": True})


class AutonomousLoopControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        path_guard._PROJECT_ROOT_FROZEN = False  # type: ignore[attr-defined]
        path_guard.set_project_root(self.root, freeze=False)
        self.audit = AuditLog(self.root / "runtime" / "state" / "audit.sqlite")
        path_guard.set_audit_logger(self.audit)

    def tearDown(self) -> None:
        path_guard.set_audit_logger(None)
        self._tmp.cleanup()

    def test_loop_stops_at_max_steps(self) -> None:
        executor = _ScriptedExecutor(
            reasoning_script=[
                {"state": "continue", "action": {"kind": "none"}},
                {"state": "continue", "action": {"kind": "none"}},
                {"state": "continue", "action": {"kind": "none"}},
            ]
        )
        controller = AutonomousLoopController(
            capability_enforcer=CapabilityEnforcer(audit_log=self.audit),
            audit_log=self.audit,
            tool_executor=executor,
            registered_tools={"local_reasoning_tool"},
        )
        job = _job_contract(mcp_ids=["local_reasoning_tool"])
        result = controller.run(goal="plan", org_id="ops", max_steps=2, max_tool_calls=10, job_contract=job)

        self.assertEqual(result["status"], "stopped")
        self.assertEqual(result["stop_reason"], "max_steps_reached")
        self.assertEqual(result["steps_executed"], 2)
        self.assertEqual(result["tool_calls"], 2)
        self.assertEqual(executor.calls, ["local_reasoning_tool", "local_reasoning_tool"])

    def test_loop_stops_at_max_tool_calls(self) -> None:
        executor = _ScriptedExecutor(
            reasoning_script=[
                {"state": "continue", "action": {"kind": "tool", "tool_id": "research_tool", "payload": {}}}
            ]
        )
        controller = AutonomousLoopController(
            capability_enforcer=CapabilityEnforcer(audit_log=self.audit),
            audit_log=self.audit,
            tool_executor=executor,
            registered_tools={"local_reasoning_tool", "research_tool"},
        )
        job = _job_contract(mcp_ids=["local_reasoning_tool", "research_tool"])
        result = controller.run(goal="research", org_id="ops", max_steps=5, max_tool_calls=1, job_contract=job)

        self.assertEqual(result["status"], "stopped")
        self.assertEqual(result["stop_reason"], "max_tool_calls_reached")
        self.assertEqual(result["steps_executed"], 1)
        self.assertEqual(result["tool_calls"], 1)
        self.assertEqual(executor.calls, ["local_reasoning_tool"])

    def test_kill_switch_abort(self) -> None:
        executor = _ScriptedExecutor(reasoning_script=[{"state": "done", "result": {"message": "unreachable"}}])
        controller = AutonomousLoopController(
            capability_enforcer=CapabilityEnforcer(audit_log=self.audit),
            audit_log=self.audit,
            tool_executor=executor,
            registered_tools={"local_reasoning_tool"},
        )
        job = _job_contract(kill_switch_active=True, mcp_ids=["local_reasoning_tool"])
        result = controller.run(goal="anything", org_id="ops", max_steps=5, max_tool_calls=5, job_contract=job)

        self.assertEqual(result["status"], "aborted")
        self.assertEqual(result["stop_reason"], "kill_switch_active")
        self.assertEqual(result["steps_executed"], 0)
        self.assertEqual(result["tool_calls"], 0)
        self.assertEqual(executor.calls, [])
        self.assertGreaterEqual(self._count_loop_steps(), 1)

    def test_valid_multi_step_progression(self) -> None:
        executor = _ScriptedExecutor(
            reasoning_script=[
                {"state": "continue", "action": {"kind": "tool", "tool_id": "research_tool", "payload": {"q": "a"}}},
                {"state": "continue", "action": {"kind": "tool", "tool_id": "planner_tool", "payload": {"x": 1}}},
                {"state": "done", "result": {"summary": "complete"}},
            ],
            action_outputs={
                "research_tool": {"result": "research-ok"},
                "planner_tool": {"result": "planner-ok"},
            },
        )
        controller = AutonomousLoopController(
            capability_enforcer=CapabilityEnforcer(audit_log=self.audit),
            audit_log=self.audit,
            tool_executor=executor,
            registered_tools={"local_reasoning_tool", "research_tool", "planner_tool"},
        )
        job = _job_contract(mcp_ids=["local_reasoning_tool", "research_tool", "planner_tool"])
        result = controller.run(goal="deliver", org_id="ops", max_steps=10, max_tool_calls=10, job_contract=job)

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["stop_reason"], "done")
        self.assertEqual(result["steps_executed"], 3)
        self.assertEqual(result["tool_calls"], 5)
        self.assertEqual(
            executor.calls,
            ["local_reasoning_tool", "research_tool", "local_reasoning_tool", "planner_tool", "local_reasoning_tool"],
        )
        self.assertEqual(len(result["history"]), 3)
        self.assertGreaterEqual(self._count_loop_steps(), 3)

    def test_ref_mcp_mutation_gating_requires_confirmation(self) -> None:
        executor = _ScriptedExecutor(
            reasoning_script=[
                {"state": "continue", "action": {"kind": "tool", "tool_id": "ref_tools_mcp", "payload": {"query": "x"}}}
            ]
        )
        controller = AutonomousLoopController(
            capability_enforcer=CapabilityEnforcer(audit_log=self.audit),
            audit_log=self.audit,
            tool_executor=executor,
            registered_tools={"local_reasoning_tool", "ref_tools_mcp"},
        )
        job = _job_contract(mcp_ids=["local_reasoning_tool", "ref_tools_mcp"])
        with self.assertRaises(PolicyViolationError):
            controller.run(goal="mutate", org_id="ops", max_steps=3, max_tool_calls=3, job_contract=job)

    def test_ref_mcp_mutation_gating_allows_confirmed(self) -> None:
        executor = _ScriptedExecutor(
            reasoning_script=[
                {
                    "state": "continue",
                    "action": {
                        "kind": "tool",
                        "tool_id": "ref_tools_mcp",
                        "payload": {"query": "x", "allow_ref_tools_execution": True},
                    },
                },
                {"state": "done", "result": {"summary": "ok"}},
            ],
            action_outputs={"ref_tools_mcp": {"patched": True}},
        )
        controller = AutonomousLoopController(
            capability_enforcer=CapabilityEnforcer(audit_log=self.audit),
            audit_log=self.audit,
            tool_executor=executor,
            registered_tools={"local_reasoning_tool", "ref_tools_mcp"},
        )
        job = _job_contract(mcp_ids=["local_reasoning_tool", "ref_tools_mcp"])
        result = controller.run(goal="mutate", org_id="ops", max_steps=3, max_tool_calls=5, job_contract=job)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["stop_reason"], "done")
        self.assertIn("ref_tools_mcp", executor.calls)

    def _count_loop_steps(self) -> int:
        conn = sqlite3.connect(str(self.audit.path))
        try:
            row = conn.execute("SELECT COUNT(*) FROM audit_entries WHERE action = 'loop.step';").fetchone()
            return int(row[0]) if row is not None else 0
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
