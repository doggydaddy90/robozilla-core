from __future__ import annotations

import sys
import unittest
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from errors import PolicyViolationError
from security.capabilityEnforcer import CapabilityEnforcer, CapabilityRequest


class _AuditSink:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    def append(self, *, actor: str, action: str, target: str, details=None):  # type: ignore[no-untyped-def]
        self.rows.append({"actor": actor, "action": action, "target": target, "details": details or {}})


def _job() -> dict[str, object]:
    return {
        "metadata": {"job_id": "job-1"},
        "spec": {
            "status": {"state": "running"},
            "invariants": {"no_side_effects_without_active_job_contract": True},
            "permissions_snapshot": {
                "skills": {
                    "allowed_skill_ids": ["skill.ok"],
                    "allowed_skill_categories": ["ops"],
                },
                "mcp": {
                    "allowed": [
                        {
                            "mcp_id": "mcp.safe",
                            "ref": "mcp://safe",
                            "allowed_scopes": ["read", "write"],
                        }
                    ]
                },
            },
        },
    }


def _skill(category: str = "ops") -> dict[str, object]:
    return {"spec": {"classification": {"category_id": category}}}


class CapabilityEnforcerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = _AuditSink()
        self.enforcer = CapabilityEnforcer(audit_log=self.audit)

    def test_allows_valid_request(self) -> None:
        req = CapabilityRequest(
            actor="tester",
            job_contract=_job(),
            skill_contract=_skill(),
            skill_id="skill.ok",
            requested_side_effects=False,
            requested_channel="mcp",
            requested_mcp_id="mcp.safe",
            requested_mcp_scopes=["read"],
        )
        self.enforcer.enforceCapability(req)
        self.assertTrue(any(row["action"] == "capability.allowed" for row in self.audit.rows))

    def test_denies_disallowed_skill(self) -> None:
        req = CapabilityRequest(
            actor="tester",
            job_contract=_job(),
            skill_contract=_skill(category="not-allowed"),
            skill_id="skill.nope",
            requested_side_effects=False,
            requested_channel="none",
        )
        with self.assertRaises(PolicyViolationError):
            self.enforcer.enforceCapability(req)
        self.assertTrue(any(row["action"] == "attempt.denied" for row in self.audit.rows))

    def test_denies_shell_without_mcp(self) -> None:
        req = CapabilityRequest(
            actor="tester",
            job_contract=_job(),
            skill_contract=_skill(),
            skill_id="skill.ok",
            requested_side_effects=False,
            requested_channel="shell",
            requested_mcp_id=None,
        )
        with self.assertRaises(PolicyViolationError):
            self.enforcer.enforceCapability(req)

    def test_denies_scope_escalation(self) -> None:
        req = CapabilityRequest(
            actor="tester",
            job_contract=_job(),
            skill_contract=_skill(),
            skill_id="skill.ok",
            requested_side_effects=False,
            requested_channel="mcp",
            requested_mcp_id="mcp.safe",
            requested_mcp_scopes=["admin"],
        )
        with self.assertRaises(PolicyViolationError):
            self.enforcer.enforceCapability(req)


if __name__ == "__main__":
    unittest.main()
