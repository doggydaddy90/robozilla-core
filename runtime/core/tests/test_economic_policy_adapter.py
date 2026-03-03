from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from economics.economic_policy_adapter import apply_economic_policy
from errors import PolicyViolationError


class _AuditSink:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def append(self, *, actor: str, action: str, target: str, details=None) -> None:  # type: ignore[no-untyped-def]
        self.rows.append({"actor": actor, "action": action, "target": target, "details": details or {}})


def _org_policy(max_writes: int = 3) -> dict[str, Any]:
    return {"spec": {"knowledge_policy": {"max_memory_writes_per_loop": max_writes}}}


class EconomicPolicyAdapterTests(unittest.TestCase):
    def test_low_scarcity_full_capability(self) -> None:
        out = apply_economic_policy(
            scarcity_index_by_platform={"openai": 0.2},
            org_policy=_org_policy(4),
        )
        self.assertTrue(out["deep_enabled"])
        self.assertTrue(out["minority_escalation_enabled"])
        self.assertLess(out["adjusted_deep_threshold"], 0.85)
        self.assertEqual(out["adjusted_write_budget"], 4)

    def test_moderate_scarcity_minor_adjustments(self) -> None:
        out = apply_economic_policy(
            scarcity_index_by_platform={"openai": 0.6, "perplexity": 0.4},
            org_policy=_org_policy(3),
        )
        self.assertTrue(out["deep_enabled"])
        self.assertTrue(out["minority_escalation_enabled"])
        self.assertGreater(out["adjusted_high_threshold"], 0.8)
        self.assertGreater(out["adjusted_deep_threshold"], 0.85)

    def test_high_scarcity_deep_disabled(self) -> None:
        audit = _AuditSink()
        out = apply_economic_policy(
            scarcity_index_by_platform={"openai": 0.95},
            org_policy=_org_policy(2),
            audit_log=audit,
        )
        self.assertFalse(out["deep_enabled"])
        self.assertFalse(out["minority_escalation_enabled"])
        self.assertEqual(out["adjusted_write_budget"], 1)
        self.assertGreaterEqual(sum(1 for row in audit.rows if row["action"] == "economics.deep_disabled"), 1)

    def test_bounds_enforcement(self) -> None:
        out = apply_economic_policy(
            scarcity_index_by_platform={"openai": 1.0},
            org_policy=_org_policy(1),
            base_high_threshold=0.89,
            base_deep_threshold=0.89,
        )
        self.assertLessEqual(out["adjusted_high_threshold"], 0.90)
        self.assertLessEqual(out["adjusted_deep_threshold"], 0.90)
        self.assertGreaterEqual(out["adjusted_high_threshold"], 0.75)
        self.assertGreaterEqual(out["adjusted_deep_threshold"], 0.80)

    def test_atomic_threshold_unchanged(self) -> None:
        out = apply_economic_policy(
            scarcity_index_by_platform={"openai": 0.5},
            org_policy=_org_policy(3),
            base_atomic_threshold=0.7,
        )
        self.assertIn("adjusted_high_threshold", out)
        with self.assertRaises(PolicyViolationError):
            apply_economic_policy(
                scarcity_index_by_platform={"openai": 0.5},
                org_policy=_org_policy(3),
                base_atomic_threshold=0.71,
            )

    def test_minority_escalation_disabled_when_required(self) -> None:
        out = apply_economic_policy(
            scarcity_index_by_platform={"openai": 0.8},
            org_policy=_org_policy(5),
        )
        self.assertFalse(out["minority_escalation_enabled"])
        self.assertTrue(out["deep_enabled"])
        self.assertEqual(out["adjusted_write_budget"], 4)


if __name__ == "__main__":
    unittest.main()

