from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from typing import Any

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from api.dashboard_endpoints import DashboardDataProviders, build_dashboard_router


class _MockSources:
    def __init__(self) -> None:
        self.calls = {"telemetry": 0, "caps": 0, "policy": 0, "rag": 0, "truth": 0}
        self.telemetry_rows: list[dict[str, Any]] = [
            {"timestamp": "2026-03-02T01:00:00Z", "tool_id": "openai_planner_tool", "tokens_used": 200, "latency_ms": 120},
            {"timestamp": "2026-03-02T01:01:00Z", "tool_id": "perplexity_research_tool", "tokens_used": 50, "latency_ms": 300},
        ]
        self.caps: dict[str, Any] = {"openai": 1000, "perplexity": 100}
        self.policy: dict[str, Any] = {"spec": {"knowledge_policy": {"max_memory_writes_per_loop": 4}}}
        self.rag: dict[str, Any] = {
            "topic_count": 1,
            "document_count": 2,
            "topics": [
                {
                    "topic_hash": "a" * 64,
                    "topic": "Macro Policy",
                    "document_count": 2,
                    "latest_version": 3,
                    "average_confidence": 0.88,
                }
            ],
        }
        self.truth: list[dict[str, Any]] = [{"id": "TL-1", "status": "confirmed"}]

    def telemetry(self) -> list[dict[str, Any]]:
        self.calls["telemetry"] += 1
        return copy.deepcopy(self.telemetry_rows)

    def daily_caps(self) -> dict[str, Any]:
        self.calls["caps"] += 1
        return copy.deepcopy(self.caps)

    def org_policy(self) -> dict[str, Any]:
        self.calls["policy"] += 1
        return copy.deepcopy(self.policy)

    def rag_index(self) -> dict[str, Any]:
        self.calls["rag"] += 1
        return copy.deepcopy(self.rag)

    def truth_ledger(self) -> list[dict[str, Any]]:
        self.calls["truth"] += 1
        return copy.deepcopy(self.truth)


class DashboardEndpointsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sources = _MockSources()
        providers = DashboardDataProviders(
            telemetry_records=self.sources.telemetry,
            daily_caps=self.sources.daily_caps,
            org_policy=self.sources.org_policy,
            rag_index=self.sources.rag_index,
            truth_ledger=self.sources.truth_ledger,
        )
        self.router = build_dashboard_router(providers=providers)

    def test_get_dashboard_telemetry(self) -> None:
        payload = _invoke(self.router, "/dashboard/telemetry")
        self.assertIn("telemetry", payload)
        self.assertEqual(payload["telemetry"]["record_count"], 2)
        self.assertEqual(payload["telemetry"]["total_tokens_used"], 250.0)
        self.assertEqual(self.sources.calls["telemetry"], 1)

    def test_get_dashboard_economics(self) -> None:
        original_caps = copy.deepcopy(self.sources.caps)
        original_rows = copy.deepcopy(self.sources.telemetry_rows)

        payload = _invoke(self.router, "/dashboard/economics")
        self.assertIn("economics", payload)
        self.assertIn("scarcity_snapshot", payload["economics"])
        self.assertIn("policy_adjustment", payload["economics"])
        self.assertEqual(payload["economics"]["atomic_threshold"], 0.7)
        self.assertGreaterEqual(self.sources.calls["telemetry"], 1)
        self.assertEqual(self.sources.calls["caps"], 1)
        self.assertEqual(self.sources.calls["policy"], 1)

        # Read-only contract: endpoint should not mutate source payloads.
        self.assertEqual(self.sources.caps, original_caps)
        self.assertEqual(self.sources.telemetry_rows, original_rows)

    def test_get_dashboard_rag(self) -> None:
        payload = _invoke(self.router, "/dashboard/rag")
        self.assertIn("rag", payload)
        self.assertEqual(payload["rag"]["topic_count"], 1)
        self.assertEqual(self.sources.calls["rag"], 1)

    def test_get_dashboard_truth_ledger(self) -> None:
        payload = _invoke(self.router, "/dashboard/truth-ledger")
        self.assertIn("truth_ledger", payload)
        self.assertIn("entries", payload["truth_ledger"])
        self.assertEqual(len(payload["truth_ledger"]["entries"]), 1)
        self.assertEqual(self.sources.calls["truth"], 1)


def _invoke(router: Any, path: str) -> dict[str, Any]:
    for route in getattr(router, "routes", []):
        route_path = getattr(route, "path", None)
        if route_path != path:
            continue
        endpoint = getattr(route, "endpoint", None)
        if callable(endpoint):
            result = endpoint()
            if isinstance(result, dict):
                return result
            raise AssertionError(f"Route {path} returned non-dict payload")
    raise AssertionError(f"Route {path} not found")


if __name__ == "__main__":
    unittest.main()
