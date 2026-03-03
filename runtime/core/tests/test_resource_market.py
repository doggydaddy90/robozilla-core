from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from economics.resource_market import compute_scarcity_snapshot


class _AuditSink:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def append(self, *, actor: str, action: str, target: str, details=None) -> None:  # type: ignore[no-untyped-def]
        self.rows.append({"actor": actor, "action": action, "target": target, "details": details or {}})


def _ts() -> str:
    return datetime(2026, 3, 2, 12, 0, 0, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


class ResourceMarketTests(unittest.TestCase):
    def test_zero_usage(self) -> None:
        audit = _AuditSink()
        snap = compute_scarcity_snapshot(
            telemetry_records=[],
            daily_caps={"openai": 100},
            now=datetime(2026, 3, 2, 13, 0, 0, tzinfo=timezone.utc),
            audit_log=audit,
        )
        self.assertEqual(snap["platforms"]["openai"]["scarcity_index"], 0.0)
        self.assertEqual(sum(1 for row in audit.rows if row["action"] == "economics.snapshot"), 1)

    def test_half_usage(self) -> None:
        snap = compute_scarcity_snapshot(
            telemetry_records=[{"tokens_used": 50, "tool_id": "openai_planner_tool", "timestamp": _ts()}],
            daily_caps={"openai": 100},
            now=datetime(2026, 3, 2, 13, 0, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(snap["platforms"]["openai"]["scarcity_index"], 0.5)

    def test_near_depletion(self) -> None:
        snap = compute_scarcity_snapshot(
            telemetry_records=[{"tokens_used": 95, "tool_id": "perplexity_research_tool", "timestamp": _ts()}],
            daily_caps={"perplexity": 100},
            now=datetime(2026, 3, 2, 13, 0, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(snap["platforms"]["perplexity"]["scarcity_index"], 0.95)

    def test_unlimited_resource(self) -> None:
        snap = compute_scarcity_snapshot(
            telemetry_records=[{"tokens_used": 10000, "tool_id": "reddit_search_tool", "timestamp": _ts()}],
            daily_caps={"reddit_api": "unlimited"},
            now=datetime(2026, 3, 2, 13, 0, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(snap["platforms"]["reddit_api"]["scarcity_index"], 0.0)
        self.assertTrue(snap["platforms"]["reddit_api"]["unlimited"])

    def test_overflow_beyond_cap(self) -> None:
        snap = compute_scarcity_snapshot(
            telemetry_records=[{"tokens_used": 500, "tool_id": "youtube_search_tool", "timestamp": _ts()}],
            daily_caps={"youtube_api": 100},
            now=datetime(2026, 3, 2, 13, 0, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(snap["platforms"]["youtube_api"]["scarcity_index"], 1.0)


if __name__ == "__main__":
    unittest.main()

