from __future__ import annotations

import sys
import unittest
from typing import Any

CORE_DIR = __import__("pathlib").Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from orchestration.research_cycle import run_research_cycle


class _AuditSink:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def append(self, *, actor: str, action: str, target: str, details=None) -> None:  # type: ignore[no-untyped-def]
        self.rows.append({"actor": actor, "action": action, "target": target, "details": details or {}})


class _FakeLoopController:
    def __init__(self, responses: dict[tuple[str, str], dict[str, Any]]) -> None:
        self._responses = dict(responses)
        self.calls: list[dict[str, Any]] = []

    def run(self, *, goal: str, org_id: str, max_steps: int, max_tool_calls: int, job_contract: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(
            {"goal": goal, "org_id": org_id, "max_steps": max_steps, "max_tool_calls": max_tool_calls}
        )
        topic_hash = _topic_from_goal(goal)
        tier = _tier_from_goal(goal)
        return self._responses[(topic_hash, tier)]


class _FakeAdmissionController:
    def __init__(self, *, admitted: bool = True, confidence: float = 0.9) -> None:
        self.admitted = admitted
        self.confidence = confidence

    def evaluate(self, candidate: dict[str, Any]) -> dict[str, Any]:
        return {"admit": self.admitted, "confidence_score": self.confidence, "reasons": []}


class _FakeNormalizer:
    def __call__(self, *, router_json: dict[str, Any], admission_result: dict[str, Any], previous_entry=None) -> dict[str, Any]:
        topic_hash = str(router_json["topic_hash"])
        return {
            "document_id": "a" * 64,
            "topic_hash": topic_hash,
            "source_hash": "b" * 64,
            "version": 1,
            "content_blocks": [{"fact_text": "fact"}],
            "confidence_score": admission_result["confidence_score"],
            "citations": ["https://example.org/ref"],
        }


class _FakeIngest:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *, normalized_document: dict[str, Any], job_contract: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        return {
            "status": "ingested",
            "path": f"rag/{normalized_document['topic_hash']}/{normalized_document['document_id']}.json",
            "document_id": normalized_document["document_id"],
            "version": normalized_document["version"],
        }


def _topic_from_goal(goal: str) -> str:
    marker = "topic_hash="
    idx = goal.find(marker)
    if idx < 0:
        return ""
    start = idx + len(marker)
    end = goal.find(" ", start)
    return goal[start:] if end < 0 else goal[start:end]


def _tier_from_goal(goal: str) -> str:
    marker = "tier="
    idx = goal.find(marker)
    if idx < 0:
        return "high"
    start = idx + len(marker)
    end = goal.find(" ", start)
    return goal[start:] if end < 0 else goal[start:end]


def _candidate(topic_hash: str, *, tier: str = "high", anomaly: float = 0.1, compiled_confidence: float = 0.9) -> dict[str, Any]:
    return {
        "query": "refresh",
        "topic_hash": topic_hash,
        "tier": tier,
        "ingestion_mode": "optional" if tier == "high" else ("autonomous" if tier == "deep" else "none"),
        "compiled_confidence": compiled_confidence,
        "scores": {"authority": 0.9, "freshness": 0.9, "contradiction": 0.0, "anomaly": anomaly},
        "candidate_document": {
            "citations": [{"url": "https://example.org/ref"}],
            "facts": ["a fact"],
        },
    }


class ResearchCycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = _AuditSink()

    def test_single_stale_topic(self) -> None:
        topic = "1" * 64
        monitor_report = {"stale_topics": [{"topic_hash": topic}], "low_confidence_topics": [], "conflict_topics": []}
        loop = _FakeLoopController(
            responses={
                (topic, "high"): {
                    "status": "completed",
                    "stop_reason": "done",
                    "candidate": _candidate(topic),
                }
            }
        )
        ingest = _FakeIngest()

        result = run_research_cycle(
            org_id="ops",
            job_contract={"metadata": {"job_id": "j1"}},
            loop_controller=loop,
            monitor_fn=lambda **_: monitor_report,
            admission_controller=_FakeAdmissionController(admitted=True, confidence=0.9),
            normalize_fn=_FakeNormalizer(),
            ingest_fn=ingest,
            max_steps=3,
            max_tool_calls=5,
            write_budget=2,
            research_tier="high",
            ingestion_confidence_threshold=0.6,
        )

        self.assertEqual(len(result["topics_processed"]), 1)
        self.assertEqual(len(result["ingestions"]), 1)
        self.assertEqual(result["topics_skipped"], [])
        self.assertEqual(result["errors"], [])
        self.assertEqual(ingest.calls, 1)
        self.assertEqual(len(loop.calls), 1)
        self.assertEqual(loop.calls[0]["max_steps"], 3)
        self.assertEqual(loop.calls[0]["max_tool_calls"], 5)
        self.assertEqual(result["truth_ledger"][0]["ingested"], True)

    def test_no_topics(self) -> None:
        loop = _FakeLoopController(responses={})
        ingest = _FakeIngest()

        result = run_research_cycle(
            org_id="ops",
            job_contract={"metadata": {"job_id": "j1"}},
            loop_controller=loop,
            monitor_fn=lambda **_: {"stale_topics": [], "low_confidence_topics": [], "conflict_topics": []},
            admission_controller=_FakeAdmissionController(admitted=True, confidence=0.9),
            normalize_fn=_FakeNormalizer(),
            ingest_fn=ingest,
            write_budget=1,
        )

        self.assertEqual(result, {"topics_processed": [], "topics_skipped": [], "ingestions": [], "errors": [], "truth_ledger": []})
        self.assertEqual(loop.calls, [])
        self.assertEqual(ingest.calls, 0)

    def test_threshold_reject(self) -> None:
        topic = "2" * 64
        monitor_report = {"stale_topics": [{"topic_hash": topic}], "low_confidence_topics": [], "conflict_topics": []}
        loop = _FakeLoopController(
            responses={
                (topic, "high"): {
                    "status": "completed",
                    "stop_reason": "done",
                    "candidate": _candidate(topic, compiled_confidence=0.4),
                }
            }
        )
        ingest = _FakeIngest()

        result = run_research_cycle(
            org_id="ops",
            job_contract={"metadata": {"job_id": "j1"}},
            loop_controller=loop,
            monitor_fn=lambda **_: monitor_report,
            admission_controller=_FakeAdmissionController(admitted=True, confidence=0.4),
            normalize_fn=_FakeNormalizer(),
            ingest_fn=ingest,
            ingestion_confidence_threshold=0.6,
        )

        self.assertEqual(len(result["topics_processed"]), 1)
        self.assertEqual(len(result["ingestions"]), 0)
        self.assertEqual(len(result["topics_skipped"]), 1)
        self.assertEqual(result["topics_skipped"][0]["skip_reason"], "ingestion_threshold_not_met")
        self.assertEqual(ingest.calls, 0)

    def test_write_budget_exhaustion(self) -> None:
        t1 = "3" * 64
        t2 = "4" * 64
        monitor_report = {
            "stale_topics": [{"topic_hash": t1}, {"topic_hash": t2}],
            "low_confidence_topics": [],
            "conflict_topics": [],
        }
        loop = _FakeLoopController(
            responses={
                (t1, "high"): {"status": "completed", "stop_reason": "done", "candidate": _candidate(t1)},
                (t2, "high"): {"status": "completed", "stop_reason": "done", "candidate": _candidate(t2)},
            }
        )
        ingest = _FakeIngest()

        result = run_research_cycle(
            org_id="ops",
            job_contract={"metadata": {"job_id": "j1"}},
            loop_controller=loop,
            monitor_fn=lambda **_: monitor_report,
            admission_controller=_FakeAdmissionController(admitted=True, confidence=0.95),
            normalize_fn=_FakeNormalizer(),
            ingest_fn=ingest,
            write_budget=1,
        )

        self.assertEqual(len(result["ingestions"]), 1)
        self.assertEqual(len(result["topics_skipped"]), 1)
        self.assertEqual(result["topics_skipped"][0]["skip_reason"], "write_budget_exhausted")
        self.assertEqual(ingest.calls, 1)
        self.assertEqual(len(loop.calls), 1)

    def test_minority_anomaly_escalation(self) -> None:
        topic = "5" * 64
        monitor_report = {"stale_topics": [{"topic_hash": topic}], "low_confidence_topics": [], "conflict_topics": []}
        loop = _FakeLoopController(
            responses={
                (topic, "high"): {
                    "status": "completed",
                    "stop_reason": "done",
                    "candidate": _candidate(topic, tier="high", anomaly=0.9, compiled_confidence=0.9),
                },
                (topic, "deep"): {
                    "status": "completed",
                    "stop_reason": "done",
                    "candidate": _candidate(topic, tier="deep", anomaly=0.3, compiled_confidence=0.92),
                },
            }
        )
        ingest = _FakeIngest()

        result = run_research_cycle(
            org_id="ops",
            job_contract={"metadata": {"job_id": "j1"}},
            loop_controller=loop,
            monitor_fn=lambda **_: monitor_report,
            admission_controller=_FakeAdmissionController(admitted=True, confidence=0.95),
            normalize_fn=_FakeNormalizer(),
            ingest_fn=ingest,
            audit_log=self.audit,
            research_tier="high",
        )

        self.assertEqual(len(loop.calls), 2)
        self.assertTrue(any("tier=deep" in c["goal"] for c in loop.calls))
        self.assertEqual(len(result["ingestions"]), 1)
        self.assertTrue(result["truth_ledger"][0]["minority_escalated"])
        self.assertGreaterEqual(self._count_minority_escalation_logs(), 1)

    def _count_minority_escalation_logs(self) -> int:
        return sum(1 for row in self.audit.rows if row["action"] == "rag.escalation.minority_signal")


if __name__ == "__main__":
    unittest.main()
