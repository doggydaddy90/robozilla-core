from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from orchestration.knowledge_monitor import monitor_knowledge
import security.pathGuard as path_guard


def _doc(
    *,
    document_id: str,
    topic_hash: str,
    source_hash: str,
    created_at: str,
    confidence_score: float,
) -> dict[str, Any]:
    return {
        "document_id": document_id,
        "topic_hash": topic_hash,
        "source_hash": source_hash,
        "version": 1,
        "created_at": created_at,
        "confidence_score": confidence_score,
        "content_blocks": [{"fact_text": "fact"}],
        "citations": ["https://example.org/ref"],
    }


class KnowledgeMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        path_guard._PROJECT_ROOT_FROZEN = False  # type: ignore[attr-defined]
        path_guard.set_project_root(self.root, freeze=False)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_detects_stale_topics(self) -> None:
        rag = self.root / "rag" / ("a" * 64)
        rag.mkdir(parents=True, exist_ok=True)
        old_doc = _doc(
            document_id="d1",
            topic_hash="a" * 64,
            source_hash="b" * 64,
            created_at="2025-01-01T00:00:00Z",
            confidence_score=0.9,
        )
        (rag / "d1.json").write_text(json.dumps(old_doc), encoding="utf-8")

        report = monitor_knowledge(
            now=datetime(2026, 3, 2, 0, 0, 0, tzinfo=timezone.utc),
            freshness_threshold_days=30,
            review_confidence_threshold=0.6,
        )

        self.assertEqual(len(report["stale_topics"]), 1)
        self.assertEqual(report["stale_topics"][0]["topic_hash"], "a" * 64)

    def test_detects_low_confidence_topics(self) -> None:
        rag = self.root / "rag" / ("c" * 64)
        rag.mkdir(parents=True, exist_ok=True)
        low = _doc(
            document_id="d2",
            topic_hash="c" * 64,
            source_hash="d" * 64,
            created_at="2026-03-01T00:00:00Z",
            confidence_score=0.2,
        )
        (rag / "d2.json").write_text(json.dumps(low), encoding="utf-8")

        report = monitor_knowledge(
            now=datetime(2026, 3, 2, 0, 0, 0, tzinfo=timezone.utc),
            freshness_threshold_days=90,
            review_confidence_threshold=0.6,
        )

        self.assertEqual(len(report["low_confidence_topics"]), 1)
        self.assertEqual(report["low_confidence_topics"][0]["topic_hash"], "c" * 64)

    def test_detects_conflicting_source_hashes_for_same_topic(self) -> None:
        topic = "e" * 64
        rag = self.root / "rag" / topic
        rag.mkdir(parents=True, exist_ok=True)
        d1 = _doc(
            document_id="d3",
            topic_hash=topic,
            source_hash="1" * 64,
            created_at="2026-03-01T00:00:00Z",
            confidence_score=0.8,
        )
        d2 = _doc(
            document_id="d4",
            topic_hash=topic,
            source_hash="2" * 64,
            created_at="2026-03-01T00:00:00Z",
            confidence_score=0.8,
        )
        (rag / "d3.json").write_text(json.dumps(d1), encoding="utf-8")
        (rag / "d4.json").write_text(json.dumps(d2), encoding="utf-8")

        report = monitor_knowledge(
            now=datetime(2026, 3, 2, 0, 0, 0, tzinfo=timezone.utc),
            freshness_threshold_days=365,
            review_confidence_threshold=0.1,
        )

        self.assertEqual(len(report["conflict_topics"]), 1)
        conflict = report["conflict_topics"][0]
        self.assertEqual(conflict["topic_hash"], topic)
        self.assertEqual(conflict["source_hashes"], ["1" * 64, "2" * 64])

    def test_empty_rag_returns_empty_report(self) -> None:
        report = monitor_knowledge(
            now=datetime(2026, 3, 2, 0, 0, 0, tzinfo=timezone.utc),
            freshness_threshold_days=30,
            review_confidence_threshold=0.6,
        )
        self.assertEqual(report, {"stale_topics": [], "low_confidence_topics": [], "conflict_topics": []})


if __name__ == "__main__":
    unittest.main()

