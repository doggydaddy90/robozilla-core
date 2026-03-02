from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from orchestration.normalizer import normalize_candidate


def _router_json() -> dict[str, Any]:
    return {
        "query": "global inflation trend",
        "scores": {
            "authority": 0.88,
            "diversity": 0.75,
            "freshness": 0.90,
            "contradiction": 0.0,
        },
        "candidate_document": {
            "summary": "Inflation is easing in several regions while core services remain sticky.",
            "citations": [
                {"url": "https://www.imf.org/en/Publications"},
                {"url": "https://www.oecd.org/economy/outlook"},
                {"url": "https://www.reuters.com/world/economy"},
            ],
            "facts": [
                "Headline inflation has decelerated versus prior year peaks.",
                "Services inflation remains relatively elevated.",
            ],
        },
    }


def _admission() -> dict[str, Any]:
    return {"admit": True, "confidence_score": 0.86, "reasons": []}


class NormalizerTests(unittest.TestCase):
    def test_canonical_structure(self) -> None:
        out = normalize_candidate(
            router_json=_router_json(),
            admission_result=_admission(),
            created_at="2026-03-01T00:00:00Z",
        )

        required = {
            "document_id",
            "topic",
            "topic_hash",
            "source_hash",
            "version",
            "created_at",
            "confidence_score",
            "citations",
            "content_blocks",
        }
        self.assertTrue(required.issubset(set(out.keys())))
        self.assertEqual(out["topic"], "global inflation trend")
        self.assertEqual(out["version"], 1)
        self.assertEqual(out["created_at"], "2026-03-01T00:00:00Z")
        self.assertEqual(len(out["citations"]), 3)
        self.assertGreaterEqual(len(out["content_blocks"]), 1)

    def test_hash_stability(self) -> None:
        r = _router_json()
        a = _admission()
        first = normalize_candidate(router_json=r, admission_result=a, created_at="2026-03-01T00:00:00Z")
        second = normalize_candidate(router_json=r, admission_result=a, created_at="2026-03-01T00:00:00Z")

        self.assertEqual(first["topic_hash"], second["topic_hash"])
        self.assertEqual(first["source_hash"], second["source_hash"])
        self.assertEqual(first["document_id"], second["document_id"])
        self.assertEqual(first["content_blocks"], second["content_blocks"])

    def test_version_increment_scenario(self) -> None:
        base = normalize_candidate(
            router_json=_router_json(),
            admission_result=_admission(),
            created_at="2026-03-01T00:00:00Z",
        )
        nxt = normalize_candidate(
            router_json=_router_json(),
            admission_result=_admission(),
            previous_entry=base,
            created_at="2026-03-02T00:00:00Z",
        )

        self.assertEqual(base["version"], 1)
        self.assertEqual(nxt["version"], 2)
        self.assertNotEqual(base["document_id"], nxt["document_id"])


if __name__ == "__main__":
    unittest.main()

