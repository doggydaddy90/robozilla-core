from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from orchestration.admission_controller import AdmissionController


def _base_candidate() -> dict[str, Any]:
    return {
        "query": "sample topic",
        "scores": {
            "authority": 0.82,
            "diversity": 0.75,
            "freshness": 0.90,
            "contradiction": 0.0,
        },
        "candidate_document": {
            "summary": "Structured extraction",
            "citations": [
                {"url": "https://www.cdc.gov/topic"},
                {"url": "https://www.nih.gov/research"},
                {"url": "https://www.reuters.com/world/news"},
            ],
            "unresolved_contradictions": [],
        },
    }


class AdmissionControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = AdmissionController()

    def test_pass_case(self) -> None:
        result = self.controller.evaluate(_base_candidate())
        self.assertTrue(result["admit"])
        self.assertEqual(result["reasons"], [])
        self.assertGreaterEqual(float(result["confidence_score"]), 0.80)

    def test_fail_due_to_low_authority(self) -> None:
        candidate = _base_candidate()
        candidate["scores"]["authority"] = 0.30

        result = self.controller.evaluate(candidate)
        self.assertFalse(result["admit"])
        self.assertTrue(any("authority score below threshold" in r for r in result["reasons"]))

    def test_fail_due_to_contradiction(self) -> None:
        candidate = _base_candidate()
        candidate["candidate_document"]["unresolved_contradictions"] = [{"id": "c-1"}]

        result = self.controller.evaluate(candidate)
        self.assertFalse(result["admit"])
        self.assertTrue(any("unresolved contradiction flags present" in r for r in result["reasons"]))

    def test_fail_due_to_staleness(self) -> None:
        candidate = _base_candidate()
        candidate["scores"]["freshness"] = 0.10

        result = self.controller.evaluate(candidate)
        self.assertFalse(result["admit"])
        self.assertTrue(any("freshness policy not satisfied" in r for r in result["reasons"]))


if __name__ == "__main__":
    unittest.main()

