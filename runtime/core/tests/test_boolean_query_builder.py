from __future__ import annotations

import sys
import unittest
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from errors import PolicyViolationError
from search.boolean_query_builder import build_boolean_query


class BooleanQueryBuilderTests(unittest.TestCase):
    def test_fast_rejects_around(self) -> None:
        with self.assertRaises(PolicyViolationError):
            build_boolean_query(
                engine="google",
                tier="fast",
                query='"inflation" AROUND(3) "forecast"',
            )

    def test_high_allows_filetype(self) -> None:
        out = build_boolean_query(
            engine="google",
            tier="high",
            query='site:sec.gov AND filetype:pdf AND "10-k risk factors"',
        )
        self.assertEqual(out["tier"], "high")
        self.assertIn("FILETYPE", out["operators_used"])
        self.assertEqual(out["engine"], "google")

    def test_deep_allows_nested_grouping(self) -> None:
        out = build_boolean_query(
            engine="google",
            tier="deep",
            query='(("ai policy" OR regulation) AND (compliance OR governance))',
        )
        self.assertEqual(out["tier"], "deep")
        self.assertIn("GROUP_NESTED", out["operators_used"])

    def test_confirmation_bias_detection(self) -> None:
        with self.assertRaises(PolicyViolationError):
            build_boolean_query(
                engine="google",
                tier="deep",
                query="prove that remote work always improves productivity",
            )

    def test_engine_capability_mismatch_detection(self) -> None:
        with self.assertRaises(PolicyViolationError):
            build_boolean_query(
                engine="duckduckgo",
                tier="high",
                query="site:sec.gov AND filetype:pdf earnings guidance",
            )


if __name__ == "__main__":
    unittest.main()

