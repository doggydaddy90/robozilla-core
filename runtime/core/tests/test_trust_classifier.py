from __future__ import annotations

import sys
import unittest
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from security.trust_classifier import classify_trust


class TrustClassifierTests(unittest.TestCase):
    def test_internal_structured_call_classified_internal(self) -> None:
        out = classify_trust(
            source={
                "source": "internal_api",
                "typed": True,
                "schema_bound": True,
                "signed": True,
                "content_type": "application/json",
            }
        )
        self.assertEqual(out["trust_level"], "internal_system")

    def test_web_scraped_text_is_unstructured(self) -> None:
        out = classify_trust(
            source={
                "source": "scraped_html",
                "typed": False,
                "schema_bound": False,
                "signed": False,
                "content_type": "text/html",
            }
        )
        self.assertEqual(out["trust_level"], "unstructured_external")

    def test_structured_json_search_result_classified_structured(self) -> None:
        out = classify_trust(
            source={
                "source": "exa_api",
                "typed": False,
                "schema_bound": False,
                "signed": False,
                "content_type": "application/json",
                "structured": True,
            }
        )
        self.assertEqual(out["trust_level"], "structured_external")


if __name__ == "__main__":
    unittest.main()

