from __future__ import annotations

import sys
import unittest
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from errors import PolicyViolationError
from orchestration.redaction_layer import sanitize_for_ingestion


def _base_document() -> dict[str, object]:
    return {
        "document_id": "a" * 64,
        "topic_hash": "b" * 64,
        "source_hash": "c" * 64,
        "version": 1,
        "content_blocks": [{"fact_text": "safe text"}],
    }


class RedactionLayerTests(unittest.TestCase):
    def test_email_detection(self) -> None:
        doc = _base_document()
        doc["content_blocks"] = [{"fact_text": "Contact me at alice@example.com"}]
        with self.assertRaises(PolicyViolationError):
            sanitize_for_ingestion(
                normalized_document=doc,
                org_policy={"allow_pii_ingestion": False},
            )

    def test_phone_detection(self) -> None:
        doc = _base_document()
        doc["content_blocks"] = [{"fact_text": "Call +1 (415) 555-1212 for details"}]
        with self.assertRaises(PolicyViolationError):
            sanitize_for_ingestion(
                normalized_document=doc,
                org_policy={"allow_pii_ingestion": False},
            )

    def test_api_key_detection(self) -> None:
        doc = _base_document()
        doc["content_blocks"] = [{"fact_text": "key sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"}]
        with self.assertRaises(PolicyViolationError):
            sanitize_for_ingestion(
                normalized_document=doc,
                org_policy={"allow_pii_ingestion": False},
            )

    def test_public_figure_allowed(self) -> None:
        doc = _base_document()
        doc["author_name"] = "Warren Buffett"
        sanitized = sanitize_for_ingestion(
            normalized_document=doc,
            org_policy={
                "allow_pii_ingestion": False,
                "public_figure_whitelist": ["Warren Buffett"],
            },
        )
        self.assertEqual(sanitized["author_name"], "Warren Buffett")

    def test_private_name_rejection(self) -> None:
        doc = _base_document()
        doc["author_name"] = "Jane Smith"
        with self.assertRaises(PolicyViolationError):
            sanitize_for_ingestion(
                normalized_document=doc,
                org_policy={"allow_pii_ingestion": False},
            )


if __name__ == "__main__":
    unittest.main()
