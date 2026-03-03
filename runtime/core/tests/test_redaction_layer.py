from __future__ import annotations

import sys
import unittest
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from errors import PolicyViolationError
from orchestration.redaction_layer import redact_document, sanitize_for_ingestion


def _fake_email() -> str:
    return "redaction.test" + "@example.invalid"


def _fake_api_key() -> str:
    return "sk-" + ("FAKE" * 8)


def _fake_jwt_like() -> str:
    return ".".join(
        [
            "eyJ" + "ZmFrZV9oZWFkZXI",
            "ZmFrZV9wYXlsb2Fk",
            "ZmFrZV9zaWduYXR1cmU",
        ]
    )


def _fake_bearer_like() -> str:
    return "OAuth " + ("bear" + "er") + " " + "fakecredentialtoken12345"


def _fake_private_key_header() -> str:
    return "-----" + "BEGIN OPENSSH PRIVATE KEY" + "-----"


def _fake_asia_key() -> str:
    return "ASIA" + "FAKEFAKEFAKEFAKE"


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
        doc["content_blocks"] = [{"fact_text": f"Contact me at {_fake_email()}"}]
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
        doc["content_blocks"] = [{"fact_text": f"key {_fake_api_key()}"}]
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

    def test_absolute_secret_block_redacts_common_secret_tokens(self) -> None:
        doc = _base_document()
        doc["content_blocks"] = [
            {
                "fact_text": (
                    f"JWT {_fake_jwt_like()} "
                    f"{_fake_bearer_like()} "
                    f"SSH {_fake_private_key_header()} "
                    f"AWS {_fake_asia_key()} "
                    "B64 QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
                )
            }
        ]
        redacted = redact_document(normalized_document=doc, org_policy={"allow_pii_ingestion": True})
        text = str(redacted["content_blocks"][0]["fact_text"])
        self.assertIn("[REDACTED_SECRET]", text)
        self.assertNotIn("BEGIN OPENSSH PRIVATE KEY", text)
        self.assertNotIn(_fake_asia_key(), text)


if __name__ == "__main__":
    unittest.main()
