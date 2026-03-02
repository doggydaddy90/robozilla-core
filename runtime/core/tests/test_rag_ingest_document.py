from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from audit.auditLog import AuditLog
from errors import PolicyViolationError
import security.pathGuard as path_guard
from skills.rag_ingest_document import ingest_document


def _prompt() -> str:
    return "rag ingest topic"


def _topic_hash_from_prompt(prompt: str) -> str:
    return hashlib.sha256(prompt.strip().lower().encode("utf-8")).hexdigest()


def _job(allow_diff_apply: bool, *, intent_hash: str | None = None, prompt: str | None = None) -> dict[str, Any]:
    value = prompt or _prompt()
    computed_intent_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return {
        "spec": {
            "intent_envelope": {
                "original_prompt": value,
                "intent_hash": intent_hash or computed_intent_hash,
                "allowed_domains": ["example.org"],
                "allowed_scopes": ["ingestion", "execute"],
                "created_at": "2026-03-02T00:00:00Z",
            },
            "permissions_snapshot": {
                "confirmations": {
                    "allow_diff_apply": allow_diff_apply,
                }
            }
        }
    }


def _hash(ch: str) -> str:
    return ch * 64


def _doc(*, version: int, fact_suffix: str = "v1") -> dict[str, Any]:
    topic_hash = _topic_hash_from_prompt(_prompt())
    return {
        "document_id": _hash("a"),
        "topic_hash": topic_hash,
        "source_hash": _hash("c"),
        "version": version,
        "content_blocks": [{"fact_text": f"fact-{fact_suffix}"}],
        "citations": ["https://example.org/a", "https://example.org/b"],
        "confidence_score": 0.9,
    }


class RagIngestDocumentTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        path_guard._PROJECT_ROOT_FROZEN = False  # type: ignore[attr-defined]
        path_guard.set_project_root(self.root, freeze=False)
        self.audit = AuditLog(self.root / "runtime" / "state" / "audit.sqlite")
        path_guard.set_audit_logger(self.audit)

    def tearDown(self) -> None:
        path_guard.set_audit_logger(None)
        self._tmp.cleanup()

    def test_new_document_ingestion(self) -> None:
        normalized = _doc(version=1, fact_suffix="v1")
        res = ingest_document(normalized_document=normalized, job_contract=_job(True), audit_log=self.audit)

        expected_rel = f"rag/{normalized['topic_hash']}/{normalized['document_id']}.json"
        expected_abs = self.root / expected_rel
        self.assertEqual(res["status"], "ingested")
        self.assertEqual(res["path"], expected_rel)
        self.assertEqual(res["document_id"], normalized["document_id"])
        self.assertEqual(res["version"], 1)
        self.assertTrue(expected_abs.exists())

        stored = json.loads(expected_abs.read_text(encoding="utf-8"))
        self.assertEqual(stored["version"], 1)
        self.assertEqual(stored["content_blocks"][0]["fact_text"], "fact-v1")
        self.assertTrue(self._has_audit_action("rag.ingest_document"))

    def test_version_increment_ingestion(self) -> None:
        v1 = _doc(version=1, fact_suffix="v1")
        ingest_document(normalized_document=v1, job_contract=_job(True), audit_log=self.audit)

        v2 = _doc(version=2, fact_suffix="v2")
        res = ingest_document(normalized_document=v2, job_contract=_job(True), audit_log=self.audit)

        expected_abs = self.root / res["path"]
        stored = json.loads(expected_abs.read_text(encoding="utf-8"))
        self.assertEqual(stored["version"], 2)
        self.assertEqual(stored["content_blocks"][0]["fact_text"], "fact-v2")

    def test_missing_confirmation_flag_must_fail(self) -> None:
        normalized = _doc(version=1, fact_suffix="denied")
        with self.assertRaises(PolicyViolationError):
            ingest_document(normalized_document=normalized, job_contract=_job(False), audit_log=self.audit)

    def test_schema_invalid_must_fail(self) -> None:
        invalid = {
            "document_id": _hash("a"),
            "topic_hash": _hash("b"),
            "source_hash": _hash("c"),
            "version": 1,
            # content_blocks intentionally missing.
        }
        with self.assertRaises(PolicyViolationError):
            ingest_document(normalized_document=invalid, job_contract=_job(True), audit_log=self.audit)

    def test_mismatched_intent_hash_must_fail(self) -> None:
        normalized = _doc(version=1, fact_suffix="mismatch")
        with self.assertRaises(PolicyViolationError):
            ingest_document(
                normalized_document=normalized,
                job_contract=_job(True, intent_hash="0" * 64),
                audit_log=self.audit,
            )

    def _has_audit_action(self, action: str) -> bool:
        conn = sqlite3.connect(str(self.audit.path))
        try:
            row = conn.execute("SELECT COUNT(*) FROM audit_entries WHERE action = ?;", (action,)).fetchone()
            return bool(row and int(row[0]) > 0)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
