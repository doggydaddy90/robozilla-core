from __future__ import annotations

import sys
import sqlite3
import tempfile
import unittest
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from audit.auditLog import AuditLog
import security.pathGuard as path_guard


class AuditLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        path_guard._PROJECT_ROOT_FROZEN = False  # type: ignore[attr-defined]
        path_guard.set_project_root(self.root, freeze=False)
        path_guard.set_audit_logger(None)
        self.audit_path = self.root / "runtime" / "state" / "audit.sqlite"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_append_and_verify_chain(self) -> None:
        log = AuditLog(self.audit_path)
        log.append(actor="tester", action="write", target="a.txt", details={"ok": True})
        log.append(actor="tester", action="delete", target="b.txt", details={"ok": True})
        res = log.verifyAuditChain()
        self.assertTrue(res.valid)
        self.assertEqual(res.entries, 2)
        self.assertEqual(res.errors, [])

    def test_update_is_blocked_by_trigger(self) -> None:
        log = AuditLog(self.audit_path)
        log.append(actor="tester", action="write", target="a.txt", details={})
        conn = sqlite3.connect(str(self.audit_path))
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE audit_entries SET actor = 'tampered' WHERE id = 1;")
        finally:
            conn.close()

    def test_verify_detects_chain_tamper(self) -> None:
        log = AuditLog(self.audit_path)
        first = log.append(actor="tester", action="write", target="a.txt", details={})
        conn = sqlite3.connect(str(self.audit_path))
        try:
            conn.execute(
                """
                INSERT INTO audit_entries(id, timestamp, actor, action, target, details_json, prev_hash, hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (2, first["timestamp"], "tamper", "write", "x", "{}", "bad-prev", "bad-hash"),
            )
            conn.commit()
        finally:
            conn.close()

        res = log.verifyAuditChain()
        self.assertFalse(res.valid)
        self.assertGreater(len(res.errors), 0)


if __name__ == "__main__":
    unittest.main()
