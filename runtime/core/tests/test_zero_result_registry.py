from __future__ import annotations

import sqlite3
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from security.pathGuard import resolve_path
from search.zero_result_registry import (
    compute_query_signature,
    decay_old_entries,
    record_zero_result,
    reset_entry,
    should_block_premium,
)


class ZeroResultRegistryTests(unittest.TestCase):
    def _tmp_db(self) -> Path:
        return Path("runtime/tmp/zero_result_registry_tests") / f"{uuid.uuid4().hex}.sqlite"

    def test_zero_result_increments(self) -> None:
        db = self._tmp_db()
        query = 'site:sec.gov "earnings guidance" after:2025-01-01'
        record_zero_result("perplexity_research_tool", query, 0.2, db_path=db)
        record_zero_result("perplexity_research_tool", query, 0.3, db_path=db)

        sig = compute_query_signature(query)
        resolved_db = resolve_path(db, operation="zero_result_registry_test_read", require_exists=True)
        conn = sqlite3.connect(str(resolved_db))
        try:
            row = conn.execute(
                "SELECT zero_count FROM zero_result_registry WHERE engine = ? AND query_signature = ?",
                ("perplexity_research_tool", sig),
            ).fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(int(row[0]), 2)

    def test_premium_block_triggered(self) -> None:
        db = self._tmp_db()
        query = "market microstructure dislocation pattern"
        for _ in range(3):
            record_zero_result("perplexity_research_tool", query, 0.1, db_path=db)
        self.assertTrue(should_block_premium("perplexity_research_tool", query, 0.1, db_path=db))

    def test_decay_expiration(self) -> None:
        db = self._tmp_db()
        query = "rare filings set"
        record_zero_result("perplexity_research_tool", query, 0.4, db_path=db)
        old = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat().replace("+00:00", "Z")
        sig = compute_query_signature(query)
        resolved_db = resolve_path(db, operation="zero_result_registry_test_update", require_exists=True)
        conn = sqlite3.connect(str(resolved_db))
        try:
            conn.execute(
                "UPDATE zero_result_registry SET last_seen = ? WHERE engine = ? AND query_signature = ?",
                (old, "perplexity_research_tool", sig),
            )
            conn.commit()
        finally:
            conn.close()

        removed = decay_old_entries(days=30, db_path=db)
        self.assertEqual(removed, 1)
        self.assertFalse(should_block_premium("perplexity_research_tool", query, 0.4, db_path=db))

    def test_reset_after_successful_hit(self) -> None:
        db = self._tmp_db()
        query = "emerging policy volatility"
        for _ in range(2):
            record_zero_result("perplexity_research_tool", query, 0.2, db_path=db)
        sig = compute_query_signature(query)
        reset_entry("perplexity_research_tool", sig, db_path=db)
        self.assertFalse(should_block_premium("perplexity_research_tool", query, 0.2, db_path=db))


if __name__ == "__main__":
    unittest.main()
