"""Immutable append-only audit log with hash-chain verification."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security.pathGuard import resolve_path

_GENESIS_PREV_HASH = "0" * 64


@dataclass(frozen=True)
class AuditVerificationResult:
    valid: bool
    entries: int
    errors: list[str]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(obj: dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _entry_hash(prev_hash: str, entry_without_hash: dict[str, Any]) -> str:
    payload = prev_hash + _canonical_json(entry_without_hash)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Path | str):
        resolved = resolve_path(path, operation="audit_log", require_exists=False)
        self._path = resolved
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._migrate()

    @property
    def path(self) -> Path:
        return self._path

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(str(self._path), timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _migrate(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_entries (
                  id INTEGER PRIMARY KEY,
                  timestamp TEXT NOT NULL,
                  actor TEXT NOT NULL,
                  action TEXT NOT NULL,
                  target TEXT NOT NULL,
                  details_json TEXT NOT NULL,
                  prev_hash TEXT NOT NULL,
                  hash TEXT NOT NULL UNIQUE
                );
                """
            )
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_audit_entries_no_update
                BEFORE UPDATE ON audit_entries
                BEGIN
                  SELECT RAISE(ABORT, 'audit_entries are immutable');
                END;
                """
            )
            conn.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trg_audit_entries_no_delete
                BEFORE DELETE ON audit_entries
                BEGIN
                  SELECT RAISE(ABORT, 'audit_entries are immutable');
                END;
                """
            )

    def append(self, *, actor: str, action: str, target: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        details_obj = details or {}
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                row = conn.execute("SELECT id, hash FROM audit_entries ORDER BY id DESC LIMIT 1;").fetchone()
                next_id = 1 if row is None else int(row["id"]) + 1
                prev_hash = _GENESIS_PREV_HASH if row is None else str(row["hash"])

                entry_wo_hash: dict[str, Any] = {
                    "id": next_id,
                    "timestamp": _utc_now_iso(),
                    "actor": str(actor),
                    "action": str(action),
                    "target": str(target),
                    "details": details_obj,
                    "prev_hash": prev_hash,
                }
                digest = _entry_hash(prev_hash, entry_wo_hash)

                conn.execute(
                    """
                    INSERT INTO audit_entries(
                      id, timestamp, actor, action, target, details_json, prev_hash, hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        entry_wo_hash["id"],
                        entry_wo_hash["timestamp"],
                        entry_wo_hash["actor"],
                        entry_wo_hash["action"],
                        entry_wo_hash["target"],
                        _canonical_json(details_obj),
                        entry_wo_hash["prev_hash"],
                        digest,
                    ),
                )
                conn.execute("COMMIT;")
                return {**entry_wo_hash, "hash": digest}
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def verifyAuditChain(self) -> AuditVerificationResult:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, timestamp, actor, action, target, details_json, prev_hash, hash
                FROM audit_entries
                ORDER BY id ASC;
                """
            ).fetchall()

        expected_id = 1
        expected_prev_hash = _GENESIS_PREV_HASH
        errors: list[str] = []

        for row in rows:
            row_id = int(row["id"])
            if row_id != expected_id:
                errors.append(f"id sequence break: expected {expected_id}, got {row_id}")

            details: dict[str, Any]
            try:
                parsed = json.loads(str(row["details_json"]))
                details = parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                details = {}
                errors.append(f"invalid details_json at id {row_id}")

            entry_wo_hash = {
                "id": row_id,
                "timestamp": str(row["timestamp"]),
                "actor": str(row["actor"]),
                "action": str(row["action"]),
                "target": str(row["target"]),
                "details": details,
                "prev_hash": str(row["prev_hash"]),
            }

            if entry_wo_hash["prev_hash"] != expected_prev_hash:
                errors.append(f"prev_hash mismatch at id {row_id}")

            computed_hash = _entry_hash(expected_prev_hash, entry_wo_hash)
            if str(row["hash"]) != computed_hash:
                errors.append(f"hash mismatch at id {row_id}")

            expected_prev_hash = str(row["hash"])
            expected_id += 1

        return AuditVerificationResult(valid=len(errors) == 0, entries=len(rows), errors=errors)


def verifyAuditChain(audit_log: AuditLog) -> AuditVerificationResult:
    return audit_log.verifyAuditChain()
