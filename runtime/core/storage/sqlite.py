"""SQLite storage driver (default build-mode persistence).

This module provides a simple SQLite implementation behind the DB-agnostic
storage interfaces. SQLite is used only as a local, file-backed state store.

Tables are append-only where required by the constitutional contracts:
- artifacts: append-only, immutable
- evaluations: append-only, immutable
- job_events: append-only audit log
Jobs are mutable only in the `spec.status` portion of the JobContract document.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from errors import ConflictError, NotFoundError, PolicyViolationError
from storage.interfaces import ArtifactStore, EvaluationStore, JobStore
from utils import deep_get, json_dumps


def _utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _extract_job_columns(job: dict[str, Any]) -> dict[str, Any]:
    job_id = str(deep_get(job, ["metadata", "job_id"]))
    org_id = str(deep_get(job, ["metadata", "org_id"]))
    state = str(deep_get(job, ["spec", "status", "state"]))
    created_at = str(deep_get(job, ["spec", "timestamps", "created_at"]))
    expires_at = str(deep_get(job, ["spec", "timestamps", "expires_at"]))
    status_updated_at = str(deep_get(job, ["spec", "status", "status_updated_at"]))

    status = deep_get(job, ["spec", "status"])
    started_at = status.get("started_at")
    terminal_at = status.get("terminal_at")
    final_evaluation_ref = status.get("final_evaluation_ref")
    failure_mode = status.get("failure_mode")
    expiry_reason = status.get("expiry_reason")

    return {
        "job_id": job_id,
        "org_id": org_id,
        "state": state,
        "created_at": created_at,
        "expires_at": expires_at,
        "status_updated_at": status_updated_at,
        "started_at": started_at,
        "terminal_at": terminal_at,
        "final_evaluation_ref": final_evaluation_ref,
        "failure_mode": failure_mode,
        "expiry_reason": expiry_reason,
        "doc_json": json_dumps(job),
    }


def _extract_artifact_columns(artifact: dict[str, Any]) -> dict[str, Any]:
    artifact_id = str(deep_get(artifact, ["metadata", "artifact_id"]))
    org_id = str(deep_get(artifact, ["metadata", "org_id"]))
    artifact_type = str(deep_get(artifact, ["metadata", "artifact_type"]))
    job_id = str(deep_get(artifact, ["spec", "job_ref", "job_id"]))
    created_at = str(deep_get(artifact, ["spec", "created_at"]))
    produced_by_agent_id = str(deep_get(artifact, ["spec", "produced_by", "agent_id"]))
    return {
        "artifact_id": artifact_id,
        "org_id": org_id,
        "job_id": job_id,
        "artifact_type": artifact_type,
        "created_at": created_at,
        "produced_by_agent_id": produced_by_agent_id,
        "doc_json": json_dumps(artifact),
    }


def _extract_evaluation_columns(evaluation: dict[str, Any]) -> dict[str, Any]:
    evaluation_id = str(deep_get(evaluation, ["metadata", "evaluation_id"]))
    org_id = str(deep_get(evaluation, ["metadata", "org_id"]))
    job_id = str(deep_get(evaluation, ["spec", "job_ref", "job_id"]))
    created_at = str(deep_get(evaluation, ["spec", "created_at"]))
    outcome_status = str(deep_get(evaluation, ["spec", "outcome", "status"]))
    next_job_state = str(deep_get(evaluation, ["spec", "outcome", "next_job_state"]))
    evaluator = deep_get(evaluation, ["spec", "evaluator"])
    evaluator_actor_type = str(evaluator.get("actor_type", ""))
    evaluator_actor_id = str(evaluator.get("actor_id", ""))
    return {
        "evaluation_id": evaluation_id,
        "org_id": org_id,
        "job_id": job_id,
        "created_at": created_at,
        "outcome_status": outcome_status,
        "next_job_state": next_job_state,
        "evaluator_actor_type": evaluator_actor_type,
        "evaluator_actor_id": evaluator_actor_id,
        "doc_json": json_dumps(evaluation),
    }


class SQLiteDatabase:
    def __init__(self, path: Path):
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
        finally:
            conn.close()

    def _migrate(self) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_version (
                  version INTEGER NOT NULL
                );
                """
            )
            row = conn.execute("SELECT version FROM schema_version LIMIT 1;").fetchone()
            if row is None:
                conn.execute("INSERT INTO schema_version(version) VALUES (1);")
                version = 1
            else:
                version = int(row["version"])

            if version != 1:
                raise PolicyViolationError(f"Unsupported SQLite schema_version: {version}")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                  job_id TEXT PRIMARY KEY,
                  org_id TEXT NOT NULL,
                  state TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  expires_at TEXT NOT NULL,
                  status_updated_at TEXT NOT NULL,
                  started_at TEXT,
                  terminal_at TEXT,
                  final_evaluation_ref TEXT,
                  failure_mode TEXT,
                  expiry_reason TEXT,
                  doc_json TEXT NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_org_state ON jobs(org_id, state);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_org_created_at ON jobs(org_id, created_at);")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                  artifact_id TEXT PRIMARY KEY,
                  org_id TEXT NOT NULL,
                  job_id TEXT NOT NULL,
                  artifact_type TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  produced_by_agent_id TEXT NOT NULL,
                  doc_json TEXT NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_artifacts_job_id ON artifacts(job_id, created_at);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_artifacts_org_id ON artifacts(org_id, created_at);")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evaluations (
                  evaluation_id TEXT PRIMARY KEY,
                  org_id TEXT NOT NULL,
                  job_id TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  outcome_status TEXT NOT NULL,
                  next_job_state TEXT NOT NULL,
                  evaluator_actor_type TEXT NOT NULL,
                  evaluator_actor_id TEXT NOT NULL,
                  doc_json TEXT NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_evaluations_job_id ON evaluations(job_id, created_at);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_evaluations_org_id ON evaluations(org_id, created_at);")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS job_events (
                  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ts TEXT NOT NULL,
                  org_id TEXT NOT NULL,
                  job_id TEXT NOT NULL,
                  event_type TEXT NOT NULL,
                  details_json TEXT
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_job_events_org_ts ON job_events(org_id, ts);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_job_events_job_ts ON job_events(job_id, ts);")


class SQLiteJobStore(JobStore):
    def __init__(self, db: SQLiteDatabase):
        self._db = db

    def create(self, job: dict[str, Any]) -> None:
        cols = _extract_job_columns(job)
        with self._db.connect() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO jobs(
                      job_id, org_id, state, created_at, expires_at, status_updated_at,
                      started_at, terminal_at, final_evaluation_ref, failure_mode, expiry_reason, doc_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        cols["job_id"],
                        cols["org_id"],
                        cols["state"],
                        cols["created_at"],
                        cols["expires_at"],
                        cols["status_updated_at"],
                        cols["started_at"],
                        cols["terminal_at"],
                        cols["final_evaluation_ref"],
                        cols["failure_mode"],
                        cols["expiry_reason"],
                        cols["doc_json"],
                    ),
                )
            except sqlite3.IntegrityError as e:
                raise ConflictError(f"Job already exists: {cols['job_id']}") from e

    def get(self, job_id: str) -> dict[str, Any]:
        with self._db.connect() as conn:
            row = conn.execute("SELECT doc_json FROM jobs WHERE job_id = ?;", (job_id,)).fetchone()
            if row is None:
                raise NotFoundError("JobContract", job_id)
            return json.loads(row["doc_json"])

    def update(self, job: dict[str, Any]) -> None:
        cols = _extract_job_columns(job)
        with self._db.connect() as conn:
            cur = conn.execute(
                """
                UPDATE jobs SET
                  org_id = ?,
                  state = ?,
                  created_at = ?,
                  expires_at = ?,
                  status_updated_at = ?,
                  started_at = ?,
                  terminal_at = ?,
                  final_evaluation_ref = ?,
                  failure_mode = ?,
                  expiry_reason = ?,
                  doc_json = ?
                WHERE job_id = ?;
                """,
                (
                    cols["org_id"],
                    cols["state"],
                    cols["created_at"],
                    cols["expires_at"],
                    cols["status_updated_at"],
                    cols["started_at"],
                    cols["terminal_at"],
                    cols["final_evaluation_ref"],
                    cols["failure_mode"],
                    cols["expiry_reason"],
                    cols["doc_json"],
                    cols["job_id"],
                ),
            )
            if cur.rowcount != 1:
                raise NotFoundError("JobContract", cols["job_id"])

    def count_active_by_org(self, org_id: str) -> int:
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(1) AS c FROM jobs WHERE org_id = ? AND state IN ('running','waiting');",
                (org_id,),
            ).fetchone()
            return int(row["c"]) if row is not None else 0

    def record_event(self, *, org_id: str, job_id: str, event_type: str, details: dict[str, Any] | None = None) -> None:
        with self._db.connect() as conn:
            conn.execute(
                "INSERT INTO job_events(ts, org_id, job_id, event_type, details_json) VALUES (?, ?, ?, ?, ?);",
                (_utc_iso(_now_utc()), org_id, job_id, event_type, json_dumps(details or {})),
            )

    def count_events_since(self, *, org_id: str, event_type: str, since: datetime) -> int:
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(1) AS c FROM job_events WHERE org_id = ? AND event_type = ? AND ts >= ?;",
                (org_id, event_type, _utc_iso(since)),
            ).fetchone()
            return int(row["c"]) if row is not None else 0


class SQLiteArtifactStore(ArtifactStore):
    def __init__(self, db: SQLiteDatabase):
        self._db = db

    def append(self, artifact: dict[str, Any]) -> None:
        cols = _extract_artifact_columns(artifact)
        with self._db.connect() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO artifacts(
                      artifact_id, org_id, job_id, artifact_type, created_at, produced_by_agent_id, doc_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        cols["artifact_id"],
                        cols["org_id"],
                        cols["job_id"],
                        cols["artifact_type"],
                        cols["created_at"],
                        cols["produced_by_agent_id"],
                        cols["doc_json"],
                    ),
                )
            except sqlite3.IntegrityError as e:
                raise ConflictError(f"Artifact already exists: {cols['artifact_id']}") from e

    def get(self, artifact_id: str) -> dict[str, Any]:
        with self._db.connect() as conn:
            row = conn.execute("SELECT doc_json FROM artifacts WHERE artifact_id = ?;", (artifact_id,)).fetchone()
            if row is None:
                raise NotFoundError("Artifact", artifact_id)
            return json.loads(row["doc_json"])

    def list_for_job(self, job_id: str) -> Iterable[dict[str, Any]]:
        with self._db.connect() as conn:
            rows = conn.execute("SELECT doc_json FROM artifacts WHERE job_id = ? ORDER BY created_at ASC;", (job_id,)).fetchall()
            return [json.loads(r["doc_json"]) for r in rows]


class SQLiteEvaluationStore(EvaluationStore):
    def __init__(self, db: SQLiteDatabase):
        self._db = db

    def append(self, evaluation: dict[str, Any]) -> None:
        cols = _extract_evaluation_columns(evaluation)
        with self._db.connect() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO evaluations(
                      evaluation_id, org_id, job_id, created_at,
                      outcome_status, next_job_state, evaluator_actor_type, evaluator_actor_id, doc_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        cols["evaluation_id"],
                        cols["org_id"],
                        cols["job_id"],
                        cols["created_at"],
                        cols["outcome_status"],
                        cols["next_job_state"],
                        cols["evaluator_actor_type"],
                        cols["evaluator_actor_id"],
                        cols["doc_json"],
                    ),
                )
            except sqlite3.IntegrityError as e:
                raise ConflictError(f"Evaluation already exists: {cols['evaluation_id']}") from e

    def get(self, evaluation_id: str) -> dict[str, Any]:
        with self._db.connect() as conn:
            row = conn.execute("SELECT doc_json FROM evaluations WHERE evaluation_id = ?;", (evaluation_id,)).fetchone()
            if row is None:
                raise NotFoundError("Evaluation", evaluation_id)
            return json.loads(row["doc_json"])

    def list_for_job(self, job_id: str) -> Iterable[dict[str, Any]]:
        with self._db.connect() as conn:
            rows = conn.execute("SELECT doc_json FROM evaluations WHERE job_id = ? ORDER BY created_at ASC;", (job_id,)).fetchall()
            return [json.loads(r["doc_json"]) for r in rows]


class SQLiteStores:
    """Convenience container for the three stores backed by one SQLite file."""

    def __init__(self, sqlite_path: Path):
        db = SQLiteDatabase(sqlite_path)
        self.jobs: JobStore = SQLiteJobStore(db)
        self.artifacts: ArtifactStore = SQLiteArtifactStore(db)
        self.evaluations: EvaluationStore = SQLiteEvaluationStore(db)

