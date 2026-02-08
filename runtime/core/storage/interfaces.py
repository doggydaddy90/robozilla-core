"""DB-agnostic storage interfaces.

The runtime is stateless except for DB-backed state. These interfaces define
the persistence boundary for:
- JobContract documents and lifecycle updates
- Artifact documents (append-only)
- Evaluation documents (append-only)

Concrete drivers live in `storage/` (SQLite default in build mode).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable


@dataclass(frozen=True)
class StoredRow:
    id: str
    org_id: str
    created_at: datetime
    document: dict[str, Any]


class JobStore(ABC):
    @abstractmethod
    def create(self, job: dict[str, Any]) -> None:
        """Insert a new JobContract. Must fail if job_id already exists."""

    @abstractmethod
    def get(self, job_id: str) -> dict[str, Any]:
        """Fetch a JobContract by id. Must raise if not found."""

    @abstractmethod
    def update(self, job: dict[str, Any]) -> None:
        """Replace the stored JobContract document (job_id is the key)."""

    @abstractmethod
    def count_active_by_org(self, org_id: str) -> int:
        """Count active (non-terminal) jobs for an org."""

    @abstractmethod
    def record_event(self, *, org_id: str, job_id: str, event_type: str, details: dict[str, Any] | None = None) -> None:
        """Append an audit event for a job (append-only)."""

    @abstractmethod
    def count_events_since(self, *, org_id: str, event_type: str, since: datetime) -> int:
        """Count events of a given type since a timestamp (inclusive)."""


class ArtifactStore(ABC):
    @abstractmethod
    def append(self, artifact: dict[str, Any]) -> None:
        """Append an immutable Artifact. Must fail if artifact_id already exists."""

    @abstractmethod
    def get(self, artifact_id: str) -> dict[str, Any]:
        """Fetch an Artifact by id. Must raise if not found."""

    @abstractmethod
    def list_for_job(self, job_id: str) -> Iterable[dict[str, Any]]:
        """List artifacts for a job."""


class EvaluationStore(ABC):
    @abstractmethod
    def append(self, evaluation: dict[str, Any]) -> None:
        """Append an immutable Evaluation. Must fail if evaluation_id already exists."""

    @abstractmethod
    def get(self, evaluation_id: str) -> dict[str, Any]:
        """Fetch an Evaluation by id. Must raise if not found."""

    @abstractmethod
    def list_for_job(self, job_id: str) -> Iterable[dict[str, Any]]:
        """List evaluations for a job."""

