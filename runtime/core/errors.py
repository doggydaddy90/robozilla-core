"""Core runtime error types.

The runtime is fail-closed: it rejects requests when it cannot prove safety.
These exception types are mapped to HTTP responses in the API layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


class RoboZillaRuntimeError(Exception):
    """Base class for runtime errors."""


@dataclass(frozen=True)
class SchemaViolation:
    path: str
    message: str


class SchemaValidationError(RoboZillaRuntimeError):
    def __init__(self, kind: str, violations: Iterable[SchemaViolation]):
        self.kind = kind
        self.violations = list(violations)
        super().__init__(f"{kind} failed schema validation ({len(self.violations)} violation(s))")


class NotFoundError(RoboZillaRuntimeError):
    def __init__(self, resource_type: str, resource_id: str):
        self.resource_type = resource_type
        self.resource_id = resource_id
        super().__init__(f"{resource_type} not found: {resource_id}")


class ConflictError(RoboZillaRuntimeError):
    def __init__(self, message: str, details: Any | None = None):
        self.details = details
        super().__init__(message)


class PolicyViolationError(RoboZillaRuntimeError):
    def __init__(self, message: str, details: Any | None = None):
        self.details = details
        super().__init__(message)


class ContractViolationError(RoboZillaRuntimeError):
    def __init__(self, message: str, code: str = "CONTRACT_VIOLATION", details: Any | None = None):
        self.code = code
        self.details = details
        super().__init__(message)

