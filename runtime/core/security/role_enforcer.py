"""Role-based data access controls with absolute credential protection."""

from __future__ import annotations

import re
from typing import Any

from errors import PolicyViolationError

_VALID_ROLES = {"admin", "operator", "viewer", "agent_internal"}
_ADMIN_ONLY_PERSONAL_FIELDS = {"address", "phone", "ssn"}
_SECRET_FIELD_HINTS = {
    "api_key",
    "apikey",
    "token",
    "oauth",
    "jwt",
    "access_key",
    "secret_key",
    "private_key",
    "env",
    "environment",
    "ssh_key",
}

_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\b"),  # JWT-like
    re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC|DSA)? ?PRIVATE KEY-----"),
    re.compile(r"\b(?:oauth|bearer)\s+[A-Za-z0-9._-]{10,}\b", re.IGNORECASE),
    re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b"),
)

REDACTED_SECRET = "[REDACTED_SECRET]"


def enforce_role_data_access(
    *,
    role: str,
    field_name: str,
    value: Any,
    channel: str = "chat",
    audit_log: Any | None = None,
) -> Any:
    role_norm = _normalize_role(role)
    field = str(field_name).strip().lower()
    channel_norm = str(channel).strip().lower()

    if _looks_like_secret(field=field, value=value):
        _log_role_event(audit_log, role=role_norm, field=field, decision="secret_redacted")
        if channel_norm == "chat":
            return REDACTED_SECRET
        raise PolicyViolationError("credential retrieval is forbidden")

    if field in _ADMIN_ONLY_PERSONAL_FIELDS and role_norm != "admin":
        _log_role_event(audit_log, role=role_norm, field=field, decision="denied")
        raise PolicyViolationError(f"{role_norm} is not authorized to access '{field}'")
    _log_role_event(audit_log, role=role_norm, field=field, decision="allowed")
    return value


def can_adjust_strictness(*, role: str) -> bool:
    return _normalize_role(role) == "admin"


def can_approve_mutation(*, role: str) -> bool:
    return _normalize_role(role) == "admin"


def redact_record_for_chat(*, role: str, record: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise PolicyViolationError("record must be an object")
    out: dict[str, Any] = {}
    for k, v in record.items():
        key = str(k)
        out[key] = enforce_role_data_access(role=role, field_name=key, value=v, channel="chat")
    return out


def _normalize_role(role: str) -> str:
    value = str(role).strip().lower()
    if value not in _VALID_ROLES:
        raise PolicyViolationError(f"invalid role '{role}'")
    return value


def _looks_like_secret(*, field: str, value: Any) -> bool:
    for hint in _SECRET_FIELD_HINTS:
        if hint in field:
            return True
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text:
        return False
    for pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            return True
    return False


def _log_role_event(audit_log: Any | None, *, role: str, field: str, decision: str) -> None:
    if audit_log is None:
        return
    audit_log.append(
        actor="runtime.core.security.role_enforcer",
        action="role.access",
        target="chat",
        details={"role": role, "field": field, "decision": decision},
    )
