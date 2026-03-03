"""Runtime event model for kernel-owned event emission."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from errors import PolicyViolationError

ALLOWED_EVENT_TYPES = frozenset(
    {
        "module_spawn",
        "module_timeout_kill",
        "capability_request",
        "capability_denied",
        "kill_switch_activated",
    }
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sanitize_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            out[str(key)] = _sanitize_value(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(item) for item in value]
    return str(value)


def sanitize_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    if metadata is None:
        return {}
    if not isinstance(metadata, dict):
        raise PolicyViolationError("RuntimeEvent.metadata must be an object")
    out: dict[str, Any] = {}
    for key, value in metadata.items():
        out[str(key)] = _sanitize_value(value)
    return out


@dataclass(frozen=True)
class RuntimeEvent:
    event_type: str
    timestamp: datetime = field(default_factory=_utc_now)
    job_id: str | None = None
    module_name: str | None = None
    capability: str | None = None
    actor_role: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        event_type = str(self.event_type).strip()
        if not event_type:
            raise PolicyViolationError("RuntimeEvent.event_type must be non-empty")
        if event_type not in ALLOWED_EVENT_TYPES:
            raise PolicyViolationError(f"Unsupported RuntimeEvent.event_type: {event_type}")
        object.__setattr__(self, "event_type", event_type)

        ts = self.timestamp
        if not isinstance(ts, datetime):
            raise PolicyViolationError("RuntimeEvent.timestamp must be a datetime")
        if ts.tzinfo is None:
            raise PolicyViolationError("RuntimeEvent.timestamp must include timezone info")
        object.__setattr__(self, "timestamp", ts.astimezone(timezone.utc))

        object.__setattr__(self, "job_id", _optional_str(self.job_id))
        object.__setattr__(self, "module_name", _optional_str(self.module_name))
        object.__setattr__(self, "capability", _optional_str(self.capability))
        object.__setattr__(self, "actor_role", _optional_str(self.actor_role))
        object.__setattr__(self, "metadata", sanitize_metadata(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "job_id": self.job_id,
            "module_name": self.module_name,
            "capability": self.capability,
            "actor_role": self.actor_role,
            "metadata": dict(self.metadata),
        }


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None

