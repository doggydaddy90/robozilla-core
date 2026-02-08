"""Small utility helpers used across the core runtime."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_rfc3339(dt: str) -> datetime:
    """Parse RFC3339-ish timestamps used by JSON Schema date-time.

    Python's datetime.fromisoformat does not accept trailing "Z", so we normalize.
    """
    s = dt.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    parsed = datetime.fromisoformat(s)
    if parsed.tzinfo is None:
        # Fail closed: require timezone-aware timestamps.
        raise ValueError("date-time must be timezone-aware (include Z or offset)")
    return parsed.astimezone(timezone.utc)


def format_rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def is_external_uri_reference(ref: str) -> bool:
    """True if ref looks like a non-file, non-relative URI reference."""
    p = urlparse(ref)
    if not p.scheme:
        return False
    # file: is allowed (local file paths).
    return p.scheme.lower() != "file"


def deep_get(d: dict[str, Any], path: list[str]) -> Any:
    cur: Any = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            raise KeyError("missing path: " + ".".join(path))
        cur = cur[k]
    return cur

