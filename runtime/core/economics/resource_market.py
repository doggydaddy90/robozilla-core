"""Telemetry-based scarcity index computation for external resources."""

from __future__ import annotations

from datetime import datetime, timezone
from math import isinf
from typing import Any

from errors import PolicyViolationError

_DEFAULT_PLATFORM_MAP = {
    "openai": "openai",
    "chatgpt": "openai",
    "perplexity": "perplexity",
    "search": "search_api",
    "reddit": "reddit_api",
    "youtube": "youtube_api",
    "zlib": "zlib",
    "ref_tools": "ref_tools",
    "ref.tools": "ref_tools",
}


def compute_scarcity_snapshot(
    *,
    telemetry_records: list[dict[str, Any]],
    daily_caps: dict[str, Any],
    now: datetime | None = None,
    tool_platform_map: dict[str, str] | None = None,
    audit_log: Any | None = None,
) -> dict[str, Any]:
    """Compute per-platform scarcity index in [0.0, 1.0] from daily usage."""
    if not isinstance(telemetry_records, list):
        raise PolicyViolationError("telemetry_records must be a list")
    if not isinstance(daily_caps, dict):
        raise PolicyViolationError("daily_caps must be an object")

    now_utc = now.astimezone(timezone.utc) if now is not None else datetime.now(timezone.utc)
    usage_by_platform: dict[str, float] = {}
    normalized_map = _normalized_platform_map(tool_platform_map)

    for rec in telemetry_records:
        if not isinstance(rec, dict):
            continue
        ts = _parse_timestamp(rec.get("timestamp"))
        if ts is None or ts.date() != now_utc.date():
            continue
        platform = _platform_for_tool_id(str(rec.get("tool_id", "")), normalized_map)
        if not platform:
            continue
        usage = _non_negative_float(rec.get("tokens_used", 0.0))
        usage_by_platform[platform] = round(usage_by_platform.get(platform, 0.0) + usage, 6)

    known_platforms = sorted(set(daily_caps.keys()) | set(usage_by_platform.keys()))
    platforms: dict[str, dict[str, Any]] = {}

    for platform in known_platforms:
        usage = round(usage_by_platform.get(platform, 0.0), 6)
        cap_raw = daily_caps.get(platform, None)
        unlimited = _is_unlimited_cap(cap_raw)
        if unlimited:
            scarcity = 0.0
            cap_value: float | None = None
        else:
            cap_value = _strict_positive_float(cap_raw, f"daily_caps[{platform}]")
            scarcity = _clamp01(usage / cap_value)

        platforms[str(platform)] = {
            "daily_usage": usage,
            "daily_cap": cap_value,
            "unlimited": unlimited,
            "scarcity_index": round(scarcity, 4),
        }

    max_scarcity = max((row["scarcity_index"] for row in platforms.values()), default=0.0)
    snapshot = {
        "as_of_date": now_utc.date().isoformat(),
        "platforms": platforms,
        "max_scarcity_index": round(max_scarcity, 4),
    }

    if audit_log is not None:
        audit_log.append(
            actor="runtime.core.economics.resource_market",
            action="economics.snapshot",
            target="resource_market",
            details=snapshot,
        )
    return snapshot


def _normalized_platform_map(tool_platform_map: dict[str, str] | None) -> dict[str, str]:
    out = dict(_DEFAULT_PLATFORM_MAP)
    if not isinstance(tool_platform_map, dict):
        return out
    for k, v in tool_platform_map.items():
        key = str(k).strip().lower()
        value = str(v).strip().lower()
        if key and value:
            out[key] = value
    return out


def _platform_for_tool_id(tool_id: str, mapping: dict[str, str]) -> str:
    token = tool_id.strip().lower()
    if not token:
        return ""
    for needle in sorted(mapping.keys(), key=len, reverse=True):
        platform = mapping[needle]
        if needle in token:
            return platform
    return "other"


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(timezone.utc)


def _non_negative_float(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number < 0.0:
        return 0.0
    return number


def _strict_positive_float(value: Any, field: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise PolicyViolationError(f"{field} must be numeric or unlimited") from exc
    if number <= 0.0:
        raise PolicyViolationError(f"{field} must be > 0 for bounded resources")
    return number


def _is_unlimited_cap(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        text = value.strip().lower()
        return text in {"unlimited", "infinite", "inf", "none"}
    if isinstance(value, (int, float)):
        return bool(isinf(float(value)))
    return False


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value
