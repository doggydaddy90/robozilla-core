"""Read-only dashboard endpoints for telemetry/economics/RAG/truth-ledger."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass as _dataclass
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

try:  # pragma: no cover - exercised implicitly in environment-dependent tests
    from fastapi import APIRouter
except ModuleNotFoundError:  # pragma: no cover
    @_dataclass(frozen=True)
    class _FallbackRoute:
        path: str
        endpoint: Callable[..., Any]

    class APIRouter:  # type: ignore[override]
        def __init__(self, *args, **kwargs):
            self.routes: list[_FallbackRoute] = []

        def get(self, path: str):
            def _decorator(fn: Callable[..., Any]):
                self.routes.append(_FallbackRoute(path=path, endpoint=fn))
                return fn

            return _decorator

from economics.economic_policy_adapter import apply_economic_policy
from economics.resource_market import compute_scarcity_snapshot
from errors import PolicyViolationError
from security.pathGuard import resolve_path, safeRead


@dataclass(frozen=True)
class DashboardDataProviders:
    telemetry_records: Callable[[], list[dict[str, Any]]]
    daily_caps: Callable[[], dict[str, Any]]
    org_policy: Callable[[], dict[str, Any] | None]
    rag_index: Callable[[], dict[str, Any]]
    truth_ledger: Callable[[], list[dict[str, Any]] | dict[str, Any]]


def build_dashboard_router(*, providers: DashboardDataProviders) -> APIRouter:
    if not isinstance(providers, DashboardDataProviders):
        raise PolicyViolationError("providers must be DashboardDataProviders")

    router = APIRouter(tags=["dashboard"])

    @router.get("/dashboard/telemetry")
    def get_dashboard_telemetry() -> dict[str, Any]:
        records = providers.telemetry_records()
        return {"telemetry": summarize_telemetry(records)}

    @router.get("/dashboard/economics")
    def get_dashboard_economics() -> dict[str, Any]:
        records = providers.telemetry_records()
        caps = providers.daily_caps()
        policy = providers.org_policy()
        snapshot = compute_scarcity_snapshot(
            telemetry_records=records,
            daily_caps=caps,
            audit_log=None,
        )
        scarcity_index_by_platform = {
            platform: float(meta.get("scarcity_index", 0.0))
            for platform, meta in snapshot.get("platforms", {}).items()
            if isinstance(meta, dict)
        }
        adjustment = apply_economic_policy(
            scarcity_index_by_platform=scarcity_index_by_platform,
            org_policy=policy,
            base_atomic_threshold=0.7,
            base_high_threshold=0.8,
            base_deep_threshold=0.85,
            audit_log=None,
        )
        return {
            "economics": {
                "scarcity_snapshot": snapshot,
                "policy_adjustment": adjustment,
                "atomic_threshold": 0.7,
            }
        }

    @router.get("/dashboard/rag")
    def get_dashboard_rag() -> dict[str, Any]:
        return {"rag": providers.rag_index()}

    @router.get("/dashboard/truth-ledger")
    def get_dashboard_truth_ledger() -> dict[str, Any]:
        ledger = providers.truth_ledger()
        if isinstance(ledger, dict):
            return {"truth_ledger": ledger}
        return {"truth_ledger": {"entries": list(ledger)}}

    return router


def summarize_telemetry(records: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(records, list):
        raise PolicyViolationError("telemetry records must be a list")

    by_tool: dict[str, dict[str, Any]] = {}
    total_tokens = 0.0
    latencies: list[float] = []

    for rec in records:
        if not isinstance(rec, dict):
            continue
        tool_id = str(rec.get("tool_id", "")).strip() or "unknown"
        tokens = _to_non_negative_float(rec.get("tokens_used", 0.0))
        latency = _to_non_negative_float(rec.get("latency_ms", 0.0))

        row = by_tool.setdefault(tool_id, {"tool_id": tool_id, "calls": 0, "tokens_used": 0.0})
        row["calls"] = int(row["calls"]) + 1
        row["tokens_used"] = round(float(row["tokens_used"]) + tokens, 6)
        total_tokens += tokens
        if latency > 0.0:
            latencies.append(latency)

    tools = [by_tool[key] for key in sorted(by_tool.keys())]
    avg_latency = round(sum(latencies) / len(latencies), 4) if latencies else 0.0
    p95_latency = _percentile(latencies, 95.0) if latencies else 0.0
    return {
        "record_count": len([r for r in records if isinstance(r, dict)]),
        "total_tokens_used": round(total_tokens, 6),
        "by_tool": tools,
        "latency_ms": {"avg": avg_latency, "p95": p95_latency},
    }


def load_telemetry_from_audit(*, audit_db_path: Path | str, limit: int = 5000) -> list[dict[str, Any]]:
    db = Path(audit_db_path)
    if not db.exists():
        return []
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT timestamp, action, target, details_json
            FROM audit_entries
            WHERE action IN ('mcp.call', 'loop.step')
            ORDER BY id DESC
            LIMIT ?;
            """,
            (int(limit),),
        ).fetchall()
    finally:
        conn.close()

    out: list[dict[str, Any]] = []
    for row in rows:
        details = _parse_details_json(str(row["details_json"]))
        tool_id = str(details.get("mcp_id") or details.get("target_tool") or row["target"] or "").strip()
        out.append(
            {
                "timestamp": str(row["timestamp"]),
                "tool_id": tool_id or "unknown",
                "tokens_used": _to_non_negative_float(details.get("tokens_used", 0.0)),
                "latency_ms": _to_non_negative_float(details.get("latency_ms", 0.0)),
            }
        )
    out.reverse()  # deterministic oldest->newest ordering for dashboard display.
    return out


def load_truth_ledger_from_audit(*, audit_db_path: Path | str, limit: int = 500) -> list[dict[str, Any]]:
    db = Path(audit_db_path)
    if not db.exists():
        return []
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT timestamp, action, target, details_json
            FROM audit_entries
            WHERE action LIKE 'truth.%' OR action LIKE 'truth_%' OR action = 'rag.truth_ledger'
            ORDER BY id DESC
            LIMIT ?;
            """,
            (int(limit),),
        ).fetchall()
    finally:
        conn.close()

    out: list[dict[str, Any]] = []
    for row in rows:
        out.append(
            {
                "timestamp": str(row["timestamp"]),
                "action": str(row["action"]),
                "target": str(row["target"]),
                "details": _parse_details_json(str(row["details_json"])),
            }
        )
    out.reverse()
    return out


def load_rag_index(*, rag_dir: Path | str = "rag") -> dict[str, Any]:
    root = resolve_path(rag_dir, operation="read", require_exists=False)
    if not root.exists() or not root.is_dir():
        return {"topic_count": 0, "document_count": 0, "topics": []}

    topics: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*.json"), key=lambda p: str(p).replace("\\", "/")):
        resolved = resolve_path(path, operation="read", require_exists=True)
        raw = safeRead(resolved, actor="runtime.core.api.dashboard")
        try:
            data = json.loads(str(raw))
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue

        topic_hash = str(data.get("topic_hash", "")).strip()
        if not topic_hash:
            continue
        topic = str(data.get("topic", "")).strip() or topic_hash
        version = _to_non_negative_int(data.get("version", 0))
        confidence = _to_non_negative_float(data.get("confidence_score", 0.0))

        row = topics.setdefault(
            topic_hash,
            {
                "topic_hash": topic_hash,
                "topic": topic,
                "document_count": 0,
                "latest_version": 0,
                "average_confidence": 0.0,
                "_confidence_sum": 0.0,
            },
        )
        row["document_count"] = int(row["document_count"]) + 1
        row["latest_version"] = max(int(row["latest_version"]), version)
        row["_confidence_sum"] = float(row["_confidence_sum"]) + confidence

    out_topics: list[dict[str, Any]] = []
    for key in sorted(topics.keys()):
        row = topics[key]
        count = int(row["document_count"])
        avg = float(row["_confidence_sum"]) / float(count) if count > 0 else 0.0
        out_topics.append(
            {
                "topic_hash": row["topic_hash"],
                "topic": row["topic"],
                "document_count": count,
                "latest_version": int(row["latest_version"]),
                "average_confidence": round(avg, 4),
            }
        )

    return {"topic_count": len(out_topics), "document_count": sum(int(t["document_count"]) for t in out_topics), "topics": out_topics}


def _parse_details_json(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _to_non_negative_float(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number < 0.0:
        return 0.0
    return number


def _to_non_negative_int(value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    if number < 0:
        return 0
    return number


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    idx = int(round((percentile / 100.0) * (len(sorted_values) - 1)))
    if idx < 0:
        idx = 0
    if idx >= len(sorted_values):
        idx = len(sorted_values) - 1
    return round(sorted_values[idx], 4)
