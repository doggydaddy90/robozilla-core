"""Deterministic end-to-end research cycle orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol

from errors import PolicyViolationError
from orchestration.admission_controller import AdmissionController
from orchestration.knowledge_monitor import monitor_knowledge
from orchestration.normalizer import normalize_candidate
from skills.rag_ingest_document import ingest_document


class _LoopController(Protocol):
    def run(
        self,
        *,
        goal: str,
        org_id: str,
        max_steps: int,
        max_tool_calls: int,
        job_contract: dict[str, Any],
    ) -> dict[str, Any]:
        ...


NormalizeFn = Callable[..., dict[str, Any]]
IngestFn = Callable[..., dict[str, Any]]
MonitorFn = Callable[..., dict[str, Any]]


@dataclass(frozen=True)
class ResearchCycleConfig:
    max_steps: int
    max_tool_calls: int
    write_budget: int
    ingestion_confidence_threshold: float


def run_research_cycle(
    *,
    org_id: str,
    job_contract: dict[str, Any],
    loop_controller: _LoopController,
    org_policy: dict[str, Any] | None = None,
    max_steps: int = 4,
    max_tool_calls: int = 8,
    write_budget: int = 5,
    ingestion_confidence_threshold: float = 0.60,
    research_tier: str = "high",
    monitor_fn: MonitorFn = monitor_knowledge,
    admission_controller: AdmissionController | None = None,
    normalize_fn: NormalizeFn = normalize_candidate,
    ingest_fn: IngestFn = ingest_document,
    audit_log: Any | None = None,
    rag_dir: str = "rag",
) -> dict[str, Any]:
    _validate_inputs(
        org_id=org_id,
        job_contract=job_contract,
        max_steps=max_steps,
        max_tool_calls=max_tool_calls,
        write_budget=write_budget,
        ingestion_confidence_threshold=ingestion_confidence_threshold,
        research_tier=research_tier,
    )
    if admission_controller is None:
        admission_controller = AdmissionController()

    if not _org_policy_allows_cycle(org_policy=org_policy, org_id=org_id):
        return {
            "topics_processed": [],
            "topics_skipped": [],
            "ingestions": [],
            "errors": [{"org_id": org_id, "reason": "org_policy_denied"}],
            "truth_ledger": [],
        }

    memory_controls = _memory_controls(
        org_policy=org_policy,
        default_threshold=ingestion_confidence_threshold,
        default_budget=write_budget,
    )
    report = monitor_fn(
        rag_dir=rag_dir,
        org_policy=org_policy,
    )
    topic_queue = _topic_queue(report)

    topics_processed: list[dict[str, Any]] = []
    topics_skipped: list[dict[str, Any]] = []
    ingestions: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    truth_ledger: list[dict[str, Any]] = []

    writes_used = 0
    for item in topic_queue:
        topic_hash = item["topic_hash"]
        reasons = item["reasons"]

        if writes_used >= memory_controls["effective_write_budget"]:
            topics_skipped.append({"topic_hash": topic_hash, "reasons": reasons, "skip_reason": "write_budget_exhausted"})
            continue

        goal = _build_goal(topic_hash=topic_hash, reasons=reasons, tier=research_tier)
        try:
            loop_result = loop_controller.run(
                goal=goal,
                org_id=org_id,
                max_steps=max_steps,
                max_tool_calls=max_tool_calls,
                job_contract=job_contract,
            )
        except Exception as exc:
            errors.append({"topic_hash": topic_hash, "stage": "loop", "error": str(exc)})
            continue

        loop_result, minority_escalated = _maybe_escalate_for_minority_signal(
            loop_result=loop_result,
            loop_controller=loop_controller,
            topic_hash=topic_hash,
            reasons=reasons,
            org_id=org_id,
            max_steps=max_steps,
            max_tool_calls=max_tool_calls,
            job_contract=job_contract,
            current_tier=research_tier,
            audit_log=audit_log,
        )
        topics_processed.append({"topic_hash": topic_hash, "reasons": reasons, "goal": goal})

        if not _loop_completed(loop_result):
            topics_skipped.append({"topic_hash": topic_hash, "reasons": reasons, "skip_reason": "loop_not_completed"})
            continue

        candidate = _extract_candidate(loop_result)
        if candidate is None:
            topics_skipped.append({"topic_hash": topic_hash, "reasons": reasons, "skip_reason": "no_candidate"})
            continue

        admission = admission_controller.evaluate(candidate)
        if not bool(admission.get("admit", False)):
            topics_skipped.append({"topic_hash": topic_hash, "reasons": reasons, "skip_reason": "admission_rejected"})
            truth_ledger.append(
                {
                    "topic_hash": topic_hash,
                    "tier": _candidate_tier(candidate, research_tier),
                    "admitted": False,
                    "minority_escalated": minority_escalated,
                }
            )
            continue

        confidence = _candidate_confidence(candidate, admission)
        if confidence < memory_controls["memory_write_threshold"]:
            topics_skipped.append(
                {
                    "topic_hash": topic_hash,
                    "reasons": reasons,
                    "skip_reason": "ingestion_threshold_not_met",
                    "confidence_score": confidence,
                }
            )
            truth_ledger.append(
                {
                    "topic_hash": topic_hash,
                    "tier": _candidate_tier(candidate, research_tier),
                    "admitted": True,
                    "minority_escalated": minority_escalated,
                    "confidence_score": confidence,
                    "ingested": False,
                }
            )
            continue

        ingestion_mode = str(candidate.get("ingestion_mode", "optional")).strip().lower()
        if ingestion_mode == "none":
            topics_skipped.append({"topic_hash": topic_hash, "reasons": reasons, "skip_reason": "tier_disallows_ingestion"})
            truth_ledger.append(
                {
                    "topic_hash": topic_hash,
                    "tier": _candidate_tier(candidate, research_tier),
                    "admitted": True,
                    "minority_escalated": minority_escalated,
                    "confidence_score": confidence,
                    "ingested": False,
                }
            )
            continue

        if not memory_controls["autonomous_memory_write"]:
            topics_skipped.append({"topic_hash": topic_hash, "reasons": reasons, "skip_reason": "autonomous_memory_write_disabled"})
            truth_ledger.append(
                {
                    "topic_hash": topic_hash,
                    "tier": _candidate_tier(candidate, research_tier),
                    "admitted": True,
                    "minority_escalated": minority_escalated,
                    "confidence_score": confidence,
                    "ingested": False,
                }
            )
            continue

        previous_entry = None
        if isinstance(candidate, dict):
            maybe_prev = candidate.get("previous_entry")
            if isinstance(maybe_prev, dict):
                previous_entry = maybe_prev

        try:
            normalized = normalize_fn(
                router_json=candidate,
                admission_result=admission,
                previous_entry=previous_entry,
            )
            ingest_result = ingest_fn(
                normalized_document=normalized,
                job_contract=job_contract,
            )
        except Exception as exc:
            errors.append({"topic_hash": topic_hash, "stage": "ingest", "error": str(exc)})
            continue

        writes_used += 1
        ingestions.append(
            {
                "topic_hash": topic_hash,
                "document_id": ingest_result.get("document_id"),
                "path": ingest_result.get("path"),
                "version": ingest_result.get("version"),
            }
        )
        truth_ledger.append(
            {
                "topic_hash": topic_hash,
                "tier": _candidate_tier(candidate, research_tier),
                "admitted": True,
                "minority_escalated": minority_escalated,
                "confidence_score": confidence,
                "ingested": True,
            }
        )

    return {
        "topics_processed": topics_processed,
        "topics_skipped": topics_skipped,
        "ingestions": ingestions,
        "errors": errors,
        "truth_ledger": truth_ledger,
    }


def _build_goal(*, topic_hash: str, reasons: list[str], tier: str) -> str:
    ordered = ",".join(sorted(reasons))
    return f"re-research topic_hash={topic_hash} reasons={ordered} tier={tier}"


def _topic_queue(report: dict[str, Any]) -> list[dict[str, Any]]:
    merged: dict[str, set[str]] = {}
    _add_topic_reasons(merged, report.get("stale_topics"), "stale")
    _add_topic_reasons(merged, report.get("low_confidence_topics"), "low_confidence")
    _add_topic_reasons(merged, report.get("conflict_topics"), "conflict")

    out = []
    for topic_hash in sorted(merged.keys()):
        out.append({"topic_hash": topic_hash, "reasons": sorted(merged[topic_hash])})
    return out


def _add_topic_reasons(target: dict[str, set[str]], rows: Any, reason: str) -> None:
    if not isinstance(rows, list):
        return
    for item in rows:
        if not isinstance(item, dict):
            continue
        topic_hash = str(item.get("topic_hash", "")).strip()
        if not topic_hash:
            continue
        target.setdefault(topic_hash, set()).add(reason)


def _loop_completed(loop_result: dict[str, Any]) -> bool:
    if not isinstance(loop_result, dict):
        return False
    status = str(loop_result.get("status", "")).strip().lower()
    stop_reason = str(loop_result.get("stop_reason", "")).strip().lower()
    return status == "completed" and stop_reason == "done"


def _extract_candidate(loop_result: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(loop_result, dict):
        return None

    direct = loop_result.get("candidate")
    if isinstance(direct, dict):
        return direct

    result = loop_result.get("result")
    if isinstance(result, dict) and _looks_like_router_output(result):
        return result

    history = loop_result.get("history")
    if isinstance(history, list):
        for row in reversed(history):
            if not isinstance(row, dict):
                continue
            action_result = row.get("action_result")
            if isinstance(action_result, dict):
                nested = action_result.get("candidate")
                if isinstance(nested, dict):
                    return nested
                if _looks_like_router_output(action_result):
                    return action_result
    return None


def _looks_like_router_output(value: dict[str, Any]) -> bool:
    return isinstance(value.get("candidate_document"), dict)


def _candidate_confidence(candidate: dict[str, Any], admission: dict[str, Any]) -> float:
    compiled = _to_float(candidate.get("compiled_confidence"))
    if compiled > 0.0:
        return compiled
    return _to_float(admission.get("confidence_score", 0.0))


def _candidate_anomaly(candidate: dict[str, Any]) -> float:
    direct = _to_float(candidate.get("anomaly_score", 0.0))
    scores = candidate.get("scores")
    nested = _to_float(scores.get("anomaly", 0.0)) if isinstance(scores, dict) else 0.0
    return max(direct, nested)


def _candidate_tier(candidate: dict[str, Any], default: str) -> str:
    value = str(candidate.get("tier", "")).strip().lower()
    return value if value in {"fast", "high", "deep"} else default


def _maybe_escalate_for_minority_signal(
    *,
    loop_result: dict[str, Any],
    loop_controller: _LoopController,
    topic_hash: str,
    reasons: list[str],
    org_id: str,
    max_steps: int,
    max_tool_calls: int,
    job_contract: dict[str, Any],
    current_tier: str,
    audit_log: Any | None,
) -> tuple[dict[str, Any], bool]:
    if current_tier == "deep":
        return loop_result, False
    if not _loop_completed(loop_result):
        return loop_result, False

    candidate = _extract_candidate(loop_result)
    if candidate is None:
        return loop_result, False
    anomaly = _candidate_anomaly(candidate)
    if anomaly < 0.8:
        return loop_result, False

    if audit_log is not None:
        audit_log.append(
            actor="runtime.core.research_cycle",
            action="rag.escalation.minority_signal",
            target=topic_hash,
            details={"anomaly_score": round(anomaly, 4), "from_tier": current_tier, "to_tier": "deep"},
        )
    deep_goal = _build_goal(topic_hash=topic_hash, reasons=reasons, tier="deep")
    deep_result = loop_controller.run(
        goal=deep_goal,
        org_id=org_id,
        max_steps=max_steps,
        max_tool_calls=max_tool_calls,
        job_contract=job_contract,
    )
    return deep_result, True


def _org_policy_allows_cycle(*, org_policy: dict[str, Any] | None, org_id: str) -> bool:
    if not isinstance(org_policy, dict):
        return True

    metadata = org_policy.get("metadata")
    if isinstance(metadata, dict):
        policy_org_id = str(metadata.get("org_id", "")).strip()
        if policy_org_id and policy_org_id != org_id:
            return False

    spec = org_policy.get("spec")
    if isinstance(spec, dict):
        routing = spec.get("flo_routing")
        if isinstance(routing, dict) and routing.get("enabled") is False:
            return False

    return True


def _validate_inputs(
    *,
    org_id: str,
    job_contract: dict[str, Any],
    max_steps: int,
    max_tool_calls: int,
    write_budget: int,
    ingestion_confidence_threshold: float,
    research_tier: str,
) -> None:
    if not isinstance(org_id, str) or not org_id.strip():
        raise PolicyViolationError("org_id must be a non-empty string")
    if not isinstance(job_contract, dict):
        raise PolicyViolationError("job_contract must be an object")
    if not isinstance(max_steps, int) or max_steps < 0:
        raise PolicyViolationError("max_steps must be an integer >= 0")
    if not isinstance(max_tool_calls, int) or max_tool_calls < 0:
        raise PolicyViolationError("max_tool_calls must be an integer >= 0")
    if not isinstance(write_budget, int) or write_budget < 0:
        raise PolicyViolationError("write_budget must be an integer >= 0")
    conf = _to_float(ingestion_confidence_threshold)
    if conf < 0.0 or conf > 1.0:
        raise PolicyViolationError("ingestion_confidence_threshold must be within [0,1]")
    if str(research_tier).strip().lower() not in {"fast", "high", "deep"}:
        raise PolicyViolationError("research_tier must be one of: fast|high|deep")


def _memory_controls(
    *,
    org_policy: dict[str, Any] | None,
    default_threshold: float,
    default_budget: int,
) -> dict[str, Any]:
    threshold = _to_float(default_threshold)
    autonomous = True
    max_writes = int(default_budget)

    if isinstance(org_policy, dict):
        spec = org_policy.get("spec")
        if isinstance(spec, dict):
            knowledge = spec.get("knowledge_policy")
            if isinstance(knowledge, dict):
                if isinstance(knowledge.get("autonomous_memory_write"), bool):
                    autonomous = bool(knowledge.get("autonomous_memory_write"))
                threshold = _to_float(knowledge.get("memory_write_threshold", threshold))
                raw_max = knowledge.get("max_memory_writes_per_loop", max_writes)
                try:
                    max_writes = int(raw_max)
                except (TypeError, ValueError):
                    max_writes = default_budget

    if threshold < 0.0:
        threshold = 0.0
    if threshold > 1.0:
        threshold = 1.0
    if max_writes < 0:
        max_writes = 0
    effective_write_budget = min(default_budget, max_writes)
    return {
        "autonomous_memory_write": autonomous,
        "memory_write_threshold": round(threshold, 4),
        "max_memory_writes_per_loop": max_writes,
        "effective_write_budget": effective_write_budget,
    }


def _to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
