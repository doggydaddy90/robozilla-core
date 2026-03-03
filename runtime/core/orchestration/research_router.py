"""Deterministic research acquisition router with three-tier search model.

Tiers:
- FAST: RAG-first + boolean + search + perplexity atomic scoring, no ingestion
- HIGH: FAST + extended public surfaces, compiled threshold >= 0.80
- DEEP: HIGH + web-ui expansion/recon, compiled threshold >= 0.85
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from execution.module_executor import BaseModuleExecutor, SubprocessModuleExecutor
from errors import PolicyViolationError
from search.zero_result_registry import (
    compute_query_signature,
    decay_old_entries,
    record_zero_result,
    reset_entry,
    should_block_premium,
)
from security.capabilityEnforcer import CapabilityEnforcer, CapabilityRequest
from security.endpoint_allowlist_enforcer import enforce_endpoint_allowlist

RAG_LOOKUP_TOOL = "rag_lookup_tool"
BOOLEAN_SEARCH_TOOL = "boolean_search_tool"
SEARCH_ENGINE_TOOL = "search_engine_tool"
ZLIB_SEARCH_TOOL = "zlib_search_tool"
REDDIT_SEARCH_TOOL = "reddit_search_tool"
YOUTUBE_SEARCH_TOOL = "youtube_search_tool"
YOUTUBE_TRANSCRIBE_TOOL = "youtube_transcribe_tool"
EDGAR_SEARCH_TOOL = "edgar_search_tool"
SEMANTIC_SCHOLAR_TOOL = "semantic_scholar_tool"
GITHUB_OFFICIAL_TOOL = "github_official_tool"
WAYBACK_FRESHNESS_TOOL = "wayback_freshness_tool"
CHATGPT_WEB_UI_TOOL = "chatgpt_web_ui_tool"
MULTI_SURFACE_RECON_TOOL = "multi_surface_recon_tool"
OPENAI_PLANNER_TOOL = "openai_planner_tool"
PERPLEXITY_RESEARCH_TOOL = "perplexity_research_tool"

_TOOL_ALLOWED_ENDPOINTS: dict[str, list[str]] = {
    RAG_LOOKUP_TOOL: ["https://rag.local/query"],
    BOOLEAN_SEARCH_TOOL: ["https://search.local/boolean"],
    SEARCH_ENGINE_TOOL: ["https://search.local/query"],
    ZLIB_SEARCH_TOOL: ["https://z-lib.io/search"],
    REDDIT_SEARCH_TOOL: ["https://www.reddit.com/search"],
    YOUTUBE_SEARCH_TOOL: ["https://www.youtube.com/results"],
    YOUTUBE_TRANSCRIBE_TOOL: ["https://www.youtube.com/watch"],
    EDGAR_SEARCH_TOOL: ["https://www.sec.gov/edgar/search"],
    SEMANTIC_SCHOLAR_TOOL: ["https://api.semanticscholar.org/graph/v1/paper/search"],
    GITHUB_OFFICIAL_TOOL: ["https://api.github.com/search/repositories"],
    WAYBACK_FRESHNESS_TOOL: ["https://web.archive.org/web"],
    CHATGPT_WEB_UI_TOOL: ["https://chatgpt.com"],
    MULTI_SURFACE_RECON_TOOL: ["https://recon.local/aggregate"],
    OPENAI_PLANNER_TOOL: ["https://planner.local/extract"],
    PERPLEXITY_RESEARCH_TOOL: ["https://api.perplexity.ai/search"],
}


ToolExecutor = Callable[[str, dict[str, Any]], dict[str, Any]]
ScoreOracle = Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], dict[str, Any]]

_CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
_SOURCE_HIERARCHY_PATH = _CONFIG_DIR / "source_hierarchy.yaml"
_DATA_TYPES_PATH = _CONFIG_DIR / "data_types.yaml"
_KNOWN_NEWS = {
    "reuters.com",
    "apnews.com",
    "bloomberg.com",
    "wsj.com",
    "ft.com",
    "nytimes.com",
}


@dataclass(frozen=True)
class TierPolicy:
    surfaces: tuple[str, ...]
    compiled_threshold: float
    ingestion_mode: str


_TIER_POLICIES: dict[str, TierPolicy] = {
    "fast": TierPolicy(
        surfaces=(
            RAG_LOOKUP_TOOL,
            BOOLEAN_SEARCH_TOOL,
            SEARCH_ENGINE_TOOL,
        ),
        compiled_threshold=0.70,
        ingestion_mode="none",
    ),
    "high": TierPolicy(
        surfaces=(
            RAG_LOOKUP_TOOL,
            BOOLEAN_SEARCH_TOOL,
            SEARCH_ENGINE_TOOL,
            ZLIB_SEARCH_TOOL,
            REDDIT_SEARCH_TOOL,
            YOUTUBE_SEARCH_TOOL,
            YOUTUBE_TRANSCRIBE_TOOL,
            EDGAR_SEARCH_TOOL,
            SEMANTIC_SCHOLAR_TOOL,
            GITHUB_OFFICIAL_TOOL,
            WAYBACK_FRESHNESS_TOOL,
        ),
        compiled_threshold=0.80,
        ingestion_mode="optional",
    ),
    "deep": TierPolicy(
        surfaces=(
            RAG_LOOKUP_TOOL,
            BOOLEAN_SEARCH_TOOL,
            SEARCH_ENGINE_TOOL,
            ZLIB_SEARCH_TOOL,
            REDDIT_SEARCH_TOOL,
            YOUTUBE_SEARCH_TOOL,
            YOUTUBE_TRANSCRIBE_TOOL,
            EDGAR_SEARCH_TOOL,
            SEMANTIC_SCHOLAR_TOOL,
            GITHUB_OFFICIAL_TOOL,
            WAYBACK_FRESHNESS_TOOL,
            CHATGPT_WEB_UI_TOOL,
            MULTI_SURFACE_RECON_TOOL,
        ),
        compiled_threshold=0.85,
        ingestion_mode="autonomous",
    ),
}
FAST = "fast"
HIGH = "high"
DEEP = "deep"


@dataclass(frozen=True)
class ResearchThresholds:
    atomic_min: float = 0.70
    high_compiled_min: float = 0.80
    deep_compiled_min: float = 0.85


class ResearchRouter:
    def __init__(
        self,
        *,
        capability_enforcer: CapabilityEnforcer,
        tool_executor: ToolExecutor | None = None,
        module_executor: BaseModuleExecutor | None = None,
        actor: str = "runtime.core.research_router",
        skill_id: str = "research_router",
        thresholds: ResearchThresholds = ResearchThresholds(),
        score_oracle: ScoreOracle | None = None,
        zero_result_registry_path: Path | str | None = None,
        audit_log: Any | None = None,
    ):
        if module_executor is None:
            if not callable(tool_executor):
                raise PolicyViolationError("tool_executor must be callable")
            module_executor = SubprocessModuleExecutor(module_runner=tool_executor)
        self._capabilities = capability_enforcer
        self._module_executor = module_executor
        self._actor = actor
        self._skill_id = skill_id
        self._thresholds = thresholds
        self._score_oracle = score_oracle or self._default_score_oracle
        self._zero_result_registry_path = zero_result_registry_path
        self._audit = audit_log if audit_log is not None else getattr(capability_enforcer, "_audit", None)

    def route(
        self,
        *,
        query: str,
        job_contract: dict[str, Any],
        skill_contract: dict[str, Any],
        tier: str = "fast",
        org_policy: dict[str, Any] | None = None,
        anomaly_score: float | None = None,
        force_escalation: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if not isinstance(query, str) or not query.strip():
            raise PolicyViolationError("query must be a non-empty string")

        now_utc = now.astimezone(timezone.utc) if now is not None else datetime.now(timezone.utc)
        effective_tier = _normalize_tier(tier)
        if force_escalation:
            effective_tier = "deep"
        tier_policy = _TIER_POLICIES[effective_tier]

        snippets: list[dict[str, Any]] = []
        for surface in tier_policy.surfaces:
            payload = {
                "query": query.strip(),
                "tier": effective_tier,
                "surface": surface,
                "results_collected": len(snippets),
            }
            response = self._call_tool(
                tool_id=surface,
                payload=payload,
                scope_tag=_scope_tag_for_tool(surface),
                job_contract=job_contract,
                skill_contract=skill_contract,
            )
            snippets.extend(_extract_results(response, surface))

        _enforce_allowed_domains(
            job_contract=job_contract,
            snippets=snippets,
            query=query,
            org_policy=org_policy,
        )
        source_weights = _load_weight_table(_SOURCE_HIERARCHY_PATH)
        source_weights = _apply_monthly_recalibration(source_weights, org_policy, now_utc)
        data_type_weights = _load_weight_table(_DATA_TYPES_PATH)
        scores = _score_results(
            snippets=snippets,
            now=now_utc,
            source_weights=source_weights,
            data_type_weights=data_type_weights,
            anomaly_hint=anomaly_score,
        )
        oracle = self._score_oracle(
            {"query": query.strip(), "tier": effective_tier, "snippets": snippets, "scores": scores},
            job_contract,
            skill_contract,
        )
        atomic_confidence = float(oracle["confidence_score"])
        atomic_pass = atomic_confidence >= self._thresholds.atomic_min
        compiled_confidence = _compiled_confidence(scores=scores, atomic_confidence=atomic_confidence)
        compiled_threshold = _compiled_threshold(effective_tier, self._thresholds)
        compiled_pass = compiled_confidence >= compiled_threshold
        contradiction_flag = bool(oracle["contradiction_flag"]) or scores["contradiction"] > 0.30
        criteria_satisfied = atomic_pass and (effective_tier == "fast" or compiled_pass) and not contradiction_flag

        selected_tool = OPENAI_PLANNER_TOOL if criteria_satisfied else PERPLEXITY_RESEARCH_TOOL
        premium_selected = selected_tool == PERPLEXITY_RESEARCH_TOOL
        zero_memory_blocked = False
        query_text = query.strip()
        entropy_score = _clamp01(scores.get("anomaly", anomaly_score if anomaly_score is not None else 0.0))
        if premium_selected:
            decay_old_entries(db_path=self._zero_result_registry_db_path())
            if should_block_premium(
                engine=PERPLEXITY_RESEARCH_TOOL,
                normalized_query=query_text,
                entropy_score=entropy_score,
                db_path=self._zero_result_registry_db_path(),
            ):
                zero_memory_blocked = True
                selected_tool = OPENAI_PLANNER_TOOL
                self._log_event(
                    action="search.zero_memory_block",
                    target=query_text,
                    details={
                        "engine": PERPLEXITY_RESEARCH_TOOL,
                        "query_signature": compute_query_signature(query_text),
                        "entropy_score": entropy_score,
                    },
                )
        extraction_payload = {
            "query": query_text,
            "search_results": snippets,
            "scores": scores,
            "criteria_satisfied": criteria_satisfied,
            "tier": effective_tier,
            "compiled_confidence": compiled_confidence,
            "atomic_confidence": atomic_confidence,
            "oracle": oracle,
            "force_escalation": force_escalation,
            "zero_memory_blocked": zero_memory_blocked,
        }
        extraction = self._call_tool(
            tool_id=selected_tool,
            payload=extraction_payload,
            scope_tag=_scope_tag_for_tool(selected_tool),
            job_contract=job_contract,
            skill_contract=skill_contract,
        )
        if premium_selected and not zero_memory_blocked:
            signature = compute_query_signature(query_text)
            if _has_zero_results(extraction):
                record_zero_result(
                    engine=PERPLEXITY_RESEARCH_TOOL,
                    normalized_query=query_text,
                    entropy_score=entropy_score,
                    db_path=self._zero_result_registry_db_path(),
                )
            else:
                reset_entry(
                    engine=PERPLEXITY_RESEARCH_TOOL,
                    query_signature=signature,
                    db_path=self._zero_result_registry_db_path(),
                )

        return {
            "query": query_text,
            "tier": effective_tier,
            "selected_tool": selected_tool,
            "criteria_satisfied": criteria_satisfied,
            "force_escalation": force_escalation,
            "zero_memory_blocked": zero_memory_blocked,
            "atomic_confidence": round(atomic_confidence, 4),
            "compiled_confidence": compiled_confidence,
            "compiled_threshold": compiled_threshold,
            "ingestion_mode": tier_policy.ingestion_mode,
            "scores": scores,
            "thresholds": asdict(self._thresholds),
            "search_summary": {
                "result_count": len(snippets),
                "surfaces": list(tier_policy.surfaces),
                "domains": sorted({str(item.get("domain", "")) for item in snippets if item.get("domain")}),
            },
            "oracle": oracle,
            "candidate_document": extraction,
        }

    def _zero_result_registry_db_path(self) -> Path | str:
        return (
            self._zero_result_registry_path
            if self._zero_result_registry_path is not None
            else Path("runtime/core/state/zero_result_registry.sqlite")
        )

    def _log_event(self, *, action: str, target: str, details: dict[str, Any]) -> None:
        if self._audit is None:
            return
        self._audit.append(
            actor=self._actor,
            action=action,
            target=target,
            details={k: v for k, v in details.items() if "query" not in str(k).lower()},
        )

    def _default_score_oracle(
        self,
        payload: dict[str, Any],
        job_contract: dict[str, Any],
        skill_contract: dict[str, Any],
    ) -> dict[str, Any]:
        out = self._call_tool(
            tool_id=PERPLEXITY_RESEARCH_TOOL,
            payload=payload,
            scope_tag="external_research",
            job_contract=job_contract,
            skill_contract=skill_contract,
        )
        _validate_oracle_response(out)
        return {
            "confidence_score": float(out["confidence_score"]),
            "authority_score": float(out["authority_score"]),
            "contradiction_flag": bool(out["contradiction_flag"]),
        }

    def _call_tool(
        self,
        *,
        tool_id: str,
        payload: dict[str, Any],
        scope_tag: str,
        job_contract: dict[str, Any],
        skill_contract: dict[str, Any],
    ) -> dict[str, Any]:
        # Mandatory capability chokepoint for every tool invocation.
        self._capabilities.enforceCapability(
            CapabilityRequest(
                actor=self._actor,
                job_contract=job_contract,
                skill_contract=skill_contract,
                skill_id=self._skill_id,
                requested_side_effects=False,
                requested_channel="mcp",
                requested_mcp_id=tool_id,
                requested_mcp_scopes=["execute"],
                requested_scope_tags=[scope_tag],
            )
        )

        request_url = payload.get("request_url")
        if isinstance(request_url, str) and request_url.strip():
            allowed = _TOOL_ALLOWED_ENDPOINTS.get(tool_id)
            if not isinstance(allowed, list) or not allowed:
                raise PolicyViolationError(f"allowed_endpoints missing for tool: {tool_id}")
            enforce_endpoint_allowlist(request_url=request_url, allowed_endpoints=allowed)

        out = self._module_executor.execute_module(tool_id, payload)
        if not isinstance(out, dict):
            raise PolicyViolationError(f"Tool '{tool_id}' returned invalid response type (expected object)")
        return out


def _normalize_tier(tier: str) -> str:
    value = str(tier).strip().lower()
    if value not in _TIER_POLICIES:
        raise PolicyViolationError(f"Unknown research tier: {tier}")
    return value


def _scope_tag_for_tool(tool_id: str) -> str:
    if tool_id in {RAG_LOOKUP_TOOL, OPENAI_PLANNER_TOOL}:
        return "research"
    return "external_research"


def _extract_results(response: dict[str, Any], tool_id: str) -> list[dict[str, Any]]:
    raw = response.get("results")
    if not isinstance(raw, list):
        alt = response.get("snippets")
        raw = alt if isinstance(alt, list) else []

    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url", "")).strip()
        domain = _domain_from_url(url) or str(item.get("domain", "")).strip().lower()
        source_type = str(item.get("source_type", "")).strip().lower() or _infer_source_type(item, tool_id, domain)
        data_type = str(item.get("data_type", "")).strip().lower() or _infer_data_type(item, source_type)
        out.append(
            {
                "title": str(item.get("title", "")).strip(),
                "snippet": str(item.get("snippet", "")).strip(),
                "url": url,
                "domain": domain,
                "tool_id": tool_id,
                "source_type": source_type,
                "data_type": data_type,
                "published_at": str(item.get("published_at", "")).strip(),
                "contradiction_signal": bool(item.get("contradiction_signal", False)),
                "alignment_score": _clamp01(item.get("alignment_score", 0.0)),
                "informational_gain_score": _clamp01(item.get("informational_gain_score", 0.0)),
                "anomaly_score": _clamp01(item.get("anomaly_score", 0.0)),
            }
        )
    return out


def _has_zero_results(response: dict[str, Any]) -> bool:
    if not isinstance(response, dict):
        return True
    results = response.get("results")
    if isinstance(results, list):
        return len(results) == 0
    snippets = response.get("snippets")
    if isinstance(snippets, list):
        return len(snippets) == 0
    citations = response.get("citations")
    if isinstance(citations, list):
        return len(citations) == 0
    return False


def _score_results(
    *,
    snippets: list[dict[str, Any]],
    now: datetime,
    source_weights: dict[str, float],
    data_type_weights: dict[str, float],
    anomaly_hint: float | None,
) -> dict[str, float]:
    if not snippets:
        return {
            "authority": 0.0,
            "diversity": 0.0,
            "freshness": 0.0,
            "contradiction": 1.0,
            "alignment": 0.0,
            "informational_gain": 0.0,
            "anomaly": _clamp01(anomaly_hint),
        }

    authority_total = 0.0
    domains: list[str] = []
    fresh_count = 0
    contradiction_hits = 0
    alignment_total = 0.0
    gain_total = 0.0
    anomaly_values: list[float] = []

    for item in snippets:
        domain = str(item.get("domain", "")).lower()
        domains.append(domain)
        source_type = str(item.get("source_type", "blog"))
        data_type = str(item.get("data_type", "blog_post"))
        base_source = _clamp01(source_weights.get(source_type, source_weights.get("blog", 0.6)))
        base_data_type = _clamp01(data_type_weights.get(data_type, data_type_weights.get("blog_post", 0.6)))
        base_authority = round((base_source + base_data_type) / 2.0, 4)
        alignment_score = _clamp01(item.get("alignment_score", 0.0))
        informational_gain = _clamp01(item.get("informational_gain_score", 0.0))
        contextual_authority = compute_contextual_authority(
            base_authority=base_authority,
            alignment_score=alignment_score,
            informational_gain_score=informational_gain,
        )
        authority_total += contextual_authority
        alignment_total += alignment_score
        gain_total += informational_gain
        anomaly_values.append(_clamp01(item.get("anomaly_score", 0.0)))

        published_at = str(item.get("published_at", ""))
        parsed = _parse_rfc3339(published_at)
        if parsed is not None and now - parsed <= timedelta(days=30):
            fresh_count += 1

        snippet = str(item.get("snippet", "")).lower()
        has_signal = bool(item.get("contradiction_signal", False)) or _has_contradiction_markers(snippet)
        if has_signal:
            contradiction_hits += 1

    total = float(len(snippets))
    unique_domains = len({d for d in domains if d})
    anomaly = max(anomaly_values) if anomaly_values else 0.0
    if anomaly_hint is not None:
        anomaly = max(anomaly, _clamp01(anomaly_hint))
    return {
        "authority": round(authority_total / total, 4),
        "diversity": round(unique_domains / total, 4),
        "freshness": round(fresh_count / total, 4),
        "contradiction": round(contradiction_hits / total, 4),
        "alignment": round(alignment_total / total, 4),
        "informational_gain": round(gain_total / total, 4),
        "anomaly": round(_clamp01(anomaly), 4),
    }


def _compiled_threshold(tier: str, thresholds: ResearchThresholds) -> float:
    if tier == "deep":
        return thresholds.deep_compiled_min
    if tier == "high":
        return thresholds.high_compiled_min
    return thresholds.atomic_min


def _compiled_confidence(*, scores: dict[str, float], atomic_confidence: float) -> float:
    compiled = (
        0.45 * _clamp01(atomic_confidence)
        + 0.25 * _clamp01(scores.get("authority", 0.0))
        + 0.10 * _clamp01(scores.get("diversity", 0.0))
        + 0.10 * _clamp01(scores.get("freshness", 0.0))
        + 0.10 * _clamp01(scores.get("informational_gain", 0.0))
    )
    contradiction = _clamp01(scores.get("contradiction", 0.0))
    penalized = compiled - (0.20 * contradiction)
    return round(_clamp01(penalized), 4)


def _domain_from_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return host


def compute_contextual_authority(
    *,
    base_authority: float,
    alignment_score: float,
    informational_gain_score: float,
    elevation_cap: float = 0.15,
) -> float:
    base = _clamp01(base_authority)
    alignment = _clamp01(alignment_score)
    gain = _clamp01(informational_gain_score)
    cap = _clamp01(elevation_cap)
    if alignment < 0.8:
        return round(base, 4)
    elevation_factor = min(cap, gain * 0.20)
    return round(min(1.0, base + elevation_factor), 4)


def _parse_rfc3339(value: str) -> datetime | None:
    if not value:
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


def _has_contradiction_markers(text: str) -> bool:
    markers = (
        "conflicting",
        "contradict",
        "in contrast",
        "however",
        "disputed",
        "mixed evidence",
    )
    return any(marker in text for marker in markers)


def _enforce_allowed_domains(
    *,
    job_contract: dict[str, Any],
    snippets: list[dict[str, Any]],
    query: str,
    org_policy: dict[str, Any] | None,
) -> None:
    envelope = _intent_envelope(job_contract)
    allowed_domains_raw = envelope.get("allowed_domains")
    if not isinstance(allowed_domains_raw, list):
        raise PolicyViolationError("IntentEnvelope.allowed_domains must be a list")

    allowed = [str(x).strip().lower() for x in allowed_domains_raw if str(x).strip()]
    allowed.extend(_domain_overrides_for_query(query=query, org_policy=org_policy))
    allowed = sorted({x for x in allowed if x})
    if not allowed:
        raise PolicyViolationError("IntentEnvelope.allowed_domains cannot be empty")

    observed = sorted({str(item.get("domain", "")).strip().lower() for item in snippets if item.get("domain")})
    if not observed:
        raise PolicyViolationError("Cannot verify topic domain: no search result domains returned")

    for domain in observed:
        if not _domain_allowed(domain=domain, allowed_domains=allowed):
            raise PolicyViolationError(f"Topic domain is outside IntentEnvelope.allowed_domains: {domain}")


def _domain_allowed(*, domain: str, allowed_domains: list[str]) -> bool:
    for allowed in allowed_domains:
        if not allowed:
            continue
        if allowed.startswith("*."):
            suffix = allowed[1:]
            if domain.endswith(suffix):
                return True
            continue
        if domain == allowed or domain.endswith(f".{allowed}"):
            return True
    return False


def _intent_envelope(job_contract: dict[str, Any]) -> dict[str, Any]:
    spec = job_contract.get("spec")
    if not isinstance(spec, dict):
        raise PolicyViolationError("JobContract.spec is required")
    envelope = spec.get("intent_envelope")
    if not isinstance(envelope, dict):
        raise PolicyViolationError("JobContract.spec.intent_envelope is required")

    original_prompt = envelope.get("original_prompt")
    intent_hash = envelope.get("intent_hash")
    if not isinstance(original_prompt, str) or not original_prompt:
        raise PolicyViolationError("IntentEnvelope.original_prompt must be a non-empty string")
    if not isinstance(intent_hash, str):
        raise PolicyViolationError("IntentEnvelope.intent_hash is required")
    computed = hashlib.sha256(original_prompt.encode("utf-8")).hexdigest()
    if computed != intent_hash:
        raise PolicyViolationError("IntentEnvelope.intent_hash does not match original_prompt")
    return envelope


def _domain_overrides_for_query(*, query: str, org_policy: dict[str, Any] | None) -> list[str]:
    if not _is_markets_query(query):
        return []
    if not isinstance(org_policy, dict):
        return []
    spec = org_policy.get("spec")
    if not isinstance(spec, dict):
        return []
    search_policy = spec.get("search_policy")
    if not isinstance(search_policy, dict):
        return []
    domain_overrides = search_policy.get("domain_overrides")
    if not isinstance(domain_overrides, dict):
        return []
    markets = domain_overrides.get("markets")
    if not isinstance(markets, list):
        return []
    return [str(x).strip().lower() for x in markets if str(x).strip()]


def _is_markets_query(query: str) -> bool:
    q = query.lower()
    needles = ("market", "equity", "stock", "fed", "earnings", "macro")
    return any(n in q for n in needles)


def _load_weight_table(path: Path) -> dict[str, float]:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        raise PolicyViolationError(f"Failed loading weight config: {path}") from exc

    in_weights = False
    out: dict[str, float] = {}
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "weights:":
            in_weights = True
            continue
        if not in_weights:
            continue
        if line.startswith(" ") is False:
            # Left the weights map.
            break
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        name = key.strip().lower()
        if not name:
            continue
        out[name] = _clamp01(value.strip())
    if not out:
        raise PolicyViolationError(f"Weight config is empty: {path}")
    return out


def _apply_monthly_recalibration(
    weights: dict[str, float],
    org_policy: dict[str, Any] | None,
    now: datetime,
) -> dict[str, float]:
    if not isinstance(org_policy, dict):
        return dict(weights)
    spec = org_policy.get("spec")
    if not isinstance(spec, dict):
        return dict(weights)
    search_policy = spec.get("search_policy")
    if not isinstance(search_policy, dict):
        return dict(weights)
    recalibration = search_policy.get("monthly_weight_recalibration")
    if not isinstance(recalibration, dict):
        return dict(weights)
    if recalibration.get("enabled") is not True:
        return dict(weights)
    apply_month = str(recalibration.get("apply_month", "")).strip()
    if apply_month and apply_month != now.strftime("%Y-%m"):
        return dict(weights)
    overrides = recalibration.get("overrides")
    if not isinstance(overrides, dict):
        return dict(weights)

    out = dict(weights)
    for key, override in overrides.items():
        if not isinstance(key, str):
            continue
        name = key.strip().lower()
        if name not in out:
            continue
        base = out[name]
        try:
            desired = float(override)
        except (TypeError, ValueError):
            continue
        lower = base * 0.90
        upper = base * 1.10
        bounded = min(max(desired, lower), upper)
        out[name] = round(_clamp01(bounded), 4)
    return out


def _infer_source_type(item: dict[str, Any], tool_id: str, domain: str) -> str:
    if tool_id == ZLIB_SEARCH_TOOL:
        return "zlib"
    if tool_id == REDDIT_SEARCH_TOOL:
        return "reddit"
    if tool_id in {YOUTUBE_SEARCH_TOOL, YOUTUBE_TRANSCRIBE_TOOL}:
        return "youtube_official" if bool(item.get("official_channel")) else "youtube_third_party"
    if tool_id == EDGAR_SEARCH_TOOL:
        return "court_edgar"
    if tool_id == SEMANTIC_SCHOLAR_TOOL:
        return "academic"
    if tool_id == GITHUB_OFFICIAL_TOOL:
        return "github_official"

    if domain.endswith(".gov"):
        return "regulatory"
    if domain == "sec.gov":
        return "court_edgar"
    if domain.endswith(".edu"):
        return "academic"
    if domain in _KNOWN_NEWS:
        return "news"
    if domain == "github.com" and bool(item.get("official_repo")):
        return "github_official"
    if bool(item.get("official_company")):
        return "official_company"
    return "blog"


def _infer_data_type(item: dict[str, Any], source_type: str) -> str:
    if source_type == "regulatory":
        return "regulatory_document"
    if source_type == "court_edgar":
        return "sec_filing"
    if source_type == "official_company":
        return "official_company_statement"
    if source_type == "academic":
        return "peer_reviewed_paper"
    if source_type == "github_official":
        return "official_repository"
    if source_type == "news":
        return "news_report"
    if source_type == "zlib":
        return "zlib_record"
    if source_type == "reddit":
        return "reddit_post"
    if source_type == "youtube_official":
        return "youtube_official_transcript"
    if source_type == "youtube_third_party":
        return "youtube_third_party_transcript"
    if bool(item.get("court_filing")):
        return "court_filing"
    return "blog_post"


def _validate_oracle_response(response: dict[str, Any]) -> None:
    expected = {"confidence_score", "authority_score", "contradiction_flag"}
    keys = set(response.keys())
    if keys != expected:
        raise PolicyViolationError("Perplexity scoring response schema is invalid")
    for key in ("confidence_score", "authority_score"):
        value = response.get(key)
        if isinstance(value, bool):
            raise PolicyViolationError(f"{key} must be numeric")
        try:
            score = float(value)
        except (TypeError, ValueError) as exc:
            raise PolicyViolationError(f"{key} must be numeric") from exc
        if score < 0.0 or score > 1.0:
            raise PolicyViolationError(f"{key} must be within [0,1]")
    if not isinstance(response.get("contradiction_flag"), bool):
        raise PolicyViolationError("contradiction_flag must be boolean")


def _clamp01(value: Any) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return 0.0
    if f < 0.0:
        return 0.0
    if f > 1.0:
        return 1.0
    return round(f, 4)
