"""Roland MCP/API-compatible intelligence interface endpoints."""

from __future__ import annotations

from dataclasses import dataclass as _dataclass
from dataclasses import dataclass, field
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

        def post(self, path: str):
            def _decorator(fn: Callable[..., Any]):
                self.routes.append(_FallbackRoute(path=path, endpoint=fn))
                return fn

            return _decorator

from economics.economic_policy_adapter import apply_economic_policy
from errors import PolicyViolationError
from governance.strictness_adapter import derive_strictness_profile
from security.capabilityEnforcer import CapabilityEnforcer, CapabilityRequest
from security.defense_matrix import apply_defense_matrix
from security.trust_classifier import classify_trust

RUNTIME_SKILL_ID = "roland_interface"
_VALID_TIERS = {"fast", "high", "deep"}


@dataclass(frozen=True)
class RolandInterfaceProviders:
    capability_enforcer: CapabilityEnforcer
    rag_first_lookup: Callable[..., dict[str, Any]]
    research_executor: Callable[..., dict[str, Any]]
    scarcity_index: Callable[[], dict[str, Any]]
    org_policy: Callable[[str], dict[str, Any] | None]
    health: Callable[[], dict[str, Any]] = field(
        default=lambda: {"status": "ok", "component": "roland", "mode": "modular"}
    )
    audit_log: Any | None = None
    skill_contract: dict[str, Any] = field(
        default_factory=lambda: {"spec": {"classification": {"category_id": "api"}}}
    )
    actor: str = "runtime.core.api.roland_interface"


def build_roland_router(*, providers: RolandInterfaceProviders) -> APIRouter:
    if not isinstance(providers, RolandInterfaceProviders):
        raise PolicyViolationError("providers must be RolandInterfaceProviders")
    if not callable(providers.rag_first_lookup):
        raise PolicyViolationError("rag_first_lookup provider must be callable")
    if not callable(providers.research_executor):
        raise PolicyViolationError("research_executor provider must be callable")
    if not callable(providers.scarcity_index):
        raise PolicyViolationError("scarcity_index provider must be callable")
    if not callable(providers.org_policy):
        raise PolicyViolationError("org_policy provider must be callable")
    if not callable(providers.health):
        raise PolicyViolationError("health provider must be callable")

    router = APIRouter(tags=["roland"])

    @router.post("/roland/query")
    def post_roland_query(payload: dict[str, Any]) -> dict[str, Any]:
        return _handle_post(payload=payload, mode="query", providers=providers)

    @router.post("/roland/research")
    def post_roland_research(payload: dict[str, Any]) -> dict[str, Any]:
        return _handle_post(payload=payload, mode="research", providers=providers)

    @router.get("/roland/health")
    def get_roland_health() -> dict[str, Any]:
        out = providers.health()
        if not isinstance(out, dict):
            raise PolicyViolationError("health provider must return an object")
        return out

    @router.get("/roland/economics_summary")
    def get_roland_economics_summary() -> dict[str, Any]:
        scarcity = _read_scarcity(providers=providers)
        adjustment = apply_economic_policy(
            scarcity_index_by_platform=scarcity,
            org_policy=None,
            base_atomic_threshold=0.7,
            base_high_threshold=0.8,
            base_deep_threshold=0.85,
            audit_log=providers.audit_log,
        )
        return {
            "economics_summary": {
                "scarcity_index_by_platform": scarcity,
                "adjustment": adjustment,
                "atomic_threshold": 0.7,
            }
        }

    return router


def _handle_post(*, payload: dict[str, Any], mode: str, providers: RolandInterfaceProviders) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise PolicyViolationError("request payload must be an object")
    if mode not in {"query", "research"}:
        raise PolicyViolationError(f"Unsupported Roland mode: {mode}")

    query = _require_query(payload)
    tier = _require_tier(payload)
    job_contract = payload.get("job_contract")
    if not isinstance(job_contract, dict):
        raise PolicyViolationError("job_contract is required")

    _enforce_entry_capability(
        capability_enforcer=providers.capability_enforcer,
        actor=providers.actor,
        skill_contract=providers.skill_contract,
        job_contract=job_contract,
    )

    org_id = _org_id(payload=payload, job_contract=job_contract)
    org_policy = providers.org_policy(org_id)
    _enforce_org_policy(org_policy=org_policy, org_id=org_id, job_contract=job_contract)
    system_strictness = _resolve_system_strictness(payload=payload, org_policy=org_policy)
    strictness_profile = derive_strictness_profile(system_strictness=system_strictness)
    trust = classify_trust(source=_source_context(payload))
    _append_audit(
        providers=providers,
        action="trust.classified",
        details={"trust_level": trust["trust_level"], "source": trust["source"], "reason": trust["reason"]},
    )
    _append_audit(
        providers=providers,
        action="strictness.profile.applied",
        details={
            "system_strictness": strictness_profile.system_strictness,
            "risk_deny_threshold": strictness_profile.risk_deny_threshold,
            "entropy_tolerance": strictness_profile.entropy_tolerance,
        },
    )

    defense = apply_defense_matrix(
        trust_assessment=trust,
        content=query,
        strictness=system_strictness,
        capability_check=lambda: _enforce_entry_capability(
            capability_enforcer=providers.capability_enforcer,
            actor=providers.actor,
            skill_contract=providers.skill_contract,
            job_contract=job_contract,
        ),
        audit_log=providers.audit_log,
    )
    safe_query = str(defense["sanitized_content"])

    economics = _economics_adjustment(
        providers=providers,
        org_policy=org_policy,
    )
    effective_tier, fallback_reason = _effective_tier(requested_tier=tier, economics=economics)

    # RAG-first routing is mandatory for all POST execution modes.
    rag = providers.rag_first_lookup(
        query=safe_query,
        tier=effective_tier,
        job_contract=job_contract,
        org_policy=org_policy,
    )
    if not isinstance(rag, dict):
        raise PolicyViolationError("rag_first_lookup must return an object")
    if _rag_satisfied(rag):
        return {
            "status": "ok",
            "mode": mode,
            "requested_tier": tier,
            "effective_tier": effective_tier,
            "fallback_reason": fallback_reason,
            "rag_first_satisfied": True,
            "research_triggered": False,
            "result": rag,
            "economics": economics,
            "trust": trust,
            "defense": {"filter_mode": defense["filter_mode"], "intent": defense["intent"]},
            "strictness": {"system_strictness": strictness_profile.system_strictness},
        }

    research = providers.research_executor(
        query=safe_query,
        tier=effective_tier,
        job_contract=job_contract,
        org_policy=org_policy,
        mode=mode,
    )
    if not isinstance(research, dict):
        raise PolicyViolationError("research_executor must return an object")
    return {
        "status": "ok",
        "mode": mode,
        "requested_tier": tier,
        "effective_tier": effective_tier,
        "fallback_reason": fallback_reason,
        "rag_first_satisfied": False,
        "research_triggered": True,
        "result": research,
        "economics": economics,
        "trust": trust,
        "defense": {"filter_mode": defense["filter_mode"], "intent": defense["intent"]},
        "strictness": {"system_strictness": strictness_profile.system_strictness},
    }


def _enforce_entry_capability(
    *,
    capability_enforcer: CapabilityEnforcer,
    actor: str,
    skill_contract: dict[str, Any],
    job_contract: dict[str, Any],
) -> None:
    capability_enforcer.enforceCapability(
        CapabilityRequest(
            actor=actor,
            job_contract=job_contract,
            skill_contract=skill_contract,
            skill_id=RUNTIME_SKILL_ID,
            requested_side_effects=False,
            requested_channel="none",
            requested_mcp_id=None,
            requested_mcp_scopes=[],
            requested_scope_tags=[],
        )
    )


def _economics_adjustment(
    *,
    providers: RolandInterfaceProviders,
    org_policy: dict[str, Any] | None,
) -> dict[str, Any]:
    scarcity = _read_scarcity(providers=providers)
    return apply_economic_policy(
        scarcity_index_by_platform=scarcity,
        org_policy=org_policy,
        base_atomic_threshold=0.7,
        base_high_threshold=0.8,
        base_deep_threshold=0.85,
        audit_log=providers.audit_log,
    )


def _read_scarcity(*, providers: RolandInterfaceProviders) -> dict[str, Any]:
    scarcity = providers.scarcity_index()
    if not isinstance(scarcity, dict):
        raise PolicyViolationError("scarcity_index provider must return an object")
    return scarcity


def _org_id(*, payload: dict[str, Any], job_contract: dict[str, Any]) -> str:
    direct = str(payload.get("org_id", "")).strip()
    if direct:
        return direct
    metadata = job_contract.get("metadata")
    if isinstance(metadata, dict):
        job_org_id = str(metadata.get("org_id", "")).strip()
        if job_org_id:
            return job_org_id
    raise PolicyViolationError("org_id is required (payload.org_id or job_contract.metadata.org_id)")


def _enforce_org_policy(*, org_policy: dict[str, Any] | None, org_id: str, job_contract: dict[str, Any]) -> None:
    if not isinstance(org_policy, dict):
        return

    metadata = org_policy.get("metadata")
    if isinstance(metadata, dict):
        policy_org_id = str(metadata.get("org_id", "")).strip()
        if policy_org_id and policy_org_id != org_id:
            raise PolicyViolationError("org policy org_id mismatch")

    job_meta = job_contract.get("metadata")
    if isinstance(job_meta, dict):
        job_org_id = str(job_meta.get("org_id", "")).strip()
        if job_org_id and job_org_id != org_id:
            raise PolicyViolationError("job_contract.metadata.org_id mismatch")

    spec = org_policy.get("spec")
    if isinstance(spec, dict):
        flo_routing = spec.get("flo_routing")
        if isinstance(flo_routing, dict) and flo_routing.get("enabled") is False:
            raise PolicyViolationError("org policy denies Roland routing")


def _effective_tier(*, requested_tier: str, economics: dict[str, Any]) -> tuple[str, str | None]:
    if requested_tier == "deep" and not bool(economics.get("deep_enabled", True)):
        return "high", "deep_disabled_by_economic_policy"
    return requested_tier, None


def _require_tier(payload: dict[str, Any]) -> str:
    if "tier" not in payload:
        raise PolicyViolationError("tier is required")
    tier = str(payload.get("tier", "")).strip().lower()
    if tier not in _VALID_TIERS:
        raise PolicyViolationError("tier must be one of: fast|high|deep")
    return tier


def _require_query(payload: dict[str, Any]) -> str:
    query = str(payload.get("query", "")).strip()
    if not query:
        raise PolicyViolationError("query is required")
    return query


def _rag_satisfied(rag_result: dict[str, Any]) -> bool:
    satisfied = rag_result.get("satisfied")
    if isinstance(satisfied, bool):
        return satisfied
    hit = rag_result.get("hit")
    if isinstance(hit, bool):
        return hit
    confidence = rag_result.get("confidence_score")
    if isinstance(confidence, (int, float)):
        return float(confidence) >= 0.7
    return False


def _source_context(payload: dict[str, Any]) -> dict[str, Any]:
    raw = payload.get("source_context")
    if isinstance(raw, dict):
        return raw
    return {
        "source": "user_prompt",
        "content_type": "text/plain",
        "typed": False,
        "schema_bound": False,
        "signed": False,
    }


def _resolve_system_strictness(*, payload: dict[str, Any], org_policy: dict[str, Any] | None) -> float:
    value: Any = payload.get("system_strictness")
    if value is None and isinstance(org_policy, dict):
        spec = org_policy.get("spec")
        if isinstance(spec, dict):
            security = spec.get("security")
            if isinstance(security, dict):
                value = security.get("system_strictness")
    try:
        strictness = float(value if value is not None else 0.75)
    except (TypeError, ValueError):
        strictness = 0.75
    if strictness < 0.0:
        return 0.0
    if strictness > 1.0:
        return 1.0
    return round(strictness, 4)


def _append_audit(*, providers: RolandInterfaceProviders, action: str, details: dict[str, Any]) -> None:
    if providers.audit_log is None:
        return
    providers.audit_log.append(
        actor=providers.actor,
        action=action,
        target="roland",
        details={k: v for k, v in details.items() if "secret" not in k.lower() and "token" not in k.lower()},
    )
