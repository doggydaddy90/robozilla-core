"""FastAPI surface for RoboZilla Core Runtime (build mode)."""

from __future__ import annotations

import logging
import logging.config
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from fastapi import Body, FastAPI
from fastapi.responses import JSONResponse

from api.dashboard_endpoints import (
    DashboardDataProviders,
    build_dashboard_router,
    load_rag_index,
    load_telemetry_from_audit,
    load_truth_ledger_from_audit,
)
from api.isolation import enforce_route_isolation, is_roland_strict_mode_enabled, run_startup_isolation_check
from audit.auditLog import AuditLog, verifyAuditChain
from capability.capability_registry import CapabilityRegistry, default_kernel_capability_registry
from config.config_loader import ConfigLoader, KernelConfig
from errors import (
    ConflictError,
    ContractViolationError,
    NotFoundError,
    PolicyViolationError,
    SchemaValidationError,
)
from evaluator.service import EvaluationService
from executor.engine import JobEngine
from events.event_bus import EventBus
from kernel.kernel_info import build_kernel_info
from registry.registry import Registry
from registry.schema_validator import SchemaValidator
from security.capabilityEnforcer import CapabilityEnforcer
from security.pathGuard import derive_project_root, safeRead, set_audit_logger, set_project_root
from storage.interfaces import ArtifactStore
from storage.sqlite import SQLiteStores
from utils import deep_get

logger = logging.getLogger(__name__)


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else []


def _as_dict(v: Any) -> dict[str, Any]:
    if not isinstance(v, dict):
        raise PolicyViolationError("Expected object")
    return v


@dataclass(frozen=True)
class AppComponents:
    engine: JobEngine
    evaluator: EvaluationService
    schema_validator: SchemaValidator
    registry: Registry
    config: KernelConfig
    capability_registry: CapabilityRegistry
    artifact_store: ArtifactStore
    audit_log: AuditLog
    capability_enforcer: CapabilityEnforcer
    event_bus: EventBus
    isolation_mode: str


def _load_logging_config(path: Path) -> dict[str, Any]:
    raw = yaml.safe_load(safeRead(path))
    if not isinstance(raw, dict):
        raise PolicyViolationError(f"Invalid logging config YAML root object: {path}")
    return raw


def _apply_logging_config(logging_config_path: Path) -> None:
    cfg = _load_logging_config(logging_config_path)
    logging.config.dictConfig(cfg)


def _error_payload(err: Exception) -> dict[str, Any]:
    if isinstance(err, SchemaValidationError):
        return {
            "error": "SCHEMA_VALIDATION_ERROR",
            "kind": err.kind,
            "violations": [{"path": v.path, "message": v.message} for v in err.violations],
        }
    if isinstance(err, ContractViolationError):
        return {"error": "CONTRACT_VIOLATION", "code": err.code, "message": str(err), "details": err.details}
    if isinstance(err, PolicyViolationError):
        return {"error": "POLICY_VIOLATION", "message": str(err), "details": err.details}
    if isinstance(err, ConflictError):
        return {"error": "CONFLICT", "message": str(err), "details": err.details}
    if isinstance(err, NotFoundError):
        return {"error": "NOT_FOUND", "resource_type": err.resource_type, "resource_id": err.resource_id}
    return {"error": "INTERNAL", "message": str(err)}


def _build_components() -> AppComponents:
    config = ConfigLoader().load()
    runtime_cfg_path = config.runtime_config_path
    logging_cfg_path = config.logging_config_path
    limits_cfg_path = config.limits_config_path

    bootstrap_root = derive_project_root([runtime_cfg_path, logging_cfg_path, limits_cfg_path, Path.cwd()])
    set_project_root(bootstrap_root, freeze=False)

    runtime = config.runtime
    limits = config.limits

    enforcement_root = derive_project_root(
        [
            runtime_cfg_path,
            logging_cfg_path,
            limits_cfg_path,
            runtime.registry.schemas_dir,
            runtime.registry.orgs_dir,
            runtime.registry.agent_definitions_dir,
            runtime.registry.skill_contracts_dir,
            runtime.storage.sqlite_path,
        ]
    )
    set_project_root(enforcement_root, freeze=False)

    _apply_logging_config(logging_cfg_path)

    schema_validator = SchemaValidator.load_from_dir(runtime.registry.schemas_dir)
    registry = Registry.load(
        orgs_dir=runtime.registry.orgs_dir,
        agent_definitions_dir=runtime.registry.agent_definitions_dir,
        skill_contracts_dir=runtime.registry.skill_contracts_dir,
        schema_validator=schema_validator,
    )

    stores = SQLiteStores(runtime.storage.sqlite_path)
    audit_log = AuditLog(runtime.storage.sqlite_path.with_name("runtime_audit.sqlite"))
    set_audit_logger(audit_log)
    set_project_root(enforcement_root, freeze=True)
    run_startup_isolation_check(
        project_root=enforcement_root,
        required_paths=[
            runtime_cfg_path,
            logging_cfg_path,
            limits_cfg_path,
            runtime.registry.schemas_dir,
            runtime.registry.orgs_dir,
            runtime.registry.agent_definitions_dir,
            runtime.registry.skill_contracts_dir,
            runtime.storage.sqlite_path,
            runtime.storage.sqlite_path.with_name("runtime_audit.sqlite"),
        ],
        strict_mode=is_roland_strict_mode_enabled(),
        audit_log=audit_log,
    )
    event_bus = EventBus()
    capability_enforcer = CapabilityEnforcer(audit_log=audit_log, event_bus=event_bus)
    capability_registry = default_kernel_capability_registry()

    engine = JobEngine(
        schema_validator=schema_validator,
        registry=registry,
        job_store=stores.jobs,
        limits=limits,
        execution_deferred=True,
        audit_log=audit_log,
        capability_enforcer=capability_enforcer,
    )
    evaluator = EvaluationService(schema_validator=schema_validator, registry=registry, evaluation_store=stores.evaluations, job_store=stores.jobs)

    return AppComponents(
        engine=engine,
        evaluator=evaluator,
        schema_validator=schema_validator,
        registry=registry,
        config=config,
        capability_registry=capability_registry,
        artifact_store=stores.artifacts,
        audit_log=audit_log,
        capability_enforcer=capability_enforcer,
        event_bus=event_bus,
        isolation_mode="inprocess",
    )


app = FastAPI(title="RoboZilla Core Runtime (Build Mode)", version="0.1.0")


@app.on_event("startup")
def _startup() -> None:
    # Fail closed at startup if registry/config/schemas cannot be loaded.
    app.state.components = _build_components()
    logger.info("runtime_started", extra={"event": "runtime_started"})


@app.exception_handler(SchemaValidationError)
def _schema_validation_handler(_req, exc: SchemaValidationError):
    return JSONResponse(status_code=422, content=_error_payload(exc))


@app.exception_handler(PolicyViolationError)
def _policy_violation_handler(_req, exc: PolicyViolationError):
    return JSONResponse(status_code=403, content=_error_payload(exc))


@app.exception_handler(ContractViolationError)
def _contract_violation_handler(_req, exc: ContractViolationError):
    return JSONResponse(status_code=400, content=_error_payload(exc))


@app.exception_handler(ConflictError)
def _conflict_handler(_req, exc: ConflictError):
    return JSONResponse(status_code=409, content=_error_payload(exc))


@app.exception_handler(NotFoundError)
def _not_found_handler(_req, exc: NotFoundError):
    return JSONResponse(status_code=404, content=_error_payload(exc))


@app.exception_handler(Exception)
def _unhandled_handler(_req, exc: Exception):
    logger.exception("unhandled_error", extra={"event": "unhandled_error"})
    return JSONResponse(status_code=500, content=_error_payload(exc))


def _components() -> AppComponents:
    return app.state.components


def _enforce_legacy_mutation_route(path: str, method: str = "POST") -> None:
    enforce_route_isolation(
        path=path,
        method=method,
        strict_mode=is_roland_strict_mode_enabled(),
    )


def _dashboard_daily_caps() -> dict[str, Any]:
    return {
        "openai": 250000,
        "perplexity": 150000,
        "search_api": 100000,
        "reddit_api": 60000,
        "youtube_api": 60000,
        "zlib": "unlimited",
        "ref_tools": 20000,
        "other": "unlimited",
    }


def _dashboard_org_policy() -> dict[str, Any] | None:
    # Read-only API surface; policy can be wired to org-scoped state later.
    return None


app.include_router(
    build_dashboard_router(
        providers=DashboardDataProviders(
            telemetry_records=lambda: load_telemetry_from_audit(audit_db_path=_components().audit_log.path),
            daily_caps=_dashboard_daily_caps,
            org_policy=_dashboard_org_policy,
            rag_index=lambda: load_rag_index(rag_dir=Path("rag")),
            truth_ledger=lambda: load_truth_ledger_from_audit(audit_db_path=_components().audit_log.path),
        )
    )
)


@app.get("/health")
def health() -> dict[str, Any]:
    """Health check for runtime availability. Returns 200 when registry and stores are loaded."""
    return {"status": "ok", "mode": "build"}


@app.get("/audit/verify")
def verify_audit_chain() -> dict[str, Any]:
    res = verifyAuditChain(_components().audit_log)
    return {"valid": res.valid, "entries": res.entries, "errors": res.errors}


@app.get("/kernel/info")
def kernel_info() -> dict[str, Any]:
    comps = _components()
    info = build_kernel_info(
        config=comps.config,
        capability_registry=comps.capability_registry,
        isolation_mode=comps.isolation_mode,
    )
    return info.to_dict()


@app.post("/jobs")
def submit_job(job: dict[str, Any] = Body(...)) -> dict[str, Any]:
    _enforce_legacy_mutation_route("/jobs", "POST")
    res = _components().engine.submit_job(job)
    return {"job": res.job}


@app.get("/jobs/{job_id}")
def get_job(job_id: str) -> dict[str, Any]:
    job = _components().engine.get_job(job_id)
    return {"job": job}


@app.post("/jobs/{job_id}/run")
def run_job(job_id: str) -> dict[str, Any]:
    _enforce_legacy_mutation_route("/jobs/{job_id}/run", "POST")
    res = _components().engine.run_job(job_id)
    return {"job": res.job}


@app.post("/jobs/{job_id}/stop")
def stop_job(job_id: str) -> dict[str, Any]:
    _enforce_legacy_mutation_route("/jobs/{job_id}/stop", "POST")
    res = _components().engine.stop_job(job_id)
    return {"job": res.job}


def _enforce_artifact_policy(artifact: dict[str, Any], *, engine: JobEngine, registry: Registry) -> None:
    """Ensure artifact is allowed by job and org policy. Job must exist and be non-terminal."""
    job_id = str(deep_get(artifact, ["spec", "job_ref", "job_id"]))
    org_id = str(deep_get(artifact, ["metadata", "org_id"]))
    artifact_type = str(deep_get(artifact, ["metadata", "artifact_type"]))
    producing_agent_id = str(deep_get(artifact, ["spec", "produced_by", "agent_id"]))

    job = engine.get_job(job_id)
    job_org_id = str(deep_get(job, ["metadata", "org_id"]))
    if job_org_id != org_id:
        raise PolicyViolationError("Artifact.metadata.org_id must match JobContract.metadata.org_id")

    state = str(deep_get(job, ["spec", "status", "state"]))
    if state in ("completed", "failed", "expired"):
        raise ConflictError(f"Cannot submit artifact for terminal job (state={state})")

    if not registry.has_org(org_id):
        raise PolicyViolationError(f"Unknown org_id: {org_id}")

    org = registry.get_org(org_id).document
    allowed = {str(_as_dict(x).get("type_id")) for x in _as_list(deep_get(org, ["spec", "artifact_policy", "allowed_types"]))}
    if artifact_type not in allowed:
        raise PolicyViolationError(f"Artifact type {artifact_type} is not allowed by org policy")

    included_agents = registry.included_agent_ids_for_org(org_id)
    if producing_agent_id and producing_agent_id not in included_agents:
        raise PolicyViolationError(f"Producing agent {producing_agent_id} is not included in org {org_id}")


@app.post("/artifacts")
def submit_artifact(artifact: dict[str, Any] = Body(...)) -> dict[str, Any]:
    _enforce_legacy_mutation_route("/artifacts", "POST")
    comps = _components()
    comps.schema_validator.validate("Artifact", artifact)
    _enforce_artifact_policy(artifact, engine=comps.engine, registry=comps.registry)
    comps.artifact_store.append(artifact)
    return {"artifact": artifact}


@app.get("/artifacts/{artifact_id}")
def get_artifact(artifact_id: str) -> dict[str, Any]:
    artifact = _components().artifact_store.get(artifact_id)
    return {"artifact": artifact}


@app.post("/evaluations")
def submit_evaluation(evaluation: dict[str, Any] = Body(...)) -> dict[str, Any]:
    _enforce_legacy_mutation_route("/evaluations", "POST")
    res = _components().evaluator.submit(evaluation)
    return {"evaluation": res.evaluation, "job": res.job}

