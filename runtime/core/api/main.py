"""FastAPI surface for RoboZilla Core Runtime (build mode)."""

from __future__ import annotations

import logging
import logging.config
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from fastapi import Body, FastAPI
from fastapi.responses import JSONResponse

from config.settings import default_config_paths, load_limits_config, load_runtime_config
from errors import (
    ConflictError,
    ContractViolationError,
    NotFoundError,
    PolicyViolationError,
    SchemaValidationError,
)
from evaluator.service import EvaluationService
from executor.engine import JobEngine
from registry.registry import Registry
from registry.schema_validator import SchemaValidator
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
    artifact_store: ArtifactStore


def _load_logging_config(path: Path) -> dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise PolicyViolationError(f"Invalid logging config YAML root object: {path}")
    return raw


def _apply_logging_config(logging_config_path: Path) -> None:
    cfg = _load_logging_config(logging_config_path)
    logging.config.dictConfig(cfg)


def _env_path(name: str) -> Path | None:
    v = os.environ.get(name)
    if not v:
        return None
    return Path(v)


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
    default_runtime, default_logging, default_limits = default_config_paths()
    runtime_cfg_path = _env_path("ROBOZILLA_RUNTIME_CONFIG") or default_runtime
    logging_cfg_path = _env_path("ROBOZILLA_LOGGING_CONFIG") or default_logging
    limits_cfg_path = _env_path("ROBOZILLA_LIMITS_CONFIG") or default_limits

    runtime = load_runtime_config(runtime_cfg_path)
    limits = load_limits_config(limits_cfg_path)

    _apply_logging_config(logging_cfg_path)

    schema_validator = SchemaValidator.load_from_dir(runtime.registry.schemas_dir)
    registry = Registry.load(
        orgs_dir=runtime.registry.orgs_dir,
        agent_definitions_dir=runtime.registry.agent_definitions_dir,
        skill_contracts_dir=runtime.registry.skill_contracts_dir,
        schema_validator=schema_validator,
    )

    stores = SQLiteStores(runtime.storage.sqlite_path)

    engine = JobEngine(schema_validator=schema_validator, registry=registry, job_store=stores.jobs, limits=limits, execution_deferred=True)
    evaluator = EvaluationService(schema_validator=schema_validator, registry=registry, evaluation_store=stores.evaluations, job_store=stores.jobs)

    return AppComponents(
        engine=engine,
        evaluator=evaluator,
        schema_validator=schema_validator,
        registry=registry,
        artifact_store=stores.artifacts,
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


@app.get("/health")
def health() -> dict[str, Any]:
    """Health check for runtime availability. Returns 200 when registry and stores are loaded."""
    return {"status": "ok", "mode": "build"}


@app.post("/jobs")
def submit_job(job: dict[str, Any] = Body(...)) -> dict[str, Any]:
    res = _components().engine.submit_job(job)
    return {"job": res.job}


@app.get("/jobs/{job_id}")
def get_job(job_id: str) -> dict[str, Any]:
    job = _components().engine.get_job(job_id)
    return {"job": job}


@app.post("/jobs/{job_id}/run")
def run_job(job_id: str) -> dict[str, Any]:
    res = _components().engine.run_job(job_id)
    return {"job": res.job}


@app.post("/jobs/{job_id}/stop")
def stop_job(job_id: str) -> dict[str, Any]:
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
    res = _components().evaluator.submit(evaluation)
    return {"evaluation": res.evaluation, "job": res.job}

