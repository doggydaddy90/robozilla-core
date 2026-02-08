"""Configuration loader for the core runtime.

Rules:
- Fail closed when config is missing or invalid.
- All relative paths in runtime.yaml are resolved relative to runtime.yaml's directory.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from errors import PolicyViolationError


@dataclass(frozen=True)
class ServiceConfig:
    host: str
    port: int


@dataclass(frozen=True)
class RegistryConfig:
    schemas_dir: Path
    orgs_dir: Path
    agent_definitions_dir: Path
    skill_contracts_dir: Path

    @property
    def repo_root(self) -> Path:
        # orgs_dir is expected to be at <repo_root>/orgs
        return self.orgs_dir.parent


@dataclass(frozen=True)
class StorageConfig:
    driver: str
    sqlite_path: Path


@dataclass(frozen=True)
class SchedulerConfig:
    enabled: bool
    poll_interval_seconds: int


@dataclass(frozen=True)
class RuntimeFlags:
    role: str  # dev|compute|vps
    strict_validation: bool
    fail_closed: bool


@dataclass(frozen=True)
class RuntimeConfig:
    flags: RuntimeFlags
    service: ServiceConfig
    registry: RegistryConfig
    storage: StorageConfig
    scheduler: SchedulerConfig
    config_dir: Path


@dataclass(frozen=True)
class LimitsConfig:
    max_iterations_upper_bound: int
    max_runtime_seconds_upper_bound: int
    max_cost_upper_bound_currency: str
    max_cost_upper_bound: float
    max_expires_in_seconds_upper_bound: int
    require_known_org: bool


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise PolicyViolationError(f"Missing required config file: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise PolicyViolationError(f"Invalid YAML root object in config file: {path}")
    return data


def _resolve_path(base_dir: Path, raw: str) -> Path:
    p = Path(raw)
    if p.is_absolute():
        return p
    return (base_dir / p).resolve()


def load_runtime_config(runtime_config_path: Path) -> RuntimeConfig:
    cfg_dir = runtime_config_path.parent.resolve()
    raw = _load_yaml(runtime_config_path)

    runtime_raw = raw.get("runtime", {})
    service_raw = raw.get("service", {})
    registry_raw = raw.get("registry", {})
    storage_raw = raw.get("storage", {})
    scheduler_raw = raw.get("scheduler", {})

    flags = RuntimeFlags(
        role=str(runtime_raw.get("role", "dev")),
        strict_validation=bool(runtime_raw.get("strict_validation", True)),
        fail_closed=bool(runtime_raw.get("fail_closed", True)),
    )

    service = ServiceConfig(
        host=str(service_raw.get("host", "0.0.0.0")),
        port=int(service_raw.get("port", 8080)),
    )

    registry = RegistryConfig(
        schemas_dir=_resolve_path(cfg_dir, str(registry_raw.get("schemas_dir", "../../../schemas"))),
        orgs_dir=_resolve_path(cfg_dir, str(registry_raw.get("orgs_dir", "../../../orgs"))),
        agent_definitions_dir=_resolve_path(cfg_dir, str(registry_raw.get("agent_definitions_dir", "../../../agents/definitions"))),
        skill_contracts_dir=_resolve_path(cfg_dir, str(registry_raw.get("skill_contracts_dir", "../../../skills/contracts"))),
    )

    sqlite_path = _resolve_path(cfg_dir, str(storage_raw.get("sqlite", {}).get("path", "../state/robozilla_core.sqlite")))
    storage = StorageConfig(driver=str(storage_raw.get("driver", "sqlite")), sqlite_path=sqlite_path)

    scheduler = SchedulerConfig(
        enabled=bool(scheduler_raw.get("enabled", False)),
        poll_interval_seconds=int(scheduler_raw.get("poll_interval_seconds", 10)),
    )

    return RuntimeConfig(flags=flags, service=service, registry=registry, storage=storage, scheduler=scheduler, config_dir=cfg_dir)


def load_limits_config(limits_path: Path) -> LimitsConfig:
    raw = _load_yaml(limits_path)

    job = raw.get("job_contract", {})
    max_cost = job.get("max_cost_upper_bound", {})
    registry = raw.get("registry", {})

    return LimitsConfig(
        max_iterations_upper_bound=int(job.get("max_iterations_upper_bound", 500)),
        max_runtime_seconds_upper_bound=int(job.get("max_runtime_seconds_upper_bound", 86400)),
        max_cost_upper_bound_currency=str(max_cost.get("currency", "USD")),
        max_cost_upper_bound=float(max_cost.get("max_cost", 100.0)),
        max_expires_in_seconds_upper_bound=int(job.get("max_expires_in_seconds_upper_bound", 604800)),
        require_known_org=bool(registry.get("require_known_org", True)),
    )


def default_config_paths() -> tuple[Path, Path, Path]:
    # Default to paths relative to the runtime working directory (runtime/core).
    runtime_path = Path.cwd() / "config" / "runtime.yaml"
    logging_path = Path.cwd() / "config" / "logging.yaml"
    limits_path = Path.cwd() / "config" / "limits.yaml"
    return runtime_path, logging_path, limits_path

