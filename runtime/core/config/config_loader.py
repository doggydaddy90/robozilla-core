"""Bootstrap config loader that produces one immutable config object."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from config.settings import LimitsConfig, RuntimeConfig, default_config_paths, load_limits_config, load_runtime_config
from errors import PolicyViolationError


@dataclass(frozen=True)
class KernelConfig:
    runtime: RuntimeConfig
    limits: LimitsConfig
    runtime_config_path: Path
    logging_config_path: Path
    limits_config_path: Path


class ConfigLoader:
    """Environment + YAML config bootstrap."""

    def __init__(self, *, environ: dict[str, str] | None = None):
        self._environ = dict(environ) if environ is not None else dict(os.environ)

    def load(self) -> KernelConfig:
        default_runtime, default_logging, default_limits = default_config_paths()
        runtime_cfg_path = self._env_path("ROBOZILLA_RUNTIME_CONFIG") or default_runtime
        logging_cfg_path = self._env_path("ROBOZILLA_LOGGING_CONFIG") or default_logging
        limits_cfg_path = self._env_path("ROBOZILLA_LIMITS_CONFIG") or default_limits

        runtime = load_runtime_config(runtime_cfg_path)
        limits = load_limits_config(limits_cfg_path)
        self._validate(runtime=runtime, limits=limits)
        return KernelConfig(
            runtime=runtime,
            limits=limits,
            runtime_config_path=runtime_cfg_path,
            logging_config_path=logging_cfg_path,
            limits_config_path=limits_cfg_path,
        )

    def _env_path(self, name: str) -> Path | None:
        value = self._environ.get(name)
        if not value:
            return None
        return Path(value)

    def _validate(self, *, runtime: RuntimeConfig, limits: LimitsConfig) -> None:
        if runtime.service.port <= 0 or runtime.service.port > 65535:
            raise PolicyViolationError("Runtime service.port must be within 1..65535")
        if runtime.storage.driver.strip().lower() != "sqlite":
            raise PolicyViolationError("Runtime storage.driver must be sqlite in build mode")
        if limits.max_iterations_upper_bound <= 0:
            raise PolicyViolationError("limits.max_iterations_upper_bound must be > 0")
        if limits.max_runtime_seconds_upper_bound <= 0:
            raise PolicyViolationError("limits.max_runtime_seconds_upper_bound must be > 0")
        if limits.max_expires_in_seconds_upper_bound <= 0:
            raise PolicyViolationError("limits.max_expires_in_seconds_upper_bound must be > 0")

