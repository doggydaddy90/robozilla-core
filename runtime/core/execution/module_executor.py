"""Kernel execution boundary for module invocations.

This abstraction keeps module execution behind a narrow interface so callers
cannot bypass kernel-owned enforcement gates.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import subprocess
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from errors import PolicyViolationError

try:  # pragma: no cover - platform dependent
    import resource as _resource
except Exception:  # pragma: no cover - platform dependent
    _resource = None

ModuleRunner = Callable[[str, dict[str, Any]], Any]
ModuleCommandResolver = Callable[[str], Sequence[str] | None]

_SECRET_ENV_MARKERS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "AUTH",
    "KEY",
    "CREDENTIAL",
    "COOKIE",
    "SESSION",
)
_NETWORK_ENV_BLOCKLIST = {
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
}
_DEFAULT_ENV_WHITELIST = (
    "PATH",
    "SystemRoot",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "HOME",
    "USERPROFILE",
)
_DEFAULT_MAX_IO_BYTES = 1_000_000
_DEFAULT_MAX_REQUEST_BYTES = 1_000_000
_DEFAULT_TIMEOUT_SECONDS = 30.0
_DEFAULT_MEMORY_SOFT_LIMIT_BYTES = 512 * 1024 * 1024
_DEFAULT_CPU_TIME_LIMIT_SECONDS = 15
_SHELL_EXECUTABLES = {"sh", "bash", "zsh", "cmd", "powershell", "pwsh"}


class BaseModuleExecutor(ABC):
    """Execution interface used by orchestration/runtime modules."""

    @abstractmethod
    def execute_module(self, module_name: str, payload: dict[str, Any]) -> Any:
        """Execute one module with a structured payload."""


class InProcessModuleExecutor(BaseModuleExecutor):
    """Kernel in-process execution adapter (legacy/non-isolated path)."""

    def __init__(self, *, module_runner: ModuleRunner):
        if not callable(module_runner):
            raise TypeError("module_runner must be callable")
        self._module_runner = module_runner

    def execute_module(self, module_name: str, payload: dict[str, Any]) -> Any:
        return self._module_runner(module_name, payload)


class SubprocessModuleExecutor(BaseModuleExecutor):
    """Isolated subprocess execution boundary with strict JSON IPC."""

    def __init__(
        self,
        *,
        command_resolver: ModuleCommandResolver | Mapping[str, Sequence[str]],
        sandbox_dir: Path | str,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        max_io_bytes: int = _DEFAULT_MAX_IO_BYTES,
        max_request_bytes: int = _DEFAULT_MAX_REQUEST_BYTES,
        env_whitelist: Iterable[str] = _DEFAULT_ENV_WHITELIST,
        memory_soft_limit_bytes: int = _DEFAULT_MEMORY_SOFT_LIMIT_BYTES,
        cpu_time_limit_seconds: int = _DEFAULT_CPU_TIME_LIMIT_SECONDS,
        allow_unsupported_platform: bool = False,
        logger: logging.Logger | None = None,
    ):
        self._logger = logger or logging.getLogger(__name__)
        self._resolver = self._normalize_resolver(command_resolver)
        self._sandbox_dir = Path(sandbox_dir).resolve()
        self._timeout_seconds = float(timeout_seconds)
        self._max_io_bytes = int(max_io_bytes)
        self._max_request_bytes = int(max_request_bytes)
        self._env_whitelist = tuple(str(x) for x in env_whitelist)
        self._memory_soft_limit_bytes = int(memory_soft_limit_bytes)
        self._cpu_time_limit_seconds = int(cpu_time_limit_seconds)
        self._allow_unsupported_platform = bool(allow_unsupported_platform)
        self._resource_supported = (_resource is not None) and (os.name != "nt")
        if not self._resource_supported:
            self._logger.warning(
                "subprocess_resource_limits_unsupported",
                extra={"event": "subprocess_resource_limits_unsupported", "platform": os.name},
            )

    def execute_module(self, module_name: str, payload: dict[str, Any]) -> Any:
        if not self._resource_supported and not self._allow_unsupported_platform:
            raise PolicyViolationError("Subprocess execution blocked: resource limits unsupported on this platform")
        if not isinstance(module_name, str) or not module_name.strip():
            raise PolicyViolationError("module_name must be a non-empty string")
        if not isinstance(payload, dict):
            raise PolicyViolationError("payload must be an object")

        command = self._resolve_command(module_name)
        self._sandbox_dir.mkdir(parents=True, exist_ok=True)
        request = {"module": module_name.strip(), "payload": copy.deepcopy(payload)}
        request_bytes = _encode_request_json(request)
        if len(request_bytes) > self._max_request_bytes:
            raise PolicyViolationError("module execution request exceeded max_request_bytes")

        env = self._build_clean_env()
        popen_kwargs: dict[str, Any] = {
            "args": list(command),
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "cwd": str(self._sandbox_dir),
            "env": env,
            "shell": False,
        }
        preexec_fn = self._build_preexec_fn()
        if preexec_fn is not None:
            popen_kwargs["preexec_fn"] = preexec_fn

        proc = subprocess.Popen(**popen_kwargs)
        try:
            stdout_raw, stderr_raw = proc.communicate(input=request_bytes, timeout=self._timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            proc.kill()
            _stdout_kill, stderr_kill = proc.communicate()
            stderr_preview = _decode_bytes(stderr_kill, max_bytes=2048)
            raise PolicyViolationError(
                f"Module '{module_name}' timed out after {self._timeout_seconds:.3f}s; process killed",
                details={"stderr_preview": stderr_preview},
            ) from exc

        if len(stdout_raw) > self._max_io_bytes:
            raise PolicyViolationError(f"Module '{module_name}' stdout exceeded max_io_bytes")
        if len(stderr_raw) > self._max_io_bytes:
            raise PolicyViolationError(f"Module '{module_name}' stderr exceeded max_io_bytes")

        if proc.returncode != 0:
            stderr_preview = _decode_bytes(stderr_raw, max_bytes=2048)
            raise PolicyViolationError(
                f"Module '{module_name}' subprocess failed (exit={proc.returncode})",
                details={"stderr_preview": stderr_preview},
            )

        response_obj = _decode_response_json(stdout_raw)
        _validate_response_schema(response_obj, module_name=module_name)
        return copy.deepcopy(response_obj["result"])

    def _normalize_resolver(
        self, resolver: ModuleCommandResolver | Mapping[str, Sequence[str]]
    ) -> ModuleCommandResolver:
        if isinstance(resolver, Mapping):
            command_map = {str(k): tuple(str(v) for v in vals) for k, vals in resolver.items()}

            def _map_resolver(module_name: str) -> Sequence[str] | None:
                return command_map.get(module_name)

            return _map_resolver
        if callable(resolver):
            return resolver
        raise PolicyViolationError("command_resolver must be a mapping or callable")

    def _resolve_command(self, module_name: str) -> tuple[str, ...]:
        resolved = self._resolver(module_name)
        if resolved is None:
            raise PolicyViolationError(f"No subprocess command configured for module '{module_name}'")
        command = tuple(str(part) for part in resolved)
        if not command or not command[0].strip():
            raise PolicyViolationError(f"Invalid subprocess command for module '{module_name}'")
        executable = Path(command[0]).name.lower()
        if executable in _SHELL_EXECUTABLES:
            raise PolicyViolationError("Arbitrary shell invocation is forbidden for module execution")
        return _harden_python_command(command)

    def _build_clean_env(self) -> dict[str, str]:
        env: dict[str, str] = {}
        for key in self._env_whitelist:
            if key in os.environ:
                env[key] = os.environ[key]
        for key in list(env.keys()):
            upper = key.upper()
            if upper in _NETWORK_ENV_BLOCKLIST or _looks_secret_env_key(upper):
                env.pop(key, None)
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        env.pop("VIRTUAL_ENV", None)
        env["PYTHONNOUSERSITE"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["UNUM_SUBPROCESS_NETWORK_DISABLED"] = "1"
        return env

    def _build_preexec_fn(self) -> Callable[[], None] | None:
        if not self._resource_supported:
            return None

        def _apply_limits() -> None:
            assert _resource is not None
            if hasattr(_resource, "RLIMIT_AS") and self._memory_soft_limit_bytes > 0:
                _resource.setrlimit(
                    _resource.RLIMIT_AS,
                    (self._memory_soft_limit_bytes, self._memory_soft_limit_bytes),
                )
            if hasattr(_resource, "RLIMIT_CPU") and self._cpu_time_limit_seconds > 0:
                _resource.setrlimit(
                    _resource.RLIMIT_CPU,
                    (self._cpu_time_limit_seconds, self._cpu_time_limit_seconds),
                )

        return _apply_limits


class ContainerModuleExecutor(BaseModuleExecutor):
    """Future container-based execution boundary (intentionally not implemented)."""

    def execute_module(self, module_name: str, payload: dict[str, Any]) -> Any:
        raise NotImplementedError("Container module executor is not implemented in build mode")


def _harden_python_command(command: tuple[str, ...]) -> tuple[str, ...]:
    executable = Path(command[0]).name.lower()
    is_python = executable.startswith("python") or Path(command[0]).resolve() == Path(sys.executable).resolve()
    if not is_python:
        return command
    flags = set(command[1:])
    if "-I" in flags:
        return command
    # Isolated mode drops user/site/module-path inheritance.
    return (command[0], "-I", *command[1:])


def _looks_secret_env_key(name_upper: str) -> bool:
    return any(marker in name_upper for marker in _SECRET_ENV_MARKERS)


def _encode_request_json(request: dict[str, Any]) -> bytes:
    try:
        return json.dumps(request, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PolicyViolationError("module execution payload is not JSON serializable") from exc


def _decode_response_json(stdout_raw: bytes) -> dict[str, Any]:
    text = _decode_bytes(stdout_raw, max_bytes=_DEFAULT_MAX_IO_BYTES)
    if not text.strip():
        raise PolicyViolationError("module returned empty stdout")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PolicyViolationError("module returned non-JSON stdout") from exc
    if not isinstance(parsed, dict):
        raise PolicyViolationError("module output must be a JSON object")
    return parsed


def _validate_response_schema(response_obj: dict[str, Any], *, module_name: str) -> None:
    keys = set(response_obj.keys())
    expected = {"status", "result"}
    if keys != expected:
        raise PolicyViolationError(
            f"module '{module_name}' output schema violation (expected keys: {sorted(expected)})"
        )
    if response_obj.get("status") != "ok":
        raise PolicyViolationError(f"module '{module_name}' reported non-ok status")
    if not isinstance(response_obj.get("result"), dict):
        raise PolicyViolationError(f"module '{module_name}' output 'result' must be an object")


def _decode_bytes(raw: bytes, *, max_bytes: int) -> str:
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    return raw.decode("utf-8", errors="replace")
