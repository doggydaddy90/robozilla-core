"""Roland isolation helpers for strict-mode routing and startup checks."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

from errors import PolicyViolationError
from security.pathGuard import get_project_root, resolve_path

_STRICT_MODE_ENV = "ROLAND_STRICT_MODE"


def parse_env_bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise PolicyViolationError(f"Invalid boolean value for {_STRICT_MODE_ENV}: {value}")


def is_roland_strict_mode_enabled(environ: Mapping[str, str] | None = None) -> bool:
    env = environ if environ is not None else os.environ
    return parse_env_bool(env.get(_STRICT_MODE_ENV), default=True)


def is_mutation_method(method: str) -> bool:
    return str(method).strip().upper() in {"POST", "PUT", "PATCH", "DELETE"}


def mutation_route_allowed(*, path: str, method: str, strict_mode: bool) -> bool:
    if not strict_mode:
        return True
    if not is_mutation_method(method):
        return True
    return str(path).startswith("/roland/")


def enforce_route_isolation(*, path: str, method: str, strict_mode: bool) -> None:
    if mutation_route_allowed(path=path, method=method, strict_mode=strict_mode):
        return
    raise PolicyViolationError(f"Mutation endpoint disabled by ROLAND_STRICT_MODE: {method.upper()} {path}")


def run_startup_isolation_check(
    *,
    project_root: Path | str,
    required_paths: list[Path | str],
    strict_mode: bool,
    audit_log: Any | None = None,
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    if not root.exists() or not root.is_dir():
        raise PolicyViolationError(f"Invalid PROJECT_ROOT: {root}")
    if _is_drive_root(root):
        raise PolicyViolationError(f"Drive-root PROJECT_ROOT is forbidden: {root}")

    configured_root = get_project_root().resolve()
    if strict_mode and configured_root != root:
        raise PolicyViolationError(
            f"PROJECT_ROOT mismatch under ROLAND_STRICT_MODE: configured={configured_root}, expected={root}"
        )

    checked: list[str] = []
    for path in required_paths:
        resolved = resolve_path(path, operation="roland.isolation_check", require_exists=False)
        checked.append(str(resolved))

    details = {
        "strict_mode": strict_mode,
        "project_root": str(root),
        "checked_paths": checked,
        "checked_count": len(checked),
    }
    if audit_log is not None:
        audit_log.append(
            actor="runtime.core.api.main",
            action="roland.isolation_check",
            target=str(root),
            details=details,
        )
    return details


def _is_drive_root(path: Path) -> bool:
    if not path.anchor:
        return False
    return path == Path(path.anchor)
