"""Filesystem boundary enforcement for runtime-core.

All direct runtime file mutations must route through safeWrite()/safeDelete().
All protected reads should route through safeRead().
"""

from __future__ import annotations

import os
import shutil
import threading
from pathlib import Path
from typing import Any, Protocol

from errors import PolicyViolationError
from security.diffEnforcer import PatchApplyResult, applyPatch


class _AuditLogger(Protocol):
    def append(self, *, actor: str, action: str, target: str, details: dict[str, Any] | None = None) -> Any:
        ...


_PROJECT_ROOT = Path(os.environ.get("ROBOZILLA_PROJECT_ROOT", Path.cwd())).resolve()
_PROJECT_ROOT_LOCK = threading.RLock()
_PROJECT_ROOT_FROZEN = False
_AUDIT_LOGGER: _AuditLogger | None = None
_ALLOWED_RECURSIVE_DELETE_DIRS = (Path("runtime/tmp"), Path("runtime/build"))


def _is_drive_root(path: Path) -> bool:
    if not path.anchor:
        return False
    return path == Path(path.anchor)


def _contains_path_traversal(raw: str | Path) -> bool:
    normalized = str(raw).replace("\\", "/")
    parts = [p for p in normalized.split("/") if p]
    return ".." in parts


def _contains_glob(raw: str | Path) -> bool:
    return any(ch in str(raw) for ch in ("*", "?", "[", "]"))


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def set_audit_logger(audit_logger: _AuditLogger | None) -> None:
    global _AUDIT_LOGGER
    _AUDIT_LOGGER = audit_logger


def _audit(*, actor: str, action: str, target: Path | str, details: dict[str, Any] | None = None) -> None:
    if _AUDIT_LOGGER is None:
        return
    try:
        _AUDIT_LOGGER.append(actor=actor, action=action, target=str(target), details=details or {})
    except Exception:
        # Audit failures must never silently permit bypassed enforcement.
        raise


def get_project_root() -> Path:
    with _PROJECT_ROOT_LOCK:
        return _PROJECT_ROOT


def derive_project_root(paths: list[Path | str]) -> Path:
    if not paths:
        raise PolicyViolationError("derive_project_root requires at least one path")
    resolved: list[str] = [str(Path(p).resolve()) for p in paths]
    try:
        common = Path(os.path.commonpath(resolved)).resolve()
    except ValueError as exc:
        raise PolicyViolationError("Cannot derive one project root from paths on different volumes") from exc
    if _is_drive_root(common):
        raise PolicyViolationError(f"Drive-root project roots are not allowed: {common}")
    return common


def set_project_root(project_root: Path | str, *, freeze: bool = False) -> Path:
    global _PROJECT_ROOT, _PROJECT_ROOT_FROZEN
    with _PROJECT_ROOT_LOCK:
        root = Path(project_root).resolve()
        if _PROJECT_ROOT_FROZEN:
            if root != _PROJECT_ROOT:
                raise PolicyViolationError("PROJECT_ROOT is frozen and cannot be changed")
            return _PROJECT_ROOT
        if not root.exists() or not root.is_dir():
            raise PolicyViolationError(f"PROJECT_ROOT must be an existing directory: {root}")
        if _is_drive_root(root):
            raise PolicyViolationError(f"Drive-root PROJECT_ROOT is not allowed: {root}")
        _PROJECT_ROOT = root
        _PROJECT_ROOT_FROZEN = freeze
        return _PROJECT_ROOT


def resolve_path(path: Path | str, *, operation: str, require_exists: bool = False) -> Path:
    raw = str(path)
    if not raw.strip():
        raise PolicyViolationError(f"Empty path is not allowed for operation '{operation}'")
    if _contains_path_traversal(raw):
        raise PolicyViolationError(f"Path traversal is not allowed for operation '{operation}': {path}")

    root = get_project_root()
    candidate = Path(path)
    normalized = (candidate if candidate.is_absolute() else (root / candidate)).resolve(strict=False)

    if _is_drive_root(normalized):
        raise PolicyViolationError(f"Drive-root operations are not allowed for operation '{operation}': {normalized}")
    if not _is_within(normalized, root):
        raise PolicyViolationError(
            f"Path is outside PROJECT_ROOT for operation '{operation}': path={normalized}, project_root={root}"
        )
    if require_exists and not normalized.exists():
        raise PolicyViolationError(f"Path does not exist for operation '{operation}': {normalized}")
    return normalized


def _job_confirmation(job_contract: dict[str, Any] | None, flag_name: str) -> bool:
    if not isinstance(job_contract, dict):
        return False
    spec = job_contract.get("spec")
    if not isinstance(spec, dict):
        return False
    snapshot = spec.get("permissions_snapshot")
    if isinstance(snapshot, dict):
        confirmations = snapshot.get("confirmations")
        if isinstance(confirmations, dict) and bool(confirmations.get(flag_name)):
            return True
    confirmations = spec.get("confirmations")
    if isinstance(confirmations, dict):
        return bool(confirmations.get(flag_name))
    return False


def safeRead(path: Path | str, *, binary: bool = False, actor: str = "runtime.core") -> str | bytes:
    try:
        resolved = resolve_path(path, operation="read", require_exists=True)
        if resolved.is_dir():
            raise PolicyViolationError(f"Cannot read directory path as file: {resolved}")
        mode = "rb" if binary else "r"
        kwargs: dict[str, Any] = {}
        if not binary:
            kwargs["encoding"] = "utf-8"
        with resolved.open(mode, **kwargs) as f:
            return f.read()
    except Exception as exc:
        _audit(
            actor=actor,
            action="attempt.denied",
            target=path,
            details={"operation": "read", "reason": str(exc)},
        )
        raise


def safeWrite(
    *,
    target_path: Path | str,
    diff: str,
    job_contract: dict[str, Any] | None,
    actor: str = "runtime.core",
    dry_run: bool = False,
    confirmation_flag: str = "allow_diff_apply",
) -> PatchApplyResult:
    try:
        resolved = resolve_path(target_path, operation="write", require_exists=False)
        result = applyPatch(
            diff=diff,
            targetFile=resolved,
            jobContract=job_contract,
            dryRun=dry_run,
            confirmationFlag=confirmation_flag,
        )
    except Exception as exc:
        _audit(
            actor=actor,
            action="attempt.denied",
            target=target_path,
            details={"operation": "write", "reason": str(exc)},
        )
        raise

    _audit(
        actor=actor,
        action="fs.write",
        target=resolved,
        details={"dry_run": dry_run, "changed": result.changed, "bytes_written": result.bytes_written},
    )
    return result


def safeDelete(
    *,
    target_path: Path | str,
    job_contract: dict[str, Any] | None,
    actor: str = "runtime.core",
    recursive: bool = False,
    dry_run: bool = False,
    confirmation_flag: str = "allow_delete",
) -> None:
    try:
        if _contains_glob(target_path):
            raise PolicyViolationError(f"Glob-style deletes are forbidden: {target_path}")

        resolved = resolve_path(target_path, operation="delete", require_exists=True)
        root = get_project_root()

        if resolved == root:
            raise PolicyViolationError("Deleting PROJECT_ROOT is forbidden")
        if resolved.parent == root:
            raise PolicyViolationError(f"Root-level deletes are forbidden: {resolved}")
        if _is_drive_root(resolved):
            raise PolicyViolationError(f"Drive-root deletes are forbidden: {resolved}")
        if not _job_confirmation(job_contract, confirmation_flag):
            raise PolicyViolationError(f"JobContract confirmation flag '{confirmation_flag}' is required for deletes")

        if resolved.is_dir() and recursive:
            allowed_roots = [(root / rel).resolve() for rel in _ALLOWED_RECURSIVE_DELETE_DIRS]
            if not any(_is_within(resolved, allowed) for allowed in allowed_roots):
                raise PolicyViolationError(
                    f"Recursive delete is only allowed under runtime/tmp or runtime/build (got {resolved})"
                )
            if not _job_confirmation(job_contract, "allow_recursive_delete"):
                raise PolicyViolationError("JobContract confirmation flag 'allow_recursive_delete' is required for recursive delete")

        _audit(
            actor=actor,
            action="fs.delete",
            target=resolved,
            details={"recursive": recursive, "dry_run": dry_run},
        )
        if dry_run:
            return

        if resolved.is_dir():
            if recursive:
                shutil.rmtree(resolved)
            else:
                resolved.rmdir()
        else:
            resolved.unlink()
    except Exception as exc:
        _audit(
            actor=actor,
            action="attempt.denied",
            target=target_path,
            details={"operation": "delete", "reason": str(exc), "recursive": recursive},
        )
        raise
