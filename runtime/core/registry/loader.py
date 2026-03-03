"""Registry document loader (YAML/JSON -> dict).

The runtime registry is loaded from the repo at startup. It is treated as
configuration, not state: state lives in the DB-backed stores.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

from errors import PolicyViolationError
from security.pathGuard import resolve_path, safeRead

SKILL_CONTRACTS_DIR_ENV = "ROBOZILLA_SKILL_CONTRACTS_DIR"


@dataclass(frozen=True)
class LoadedDocument:
    path: Path
    data: dict[str, Any]

    @property
    def kind(self) -> str | None:
        k = self.data.get("kind")
        return k if isinstance(k, str) else None


def load_yaml_document(path: Path) -> LoadedDocument:
    try:
        data = yaml.safe_load(safeRead(path))
    except Exception as e:  # pragma: no cover - defensive
        raise PolicyViolationError(f"Failed to parse YAML: {path}: {e}") from e
    if not isinstance(data, dict):
        raise PolicyViolationError(f"Invalid YAML root object in {path} (expected object)")
    return LoadedDocument(path=path, data=data)


def iter_yaml_files(root: Path) -> Iterable[Path]:
    if not root.exists():
        return []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in (".yaml", ".yml"):
            continue
        yield p


def select_skill_contracts_dir(bundle_dir: Path) -> Path:
    """Load SkillContracts from env override (if set) else from the configured bundle dir."""
    override = os.environ.get(SKILL_CONTRACTS_DIR_ENV, "").strip()
    if override:
        resolved = resolve_path(Path(override), operation="registry.skill_contracts_dir", require_exists=False)
        if resolved.exists():
            return resolved
    return resolve_path(bundle_dir, operation="registry.skill_contracts_dir", require_exists=False)
