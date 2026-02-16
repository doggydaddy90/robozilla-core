"""Registry document loader (YAML/JSON -> dict).

The runtime registry is loaded from the repo at startup. It is treated as
configuration, not state: state lives in the DB-backed stores.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

from errors import PolicyViolationError

REPO_SKILL_CONTRACTS_DIR = Path("/repo/skills/contracts")


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
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
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
    """Prefer loading SkillContracts from a mounted repo path if present, else fall back to the bundle path."""
    if REPO_SKILL_CONTRACTS_DIR.exists():
        return REPO_SKILL_CONTRACTS_DIR
    return bundle_dir
