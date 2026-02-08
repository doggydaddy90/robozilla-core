"""JSON Schema validation for RoboZilla canonical documents.

All canonical schemas live in the repo under `schemas/` and are expressed as
YAML but are valid JSON Schema Draft 2020-12 documents.

This module is intentionally strict:
- Formats are checked (date-time, uri, uri-reference, email, ...).
- Unknown kinds are rejected.
- Validation errors are surfaced with stable JSON Pointer-like paths.

The runtime must not rely on network access for schema resolution. Some schemas
reference the Draft 2020-12 meta-schema by URL; we pre-register that resource
locally to keep validation deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

from errors import PolicyViolationError, SchemaValidationError, SchemaViolation


_KIND_TO_SCHEMA_FILENAME: dict[str, str] = {
    "OrganizationManifest": "organization_manifest.schema.yaml",
    "AgentDefinition": "agent_definition.schema.yaml",
    "SkillContract": "skill_contract.schema.yaml",
    "MemoryEntry": "memory_entry.schema.yaml",
    "JobContract": "job_contract.schema.yaml",
    "Artifact": "artifact.schema.yaml",
    "Evaluation": "evaluation.schema.yaml",
}


def _load_yaml_object(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as e:  # pragma: no cover - defensive
        raise PolicyViolationError(f"Failed to parse YAML: {path}: {e}") from e
    if not isinstance(raw, dict):
        raise PolicyViolationError(f"Expected YAML object at root: {path}")
    _normalize_regex_patterns(raw)
    return raw


def _escape_json_pointer_token(token: str) -> str:
    # RFC 6901 escaping.
    return token.replace("~", "~0").replace("/", "~1")


def _json_pointer(path: Iterable[Any]) -> str:
    parts: list[str] = []
    for p in path:
        if isinstance(p, int):
            parts.append(str(p))
        else:
            parts.append(_escape_json_pointer_token(str(p)))
    return "/" + "/".join(parts) if parts else "/"


def _normalize_regex_patterns(obj: Any) -> None:
    """Normalize regex `pattern` strings authored with JSON-style escaping.

    Canonical schemas are stored as YAML. Many regex patterns were authored with
    JSON-style escaping (e.g. `\\d`), which YAML single-quoted strings preserve
    literally (resulting in patterns that match a backslash and 'd').

    To keep schema intent stable and validation deterministic, we unescape a
    single layer for keys named exactly `pattern`.
    """
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if k == "pattern" and isinstance(v, str):
                obj[k] = v.replace("\\\\", "\\")
                continue
            _normalize_regex_patterns(v)
        return
    if isinstance(obj, list):
        for item in obj:
            _normalize_regex_patterns(item)
        return


def _schema_contains_ref(obj: Any, ref_value: str) -> bool:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "$ref" and v == ref_value:
                return True
            if _schema_contains_ref(v, ref_value):
                return True
        return False
    if isinstance(obj, list):
        return any(_schema_contains_ref(i, ref_value) for i in obj)
    return False


@dataclass(frozen=True)
class SchemaBundle:
    kind: str
    schema: dict[str, Any]
    source_path: Path


class SchemaValidator:
    """Loads canonical schemas and validates documents by kind."""

    def __init__(self, bundles: dict[str, SchemaBundle], *, strict_formats: bool = True):
        self._bundles = dict(bundles)
        self._strict_formats = strict_formats
        self._validators: dict[str, Any] = {}

    @classmethod
    def load_from_dir(cls, schemas_dir: Path) -> "SchemaValidator":
        schemas_dir = schemas_dir.resolve()
        if not schemas_dir.exists():
            raise PolicyViolationError(f"Schemas directory not found: {schemas_dir}")

        bundles: dict[str, SchemaBundle] = {}
        for kind, filename in _KIND_TO_SCHEMA_FILENAME.items():
            path = (schemas_dir / filename).resolve()
            if not path.exists():
                raise PolicyViolationError(f"Missing required schema file for {kind}: {path}")
            schema = _load_yaml_object(path)
            bundles[kind] = SchemaBundle(kind=kind, schema=schema, source_path=path)

        return cls(bundles)

    def schema_path_for_kind(self, kind: str) -> Path:
        return self._require_bundle(kind).source_path

    def validate(self, kind: str, document: dict[str, Any]) -> None:
        """Validate a document against the canonical schema for its kind."""
        validator = self._get_or_build_validator(kind)

        violations: list[SchemaViolation] = []
        # Use iter_errors so we can return all violations in one response.
        for err in validator.iter_errors(document):
            violations.append(SchemaViolation(path=_json_pointer(err.absolute_path), message=err.message))

        if violations:
            # Stable order: helps tests and makes errors easier to scan.
            violations.sort(key=lambda v: (v.path, v.message))
            raise SchemaValidationError(kind=kind, violations=violations)

    def _require_bundle(self, kind: str) -> SchemaBundle:
        if kind not in self._bundles:
            raise PolicyViolationError(f"Unknown schema kind: {kind}")
        return self._bundles[kind]

    def _get_or_build_validator(self, kind: str) -> Any:
        if kind in self._validators:
            return self._validators[kind]

        bundle = self._require_bundle(kind)
        schema = bundle.schema

        try:
            import jsonschema  # type: ignore
            from jsonschema import Draft202012Validator, FormatChecker  # type: ignore

            # Prevent network access by pre-registering the Draft 2020-12 meta-schema.
            # This is needed because some canonical schemas (SkillContract) reference it.
            registry = None
            try:
                from referencing import Registry, Resource  # type: ignore

                meta = Draft202012Validator.META_SCHEMA
                meta_id = str(meta.get("$id", "https://json-schema.org/draft/2020-12/schema"))
                registry = Registry().with_resource(meta_id, Resource.from_contents(meta))
            except Exception:
                # If the schema contains a remote $ref and we cannot register it locally,
                # fail closed rather than allowing non-deterministic resolution.
                if _schema_contains_ref(schema, "https://json-schema.org/draft/2020-12/schema"):
                    raise PolicyViolationError(
                        "referencing is required to validate schemas that $ref the Draft 2020-12 meta-schema without network access"
                    )

            format_checker = FormatChecker() if self._strict_formats else None

            if registry is not None:
                validator = Draft202012Validator(schema, format_checker=format_checker, registry=registry)
            else:
                validator = Draft202012Validator(schema, format_checker=format_checker)

            # Ensure the schema itself is sane.
            Draft202012Validator.check_schema(schema)

        except ModuleNotFoundError as e:
            raise PolicyViolationError("Missing dependency: jsonschema (install runtime/core/requirements.txt)") from e
        except Exception as e:
            # jsonschema raises SchemaError for invalid schemas; treat any unexpected
            # validator construction issues as fatal (fail closed).
            raise PolicyViolationError(f"Failed to build schema validator for {kind} from {bundle.source_path}: {e}") from e

        self._validators[kind] = validator
        return validator
