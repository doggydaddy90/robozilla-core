"""Trust classification for inbound Roland request sources."""

from __future__ import annotations

from typing import Any

from errors import PolicyViolationError

_INTERNAL_SOURCE_TYPES = {"internal_api", "runtime_internal", "system_call"}
_STRUCTURED_EXTERNAL_TYPES = {"exa_api", "search_api", "structured_external_api"}
_UNSTRUCTURED_HINTS = {"scraped_html", "web_content", "reddit_text", "user_prompt", "plain_text"}


def classify_trust(*, source: dict[str, Any]) -> dict[str, str]:
    if not isinstance(source, dict):
        raise PolicyViolationError("source must be an object")

    source_type = str(source.get("source", "")).strip().lower()
    content_type = str(source.get("content_type", "")).strip().lower()
    typed = bool(source.get("typed", False))
    schema_bound = bool(source.get("schema_bound", False))
    signed = bool(source.get("signed", False))

    if source_type in _INTERNAL_SOURCE_TYPES and typed and schema_bound and signed:
        return {
            "trust_level": "internal_system",
            "source": source_type or "internal_api",
            "reason": "typed+schema-bound+signed internal call",
        }

    is_structured_external = (
        source_type in _STRUCTURED_EXTERNAL_TYPES
        or bool(source.get("structured", False))
        or content_type in {"application/json", "json"}
    )
    if is_structured_external and source_type not in _UNSTRUCTURED_HINTS:
        return {
            "trust_level": "structured_external",
            "source": source_type or "external_json",
            "reason": "structured external payload",
        }

    return {
        "trust_level": "unstructured_external",
        "source": source_type or "unstructured_input",
        "reason": "free-form or scraped content",
    }

