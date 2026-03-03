"""Perplexity confidence adapter.

Uses perplexity_research_tool strictly as a confidence scoring oracle.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from execution.module_executor import BaseModuleExecutor, InProcessModuleExecutor
from errors import PolicyViolationError
from security.capabilityEnforcer import CapabilityEnforcer, CapabilityRequest

PERPLEXITY_RESEARCH_TOOL = "perplexity_research_tool"
EXPECTED_KEYS = {"confidence_score", "authority_score", "contradiction_flag"}

ToolExecutor = Callable[[str, dict[str, Any]], dict[str, Any] | str]


class PerplexityConfidenceAdapter:
    def __init__(
        self,
        *,
        capability_enforcer: CapabilityEnforcer,
        tool_executor: ToolExecutor | None = None,
        module_executor: BaseModuleExecutor | None = None,
        actor: str = "runtime.core.perplexity_confidence_adapter",
        skill_id: str = "perplexity_confidence_adapter",
    ):
        if module_executor is None:
            if not callable(tool_executor):
                raise PolicyViolationError("tool_executor must be callable")
            module_executor = InProcessModuleExecutor(module_runner=tool_executor)
        self._capabilities = capability_enforcer
        self._module_executor = module_executor
        self._actor = actor
        self._skill_id = skill_id

    def score(
        self,
        *,
        candidate_document: dict[str, Any],
        job_contract: dict[str, Any],
        skill_contract: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(candidate_document, dict):
            raise PolicyViolationError("candidate_document must be an object")

        self._capabilities.enforceCapability(
            CapabilityRequest(
                actor=self._actor,
                job_contract=job_contract,
                skill_contract=skill_contract,
                skill_id=self._skill_id,
                requested_side_effects=False,
                requested_channel="mcp",
                requested_mcp_id=PERPLEXITY_RESEARCH_TOOL,
                requested_mcp_scopes=["execute"],
                requested_scope_tags=["external_research"],
            )
        )

        payload = {"candidate_document": candidate_document}
        try:
            raw = self._module_executor.execute_module(PERPLEXITY_RESEARCH_TOOL, payload)
        except Exception as exc:  # pragma: no cover - covered by behavior test
            raise PolicyViolationError("perplexity_research_tool failed") from exc

        response = _coerce_response_object(raw)
        _validate_response(response)
        return response


def _coerce_response_object(raw: dict[str, Any] | str) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PolicyViolationError("Malformed JSON from perplexity_research_tool") from exc
        if not isinstance(parsed, dict):
            raise PolicyViolationError("Perplexity response must be a JSON object")
        return parsed
    raise PolicyViolationError("Perplexity response must be an object")


def _validate_response(response: dict[str, Any]) -> None:
    keys = set(response.keys())
    if keys != EXPECTED_KEYS:
        missing = sorted(EXPECTED_KEYS - keys)
        extra = sorted(keys - EXPECTED_KEYS)
        reason_bits: list[str] = []
        if missing:
            reason_bits.append(f"missing keys: {missing}")
        if extra:
            reason_bits.append(f"unexpected keys: {extra}")
        raise PolicyViolationError("Invalid perplexity response schema (" + ", ".join(reason_bits) + ")")

    confidence = _coerce_score(response.get("confidence_score"), "confidence_score")
    authority = _coerce_score(response.get("authority_score"), "authority_score")
    contradiction = response.get("contradiction_flag")
    if not isinstance(contradiction, bool):
        raise PolicyViolationError("contradiction_flag must be boolean")

    # Preserve deterministic canonical types.
    response["confidence_score"] = confidence
    response["authority_score"] = authority
    response["contradiction_flag"] = contradiction


def _coerce_score(value: Any, field: str) -> float:
    if isinstance(value, bool):
        raise PolicyViolationError(f"{field} must be numeric")
    try:
        score = float(value)
    except (TypeError, ValueError) as exc:
        raise PolicyViolationError(f"{field} must be numeric") from exc
    if score < 0.0 or score > 1.0:
        raise PolicyViolationError(f"{field} must be between 0.0 and 1.0")
    return score
