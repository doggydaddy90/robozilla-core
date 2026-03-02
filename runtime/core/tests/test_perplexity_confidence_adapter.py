from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path
from typing import Any

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from errors import PolicyViolationError
from orchestration.perplexity_confidence_adapter import (
    PERPLEXITY_RESEARCH_TOOL,
    PerplexityConfidenceAdapter,
)
from security.capabilityEnforcer import CapabilityEnforcer


class _AuditSink:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def append(self, *, actor: str, action: str, target: str, details=None) -> None:  # type: ignore[no-untyped-def]
        self.rows.append({"actor": actor, "action": action, "target": target, "details": details or {}})


def _job_contract() -> dict[str, Any]:
    prompt = "confidence oracle evaluation"
    return {
        "metadata": {"job_id": "job-oracle-1"},
        "spec": {
            "status": {"state": "running"},
            "invariants": {"no_side_effects_without_active_job_contract": True},
            "intent_envelope": {
                "original_prompt": prompt,
                "intent_hash": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                "allowed_domains": ["reuters.com", "nih.gov"],
                "allowed_scopes": ["external_research", "execute"],
                "created_at": "2026-03-02T00:00:00Z",
            },
            "permissions_snapshot": {
                "skills": {
                    "allowed_skill_ids": ["perplexity_confidence_adapter"],
                    "allowed_skill_categories": ["research"],
                },
                "mcp": {
                    "allowed": [
                        {
                            "mcp_id": PERPLEXITY_RESEARCH_TOOL,
                            "ref": "mcp://perplexity",
                            "allowed_scopes": ["execute"],
                        }
                    ]
                },
            },
        },
    }


def _skill_contract() -> dict[str, Any]:
    return {"spec": {"classification": {"category_id": "research"}}}


def _candidate_document() -> dict[str, Any]:
    return {
        "query": "confidence oracle evaluation",
        "scores": {"authority": 0.9},
        "candidate_document": {"citations": ["https://www.reuters.com", "https://www.nih.gov"]},
    }


class PerplexityConfidenceAdapterTests(unittest.TestCase):
    def _make_adapter(
        self,
        *,
        tool_response: dict[str, Any] | str | None = None,
        fail: bool = False,
    ) -> tuple[PerplexityConfidenceAdapter, _AuditSink]:
        audit = _AuditSink()
        response = tool_response or {
            "confidence_score": 0.88,
            "authority_score": 0.91,
            "contradiction_flag": False,
        }

        def _executor(tool_id: str, payload: dict[str, Any]) -> dict[str, Any] | str:
            self.assertEqual(tool_id, PERPLEXITY_RESEARCH_TOOL)
            self.assertIn("candidate_document", payload)
            if fail:
                raise RuntimeError("perplexity unavailable")
            return response

        adapter = PerplexityConfidenceAdapter(
            capability_enforcer=CapabilityEnforcer(audit_log=audit),
            tool_executor=_executor,
        )
        return adapter, audit

    def test_valid_response(self) -> None:
        adapter, audit = self._make_adapter(
            tool_response={
                "confidence_score": 0.83,
                "authority_score": 0.79,
                "contradiction_flag": False,
            }
        )

        out = adapter.score(
            candidate_document=_candidate_document(),
            job_contract=_job_contract(),
            skill_contract=_skill_contract(),
        )

        self.assertEqual(
            out,
            {
                "confidence_score": 0.83,
                "authority_score": 0.79,
                "contradiction_flag": False,
            },
        )
        self.assertEqual(sum(1 for row in audit.rows if row["action"] == "capability.allowed"), 1)

    def test_missing_key(self) -> None:
        adapter, _ = self._make_adapter(
            tool_response={
                "confidence_score": 0.83,
                "authority_score": 0.79,
            }
        )
        with self.assertRaises(PolicyViolationError):
            adapter.score(
                candidate_document=_candidate_document(),
                job_contract=_job_contract(),
                skill_contract=_skill_contract(),
            )

    def test_out_of_range_score(self) -> None:
        adapter, _ = self._make_adapter(
            tool_response={
                "confidence_score": 1.2,
                "authority_score": 0.79,
                "contradiction_flag": False,
            }
        )
        with self.assertRaises(PolicyViolationError):
            adapter.score(
                candidate_document=_candidate_document(),
                job_contract=_job_contract(),
                skill_contract=_skill_contract(),
            )

    def test_malformed_json(self) -> None:
        adapter, _ = self._make_adapter(tool_response="{not valid json")
        with self.assertRaises(PolicyViolationError):
            adapter.score(
                candidate_document=_candidate_document(),
                job_contract=_job_contract(),
                skill_contract=_skill_contract(),
            )

    def test_perplexity_tool_failure(self) -> None:
        adapter, _ = self._make_adapter(fail=True)
        with self.assertRaises(PolicyViolationError):
            adapter.score(
                candidate_document=_candidate_document(),
                job_contract=_job_contract(),
                skill_contract=_skill_contract(),
            )


if __name__ == "__main__":
    unittest.main()
