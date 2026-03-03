from __future__ import annotations

import copy
import hashlib
import sys
import unittest
from pathlib import Path
from typing import Any

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from api.roland_interface import RolandInterfaceProviders, build_roland_router
from errors import PolicyViolationError
from security.capabilityEnforcer import CapabilityEnforcer


def _make_job_contract(*, prompt: str = "research semiconductors", valid_intent: bool = True) -> dict[str, Any]:
    digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    if not valid_intent:
        digest = "0" * 64
    return {
        "metadata": {"job_id": "job-1", "org_id": "org-1"},
        "spec": {
            "status": {"state": "running"},
            "intent_envelope": {
                "original_prompt": prompt,
                "intent_hash": digest,
                "allowed_domains": ["*.example.com", "example.com"],
                "allowed_scopes": ["research", "external_research", "runtime"],
                "created_at": "2026-03-02T00:00:00Z",
            },
            "permissions_snapshot": {
                "skills": {
                    "allowed_skill_ids": ["roland_interface"],
                    "allowed_skill_categories": [],
                },
                "mcp": {"allowed": []},
            },
            "invariants": {"no_side_effects_without_active_job_contract": True},
        },
    }


class _MockProviders:
    def __init__(self) -> None:
        self.rag_response: dict[str, Any] = {"satisfied": False}
        self.research_response: dict[str, Any] = {"candidate_document": {"summary": "ok"}}
        self.scarcity: dict[str, Any] = {"openai": 0.2}
        self.policy: dict[str, Any] | None = {"metadata": {"org_id": "org-1"}, "spec": {"flo_routing": {"enabled": True}}}

        self.rag_calls = 0
        self.research_calls = 0
        self.research_tiers: list[str] = []
        self.policy_calls = 0

    def rag_first_lookup(self, **kwargs) -> dict[str, Any]:  # type: ignore[no-untyped-def]
        self.rag_calls += 1
        return copy.deepcopy(self.rag_response)

    def research_executor(self, **kwargs) -> dict[str, Any]:  # type: ignore[no-untyped-def]
        self.research_calls += 1
        self.research_tiers.append(str(kwargs.get("tier", "")))
        return copy.deepcopy(self.research_response)

    def scarcity_index(self) -> dict[str, Any]:
        return copy.deepcopy(self.scarcity)

    def org_policy(self, _org_id: str) -> dict[str, Any] | None:
        self.policy_calls += 1
        return copy.deepcopy(self.policy)

    def health(self) -> dict[str, Any]:
        return {"status": "ok", "component": "roland", "mode": "modular"}


class RolandInterfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mock = _MockProviders()
        providers = RolandInterfaceProviders(
            capability_enforcer=CapabilityEnforcer(audit_log=None),
            rag_first_lookup=self.mock.rag_first_lookup,
            research_executor=self.mock.research_executor,
            scarcity_index=self.mock.scarcity_index,
            org_policy=self.mock.org_policy,
            health=self.mock.health,
        )
        self.router = build_roland_router(providers=providers)

    def test_missing_job_contract_denied(self) -> None:
        payload = {"query": "market outlook", "tier": "high", "org_id": "org-1"}
        with self.assertRaises(PolicyViolationError):
            _invoke(self.router, "/roland/query", payload)

    def test_invalid_intent_denied(self) -> None:
        payload = {
            "query": "market outlook",
            "tier": "high",
            "org_id": "org-1",
            "job_contract": _make_job_contract(valid_intent=False),
        }
        with self.assertRaises(PolicyViolationError):
            _invoke(self.router, "/roland/query", payload)

    def test_economic_deep_disabled_fallback_to_high(self) -> None:
        self.mock.scarcity = {"openai": 0.95}
        payload = {
            "query": "deep research request",
            "tier": "deep",
            "org_id": "org-1",
            "job_contract": _make_job_contract(),
        }
        out = _invoke(self.router, "/roland/research", payload)
        self.assertEqual(out["requested_tier"], "deep")
        self.assertEqual(out["effective_tier"], "high")
        self.assertEqual(out["fallback_reason"], "deep_disabled_by_economic_policy")
        self.assertTrue(out["research_triggered"])
        self.assertEqual(self.mock.research_tiers[-1], "high")

    def test_rag_first_satisfied_no_research_triggered(self) -> None:
        self.mock.rag_response = {"satisfied": True, "document_id": "doc-1", "confidence_score": 0.94}
        payload = {
            "query": "already indexed topic",
            "tier": "fast",
            "org_id": "org-1",
            "job_contract": _make_job_contract(),
        }
        out = _invoke(self.router, "/roland/query", payload)
        self.assertTrue(out["rag_first_satisfied"])
        self.assertFalse(out["research_triggered"])
        self.assertEqual(self.mock.research_calls, 0)
        self.assertEqual(out["result"]["document_id"], "doc-1")

    def test_valid_deep_research_call(self) -> None:
        self.mock.scarcity = {"openai": 0.1, "perplexity": 0.25}
        self.mock.rag_response = {"satisfied": False}
        payload = {
            "query": "emerging chip export policy",
            "tier": "deep",
            "org_id": "org-1",
            "job_contract": _make_job_contract(),
        }
        out = _invoke(self.router, "/roland/research", payload)
        self.assertFalse(out["rag_first_satisfied"])
        self.assertTrue(out["research_triggered"])
        self.assertEqual(out["effective_tier"], "deep")
        self.assertEqual(self.mock.research_calls, 1)
        self.assertEqual(self.mock.research_tiers[-1], "deep")


def _invoke(router: Any, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    for route in getattr(router, "routes", []):
        if getattr(route, "path", None) != path:
            continue
        endpoint = getattr(route, "endpoint", None)
        if not callable(endpoint):
            continue
        result = endpoint(payload) if payload is not None else endpoint()
        if not isinstance(result, dict):
            raise AssertionError(f"Route {path} returned non-dict payload")
        return result
    raise AssertionError(f"Route {path} not found")


if __name__ == "__main__":
    unittest.main()
