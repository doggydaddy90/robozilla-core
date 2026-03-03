from __future__ import annotations

import hashlib
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

CORE_DIR = Path(__file__).resolve().parents[1]
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

from errors import PolicyViolationError
from orchestration.research_router import (
    BOOLEAN_SEARCH_TOOL,
    CHATGPT_WEB_UI_TOOL,
    DEEP,
    EDGAR_SEARCH_TOOL,
    GITHUB_OFFICIAL_TOOL,
    HIGH,
    MULTI_SURFACE_RECON_TOOL,
    OPENAI_PLANNER_TOOL,
    PERPLEXITY_RESEARCH_TOOL,
    RAG_LOOKUP_TOOL,
    REDDIT_SEARCH_TOOL,
    SEARCH_ENGINE_TOOL,
    SEMANTIC_SCHOLAR_TOOL,
    WAYBACK_FRESHNESS_TOOL,
    YOUTUBE_SEARCH_TOOL,
    YOUTUBE_TRANSCRIBE_TOOL,
    ZLIB_SEARCH_TOOL,
    FAST,
    ResearchRouter,
    compute_contextual_authority,
)
from security.capabilityEnforcer import CapabilityEnforcer
from search.zero_result_registry import record_zero_result


ALL_SURFACE_TOOLS = {
    RAG_LOOKUP_TOOL,
    BOOLEAN_SEARCH_TOOL,
    SEARCH_ENGINE_TOOL,
    ZLIB_SEARCH_TOOL,
    REDDIT_SEARCH_TOOL,
    YOUTUBE_SEARCH_TOOL,
    YOUTUBE_TRANSCRIBE_TOOL,
    EDGAR_SEARCH_TOOL,
    SEMANTIC_SCHOLAR_TOOL,
    GITHUB_OFFICIAL_TOOL,
    WAYBACK_FRESHNESS_TOOL,
    CHATGPT_WEB_UI_TOOL,
    MULTI_SURFACE_RECON_TOOL,
    OPENAI_PLANNER_TOOL,
    PERPLEXITY_RESEARCH_TOOL,
}


class _AuditSink:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def append(self, *, actor: str, action: str, target: str, details=None) -> None:  # type: ignore[no-untyped-def]
        self.rows.append({"actor": actor, "action": action, "target": target, "details": details or {}})


def _job_contract(*, allowed_domains: list[str] | None = None, prompt: str = "latest market guidance") -> dict[str, Any]:
    domains = allowed_domains or [
        "reuters.com",
        "sec.gov",
        "nih.gov",
        "github.com",
        "youtube.com",
        "reddit.com",
        "www.reddit.com",
        "semanticscholar.org",
        "web.archive.org",
        "example.org",
    ]
    allowed_mcp = [{"mcp_id": tid, "ref": f"mcp://{tid}", "allowed_scopes": ["execute"]} for tid in sorted(ALL_SURFACE_TOOLS)]
    return {
        "metadata": {"job_id": "job-research-1"},
        "spec": {
            "status": {"state": "running"},
            "invariants": {"no_side_effects_without_active_job_contract": True},
            "intent_envelope": {
                "original_prompt": prompt,
                "intent_hash": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                "allowed_domains": domains,
                "allowed_scopes": ["research", "external_research", "execute"],
                "created_at": "2026-03-02T00:00:00Z",
            },
            "permissions_snapshot": {
                "skills": {
                    "allowed_skill_ids": ["research_router"],
                    "allowed_skill_categories": ["research"],
                },
                "mcp": {"allowed": allowed_mcp},
            },
        },
    }


def _skill_contract() -> dict[str, Any]:
    return {"spec": {"classification": {"category_id": "research"}}}


def _iso_days_ago(days: int) -> str:
    ts = datetime.now(timezone.utc) - timedelta(days=days)
    return ts.isoformat().replace("+00:00", "Z")


def _base_results(url: str, *, alignment: float = 0.9, gain: float = 0.7, anomaly: float = 0.1) -> list[dict[str, Any]]:
    return [
        {
            "url": url,
            "title": "Result",
            "snippet": "Structured evidence snippet.",
            "published_at": _iso_days_ago(2),
            "alignment_score": alignment,
            "informational_gain_score": gain,
            "anomaly_score": anomaly,
        }
    ]


class ResearchRouterTests(unittest.TestCase):
    def _make_router(
        self,
        *,
        per_tool_results: dict[str, list[dict[str, Any]]],
        oracle: dict[str, Any] | None = None,
        zero_result_registry_path: Path | None = None,
    ) -> tuple[ResearchRouter, _AuditSink, list[str]]:
        audit = _AuditSink()
        calls: list[str] = []
        oracle_out = oracle or {
            "confidence_score": 0.9,
            "authority_score": 0.9,
            "contradiction_flag": False,
        }

        def _executor(tool_id: str, payload: dict[str, Any]) -> dict[str, Any]:
            calls.append(tool_id)
            if tool_id == OPENAI_PLANNER_TOOL:
                return {"outline": "planner extraction", "citations": ["https://www.reuters.com/world"]}
            return {"results": per_tool_results.get(tool_id, [])}

        def _score_oracle(candidate_document: dict[str, Any], job_contract: dict[str, Any], skill_contract: dict[str, Any]) -> dict[str, Any]:
            _ = candidate_document, job_contract, skill_contract
            return dict(oracle_out)

        router = ResearchRouter(
            capability_enforcer=CapabilityEnforcer(audit_log=audit),
            tool_executor=_executor,
            score_oracle=_score_oracle,
            skill_id="research_router",
            zero_result_registry_path=zero_result_registry_path,
        )
        return router, audit, calls

    def test_fast_path_skips_deep_logic(self) -> None:
        router, _, calls = self._make_router(
            per_tool_results={
                RAG_LOOKUP_TOOL: _base_results("https://example.org/rag"),
                BOOLEAN_SEARCH_TOOL: _base_results("https://www.reuters.com/markets"),
                SEARCH_ENGINE_TOOL: _base_results("https://www.nih.gov/update"),
            }
        )

        out = router.route(
            query="market update",
            tier=FAST,
            job_contract=_job_contract(),
            skill_contract=_skill_contract(),
        )

        self.assertEqual(out["tier"], FAST)
        self.assertEqual(out["ingestion_mode"], "none")
        self.assertEqual(out["selected_tool"], OPENAI_PLANNER_TOOL)
        self.assertEqual(calls[:3], [RAG_LOOKUP_TOOL, BOOLEAN_SEARCH_TOOL, SEARCH_ENGINE_TOOL])
        self.assertNotIn(CHATGPT_WEB_UI_TOOL, calls)
        self.assertNotIn(MULTI_SURFACE_RECON_TOOL, calls)

    def test_high_path_skips_minority_escalation_tools(self) -> None:
        router, _, calls = self._make_router(
            per_tool_results={
                RAG_LOOKUP_TOOL: _base_results("https://example.org/rag", anomaly=0.2),
                BOOLEAN_SEARCH_TOOL: _base_results("https://www.reuters.com/markets", anomaly=0.2),
                SEARCH_ENGINE_TOOL: _base_results("https://www.nih.gov/update", anomaly=0.2),
                ZLIB_SEARCH_TOOL: _base_results("https://example.org/zlib", anomaly=0.2),
                REDDIT_SEARCH_TOOL: _base_results("https://www.reddit.com/r/test", anomaly=0.2),
                YOUTUBE_SEARCH_TOOL: _base_results("https://www.youtube.com/watch?v=1", anomaly=0.2),
                YOUTUBE_TRANSCRIBE_TOOL: _base_results("https://www.youtube.com/watch?v=1", anomaly=0.2),
                EDGAR_SEARCH_TOOL: _base_results("https://www.sec.gov/ixviewer/doc", anomaly=0.2),
                SEMANTIC_SCHOLAR_TOOL: _base_results("https://www.semanticscholar.org/paper/1", anomaly=0.2),
                GITHUB_OFFICIAL_TOOL: _base_results("https://github.com/org/repo", anomaly=0.2),
                WAYBACK_FRESHNESS_TOOL: _base_results("https://web.archive.org/web/20250101", anomaly=0.2),
            }
        )

        out = router.route(
            query="equity market policy",
            tier=HIGH,
            anomaly_score=0.2,
            job_contract=_job_contract(),
            skill_contract=_skill_contract(),
        )

        self.assertEqual(out["tier"], HIGH)
        self.assertEqual(out["ingestion_mode"], "optional")
        self.assertGreaterEqual(out["compiled_confidence"], 0.8)
        self.assertNotIn(CHATGPT_WEB_UI_TOOL, calls)
        self.assertNotIn(MULTI_SURFACE_RECON_TOOL, calls)

    def test_deep_path_full_stack(self) -> None:
        router, _, calls = self._make_router(
            per_tool_results={tool: _base_results("https://www.reuters.com/world") for tool in ALL_SURFACE_TOOLS}
        )

        out = router.route(
            query="macro regime shift analysis",
            tier=DEEP,
            job_contract=_job_contract(),
            skill_contract=_skill_contract(),
        )

        self.assertEqual(out["tier"], DEEP)
        self.assertEqual(out["ingestion_mode"], "autonomous")
        self.assertIn(CHATGPT_WEB_UI_TOOL, calls)
        self.assertIn(MULTI_SURFACE_RECON_TOOL, calls)
        self.assertGreaterEqual(out["compiled_threshold"], 0.85)

    def test_elevation_math(self) -> None:
        self.assertEqual(
            compute_contextual_authority(
                base_authority=0.6,
                alignment_score=0.79,
                informational_gain_score=1.0,
            ),
            0.6,
        )
        elevated = compute_contextual_authority(
            base_authority=0.8,
            alignment_score=0.9,
            informational_gain_score=1.0,
            elevation_cap=0.15,
        )
        self.assertEqual(elevated, 0.95)
        self.assertEqual(
            compute_contextual_authority(
                base_authority=0.97,
                alignment_score=0.9,
                informational_gain_score=1.0,
            ),
            1.0,
        )

    def test_domain_override_markets(self) -> None:
        router, _, _ = self._make_router(
            per_tool_results={
                RAG_LOOKUP_TOOL: _base_results("https://finance.example/quote"),
                BOOLEAN_SEARCH_TOOL: _base_results("https://finance.example/news"),
                SEARCH_ENGINE_TOOL: _base_results("https://finance.example/update"),
            }
        )
        policy = {
            "spec": {
                "search_policy": {
                    "domain_overrides": {
                        "markets": ["finance.example"],
                    }
                }
            }
        }

        out = router.route(
            query="markets outlook",
            tier=FAST,
            org_policy=policy,
            job_contract=_job_contract(allowed_domains=["reuters.com", "nih.gov"], prompt="markets outlook"),
            skill_contract=_skill_contract(),
        )
        self.assertEqual(out["tier"], FAST)

    def test_domain_violation_without_override_is_denied(self) -> None:
        router, _, _ = self._make_router(
            per_tool_results={
                RAG_LOOKUP_TOOL: _base_results("https://finance.example/quote"),
                BOOLEAN_SEARCH_TOOL: _base_results("https://finance.example/news"),
                SEARCH_ENGINE_TOOL: _base_results("https://finance.example/update"),
            }
        )
        with self.assertRaises(PolicyViolationError):
            router.route(
                query="markets outlook",
                tier=FAST,
                job_contract=_job_contract(allowed_domains=["reuters.com", "nih.gov"], prompt="markets outlook"),
                skill_contract=_skill_contract(),
            )

    def test_zero_memory_blocks_premium_escalation(self) -> None:
        base = Path.cwd() / "runtime" / "tmp" / "research_router_zero_memory"
        base.mkdir(parents=True, exist_ok=True)
        db_path = Path("runtime/tmp/research_router_zero_memory") / f"{uuid.uuid4().hex}.sqlite"
        query = "rare policy discontinuity signal"
        for _ in range(3):
            record_zero_result(PERPLEXITY_RESEARCH_TOOL, query, 0.1, db_path=db_path)

        router, audit, calls = self._make_router(
            per_tool_results={
                RAG_LOOKUP_TOOL: _base_results("https://example.org/rag"),
                BOOLEAN_SEARCH_TOOL: _base_results("https://www.reuters.com/world"),
                SEARCH_ENGINE_TOOL: _base_results("https://www.nih.gov/news-events"),
            },
            oracle={
                "confidence_score": 0.2,
                "authority_score": 0.5,
                "contradiction_flag": False,
            },
            zero_result_registry_path=db_path,
        )
        out = router.route(
            query=query,
            tier=FAST,
            job_contract=_job_contract(prompt=query),
            skill_contract=_skill_contract(),
        )

        self.assertTrue(out["zero_memory_blocked"])
        self.assertEqual(out["selected_tool"], OPENAI_PLANNER_TOOL)
        self.assertNotIn(PERPLEXITY_RESEARCH_TOOL, calls)
        self.assertTrue(any(row["action"] == "search.zero_memory_block" for row in audit.rows))


if __name__ == "__main__":
    unittest.main()
