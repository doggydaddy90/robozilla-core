#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

import yaml


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def main() -> int:
    repo = _repo_root()
    sys.path.insert(0, str(repo / "runtime" / "core"))

    from errors import PolicyViolationError
    from executor.policy import enforce_job_within_org_policy
    from registry.registry import Registry
    from registry.schema_validator import SchemaValidator

    schema_validator = SchemaValidator.load_from_dir(repo / "schemas")
    registry = Registry.load(
        orgs_dir=repo / "orgs",
        agent_definitions_dir=repo / "agents" / "definitions",
        skill_contracts_dir=repo / "skills" / "contracts",
        schema_validator=schema_validator,
    )

    org = registry.get_org("ops").document
    allow = ((org.get("spec") or {}).get("skill_policy") or {}).get("allow") or {}
    allow_ids = set(map(str, allow.get("skill_ids", []) or []))
    allow_cats = set(map(str, allow.get("skill_categories", []) or []))

    skills_loaded = {rec.skill_id for rec in registry._skills.values()}
    is_allowed = "session_closeout" in allow_ids or "governance" in allow_cats
    in_registry = "session_closeout" in skills_loaded

    print(f"org=ops policy_allows_session_closeout={is_allowed}")
    print(f"registry_has_session_closeout={in_registry}")

    job = yaml.safe_load((repo / "jobs" / "templates" / "session_closeout.job.yaml").read_text(encoding="utf-8"))
    try:
        enforce_job_within_org_policy(job, org=org)
        print("policy_evaluation=PASS")
        return 0
    except PolicyViolationError as e:
        print("policy_evaluation=FAIL")
        print(f"reason={e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
