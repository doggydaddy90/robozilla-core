"""Policy enforcement helpers for JobContract submission and execution requests.

This module enforces *static* boundaries derived from:
- Organization Manifest
- Global hard limits (limits.yaml)
- The JobContract itself (timestamps, limits, permissions snapshot)

It intentionally does not execute agents/skills/MCPs. It only proves whether a
requested job is within the declared boundaries.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from config.settings import LimitsConfig
from errors import PolicyViolationError
from utils import deep_get, parse_rfc3339


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    raise PolicyViolationError("Expected list")


def _as_dict(v: Any) -> dict[str, Any]:
    if isinstance(v, dict):
        return v
    raise PolicyViolationError("Expected object")


def enforce_job_contract_submission_shape(job: dict[str, Any]) -> None:
    """Extra rules beyond schema to prevent ambiguous/misleading created jobs."""
    status = _as_dict(deep_get(job, ["spec", "status"]))
    if status.get("state") != "created":
        raise PolicyViolationError("JobContract.status.state must be 'created' at submission time")
    for forbidden in ("started_at", "terminal_at", "final_evaluation_ref", "failure_mode", "expiry_reason"):
        if forbidden in status:
            raise PolicyViolationError(f"JobContract.spec.status must not include '{forbidden}' when state=created")


def enforce_job_contract_limits(job: dict[str, Any], *, limits: LimitsConfig, now: datetime) -> None:
    """Enforce global hard limits and basic timestamp sanity."""
    created_at = parse_rfc3339(str(deep_get(job, ["spec", "timestamps", "created_at"])))
    expires_at = parse_rfc3339(str(deep_get(job, ["spec", "timestamps", "expires_at"])))

    if expires_at <= created_at:
        raise PolicyViolationError("JobContract.spec.timestamps.expires_at must be after created_at")
    if expires_at <= now:
        raise PolicyViolationError("JobContract is already expired (expires_at is in the past)")

    max_expires = timedelta(seconds=limits.max_expires_in_seconds_upper_bound)
    if expires_at - created_at > max_expires:
        raise PolicyViolationError(
            f"JobContract expires_at exceeds global upper bound ({limits.max_expires_in_seconds_upper_bound}s)"
        )

    exec_limits = _as_dict(deep_get(job, ["spec", "execution_limits"]))
    max_iterations = int(exec_limits.get("max_iterations"))
    max_runtime_seconds = int(exec_limits.get("max_runtime_seconds"))
    cost_cap = _as_dict(exec_limits.get("cost_cap"))
    currency = str(cost_cap.get("currency"))
    max_cost = float(cost_cap.get("max_cost"))

    if max_iterations > limits.max_iterations_upper_bound:
        raise PolicyViolationError(f"JobContract.max_iterations exceeds global upper bound ({limits.max_iterations_upper_bound})")
    if max_runtime_seconds > limits.max_runtime_seconds_upper_bound:
        raise PolicyViolationError(
            f"JobContract.max_runtime_seconds exceeds global upper bound ({limits.max_runtime_seconds_upper_bound})"
        )
    if currency != limits.max_cost_upper_bound_currency:
        raise PolicyViolationError(
            f"JobContract.cost_cap.currency must be {limits.max_cost_upper_bound_currency} (got {currency})"
        )
    if max_cost > limits.max_cost_upper_bound:
        raise PolicyViolationError(f"JobContract.cost_cap.max_cost exceeds global upper bound ({limits.max_cost_upper_bound})")


def enforce_job_within_org_policy(job: dict[str, Any], *, org: dict[str, Any]) -> None:
    """Ensure a job's requested artifacts and permissions snapshot do not exceed org boundaries."""
    _enforce_required_artifacts_allowed(job, org=org)
    _enforce_permissions_snapshot(job, org=org)
    _enforce_execution_limits_vs_org(job, org=org)


def _enforce_required_artifacts_allowed(job: dict[str, Any], *, org: dict[str, Any]) -> None:
    required = _as_list(deep_get(job, ["spec", "required_artifacts"]))
    artifact_policy = _as_dict(deep_get(org, ["spec", "artifact_policy"]))
    allowed_types = _as_list(artifact_policy.get("allowed_types"))
    denied_types = _as_list(artifact_policy.get("denied_types"))

    allowed_ids = {str(_as_dict(x).get("type_id")) for x in allowed_types}
    denied_ids = {str(_as_dict(x).get("type_id")) for x in denied_types}

    for ra in required:
        ra_obj = _as_dict(ra)
        a_type = str(ra_obj.get("artifact_type"))
        if a_type in denied_ids:
            raise PolicyViolationError(f"Artifact type is explicitly denied by org policy: {a_type}")
        if a_type not in allowed_ids:
            raise PolicyViolationError(f"Artifact type is not allowed by org policy: {a_type}")


def _enforce_permissions_snapshot(job: dict[str, Any], *, org: dict[str, Any]) -> None:
    snapshot = _as_dict(deep_get(job, ["spec", "permissions_snapshot"]))

    # Skills
    org_skill_policy = _as_dict(deep_get(org, ["spec", "skill_policy"]))
    org_default = str(org_skill_policy.get("default_rule"))
    org_allow = _as_dict(org_skill_policy.get("allow") or {})
    org_deny = _as_dict(org_skill_policy.get("deny") or {})

    allow_skill_ids = set(map(str, _as_list(org_allow.get("skill_ids"))))
    allow_skill_cats = set(map(str, _as_list(org_allow.get("skill_categories"))))
    deny_skill_ids = set(map(str, _as_list(org_deny.get("skill_ids"))))
    deny_skill_cats = set(map(str, _as_list(org_deny.get("skill_categories"))))

    job_skills = _as_dict(snapshot.get("skills"))
    job_skill_ids = list(map(str, _as_list(job_skills.get("allowed_skill_ids"))))
    job_skill_cats = list(map(str, _as_list(job_skills.get("allowed_skill_categories"))))

    for sid in job_skill_ids:
        if sid in deny_skill_ids:
            raise PolicyViolationError(f"Job permissions_snapshot includes denied skill_id: {sid}")
        if sid in allow_skill_ids:
            continue
        if org_default == "allow":
            continue
        raise PolicyViolationError(f"Job permissions_snapshot skill_id not allowed by org policy: {sid}")

    for cat in job_skill_cats:
        if cat in deny_skill_cats:
            raise PolicyViolationError(f"Job permissions_snapshot includes denied skill_category: {cat}")
        if cat in allow_skill_cats:
            continue
        if org_default == "allow":
            continue
        raise PolicyViolationError(f"Job permissions_snapshot skill_category not allowed by org policy: {cat}")

    # MCP allowlist
    org_mcp_allowed = _as_list(deep_get(org, ["spec", "external_access", "mcp", "allowed"]))
    org_mcp_by_id: dict[str, dict[str, Any]] = {}
    for item in org_mcp_allowed:
        obj = _as_dict(item)
        org_mcp_by_id[str(obj.get("mcp_id"))] = obj

    job_mcp_allowed = _as_list(deep_get(snapshot, ["mcp", "allowed"]))
    for item in job_mcp_allowed:
        obj = _as_dict(item)
        mcp_id = str(obj.get("mcp_id"))
        if mcp_id not in org_mcp_by_id:
            raise PolicyViolationError(f"Job permissions_snapshot includes MCP not allowed by org: {mcp_id}")
        org_obj = org_mcp_by_id[mcp_id]
        if str(obj.get("ref")) != str(org_obj.get("ref")):
            raise PolicyViolationError(f"Job MCP ref does not match org registry for {mcp_id}")

        org_scopes = set(map(str, _as_list(org_obj.get("allowed_scopes"))))
        job_scopes = _as_list(obj.get("allowed_scopes"))
        if org_scopes:
            if not job_scopes:
                raise PolicyViolationError(f"Job must declare allowed_scopes for MCP {mcp_id} (org requires scoped access)")
            if not set(map(str, job_scopes)).issubset(org_scopes):
                raise PolicyViolationError(f"Job allowed_scopes for MCP {mcp_id} exceed org allowed_scopes")

    # Direct external network
    org_net = _as_dict(deep_get(org, ["spec", "external_access", "direct_network"]))
    job_net = _as_dict(deep_get(snapshot, ["direct_external_network"]))
    org_policy = str(org_net.get("policy"))
    job_policy = str(job_net.get("policy"))

    if org_policy == "deny_all" and job_policy != "deny_all":
        raise PolicyViolationError("Org policy denies all direct network; job must set direct_external_network.policy=deny_all")

    if org_policy == "allowlist" and job_policy == "allowlist":
        org_allow = _as_dict(org_net.get("allowlist") or {})
        org_deny = _as_dict(org_net.get("denylist") or {})
        job_allow = _as_dict(job_net.get("allowlist") or {})

        def _subset_list(job_list: Any, org_list: Any, label: str) -> None:
            j = set(map(str, _as_list(job_list)))
            o = set(map(str, _as_list(org_list)))
            if not j.issubset(o):
                raise PolicyViolationError(f"Job direct network allowlist '{label}' exceeds org allowlist")
            deny = set(map(str, _as_list(org_deny.get(label))))
            if j.intersection(deny):
                raise PolicyViolationError(f"Job direct network allowlist '{label}' includes org-denied entries")

        _subset_list(job_allow.get("domains"), org_allow.get("domains"), "domains")
        _subset_list(job_allow.get("urls"), org_allow.get("urls"), "urls")
        _subset_list(job_allow.get("ip_cidrs"), org_allow.get("ip_cidrs"), "ip_cidrs")


def _enforce_execution_limits_vs_org(job: dict[str, Any], *, org: dict[str, Any]) -> None:
    job_exec = _as_dict(deep_get(job, ["spec", "execution_limits"]))
    org_exec = _as_dict(deep_get(org, ["spec", "execution_limits"]))

    org_cost_caps = _as_dict(org_exec.get("cost_caps"))
    org_currency = str(org_cost_caps.get("currency"))
    org_max_cost_per_job = float(org_cost_caps.get("max_cost_per_job"))

    job_cost_cap = _as_dict(job_exec.get("cost_cap"))
    job_currency = str(job_cost_cap.get("currency"))
    job_max_cost = float(job_cost_cap.get("max_cost"))

    if job_currency != org_currency:
        raise PolicyViolationError(f"Job cost_cap currency {job_currency} must match org currency {org_currency}")
    if job_max_cost > org_max_cost_per_job:
        raise PolicyViolationError("Job cost_cap.max_cost exceeds org max_cost_per_job")

    org_timeouts = _as_dict(org_exec.get("timeouts"))
    org_max_runtime = int(org_timeouts.get("max_job_runtime_seconds"))
    job_max_runtime = int(job_exec.get("max_runtime_seconds"))
    if job_max_runtime > org_max_runtime:
        raise PolicyViolationError("Job max_runtime_seconds exceeds org max_job_runtime_seconds")

