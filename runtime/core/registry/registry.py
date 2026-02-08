"""In-memory registry of organization and agent configuration.

Registry content is configuration loaded from the repo at startup:
- Organization Manifests (`orgs/`)
- Agent Definitions (referenced from org manifests)
- (Optional) Skill Contracts (`skills/contracts/` if present)

The registry is NOT runtime state; state is persisted via storage stores.

Fail-closed rules:
- External (network) URI refs are rejected for registry references.
- Agent role references must resolve to an AgentDefinition in the repo.
- AgentDefinitions included by an org must allow inclusion by that org.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from errors import PolicyViolationError
from registry.loader import iter_yaml_files, load_yaml_document
from registry.schema_validator import SchemaValidator
from utils import deep_get, is_external_uri_reference


def _resolve_repo_ref(repo_root: Path, ref: str) -> Path:
    """Resolve a repo-root-relative ref to an absolute path (and ensure it stays inside the repo)."""
    if not isinstance(ref, str) or not ref:
        raise PolicyViolationError("Invalid ref (must be non-empty string)")
    if is_external_uri_reference(ref):
        raise PolicyViolationError(f"External URI refs are not allowed in registry: {ref}")
    if ref.lower().startswith("file:"):
        raise PolicyViolationError(f"file: URI refs are not allowed in registry (use repo-relative paths): {ref}")
    p = Path(ref)
    if p.is_absolute():
        raise PolicyViolationError(f"Absolute refs are not allowed in registry: {ref}")
    resolved = (repo_root / p).resolve()
    try:
        resolved.relative_to(repo_root.resolve())
    except Exception as e:
        raise PolicyViolationError(f"Ref escapes repo root: {ref}") from e
    return resolved


@dataclass(frozen=True)
class OrganizationRecord:
    org_id: str
    path: Path
    document: dict[str, Any]


@dataclass(frozen=True)
class AgentRecord:
    agent_id: str
    role: str
    path: Path
    document: dict[str, Any]


@dataclass(frozen=True)
class SkillRecord:
    skill_id: str
    version: str
    path: Path
    document: dict[str, Any]


class Registry:
    def __init__(
        self,
        *,
        repo_root: Path,
        orgs: dict[str, OrganizationRecord],
        agents: dict[str, AgentRecord],
        skills: dict[tuple[str, str], SkillRecord],
    ):
        self.repo_root = repo_root
        self._orgs = dict(orgs)
        self._agents = dict(agents)
        self._skills = dict(skills)
        self._agents_by_path = {rec.path.resolve(): rec for rec in agents.values()}

    @classmethod
    def load(
        cls,
        *,
        orgs_dir: Path,
        agent_definitions_dir: Path,
        skill_contracts_dir: Path,
        schema_validator: SchemaValidator,
    ) -> "Registry":
        repo_root = orgs_dir.parent.resolve()

        agents: dict[str, AgentRecord] = {}
        agents_by_path: dict[Path, AgentRecord] = {}

        # 1) Load AgentDefinitions from the configured directory (best-effort; org refs are authoritative).
        for p in iter_yaml_files(agent_definitions_dir):
            doc = load_yaml_document(p)
            if doc.kind != "AgentDefinition":
                continue
            schema_validator.validate("AgentDefinition", doc.data)
            agent_id = str(deep_get(doc.data, ["metadata", "agent_id"]))
            role = str(deep_get(doc.data, ["metadata", "role"]))

            rec = AgentRecord(agent_id=agent_id, role=role, path=p.resolve(), document=doc.data)
            if agent_id in agents:
                raise PolicyViolationError(f"Duplicate AgentDefinition agent_id: {agent_id} ({agents[agent_id].path} and {p})")
            agents[agent_id] = rec
            agents_by_path[rec.path] = rec

        orgs: dict[str, OrganizationRecord] = {}

        # 2) Load OrganizationManifests.
        for p in iter_yaml_files(orgs_dir):
            doc = load_yaml_document(p)
            if doc.kind != "OrganizationManifest":
                continue
            schema_validator.validate("OrganizationManifest", doc.data)
            org_id = str(deep_get(doc.data, ["metadata", "org_id"]))

            rec = OrganizationRecord(org_id=org_id, path=p.resolve(), document=doc.data)
            if org_id in orgs:
                raise PolicyViolationError(f"Duplicate OrganizationManifest org_id: {org_id} ({orgs[org_id].path} and {p})")
            orgs[org_id] = rec

        # 3) Resolve and validate role references (org -> agent definition).
        for org in orgs.values():
            org_id = org.org_id
            roles = deep_get(org.document, ["spec", "agent_roles"])
            if not isinstance(roles, list):
                raise PolicyViolationError(f"Invalid OrganizationManifest agent_roles (expected list): {org.path}")
            for role_ref in roles:
                if not isinstance(role_ref, dict):
                    raise PolicyViolationError(f"Invalid agent role ref in {org.path} (expected object)")
                role_id = str(role_ref.get("role_id", ""))
                ref = role_ref.get("ref")
                if not isinstance(ref, str) or not ref:
                    raise PolicyViolationError(f"Invalid agent role ref.ref in {org.path} (expected non-empty string)")

                agent_path = _resolve_repo_ref(repo_root, ref)
                if not agent_path.exists():
                    raise PolicyViolationError(f"OrganizationManifest {org_id} references missing AgentDefinition: {ref} (resolved: {agent_path})")

                agent_rec = agents_by_path.get(agent_path.resolve())
                if agent_rec is None:
                    # Not in the default directory list; load directly (still inside repo root).
                    loaded = load_yaml_document(agent_path)
                    if loaded.kind != "AgentDefinition":
                        raise PolicyViolationError(f"Referenced agent role ref is not an AgentDefinition: {ref} (kind={loaded.kind})")
                    schema_validator.validate("AgentDefinition", loaded.data)
                    agent_id = str(deep_get(loaded.data, ["metadata", "agent_id"]))
                    role = str(deep_get(loaded.data, ["metadata", "role"]))
                    agent_rec = AgentRecord(agent_id=agent_id, role=role, path=agent_path.resolve(), document=loaded.data)
                    if agent_id in agents:
                        raise PolicyViolationError(
                            f"AgentDefinition agent_id collision when loading by ref: {agent_id} ({agents[agent_id].path} and {agent_path})"
                        )
                    agents[agent_id] = agent_rec
                    agents_by_path[agent_rec.path] = agent_rec

                # Enforce role_id alignment: prevents org manifests from aliasing roles silently.
                if role_id and agent_rec.role != role_id:
                    raise PolicyViolationError(
                        f"OrganizationManifest {org_id} role_id '{role_id}' does not match referenced AgentDefinition.metadata.role '{agent_rec.role}' ({agent_rec.path})"
                    )

                # Enforce org inclusion rules.
                inclusion = deep_get(agent_rec.document, ["spec", "org_inclusion"])
                mode = inclusion.get("mode")
                if mode == "allowlist":
                    allow = inclusion.get("allow_org_ids", [])
                    if org_id not in allow:
                        raise PolicyViolationError(
                            f"AgentDefinition {agent_rec.agent_id} is not allowed to be included by org_id {org_id} (not in allow_org_ids)"
                        )

        # 4) Load SkillContracts if the directory exists (optional in build mode).
        skills: dict[tuple[str, str], SkillRecord] = {}
        if skill_contracts_dir.exists():
            for p in iter_yaml_files(skill_contracts_dir):
                doc = load_yaml_document(p)
                if doc.kind != "SkillContract":
                    continue
                schema_validator.validate("SkillContract", doc.data)
                skill_id = str(deep_get(doc.data, ["metadata", "skill_id"]))
                version = str(deep_get(doc.data, ["metadata", "version"]))
                key = (skill_id, version)
                if key in skills:
                    raise PolicyViolationError(f"Duplicate SkillContract {skill_id}@{version} ({skills[key].path} and {p})")
                skills[key] = SkillRecord(skill_id=skill_id, version=version, path=p.resolve(), document=doc.data)

        return cls(repo_root=repo_root, orgs=orgs, agents=agents, skills=skills)

    def get_org(self, org_id: str) -> OrganizationRecord:
        if org_id not in self._orgs:
            raise PolicyViolationError(f"Unknown org_id (not in registry): {org_id}")
        return self._orgs[org_id]

    def has_org(self, org_id: str) -> bool:
        return org_id in self._orgs

    def get_agent(self, agent_id: str) -> AgentRecord:
        if agent_id not in self._agents:
            raise PolicyViolationError(f"Unknown agent_id (not in registry): {agent_id}")
        return self._agents[agent_id]

    def resolve_agent_ref(self, ref: str) -> AgentRecord:
        """Resolve an OrganizationManifest agent role ref to an AgentRecord."""
        agent_path = _resolve_repo_ref(self.repo_root, ref).resolve()
        rec = self._agents_by_path.get(agent_path)
        if rec is None:
            raise PolicyViolationError(f"Unknown AgentDefinition ref (not loaded): {ref} (resolved: {agent_path})")
        return rec

    def included_agent_ids_for_org(self, org_id: str) -> set[str]:
        """Return the set of AgentDefinition metadata.agent_id values included by an org manifest."""
        org = self.get_org(org_id)
        ids: set[str] = set()
        roles = deep_get(org.document, ["spec", "agent_roles"])
        if isinstance(roles, list):
            for role_ref in roles:
                if not isinstance(role_ref, dict):
                    continue
                ref = role_ref.get("ref")
                if isinstance(ref, str) and ref:
                    ids.add(self.resolve_agent_ref(ref).agent_id)
        return ids
