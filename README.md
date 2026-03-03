# RoboZilla Core

RoboZilla Core is a fail-closed, policy-first runtime for contract-driven agent workflows.

It is designed so enforcement stays active even as capabilities expand. The platform prioritizes deterministic validation, strict boundaries, and auditable execution over permissive behavior.

## What This Repository Contains

- A modular runtime under `runtime/core`
- Contract and policy enforcement (job lifecycle, permissions, scope limits)
- Secure API surface (health, jobs, artifacts, evaluations, dashboard)
- Roland trust-aware security modules and orchestration utilities
- Full unit and stress test coverage for core enforcement paths

## Core Security Invariants

These are non-negotiable constraints in this codebase:

1. Capability gating is deny-by-default (`CapabilityEnforcer`)
2. `IntentEnvelope` hash and scope checks are mandatory
3. Diff-only write boundary is enforced (`diffEnforcer` + `pathGuard.safeWrite`)
4. Strict mode isolation defaults to enabled (`ROLAND_STRICT_MODE=true`)
5. Secret/PII handling is fail-closed (`redaction_layer`, role controls)
6. Endpoint allowlists are enforced before tool egress
7. No global bypass switch exists for enforcement spine

## Architecture

Top-level runtime modules:

- `runtime/core/api`: HTTP routers (`main`, dashboard, Roland helpers)
- `runtime/core/security`: capability, path, diff, trust, intent, injection, role, endpoint controls
- `runtime/core/orchestration`: research routing, confidence adapters, redaction, loop controllers
- `runtime/core/governance`: strictness profile and behavioral caution controls
- `runtime/core/search`: boolean query policy + builder + zero-result memory registry
- `runtime/core/economics`: scarcity and throttle policy adaptation
- `runtime/core/registry`: schema and manifest loading/validation
- `runtime/core/executor`: contract-aware job engine and policy layer
- `runtime/core/audit`: immutable hash-chained audit logging
- `runtime/core/tests`: unit/stress test suite

## Roland Hardening Model

The request hardening path is trust-aware and layered:

1. Trust classification (`internal_system`, `structured_external`, `unstructured_external`)
2. Defense matrix selection by trust level
3. Prompt-injection filtering for non-internal input
4. Intent risk scoring and deny-threshold checks
5. Strictness-based sensitivity tuning (without weakening invariants)
6. Capability enforcement remains mandatory before tool execution

### Trust Classification

Implemented in `runtime/core/security/trust_classifier.py`.

- Internal signed typed schema-bound calls -> `internal_system`
- Structured API JSON output -> `structured_external`
- Scraped/web/user text -> `unstructured_external`

### Defense Matrix

Implemented in `runtime/core/security/defense_matrix.py`.

- `internal_system`: skips injection/intent preprocessing but still requires capability, scope, and core boundaries
- `structured_external`: light injection filtering + intent checks + schema hooks
- `unstructured_external`: full injection filtering + intent checks + entropy guard + high-risk logging

### Intent Classifier

Implemented in `runtime/core/security/intent_classifier.py`.

Detects and scores:

- secret extraction attempts
- scope override attempts
- system prompt disclosure attempts
- file access abuse
- tool misuse intent

Risk category thresholds:

- `< 0.4`: low
- `0.4 - 0.7`: medium
- `> 0.7`: high (denied before tool layer)

### Strictness Adapter

Implemented in `runtime/core/governance/strictness_adapter.py`.

`system_strictness` (default `0.75`) controls behavioral caution only:

- intent deny sensitivity
- deep trigger aggressiveness
- minority escalation sensitivity
- entropy tolerance
- economic throttle aggressiveness

Strictness cannot disable core protections or lower atomic floor below `0.7`.

### Role-Based Data Access

Implemented in `runtime/core/security/role_enforcer.py`.

Roles:

- `admin`
- `operator`
- `viewer`
- `agent_internal`

Rules:

- Admin can access sensitive personal fields (for example phone, address, SSN)
- Non-admin access to those fields is denied
- Credentials/secrets are never returned in chat responses, including for admin

### Prompt Injection Filter

Implemented in `runtime/core/security/prompt_injection_filter.py`.

Filters/blocks patterns including:

- instruction override phrasing
- key/token exfiltration requests
- script tags
- embedded large base64 payloads
- encoded instruction attempts

### Endpoint Allowlist Enforcement

Implemented in `runtime/core/security/endpoint_allowlist_enforcer.py`.

Tool egress must match declared allowed endpoints.

- unknown endpoints denied
- wildcard domains forbidden

## Search Stack

### Boolean Query Policy

- Operator policy file: `runtime/core/search/search_operator_policy.yaml`
- Builder/validator: `runtime/core/search/boolean_query_builder.py`

Features:

- tier-specific operator legality
- engine capability matrix checks
- grouping depth validation
- confirmation-bias query detection
- structured output contract

### Zero-Result Memory Registry

Implemented in `runtime/core/search/zero_result_registry.py`.

Purpose:

- persist premium zero-result memory in SQLite
- avoid repeated expensive escalation on structurally equivalent failed queries

Registry table:

- `zero_result_registry(engine, query_signature, zero_count, last_seen, entropy_score)`

Query signature behavior:

- normalize boolean/operator structure
- strip date bounds
- strip dynamic tokens
- deterministic SHA-256 hash

Router integration:

- applied before premium escalation path
- if blocked, premium call is skipped and `search.zero_memory_block` is audited
- does not block RAG or stage-1 cheap surfaces

## API Surfaces

Main FastAPI app (`runtime/core/api/main.py`) includes:

- `GET /health`
- `GET /audit/verify`
- `POST /jobs`
- `GET /jobs/{job_id}`
- `POST /jobs/{job_id}/run`
- `POST /jobs/{job_id}/stop`
- `POST /artifacts`
- `GET /artifacts/{artifact_id}`
- `POST /evaluations`

Dashboard router includes:

- `GET /dashboard/telemetry`
- `GET /dashboard/economics`
- `GET /dashboard/rag`
- `GET /dashboard/truth-ledger`

Roland router helper (`runtime/core/api/roland_interface.py`) provides:

- `POST /roland/query`
- `POST /roland/research`
- `GET /roland/health`
- `GET /roland/economics_summary`

## Local Development

Install dependencies:

```bash
cd runtime/core
python -m pip install -r requirements.txt
```

Run API:

```bash
cd runtime/core
python -m uvicorn api.main:app --host 127.0.0.1 --port 8787
```

Container run:

```bash
cd runtime/core
docker compose up --build
```

## Configuration

Primary config files:

- `runtime/core/config/runtime.yaml`
- `runtime/core/config/logging.yaml`
- `runtime/core/config/limits.yaml`

Key environment controls:

- `ROBOZILLA_PROJECT_ROOT`
- `ROBOZILLA_RUNTIME_CONFIG`
- `ROBOZILLA_LOGGING_CONFIG`
- `ROBOZILLA_LIMITS_CONFIG`
- `ROLAND_STRICT_MODE` (defaults to strict mode enabled)

## Testing

Run full core suite:

```bash
python -m unittest discover -s runtime/core/tests -p "test_*.py"
```

Run specific modules:

```bash
python -m unittest runtime/core/tests/test_research_router.py
python -m unittest runtime/core/tests/test_zero_result_registry.py
```

## Enforcement-First Development Rules

When adding new capability:

1. Keep `CapabilityEnforcer` as mandatory chokepoint
2. Preserve `IntentEnvelope` validation and scope subset checks
3. Do not bypass `safeWrite`/`safeDelete` diff/path controls
4. Maintain secret redaction and role constraints
5. Enforce endpoint allowlists before egress
6. Add tests for denial cases, not only success cases

---

For runtime-specific details, see `runtime/core/README.md`.

