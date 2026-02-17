# RoboZilla Core Runtime (Build Mode)
#
# This folder contains the minimal, contract-enforcing runtime for RoboZilla.
# It is intentionally model-agnostic and fail-closed.
#
# What this runtime DOES
# - Validates all incoming JobContract and Evaluation documents against the
#   canonical JSON Schemas in `schemas/` (Draft 2020-12).
# - Loads and validates Organization Manifests and Agent Definitions from the repo
#   (registry).
# - Enforces:
#   - Job lifecycle state machine and terminal-state rules
#   - Organization policy boundaries at job submission time
#   - Permission snapshot boundaries at execution time (future skill/MCP calls)
#   - "Only Evaluations can mark a Job complete"
#   - "No agent may self-evaluate its own artifacts" (enforced on Evaluation submit)
# - Persists state to a DB-backed store (SQLite by default, behind interfaces).
#
# **Schema note (YAML regex patterns)**
# The canonical schemas in `schemas/` are stored as YAML and contain many regex
# `pattern` strings authored with JSON-style escaping (e.g. `\\d`). The runtime
# normalizes these `pattern` fields by unescaping a single layer before
# validation to match intended JSON Schema semantics. The schema files
# themselves are not modified on disk.
#
# What this runtime DOES NOT do (intentionally deferred)
# - Execute agents (no agent runtime yet)
# - Execute skills (no skill implementations yet)
# - Wire MCPs (no external system gateways yet)
# - Auto-execute jobs in the background (no scheduler in build mode)
#
# In build mode, `POST /jobs/{id}/run` transitions the job to `running`, performs
# contract checks, and then transitions the job to `waiting` with an audit event
# explaining that execution is deferred. This stops runaway execution without
# pretending work was done.
#
# **Config**
# - `config/runtime.yaml`  : service ports, role, registry paths, storage config
# - `config/logging.yaml`  : Python logging (dictConfig)
# - `config/limits.yaml`   : global hard limits (upper bounds)
#
# **Registry source (canonical)**
# When /repo is mounted (e.g. Docker volume), registry loads from /repo/orgs,
# /repo/agents/definitions, /repo/skills/contracts. Repo is the source of truth.
# When /repo is not mounted, runtime falls back to /app/bundle/* (build-time snapshot).
# Bundle must mirror repo; do not edit bundle manually.
#
# **Build mode**
# Build mode means:
# - Contract enforcement is ON.
# - Agent execution / skills / MCP calls are NOT implemented.
# - `POST /jobs/{id}/run` never runs agents; it transitions the job into `waiting`
#   with an audit event explaining that execution is deferred.
# - No background scheduler is started, and nothing auto-executes.
#
# Explicitly: the runtime never starts jobs on its own. A client must call
# `POST /jobs/{id}/run` to request execution, and in build mode that request is
# still contract-deferred (no agent execution).
#
# **Run locally (Python)**
# 1. `cd runtime/core`
# 2. `python -m pip install -r requirements.txt`
# 3. `python -m uvicorn api.main:app --host 127.0.0.1 --port 8787`
#
# **Run locally (Docker Compose)**
# 1. `cd runtime/core`
# 2. `copy .env.example .env` (then edit paths if needed)
# 3. `docker compose up --build`
#
# Docker Compose mounts repo root at `/repo` so registry loads from repo (canonical).
# Path `../../` is relative to compose file; ensure repo root contains orgs/, agents/, skills/.
# Docker Compose uses host networking and binds to `API_BIND` only (default `127.0.0.1`).
# There are no published container ports in `docker-compose.yml`.
#
# **API**
# - `GET  /health`        health check (returns 200 when runtime is ready)
# - `POST /jobs`          submit a JobContract (validated + stored)
# - `GET  /jobs/{id}`     get job status + contract
# - `POST /jobs/{id}/run` request execution (no agent execution yet; transitions to waiting)
# - `POST /jobs/{id}/stop` stop execution (running -> waiting)
# - `POST /artifacts`     submit an Artifact (validated + stored; job must be non-terminal)
# - `GET  /artifacts/{id}` get artifact by id
# - `POST /evaluations`   submit an Evaluation (validated + stored; may transition job state)
