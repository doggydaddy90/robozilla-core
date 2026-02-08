# RoboZilla Core Runtime image (build mode)
#
# This image is self-contained for `docker compose build` with `build: .` from
# `runtime/core/` by bundling a snapshot of constitutional schemas + registry
# documents under `bundle/`.
#
# It does NOT bundle secrets or any live infrastructure.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create the non-root runtime user/group with UID/GID 986 (compatible with host mounts).
RUN addgroup --gid 986 robozilla \
    && adduser --disabled-password --gecos "" --uid 986 --gid 986 --shell /bin/false robozilla

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir -r /app/requirements.txt

# Copy runtime source (this build context is runtime/core/).
COPY . /app

# Persistent directories (mounted by docker-compose).
RUN mkdir -p /data /logs \
    && chown -R 986:986 /data /logs /app

USER 986:986

EXPOSE 8787

# ENTRYPOINT runs uvicorn serving api.main:app.
# Config is generated at container start so DB_PATH / API_* env vars can be honored without changing runtime logic.
ENTRYPOINT ["sh", "-c", "set -eu; \\\n  : \"${MODE:=build}\"; \\\n  : \"${KILL_SWITCH:=1}\"; \\\n  : \"${API_BIND:=127.0.0.1}\"; \\\n  : \"${API_PORT:=8787}\"; \\\n  : \"${STORAGE_BACKEND:=sqlite}\"; \\\n  : \"${DB_PATH:=/data/robozilla.db}\"; \\\n  if [ \"${MODE}\" != \"build\" ]; then echo \"MODE must be 'build' (got ${MODE})\" >&2; exit 1; fi; \\\n  if [ \"${KILL_SWITCH}\" != \"0\" ] && [ \"${KILL_SWITCH}\" != \"1\" ]; then echo \"KILL_SWITCH must be 0 or 1\" >&2; exit 1; fi; \\\n  if [ \"${KILL_SWITCH}\" = \"1\" ]; then echo \"KILL_SWITCH=1; runtime will still start but execution remains contract-deferred (build mode)\" >&2; fi; \\\n  cat > /tmp/robozilla-runtime.yaml <<EOF \\\nruntime:\\n  role: dev\\n  strict_validation: true\\n  fail_closed: true\\n\\nservice:\\n  host: ${API_BIND}\\n  port: ${API_PORT}\\n\\nregistry:\\n  schemas_dir: /app/bundle/schemas\\n  orgs_dir: /app/bundle/orgs\\n  agent_definitions_dir: /app/bundle/agents/definitions\\n  skill_contracts_dir: /app/bundle/skills/contracts\\n\\nstorage:\\n  driver: ${STORAGE_BACKEND}\\n  sqlite:\\n    path: ${DB_PATH}\\n\\nscheduler:\\n  enabled: false\\n  poll_interval_seconds: 10\\nEOF \\\n  export ROBOZILLA_RUNTIME_CONFIG=/tmp/robozilla-runtime.yaml; \\\n  export ROBOZILLA_LOGGING_CONFIG=/app/config/logging.yaml; \\\n  export ROBOZILLA_LIMITS_CONFIG=/app/config/limits.yaml; \\\n  exec python -m uvicorn api.main:app --host \"${API_BIND}\" --port \"${API_PORT}\"\\n"]
