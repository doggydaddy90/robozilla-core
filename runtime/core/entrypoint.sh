#!/bin/sh
set -eu

: "${MODE:=build}"
: "${KILL_SWITCH:=1}"
: "${API_BIND:=127.0.0.1}"
: "${API_PORT:=8787}"
: "${STORAGE_BACKEND:=sqlite}"
: "${DB_PATH:=/data/robozilla.db}"

if [ "${MODE}" != "build" ]; then
  echo "MODE must be 'build' (got ${MODE})" >&2
  exit 1
fi

if [ "${KILL_SWITCH}" != "0" ] && [ "${KILL_SWITCH}" != "1" ]; then
  echo "KILL_SWITCH must be 0 or 1" >&2
  exit 1
fi

if [ "${KILL_SWITCH}" = "1" ]; then
  echo "KILL_SWITCH=1; runtime will still start but execution remains contract-deferred (build mode)" >&2
fi

cat > /tmp/robozilla-runtime.yaml <<EOF
runtime:
  role: dev
  strict_validation: true
  fail_closed: true

service:
  host: ${API_BIND}
  port: ${API_PORT}

registry:
  schemas_dir: /app/bundle/schemas
  orgs_dir: /app/bundle/orgs
  agent_definitions_dir: /app/bundle/agents/definitions
  skill_contracts_dir: /app/bundle/skills/contracts

storage:
  driver: ${STORAGE_BACKEND}
  sqlite:
    path: ${DB_PATH}

scheduler:
  enabled: false
  poll_interval_seconds: 10
EOF

export ROBOZILLA_RUNTIME_CONFIG=/tmp/robozilla-runtime.yaml
export ROBOZILLA_LOGGING_CONFIG=/app/config/logging.yaml
export ROBOZILLA_LIMITS_CONFIG=/app/config/limits.yaml

exec python -m uvicorn api.main:app --host "${API_BIND}" --port "${API_PORT}"
