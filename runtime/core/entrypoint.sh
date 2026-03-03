#!/bin/sh
set -eu

: "${MODE:=build}"
: "${KILL_SWITCH:=1}"
: "${API_BIND:=localhost}"
: "${API_PORT:=8787}"
: "${STORAGE_BACKEND:=sqlite}"
: "${PROJECT_ROOT:=$(pwd)}"
: "${ROBOZILLA_RUNTIME_CONFIG_OUTPUT:=}"
: "${ROBOZILLA_STATE_DIR:=}"
: "${ROBOZILLA_BUNDLE_DIR:=}"
: "${ROBOZILLA_SCHEMAS_DIR:=}"
: "${ROBOZILLA_ORGS_DIR:=}"
: "${ROBOZILLA_AGENTS_DIR:=}"
: "${ROBOZILLA_SKILLS_DIR:=}"

if [ -z "${ROBOZILLA_STATE_DIR}" ]; then
  ROBOZILLA_STATE_DIR="${PROJECT_ROOT}/runtime/core/state"
fi
if [ -z "${ROBOZILLA_BUNDLE_DIR}" ]; then
  ROBOZILLA_BUNDLE_DIR="${PROJECT_ROOT}/runtime/core/bundle"
fi
if [ -z "${ROBOZILLA_SCHEMAS_DIR}" ]; then
  ROBOZILLA_SCHEMAS_DIR="${ROBOZILLA_BUNDLE_DIR}/schemas"
fi
if [ -z "${ROBOZILLA_ORGS_DIR}" ]; then
  ROBOZILLA_ORGS_DIR="${ROBOZILLA_BUNDLE_DIR}/orgs"
fi
if [ -z "${ROBOZILLA_AGENTS_DIR}" ]; then
  ROBOZILLA_AGENTS_DIR="${ROBOZILLA_BUNDLE_DIR}/agents/definitions"
fi
if [ -z "${ROBOZILLA_SKILLS_DIR}" ]; then
  ROBOZILLA_SKILLS_DIR="${ROBOZILLA_BUNDLE_DIR}/skills/contracts"
fi
if [ -z "${ROBOZILLA_RUNTIME_CONFIG_OUTPUT}" ]; then
  ROBOZILLA_RUNTIME_CONFIG_OUTPUT="${ROBOZILLA_STATE_DIR}/runtime.generated.yaml"
fi
: "${DB_PATH:=${ROBOZILLA_STATE_DIR}/robozilla.db}"

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

python - "${PROJECT_ROOT}" "${ROBOZILLA_STATE_DIR}" "${ROBOZILLA_RUNTIME_CONFIG_OUTPUT}" "${DB_PATH}" "${ROBOZILLA_SCHEMAS_DIR}" "${ROBOZILLA_ORGS_DIR}" "${ROBOZILLA_AGENTS_DIR}" "${ROBOZILLA_SKILLS_DIR}" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
if not root.exists() or not root.is_dir():
    raise SystemExit(f"PROJECT_ROOT must be an existing directory: {root}")
if root == pathlib.Path(root.anchor):
    raise SystemExit(f"Drive-root PROJECT_ROOT is forbidden: {root}")

for raw in sys.argv[2:]:
    p = pathlib.Path(raw).resolve()
    try:
        p.relative_to(root)
    except ValueError as exc:
        raise SystemExit(f"Configured path must stay under PROJECT_ROOT: {p}") from exc
PY

mkdir -p "${ROBOZILLA_STATE_DIR}"

cat > "${ROBOZILLA_RUNTIME_CONFIG_OUTPUT}" <<EOF
runtime:
  role: dev
  strict_validation: true
  fail_closed: true

service:
  host: ${API_BIND}
  port: ${API_PORT}

registry:
  schemas_dir: ${ROBOZILLA_SCHEMAS_DIR}
  orgs_dir: ${ROBOZILLA_ORGS_DIR}
  agent_definitions_dir: ${ROBOZILLA_AGENTS_DIR}
  skill_contracts_dir: ${ROBOZILLA_SKILLS_DIR}

storage:
  driver: ${STORAGE_BACKEND}
  sqlite:
    path: ${DB_PATH}

scheduler:
  enabled: false
  poll_interval_seconds: 10
EOF

export ROBOZILLA_PROJECT_ROOT="${PROJECT_ROOT}"
export ROBOZILLA_RUNTIME_CONFIG="${ROBOZILLA_RUNTIME_CONFIG_OUTPUT}"
: "${ROBOZILLA_LOGGING_CONFIG:=${PROJECT_ROOT}/runtime/core/config/logging.yaml}"
: "${ROBOZILLA_LIMITS_CONFIG:=${PROJECT_ROOT}/runtime/core/config/limits.yaml}"

exec python -m uvicorn api.main:app --host "${API_BIND}" --port "${API_PORT}"
