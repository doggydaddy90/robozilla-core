# Bundled Registry Snapshot

This folder exists so `docker compose build` with `build: .` from `runtime/core/` can build a self-contained image without mounting the whole repo.

Contents are a build-time snapshot of:
- `schemas/`
- `orgs/`
- `agents/definitions/`
- `skills/contracts/` (optional; may be empty in build mode)
