#!/usr/bin/env bash
# Run CloudAegis locally without Docker (needs PostgreSQL 14+, Redis optional).
#   ./scripts/dev.sh setup   # install dependencies, migrate, seed demo data
#   ./scripts/dev.sh api     # API on :8000 (scans run in-process)
#   ./scripts/dev.sh web     # Vite dev server on :5173 (proxies /api to :8000)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="$ROOT/apps/backend:$ROOT/packages/security-engine"
export SCAN_EXECUTOR="${SCAN_EXECUTOR:-inprocess}"
export COOKIE_SECURE="${COOKIE_SECURE:-false}"
export LOG_JSON="${LOG_JSON:-false}"

case "${1:-}" in
  setup)
    python3 -m pip install -r "$ROOT/apps/backend/requirements-dev.txt"
    (cd "$ROOT/apps/frontend" && npm ci)
    (cd "$ROOT/apps/backend" && alembic upgrade head && python3 -m app.cli bootstrap)
    ;;
  api)
    cd "$ROOT/apps/backend" && exec uvicorn app.main:app --reload --port 8000
    ;;
  worker)
    cd "$ROOT/apps/backend" && SCAN_EXECUTOR=rq exec python3 -m app.workers.worker
    ;;
  web)
    cd "$ROOT/apps/frontend" && exec npm run dev
    ;;
  *)
    echo "usage: $0 {setup|api|worker|web}" >&2
    exit 1
    ;;
esac
