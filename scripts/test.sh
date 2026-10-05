#!/usr/bin/env bash
# Run every test suite. API tests need PostgreSQL; set TEST_DATABASE_URL to
# point at a disposable database (its schema is dropped and rebuilt).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
echo "== backend: unit, integration, security"
python3 -m pytest "$@"
echo "== frontend: typecheck, unit/component tests, production build"
cd apps/frontend
npx tsc -b --noEmit
npx vitest run
npm run build
