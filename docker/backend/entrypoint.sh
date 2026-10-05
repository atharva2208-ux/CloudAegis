#!/bin/sh
# CloudAegis container entrypoint.
#   api     – wait for PostgreSQL, apply migrations, bootstrap catalog/admin/demo, serve the API
#   worker  – run the RQ scan worker (no migrations; the api container owns them)
#   migrate – apply migrations and exit
set -eu

wait_for_database() {
  python - <<'PY'
import sys, time
from sqlalchemy import create_engine, text
from app.core.config import get_settings

engine = create_engine(get_settings().database_url, pool_pre_ping=True)
for attempt in range(60):
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001
        print(f"waiting for database ({type(exc).__name__})", flush=True)
        time.sleep(2)
sys.exit("database did not become available")
PY
}

case "${1:-api}" in
  api)
    wait_for_database
    alembic upgrade head
    python -m app.cli bootstrap
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers \
      --forwarded-allow-ips="${FORWARDED_ALLOW_IPS:-*}" --workers "${API_WORKERS:-2}" --no-server-header
    ;;
  worker)
    wait_for_database
    exec python -m app.workers.worker
    ;;
  migrate)
    wait_for_database
    exec alembic upgrade head
    ;;
  *)
    exec "$@"
    ;;
esac
