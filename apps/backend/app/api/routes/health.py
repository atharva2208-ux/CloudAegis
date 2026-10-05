from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app import __version__
from app.core.config import get_settings
from app.core.database import engine

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "cloudaegis-api", "version": __version__}


@router.get("/health/live")
def live() -> dict:
    return {"status": "alive"}


@router.get("/health/ready")
def ready() -> JSONResponse:
    checks: dict[str, str] = {}
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "unavailable"
    settings = get_settings()
    if settings.redis_url:
        try:
            import redis

            redis.Redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1).ping()
            checks["redis"] = "ok"
        except Exception:
            checks["redis"] = "unavailable" if settings.scan_executor == "rq" else "degraded"
    healthy = all(v in ("ok", "degraded") for v in checks.values())
    return JSONResponse({"status": "ready" if healthy else "not_ready", "checks": checks},
                        status_code=200 if healthy else 503)
