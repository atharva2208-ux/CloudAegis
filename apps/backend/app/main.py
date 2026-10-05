"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.middleware import RateLimitMiddleware, RequestContextMiddleware, SecurityHeadersMiddleware
from app.api.router import api_router
from app.api.routes import health
from app.core.config import get_settings
from app.core.database import SessionLocal
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging

log = logging.getLogger("cloudaegis")


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.services.catalog import sync_catalog
    from app.services.scans import recover_interrupted_scans

    with SessionLocal() as db:
        sync_catalog(db)
        if get_settings().scan_executor == "inprocess":
            recovered = recover_interrupted_scans(db)
            if recovered:
                log.warning("recovered_interrupted_scans", extra={"count": recovered})
    log.info("startup_complete", extra={"version": __version__, "environment": get_settings().environment})
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    app = FastAPI(
        title="CloudAegis API",
        description="Cloud Security Posture Management platform API. All cloud access is read-only.",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )
    register_exception_handlers(app)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token", "X-Request-ID", "Authorization"],
        expose_headers=["X-Request-ID", "Retry-After"],
        max_age=600,
    )
    app.add_middleware(RequestContextMiddleware)
    app.include_router(health.router)
    app.include_router(api_router)
    return app


app = create_app()
