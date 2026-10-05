"""HTTP middleware: request IDs, access logging, security headers, global rate limit."""

from __future__ import annotations

import logging
import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import get_settings
from app.core.errors import error_body
from app.core.logging import request_id_ctx, user_ctx
from app.core.rate_limit import get_rate_limiter

log = logging.getLogger("cloudaegis.http")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
MAX_BODY_BYTES = 1_000_000


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
        token = request_id_ctx.set(request_id)
        user_token = user_ctx.set(None)
        started = time.perf_counter()
        try:
            length = request.headers.get("content-length")
            if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
                response: Response = JSONResponse(error_body("payload_too_large", "Request body too large"), 413)
            else:
                try:
                    response = await call_next(request)
                except Exception:
                    # Convert here (inside the request context) so the 500 still carries
                    # the request ID and is logged with it; never echo exception details.
                    log.exception("unhandled_exception", extra={"path": request.url.path, "method": request.method})
                    response = JSONResponse(error_body(
                        "internal_error", "An unexpected error occurred. Reference the request ID when reporting it."), 500)
        finally:
            elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        response.headers["X-Request-ID"] = request_id
        if not request.url.path.startswith("/health"):
            log.info("http_request", extra={"method": request.method, "path": request.url.path,
                                            "status": response.status_code, "duration_ms": elapsed_ms,
                                            "client": request.client.host if request.client else None})
        request_id_ctx.reset(token)
        user_ctx.reset(user_token)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        headers = response.headers
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Referrer-Policy", "no-referrer")
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        if request.url.path.startswith("/api/docs") or request.url.path.startswith("/api/redoc"):
            # Swagger UI needs its CDN assets.
            headers.setdefault("Content-Security-Policy",
                               "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
                               "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data: "
                               "https://fastapi.tiangolo.com; frame-ancestors 'none'")
        else:
            headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            headers.setdefault("Cache-Control", "no-store")
        if get_settings().cookie_secure:
            headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path.startswith("/api/"):
            client = request.client.host if request.client else "unknown"
            allowed, retry = get_rate_limiter().hit(f"api:{client}", get_settings().api_rate_limit_per_minute)
            if not allowed:
                return JSONResponse(error_body("rate_limited", "Too many requests. Please slow down."), 429,
                                    headers={"Retry-After": str(retry)})
        return await call_next(request)
