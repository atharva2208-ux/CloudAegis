"""Request dependencies: authentication, CSRF, RBAC, pagination."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, Query, Request
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.errors import AuthenticationError, PermissionDeniedError
from app.core.logging import user_ctx
from app.core.permissions import Perm
from app.core.security import constant_time_equals, hash_token
from app.models import User, UserSession
from app.schemas.common import PageParams
from app.services import audit
from app.services.auth import resolve_session
from app.services.context import Actor, actor_from_request

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_HEADER = "X-CSRF-Token"


@dataclass
class AuthContext:
    user: User
    session: UserSession
    via_cookie: bool
    actor: Actor


def _extract_token(request: Request) -> tuple[str | None, bool]:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip(), False
    return request.cookies.get(get_settings().session_cookie_name), True


def get_auth(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    token, via_cookie = _extract_token(request)
    resolved = resolve_session(db, token)
    if resolved is None:
        raise AuthenticationError("Authentication required")
    if via_cookie and request.method not in SAFE_METHODS:
        # Double-submit token bound to the server-side session.
        header = request.headers.get(CSRF_HEADER)
        if not header or not constant_time_equals(hash_token(header), resolved.session.csrf_hash):
            raise PermissionDeniedError("Missing or invalid CSRF token", code="csrf_failed")
    user_ctx.set(resolved.user.email)
    return AuthContext(user=resolved.user, session=resolved.session, via_cookie=via_cookie,
                       actor=actor_from_request(request, resolved.user))


def require(*permissions: Perm) -> Callable[..., AuthContext]:
    def dependency(request: Request, ctx: AuthContext = Depends(get_auth)) -> AuthContext:
        missing = [p.value for p in permissions if not ctx.user.has(p.value)]
        if missing:
            audit.record_now(ctx.actor, "access.denied", result="denied", resource_type="endpoint",
                             resource_id=f"{request.method} {request.url.path}"[:128], details={"missing": missing})
            raise PermissionDeniedError("You do not have permission to perform this action")
        return ctx

    return dependency


def page_params(page: int = Query(1, ge=1, le=100000), page_size: int = Query(25, ge=1, le=200)) -> PageParams:
    return PageParams(page=page, page_size=page_size)
