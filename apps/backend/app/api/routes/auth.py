from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth
from app.core.config import get_settings
from app.core.database import get_db
from app.schemas.auth import ChangePasswordRequest, LoginRequest, SessionOut, UserOut
from app.schemas.common import Message
from app.services import auth as auth_service, users as user_service
from app.services.context import actor_from_request

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_cookies(response: Response, token: str, csrf: str, max_age: int) -> None:
    s = get_settings()
    common = dict(secure=s.cookie_secure, samesite="strict", domain=s.cookie_domain, path="/", max_age=max_age)
    response.set_cookie(s.session_cookie_name, token, httponly=True, **common)
    response.set_cookie(s.csrf_cookie_name, csrf, httponly=False, **common)


def _clear_cookies(response: Response) -> None:
    s = get_settings()
    for name in (s.session_cookie_name, s.csrf_cookie_name):
        response.delete_cookie(name, path="/", domain=s.cookie_domain, secure=s.cookie_secure, samesite="strict")


@router.post("/login", response_model=SessionOut, summary="Sign in and start a session")
def login(data: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    actor = actor_from_request(request, None)
    issued = auth_service.login(db, data.email, data.password, actor)
    s = get_settings()
    _set_cookies(response, issued.token, issued.csrf_token, s.session_absolute_minutes * 60)
    return {"user": user_service.to_out(issued.user), "csrf_token": issued.csrf_token,
            "expires_at": issued.expires_at, "idle_timeout_minutes": s.session_idle_minutes}


@router.post("/logout", response_model=Message)
def logout(response: Response, ctx: AuthContext = Depends(get_auth), db: Session = Depends(get_db)) -> dict:
    auth_service.logout(db, ctx.session, ctx.actor)
    _clear_cookies(response)
    return {"message": "Signed out"}


@router.get("/me", response_model=SessionOut, summary="Current user and a fresh CSRF token")
def me(response: Response, ctx: AuthContext = Depends(get_auth), db: Session = Depends(get_db)) -> dict:
    s = get_settings()
    csrf = auth_service.rotate_csrf(db, ctx.session)
    if ctx.via_cookie:
        response.set_cookie(s.csrf_cookie_name, csrf, httponly=False, secure=s.cookie_secure, samesite="strict",
                            domain=s.cookie_domain, path="/")
    return {"user": user_service.to_out(ctx.user), "csrf_token": csrf, "expires_at": ctx.session.expires_at,
            "idle_timeout_minutes": s.session_idle_minutes}


@router.post("/change-password", response_model=Message)
def change_password(data: ChangePasswordRequest, ctx: AuthContext = Depends(get_auth),
                    db: Session = Depends(get_db)) -> dict:
    user_service.change_password(db, ctx.user, data.current_password, data.new_password, ctx.actor, ctx.session.jti)
    return {"message": "Password updated. Other sessions were signed out."}


@router.get("/demo-info", summary="Demo sign-in hints (only in demo mode)")
def demo_info() -> dict:
    s = get_settings()
    if not s.demo_mode:
        return {"demo_mode": False, "password": None, "accounts": []}
    from app.services.demo import DEMO_PASSWORD, DEMO_USERS

    # The admin uses the demo password only when the operator did not set one.
    accounts = ([] if s.seed_admin_password else [{"email": s.seed_admin_email, "role": "ADMIN"}]) + [
        {"email": e, "role": r.value} for e, _, r in DEMO_USERS]
    return {"demo_mode": True, "password": DEMO_PASSWORD, "accounts": accounts}


__all__ = ["router", "UserOut"]
