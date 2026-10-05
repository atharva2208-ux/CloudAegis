"""Authentication: login with lockout, server-side sessions, logout."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AccountLockedError, AuthenticationError, RateLimitedError
from app.core.rate_limit import get_rate_limiter
from app.core.security import (
    create_session_token,
    decode_session_token,
    hash_password,
    hash_token,
    new_csrf_token,
    password_needs_rehash,
    session_expiry,
    verify_password,
)
from app.models import User, UserSession
from app.services import audit
from app.services.context import Actor

log = logging.getLogger("cloudaegis.auth")

GENERIC_LOGIN_ERROR = "Invalid email or password"
LAST_SEEN_WRITE_INTERVAL = timedelta(seconds=60)


@dataclass
class IssuedSession:
    token: str
    csrf_token: str
    expires_at: datetime
    user: User


def _now() -> datetime:
    return datetime.now(timezone.utc)


def login(db: Session, email: str, password: str, actor: Actor) -> IssuedSession:
    settings = get_settings()
    limiter = get_rate_limiter()
    email = email.strip().lower()
    ok_ip, retry_ip = limiter.hit(f"login:ip:{actor.ip_address}", settings.login_rate_limit_per_minute)
    ok_user, retry_user = limiter.hit(f"login:user:{email}", settings.login_rate_limit_per_minute)
    if not (ok_ip and ok_user):
        audit.record_now(actor, "auth.login", result="denied", email=email, details={"reason": "rate_limited"})
        raise RateLimitedError(retry_after=max(retry_ip, retry_user))

    user = db.scalar(select(User).where(User.email == email))
    now = _now()
    if user and user.locked_until and user.locked_until > now:
        audit.record_now(actor, "auth.login", result="denied", email=email, resource_type="user",
                         resource_id=user.id, details={"reason": "account_locked"})
        raise AccountLockedError("Account temporarily locked after repeated failed sign-in attempts. Try again later.")

    if not verify_password(password, user.password_hash if user else None) or not user or not user.is_active:
        if user:
            user.failed_login_attempts += 1
            locked = user.failed_login_attempts >= settings.lockout_threshold
            if locked:
                user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
                user.failed_login_attempts = 0
            db.commit()
            audit.record_now(actor, "auth.login", result="failure", email=email, resource_type="user",
                             resource_id=user.id, details={"reason": "inactive" if not user.is_active else "bad_password",
                                                           "locked": locked})
        else:
            audit.record_now(actor, "auth.login", result="failure", email=email, details={"reason": "unknown_user"})
        raise AuthenticationError(GENERIC_LOGIN_ERROR)

    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    user.last_login_ip = actor.ip_address

    expires_at = session_expiry()
    token, jti = create_session_token(user.id, user.role_name, expires_at)
    csrf = new_csrf_token()
    db.add(UserSession(user_id=user.id, jti=jti, csrf_hash=hash_token(csrf), expires_at=expires_at,
                       ip_address=actor.ip_address, user_agent=actor.user_agent))
    audit.record(db, Actor(user, actor.ip_address, actor.user_agent, actor.request_id), "auth.login",
                 resource_type="user", resource_id=user.id)
    db.commit()
    return IssuedSession(token=token, csrf_token=csrf, expires_at=expires_at, user=user)


@dataclass
class ResolvedSession:
    user: User
    session: UserSession


def resolve_session(db: Session, token: str | None) -> ResolvedSession | None:
    if not token:
        return None
    claims = decode_session_token(token)
    if not claims:
        return None
    session = db.scalar(select(UserSession).where(UserSession.jti == claims["jti"]))
    now = _now()
    if session is None or session.revoked_at is not None or session.expires_at <= now:
        return None
    idle_limit = timedelta(minutes=get_settings().session_idle_minutes)
    if now - session.last_seen_at > idle_limit:
        session.revoked_at = now
        db.commit()
        return None
    user = db.get(User, session.user_id)
    if user is None or not user.is_active or str(user.id) != claims["sub"]:
        return None
    if now - session.last_seen_at > LAST_SEEN_WRITE_INTERVAL:
        session.last_seen_at = now
        db.commit()
    return ResolvedSession(user=user, session=session)


def rotate_csrf(db: Session, session: UserSession) -> str:
    csrf = new_csrf_token()
    session.csrf_hash = hash_token(csrf)
    db.commit()
    return csrf


def logout(db: Session, session: UserSession, actor: Actor) -> None:
    session.revoked_at = _now()
    audit.record(db, actor, "auth.logout", resource_type="user", resource_id=session.user_id)
    db.commit()


def revoke_all_sessions(db: Session, user_id: int, except_jti: str | None = None) -> None:
    stmt = update(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    if except_jti:
        stmt = stmt.where(UserSession.jti != except_jti)
    db.execute(stmt.values(revoked_at=_now()))
