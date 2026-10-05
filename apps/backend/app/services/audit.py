"""Audit trail recording and querying."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models import AuditLog
from app.schemas.common import PageParams, make_page
from app.services.context import Actor

SENSITIVE_KEYS = {"password", "secret_access_key", "session_token", "external_id", "token", "credentials"}


def _scrub(details: dict[str, Any] | None) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in (details or {}).items():
        if key.lower() in SENSITIVE_KEYS:
            clean[key] = "[REDACTED]"
        elif isinstance(value, dict):
            clean[key] = _scrub(value)
        else:
            clean[key] = value
    return clean


def record(
    db: Session,
    actor: Actor,
    action: str,
    *,
    resource_type: str | None = None,
    resource_id: str | int | None = None,
    result: str = "success",
    details: dict[str, Any] | None = None,
    email: str | None = None,
) -> AuditLog:
    """Add an audit entry to the caller's transaction."""
    entry = AuditLog(
        user_id=actor.user_id,
        user_email=email or actor.email,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        result=result,
        ip_address=actor.ip_address,
        user_agent=actor.user_agent,
        request_id=actor.request_id,
        details=_scrub(details),
    )
    db.add(entry)
    return entry


def record_now(actor: Actor, action: str, **kwargs: Any) -> None:
    """Write an audit entry in its own transaction (survives caller rollback,
    used for failed logins and denied requests)."""
    with SessionLocal() as db:
        record(db, actor, action, **kwargs)
        db.commit()


def query(
    db: Session,
    params: PageParams,
    *,
    q: str | None = None,
    action: str | None = None,
    user: str | None = None,
    result: str | None = None,
    resource_type: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> dict:
    stmt = select(AuditLog)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(AuditLog.action.ilike(like), AuditLog.user_email.ilike(like),
                              AuditLog.resource_id.ilike(like), AuditLog.ip_address.ilike(like)))
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if user:
        stmt = stmt.where(AuditLog.user_email == user)
    if result:
        stmt = stmt.where(AuditLog.result == result)
    if resource_type:
        stmt = stmt.where(AuditLog.resource_type == resource_type)
    if since:
        stmt = stmt.where(AuditLog.timestamp >= since)
    if until:
        stmt = stmt.where(AuditLog.timestamp <= until)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
                      .offset(params.offset).limit(params.page_size)).all()
    return make_page(list(rows), total, params)


def facets(db: Session) -> dict[str, list[str]]:
    actions = db.scalars(select(AuditLog.action).distinct().order_by(AuditLog.action)).all()
    users = db.scalars(select(AuditLog.user_email).where(AuditLog.user_email.is_not(None)).distinct()
                       .order_by(AuditLog.user_email)).all()
    return {"actions": list(actions), "users": list(users), "results": ["success", "failure", "denied"]}
