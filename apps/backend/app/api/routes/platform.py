"""Dashboard, analytics, audit, notifications, rules, settings and search."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from cloudaegis_engine.compliance.catalog import controls_for_rule
from cloudaegis_engine.resource_types import SERVICE_ORDER
from fastapi import APIRouter, Body, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth, page_params, require
from app.core.config import get_settings
from app.core.database import get_db
from app.core.errors import NotFoundError
from app.core.permissions import Perm
from app.models import ACTIVE_STATUSES, Finding, SecurityRule
from app.schemas.common import Message, Page, PageParams
from app.schemas.misc import (
    AuditLogOut,
    NotificationOut,
    RuleOut,
    RuleToggle,
    SearchResults,
    SettingsOut,
    SettingsUpdate,
)
from app.services import audit, dashboard, notifications, search as search_service, settings as app_settings

router = APIRouter(tags=["platform"])


# Dashboard & analytics -------------------------------------------------------
@router.get("/dashboard/summary", tags=["dashboard"])
def dashboard_summary(account_id: int | None = None, _: AuthContext = Depends(require(Perm.FINDINGS_READ)),
                      db: Session = Depends(get_db)) -> dict:
    return dashboard.summary(db, account_id)


@router.get("/analytics/trends", tags=["analytics"])
def analytics_trends(account_id: int | None = None, days: int = Query(90, ge=7, le=365),
                     _: AuthContext = Depends(require(Perm.FINDINGS_READ)), db: Session = Depends(get_db)) -> dict:
    return dashboard.trends(db, account_id, days)


@router.get("/analytics/risk", tags=["analytics"])
def analytics_risk(account_id: int | None = None, _: AuthContext = Depends(require(Perm.FINDINGS_READ)),
                   db: Session = Depends(get_db)) -> dict:
    return dashboard.risk(db, account_id)


# Search -----------------------------------------------------------------------
@router.get("/search", response_model=SearchResults, tags=["search"])
def search(q: str = Query(..., min_length=2, max_length=200), ctx: AuthContext = Depends(get_auth),
           db: Session = Depends(get_db)) -> dict:
    return search_service.search(db, ctx.user, q)


# Audit ------------------------------------------------------------------------
@router.get("/audit", response_model=Page[AuditLogOut], tags=["audit"])
def audit_logs(params: PageParams = Depends(page_params), q: str | None = Query(None, max_length=200),
               action: str | None = Query(None, max_length=64), user: str | None = Query(None, max_length=254),
               result: Literal["success", "failure", "denied"] | None = None,
               resource_type: str | None = Query(None, max_length=32), since: datetime | None = None,
               until: datetime | None = None, _: AuthContext = Depends(require(Perm.AUDIT_READ)),
               db: Session = Depends(get_db)) -> dict:
    return audit.query(db, params, q=q, action=action, user=user, result=result, resource_type=resource_type,
                       since=since, until=until)


@router.get("/audit/facets", tags=["audit"])
def audit_facets(_: AuthContext = Depends(require(Perm.AUDIT_READ)), db: Session = Depends(get_db)) -> dict:
    return audit.facets(db)


# Notifications ----------------------------------------------------------------
@router.get("/notifications", tags=["notifications"])
def list_notifications(ctx: AuthContext = Depends(get_auth), db: Session = Depends(get_db)) -> dict:
    data = notifications.list_for_user(db, ctx.user.id)
    return {"items": [NotificationOut.model_validate(n).model_dump() for n in data["items"]], "unread": data["unread"]}


@router.post("/notifications/read", response_model=Message, tags=["notifications"])
def read_notifications(ids: list[int] | None = Body(default=None, embed=True), ctx: AuthContext = Depends(get_auth),
                       db: Session = Depends(get_db)) -> dict:
    notifications.mark_read(db, ctx.user.id, ids)
    return {"message": "ok"}


# Rules ------------------------------------------------------------------------
def _rule_out(rule: SecurityRule, open_count: int) -> dict:
    return {
        "rule_id": rule.rule_id, "title": rule.title, "severity": rule.severity, "service": rule.service,
        "category": rule.category, "resource_type": rule.resource_type, "description": rule.description,
        "impact": rule.impact, "remediation": rule.remediation, "remediation_steps": rule.remediation_steps or [],
        "remediation_cli": rule.remediation_cli, "references": rule.references or [], "enabled": rule.enabled,
        "compliance": [{"framework": fw.short_name, "control_id": c.control_id} for fw, c in controls_for_rule(rule.rule_id)],
        "open_findings": open_count,
    }


@router.get("/rules", response_model=list[RuleOut], tags=["rules"])
def list_rules(_: AuthContext = Depends(require(Perm.RULES_READ)), db: Session = Depends(get_db)) -> list[dict]:
    counts = dict(db.execute(select(Finding.rule_id, func.count()).where(Finding.status.in_(ACTIVE_STATUSES))
                             .group_by(Finding.rule_id)).all())
    rules = db.scalars(select(SecurityRule).order_by(SecurityRule.rule_id)).all()
    return [_rule_out(r, counts.get(r.rule_id, 0)) for r in rules]


@router.patch("/rules/{rule_id}", response_model=RuleOut, tags=["rules"])
def toggle_rule(rule_id: str, data: RuleToggle, ctx: AuthContext = Depends(require(Perm.SETTINGS_MANAGE)),
                db: Session = Depends(get_db)) -> dict:
    rule = db.scalar(select(SecurityRule).where(SecurityRule.rule_id == rule_id))
    if rule is None:
        raise NotFoundError("Rule not found")
    if rule.enabled != data.enabled:
        rule.enabled = data.enabled
        audit.record(db, ctx.actor, "settings.rule_toggled", resource_type="rule", resource_id=rule_id,
                     details={"enabled": data.enabled})
        db.commit()
    return _rule_out(rule, 0)


# Settings ---------------------------------------------------------------------
def _settings_out(db: Session) -> dict:
    s = get_settings()
    return {
        "thresholds": app_settings.get(db, "thresholds"),
        "scan_services": app_settings.get(db, "scanning")["services"],
        "available_services": list(SERVICE_ORDER),
        "notify_on_critical": app_settings.get(db, "notifications")["notify_on_critical"],
        "session_idle_minutes": s.session_idle_minutes,
        "demo_mode": s.demo_mode,
    }


@router.get("/settings", response_model=SettingsOut, tags=["settings"])
def get_platform_settings(_: AuthContext = Depends(get_auth), db: Session = Depends(get_db)) -> dict:
    return _settings_out(db)


@router.patch("/settings", response_model=SettingsOut, tags=["settings"])
def update_platform_settings(data: SettingsUpdate, ctx: AuthContext = Depends(require(Perm.SETTINGS_MANAGE)),
                             db: Session = Depends(get_db)) -> dict:
    changes = {}
    if data.thresholds is not None:
        merged = {**app_settings.get(db, "thresholds"), **app_settings.validate_thresholds(data.thresholds)}
        app_settings.put(db, "thresholds", merged, ctx.user.id)
        changes["thresholds"] = merged
    if data.scan_services is not None:
        services = app_settings.validate_services(data.scan_services)
        app_settings.put(db, "scanning", {"services": services}, ctx.user.id)
        changes["scan_services"] = services
    if data.notify_on_critical is not None:
        app_settings.put(db, "notifications", {"notify_on_critical": data.notify_on_critical}, ctx.user.id)
        changes["notify_on_critical"] = data.notify_on_critical
    if changes:
        audit.record(db, ctx.actor, "settings.modified", resource_type="settings", details=changes)
        db.commit()
    return _settings_out(db)
