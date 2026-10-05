"""Finding queries and lifecycle management."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cloudaegis_engine.compliance import FRAMEWORKS, get_framework
from cloudaegis_engine.compliance.catalog import controls_for_rule
from cloudaegis_engine.models import Resource
from cloudaegis_engine.remediation import build_plan
from cloudaegis_engine.rules import default_registry
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import AppError, NotFoundError
from app.models import ACTIVE_STATUSES, Asset, CloudAccount, Finding, FindingEvent, FindingStatus, SecurityRule
from app.schemas.common import PageParams, make_page
from app.services import audit
from app.services.context import Actor

SEVERITY_ORDER = case(
    {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}, value=Finding.severity, else_=5
)
STATUS_ORDER = case(
    {"OPEN": 0, "IN_PROGRESS": 1, "ACKNOWLEDGED": 2, "SUPPRESSED": 3, "RESOLVED": 4}, value=Finding.status, else_=5
)
SORTS = {
    "severity": SEVERITY_ORDER,
    "first_detected": Finding.first_detected_at,
    "last_detected": Finding.last_detected_at,
    "service": Finding.service,
    "region": Finding.region,
    "rule": Finding.rule_id,
    "status": STATUS_ORDER,
    "title": Finding.title,
}

ACTIONS = {
    FindingStatus.ACKNOWLEDGED.value: "finding.acknowledged",
    FindingStatus.IN_PROGRESS.value: "finding.in_progress",
    FindingStatus.RESOLVED.value: "finding.resolved",
    FindingStatus.SUPPRESSED.value: "finding.suppressed",
    FindingStatus.OPEN.value: "finding.reopened",
}


def summary(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id, "display_id": f.display_id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
        "status": f.status, "service": f.service, "region": f.region,
        "category": f.rule.category if f.rule else "", "asset_id": f.asset_id,
        "asset_name": f.asset.name if f.asset else "", "resource_uid": f.asset.resource_uid if f.asset else "",
        "resource_type": f.asset.resource_type if f.asset else "", "account_id": f.cloud_account_id,
        "account_name": f.account.name if f.account else "", "first_detected_at": f.first_detected_at,
        "last_detected_at": f.last_detected_at, "public_exposure": bool(f.asset and f.asset.public_exposure),
        "ticket_ref": f.ticket_ref,
    }


def _rule_ids_for_compliance(framework_key: str, control_id: str | None) -> list[str]:
    framework = get_framework(framework_key)
    if framework is None:
        raise AppError("Unknown compliance framework", code="validation_error", status_code=422)
    if control_id:
        control = framework.control(control_id)
        return list(control.rule_ids) if control else []
    return sorted(framework.rule_ids())


def build_query(
    *,
    q: str | None = None,
    severity: list[str] | None = None,
    status: list[str] | None = None,
    service: list[str] | None = None,
    region: list[str] | None = None,
    account_id: int | None = None,
    rule_id: list[str] | None = None,
    framework: str | None = None,
    control: str | None = None,
    asset_id: int | None = None,
    detected_from: datetime | None = None,
    detected_to: datetime | None = None,
    public_only: bool = False,
):
    stmt = select(Finding).join(Asset, Finding.asset_id == Asset.id)
    if q:
        like = f"%{q.strip()}%"
        conditions = [Finding.title.ilike(like), Finding.rule_id.ilike(like), Asset.name.ilike(like),
                      Asset.resource_uid.ilike(like)]
        digits = q.upper().removeprefix("FND-").lstrip("0")
        if digits.isdigit():
            conditions.append(Finding.id == int(digits))
        stmt = stmt.where(or_(*conditions))
    if severity:
        stmt = stmt.where(Finding.severity.in_(severity))
    if status:
        stmt = stmt.where(Finding.status.in_(status))
    if service:
        stmt = stmt.where(Finding.service.in_(service))
    if region:
        stmt = stmt.where(Finding.region.in_(region))
    if account_id:
        stmt = stmt.where(Finding.cloud_account_id == account_id)
    if rule_id:
        stmt = stmt.where(Finding.rule_id.in_(rule_id))
    if framework:
        stmt = stmt.where(Finding.rule_id.in_(_rule_ids_for_compliance(framework, control)))
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if detected_from:
        stmt = stmt.where(Finding.first_detected_at >= detected_from)
    if detected_to:
        stmt = stmt.where(Finding.first_detected_at <= detected_to)
    if public_only:
        stmt = stmt.where(Asset.public_exposure.is_(True))
    return stmt


def list_findings(db: Session, params: PageParams, sort: str = "severity", order: str = "asc", **filters: Any) -> dict:
    stmt = build_query(**filters)
    total = db.scalar(select(func.count()).select_from(stmt.with_only_columns(Finding.id).subquery())) or 0
    column = SORTS.get(sort, SEVERITY_ORDER)
    primary = column.desc() if order == "desc" else column.asc()
    rows = db.scalars(stmt.order_by(primary, SEVERITY_ORDER, Finding.last_detected_at.desc(), Finding.id)
                      .offset(params.offset).limit(params.page_size)).unique().all()
    return make_page([summary(f) for f in rows], total, params)


def facets(db: Session, account_id: int | None = None, status: list[str] | None = None) -> dict[str, Any]:
    base = select(Finding)
    if account_id:
        base = base.where(Finding.cloud_account_id == account_id)
    scoped = base.where(Finding.status.in_(status or list(ACTIVE_STATUSES)))

    def counts(column, stmt=scoped):
        sub = stmt.subquery()
        col = sub.c[column.key]
        rows = db.execute(select(col, func.count()).group_by(col).order_by(func.count().desc())).all()
        return [{"value": v, "count": c} for v, c in rows]

    return {
        "severity": counts(Finding.severity),
        "status": counts(Finding.status, base),
        "service": counts(Finding.service),
        "region": counts(Finding.region),
        "rule": counts(Finding.rule_id),
    }


def get_finding(db: Session, finding_id: int) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise NotFoundError("Finding not found")
    return finding


def detail(db: Session, finding_id: int) -> dict[str, Any]:
    f = get_finding(db, finding_id)
    rule = default_registry().get(f.rule_id)
    resource = None
    if f.asset:
        resource = Resource(uid=f.asset.resource_uid, resource_type=f.asset.resource_type, service=f.asset.service,
                            name=f.asset.name, region=f.asset.region,
                            account_id=f.account.account_identifier if f.account else "",
                            properties=f.asset.properties or {})
    plan = build_plan(rule.metadata, resource).as_dict() if rule else {
        "summary": f.rule.remediation, "steps": f.rule.remediation_steps or [f.rule.remediation],
        "cli_example": f.rule.remediation_cli, "automated": False}
    events = db.scalars(select(FindingEvent).where(FindingEvent.finding_id == f.id)
                        .order_by(FindingEvent.created_at.desc(), FindingEvent.id.desc()).limit(100)).all()
    return {
        **summary(f),
        "description": f.rule.description,
        "impact": f.rule.impact,
        "message": f.message,
        "evidence": f.evidence or {},
        "remediation": plan,
        "references": f.rule.references or [],
        "compliance": [
            {"framework_key": fw.key, "framework": fw.short_name, "control_id": c.control_id, "title": c.title}
            for fw, c in controls_for_rule(f.rule_id)
        ],
        "suppression_reason": f.suppression_reason,
        "resolved_at": f.resolved_at,
        "status_changed_at": f.status_changed_at,
        "account_identifier": f.account.account_identifier if f.account else None,
        "events": [
            {"id": e.id, "event_type": e.event_type, "from_status": e.from_status, "to_status": e.to_status,
             "note": e.note, "user": e.user.email if e.user else None, "scan_id": e.scan_id, "created_at": e.created_at}
            for e in events
        ],
    }


def _apply_status(db: Session, f: Finding, status: str, note: str | None, actor: Actor) -> bool:
    if status == f.status:
        return False
    if status == FindingStatus.SUPPRESSED.value and not (note and note.strip()):
        raise AppError("A justification is required to suppress a finding", code="validation_error",
                       status_code=422, details=[{"field": "note", "message": "required for suppression"}])
    now = datetime.now(timezone.utc)
    previous = f.status
    f.status = status
    f.status_changed_at = now
    f.resolved_at = now if status == FindingStatus.RESOLVED.value else None
    f.suppression_reason = note.strip() if status == FindingStatus.SUPPRESSED.value and note else (
        None if status != FindingStatus.SUPPRESSED.value else f.suppression_reason)
    db.add(FindingEvent(finding_id=f.id, event_type="status_changed", from_status=previous, to_status=status,
                        note=note, user_id=actor.user_id, created_at=now))
    audit.record(db, actor, ACTIONS[status], resource_type="finding", resource_id=f.display_id,
                 details={"from": previous, "to": status, "rule_id": f.rule_id, "note": note})
    return True


def update_status(db: Session, finding_id: int, status: str, note: str | None, actor: Actor) -> Finding:
    f = get_finding(db, finding_id)
    _apply_status(db, f, status, note, actor)
    db.commit()
    return f


def bulk_update(db: Session, ids: list[int], status: str, note: str | None, actor: Actor) -> int:
    findings = db.scalars(select(Finding).where(Finding.id.in_(ids))).unique().all()
    if len(findings) != len(set(ids)):
        raise NotFoundError("One or more findings were not found")
    changed = sum(_apply_status(db, f, status, note, actor) for f in findings)
    db.commit()
    return changed


def add_comment(db: Session, finding_id: int, note: str, actor: Actor) -> None:
    f = get_finding(db, finding_id)
    db.add(FindingEvent(finding_id=f.id, event_type="comment", note=note, user_id=actor.user_id))
    audit.record(db, actor, "finding.commented", resource_type="finding", resource_id=f.display_id)
    db.commit()


def link_ticket(db: Session, finding_id: int, ticket_ref: str, note: str | None, actor: Actor) -> Finding:
    f = get_finding(db, finding_id)
    f.ticket_ref = ticket_ref
    db.add(FindingEvent(finding_id=f.id, event_type="ticket_linked", note=f"{ticket_ref}" + (f" — {note}" if note else ""),
                        user_id=actor.user_id))
    if f.status in (FindingStatus.OPEN.value, FindingStatus.ACKNOWLEDGED.value):
        _apply_status(db, f, FindingStatus.IN_PROGRESS.value, f"Tracked in {ticket_ref}", actor)
    audit.record(db, actor, "finding.ticket_linked", resource_type="finding", resource_id=f.display_id,
                 details={"ticket": ticket_ref})
    db.commit()
    return f


def ticket_draft(db: Session, finding_id: int) -> dict[str, str]:
    d = detail(db, finding_id)
    steps = "\n".join(f"{i}. {s}" for i, s in enumerate(d["remediation"]["steps"], 1))
    compliance = ", ".join(f"{c['framework']} {c['control_id']}" for c in d["compliance"]) or "—"
    cli = f"\n\nExample command (review before running):\n{d['remediation']['cli_example']}" if d["remediation"]["cli_example"] else ""
    body = (
        f"*{d['severity']}* — {d['title']} ({d['rule_id']})\n\n"
        f"Finding: {d['display_id']}\nResource: {d['resource_uid']}\nAccount: {d['account_name']} "
        f"({d['account_identifier']})\nRegion: {d['region']}\nFirst detected: {d['first_detected_at']:%Y-%m-%d %H:%M UTC}\n\n"
        f"Description:\n{d['description']}\n\nImpact:\n{d['impact']}\n\nRemediation:\n{steps}{cli}\n\n"
        f"Compliance: {compliance}"
    )
    return {"title": f"[{d['severity']}] {d['title']} — {d['asset_name']}", "body": body}


def framework_rule_options() -> list[dict[str, str]]:
    return [{"key": f.key, "name": f.short_name} for f in FRAMEWORKS]


def accounts_lookup(db: Session) -> dict[int, CloudAccount]:
    return {a.id: a for a in db.scalars(select(CloudAccount)).all()}


def rule_lookup(db: Session) -> dict[str, SecurityRule]:
    return {r.rule_id: r for r in db.scalars(select(SecurityRule)).all()}
