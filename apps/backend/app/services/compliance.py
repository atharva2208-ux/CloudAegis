"""Compliance posture built from the latest per-rule scan statistics."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from cloudaegis_engine.compliance import FRAMEWORKS, RuleStats, evaluate_framework, get_framework
from cloudaegis_engine.rules import default_registry
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.models import ACTIVE_STATUSES, Finding, Scan, ScanResult
from app.services.findings import SEVERITY_ORDER, summary as finding_summary
from app.services.scans import latest_completed_scans


def current_rule_stats(db: Session, account_id: int | None = None) -> tuple[dict[str, RuleStats], list[Scan]]:
    scans = latest_completed_scans(db, account_id)
    totals: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    if scans:
        rows = db.execute(select(ScanResult.rule_id, func.sum(ScanResult.evaluated), func.sum(ScanResult.failed))
                          .where(ScanResult.scan_id.in_([s.id for s in scans])).group_by(ScanResult.rule_id)).all()
        for rule_id, evaluated, failed in rows:
            totals[rule_id] = [int(evaluated or 0), int(failed or 0)]
    return {k: RuleStats(v[0], v[1]) for k, v in totals.items()}, scans


def _open_counts(db: Session, account_id: int | None) -> dict[str, int]:
    stmt = select(Finding.rule_id, func.count()).where(Finding.status.in_(ACTIVE_STATUSES)).group_by(Finding.rule_id)
    if account_id:
        stmt = stmt.where(Finding.cloud_account_id == account_id)
    return dict(db.execute(stmt).all())


def _trend(scans_by_account: list[Scan], db: Session, account_id: int | None, key: str) -> list[dict[str, Any]]:
    stmt = (select(Scan).where(Scan.status.in_(("COMPLETED", "PARTIAL"))).order_by(Scan.finished_at.desc()).limit(30))
    if account_id:
        stmt = stmt.where(Scan.cloud_account_id == account_id)
    points = []
    for scan in reversed(db.scalars(stmt).all()):
        match = next((c for c in scan.compliance_summary or [] if c.get("key") == key), None)
        if match:
            points.append({"scan_id": scan.id, "date": scan.finished_at, "score": match["score"],
                           "account_id": scan.cloud_account_id})
    return points


def overview(db: Session, account_id: int | None = None) -> dict[str, Any]:
    stats, scans = current_rule_stats(db, account_id)
    frameworks = []
    for framework in FRAMEWORKS:
        result = evaluate_framework(framework, stats)
        frameworks.append({**result.as_dict(), "description": framework.description,
                           "trend": _trend(scans, db, account_id, framework.key)})
    return {"frameworks": frameworks, "assessed": bool(scans),
            "as_of": max((s.finished_at for s in scans), default=None)}


def framework_detail(db: Session, key: str, account_id: int | None = None) -> dict[str, Any]:
    framework = get_framework(key)
    if framework is None:
        raise NotFoundError("Compliance framework not found")
    stats, scans = current_rule_stats(db, account_id)
    result = evaluate_framework(framework, stats)
    open_counts = _open_counts(db, account_id)
    registry = default_registry()
    controls = []
    for cr, control in zip(result.controls, framework.controls):
        rules = []
        for rule_id in control.rule_ids:
            rule = registry.get(rule_id)
            s = stats.get(rule_id, RuleStats())
            rules.append({
                "rule_id": rule_id, "title": rule.metadata.title if rule else rule_id,
                "severity": rule.metadata.severity.value if rule else "INFO",
                "evaluated": s.evaluated, "failed": s.failed, "open_findings": open_counts.get(rule_id, 0),
                "remediation": rule.metadata.remediation if rule else "",
            })
        ratio = cr.compliance_ratio
        controls.append({
            "control_id": cr.control_id, "title": cr.title, "section": cr.section, "description": control.description,
            "status": cr.status, "compliance": round(ratio * 100, 1) if ratio is not None else None,
            "evaluated_resources": cr.evaluated_resources, "failed_resources": cr.failed_resources,
            "failing_rules": cr.failing_rules, "rules": rules,
        })
    return {**result.as_dict(), "description": framework.description, "controls": controls,
            "as_of": max((s.finished_at for s in scans), default=None),
            "trend": _trend(scans, db, account_id, key)}


def all_controls(db: Session, account_id: int | None = None, framework: str | None = None,
                 status: str | None = None, q: str | None = None) -> list[dict[str, Any]]:
    rows = []
    for fw in FRAMEWORKS:
        if framework and fw.key != framework:
            continue
        detail = framework_detail(db, fw.key, account_id)
        for control in detail["controls"]:
            if status and control["status"] != status:
                continue
            if q and q.lower() not in f"{control['control_id']} {control['title']} {control['section']}".lower():
                continue
            rows.append({"framework_key": fw.key, "framework": fw.short_name, **control})
    return rows


def control_findings(db: Session, key: str, control_id: str, account_id: int | None = None, limit: int = 50) -> list[dict]:
    framework = get_framework(key)
    control = framework.control(control_id) if framework else None
    if control is None:
        raise NotFoundError("Control not found")
    stmt = (select(Finding).where(Finding.rule_id.in_(control.rule_ids), Finding.status.in_(ACTIVE_STATUSES))
            .order_by(SEVERITY_ORDER, Finding.first_detected_at).limit(limit))
    if account_id:
        stmt = stmt.where(Finding.cloud_account_id == account_id)
    return [finding_summary(f) for f in db.scalars(stmt).unique().all()]
