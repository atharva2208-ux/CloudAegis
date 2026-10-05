"""Dashboard and analytics aggregations."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from cloudaegis_engine.scoring.posture import CRITICAL_PENALTY_CAP, CRITICAL_PENALTY_PER_FINDING, SEVERITY_WEIGHTS
from sqlalchemy import Float, case, cast, func, select
from sqlalchemy.orm import Session

from app.models import ACTIVE_SCAN_STATUSES, ACTIVE_STATUSES, FINISHED_OK, Asset, Finding, Scan, SecurityRule
from app.services import assets as asset_service, compliance as compliance_service
from app.services.findings import SEVERITY_ORDER, summary as finding_summary
from app.services.scans import latest_completed_scans, scan_out

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def combined_score(scans: list[Scan]) -> dict[str, Any] | None:
    """Combine per-account score breakdowns into one estate-wide score using
    the same formula as a single account (weights are additive)."""
    breakdowns = [s.score_breakdown for s in scans if s.score_breakdown]
    if not breakdowns:
        return None
    if len(breakdowns) == 1:
        return breakdowns[0]
    total_weight = sum(b["total_weight"] for b in breakdowns)
    failed_weight = sum(b["failed_weight"] for b in breakdowns)
    critical = sum(b["critical_findings"] for b in breakdowns)
    pass_rate = 1 - failed_weight / total_weight if total_weight else 1.0
    penalty = min(CRITICAL_PENALTY_CAP, critical * CRITICAL_PENALTY_PER_FINDING)
    return {
        **breakdowns[0],
        "score": max(0, min(100, round(100 * pass_rate - penalty))),
        "total_checks": sum(b["total_checks"] for b in breakdowns),
        "failed_checks": sum(b["failed_checks"] for b in breakdowns),
        "total_weight": round(total_weight, 2), "failed_weight": round(failed_weight, 2),
        "weighted_pass_rate": round(pass_rate, 4), "critical_findings": critical, "critical_penalty": penalty,
    }


def _open(account_id: int | None):
    stmt = select(Finding).where(Finding.status.in_(ACTIVE_STATUSES))
    if account_id:
        stmt = stmt.where(Finding.cloud_account_id == account_id)
    return stmt


def _scan_series(db: Session, account_id: int | None, limit: int = 30) -> list[Scan]:
    stmt = select(Scan).where(Scan.status.in_(FINISHED_OK)).order_by(Scan.finished_at.desc()).limit(limit)
    if account_id:
        stmt = stmt.where(Scan.cloud_account_id == account_id)
    return list(reversed(db.scalars(stmt).all()))


def _mfa_coverage(db: Session, account_id: int | None) -> dict[str, int]:
    stmt = select(
        func.count(),
        func.sum(case((Asset.properties["mfa_enabled"].as_string() == "true", 1), else_=0)),
    ).where(Asset.resource_type == "aws.iam.user", Asset.is_active.is_(True),
            Asset.properties["password_enabled"].as_string() == "true")
    if account_id:
        stmt = stmt.where(Asset.cloud_account_id == account_id)
    total, with_mfa = db.execute(stmt).one()
    return {"total": int(total or 0), "covered": int(with_mfa or 0)}


def summary(db: Session, account_id: int | None = None) -> dict[str, Any]:
    latest = latest_completed_scans(db, account_id)
    score = combined_score(latest)
    open_sub = _open(account_id).subquery()
    severity_counts = dict(db.execute(select(open_sub.c.severity, func.count()).group_by(open_sub.c.severity)).all())
    by_service = db.execute(
        select(open_sub.c.service, open_sub.c.severity, func.count()).group_by(open_sub.c.service, open_sub.c.severity)
    ).all()
    services: dict[str, dict[str, int]] = {}
    for service, severity, count in by_service:
        services.setdefault(service, {s: 0 for s in SEVERITIES})[severity] = count
    stats = asset_service.stats(db, account_id)
    encryptable = stats["encrypted"] + stats["unencrypted"]
    series = _scan_series(db, account_id)
    active_stmt = select(Scan).where(Scan.status.in_(ACTIVE_SCAN_STATUSES)).order_by(Scan.queued_at.desc())
    if account_id:
        active_stmt = active_stmt.where(Scan.cloud_account_id == account_id)
    top_assets = db.scalars(
        select(Asset).where(Asset.is_active.is_(True), Asset.risk_score > 0,
                            *([Asset.cloud_account_id == account_id] if account_id else []))
        .order_by(Asset.risk_score.desc(), Asset.open_findings.desc()).limit(8)).all()
    recent = db.scalars(_open(account_id).order_by(Finding.first_detected_at.desc(), SEVERITY_ORDER).limit(8)).unique().all()
    last_scan = max((s.finished_at for s in latest), default=None)
    previous = series[-2] if len(series) >= 2 else None
    return {
        "score": score,
        "previous_score": previous.security_score if previous and account_id else None,
        "severity_counts": {s: severity_counts.get(s, 0) for s in SEVERITIES},
        "open_findings": sum(severity_counts.values()),
        "assets": stats["total"],
        "public_assets": stats["public"],
        "public_by_service": [{"service": s["service"], "count": s["public"]} for s in stats["by_service"] if s["public"]],
        "encryption": {"encrypted": stats["encrypted"], "unencrypted": stats["unencrypted"],
                       "coverage": round(100 * stats["encrypted"] / encryptable, 1) if encryptable else None},
        "mfa": {**(m := _mfa_coverage(db, account_id)),
                "coverage": round(100 * m["covered"] / m["total"], 1) if m["total"] else None},
        "findings_by_service": [{"service": k, **v, "total": sum(v.values())}
                                for k, v in sorted(services.items(), key=lambda kv: -sum(kv[1].values()))],
        "score_trend": [{"scan_id": s.id, "date": s.finished_at, "score": s.security_score,
                         "account_id": s.cloud_account_id} for s in series],
        "findings_trend": [{"scan_id": s.id, "date": s.finished_at, "CRITICAL": s.critical_count, "HIGH": s.high_count,
                            "MEDIUM": s.medium_count, "LOW": s.low_count, "total": s.findings_total,
                            "new": s.findings_new, "resolved": s.findings_resolved} for s in series],
        "compliance": compliance_service.overview(db, account_id)["frameworks"],
        "top_risky_assets": [asset_service.summary(a) for a in top_assets],
        "recent_findings": [finding_summary(f) for f in recent],
        "active_scans": [scan_out(s) for s in db.scalars(active_stmt).all()],
        "last_scan_at": last_scan,
        "accounts_scanned": len(latest),
    }


def trends(db: Session, account_id: int | None = None, days: int = 90) -> dict[str, Any]:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    stmt = select(Scan).where(Scan.status.in_(FINISHED_OK), Scan.finished_at >= since).order_by(Scan.finished_at)
    if account_id:
        stmt = stmt.where(Scan.cloud_account_id == account_id)
    scans = db.scalars(stmt).all()
    mttr_stmt = (select(Finding.severity,
                        func.avg(cast(func.extract("epoch", Finding.resolved_at - Finding.first_detected_at), Float)),
                        func.count())
                 .where(Finding.resolved_at.is_not(None), Finding.status == "RESOLVED").group_by(Finding.severity))
    if account_id:
        mttr_stmt = mttr_stmt.where(Finding.cloud_account_id == account_id)
    mttr = {sev: {"hours": round((avg or 0) / 3600, 1), "resolved": count} for sev, avg, count in db.execute(mttr_stmt).all()}
    now = datetime.now(timezone.utc)
    age = func.extract("epoch", now - Finding.first_detected_at) / 86400
    buckets_stmt = select(
        func.sum(case((age <= 7, 1), else_=0)), func.sum(case(((age > 7) & (age <= 30), 1), else_=0)),
        func.sum(case(((age > 30) & (age <= 90), 1), else_=0)), func.sum(case((age > 90, 1), else_=0)),
    ).where(Finding.status.in_(ACTIVE_STATUSES))
    if account_id:
        buckets_stmt = buckets_stmt.where(Finding.cloud_account_id == account_id)
    b = db.execute(buckets_stmt).one()
    return {
        "scans": [{
            "scan_id": s.id, "display_id": s.display_id, "date": s.finished_at, "account_id": s.cloud_account_id,
            "score": s.security_score, "CRITICAL": s.critical_count, "HIGH": s.high_count, "MEDIUM": s.medium_count,
            "LOW": s.low_count, "INFO": s.info_count, "total": s.findings_total, "new": s.findings_new,
            "resolved": s.findings_resolved, "assets": s.assets_discovered, "public_assets": s.public_assets,
            "compliance": {c["short_name"]: c["score"] for c in s.compliance_summary or []},
        } for s in scans],
        "mttr": {s: mttr.get(s, {"hours": None, "resolved": 0}) for s in SEVERITIES},
        "open_age": [{"bucket": "0–7 days", "count": int(b[0] or 0)}, {"bucket": "8–30 days", "count": int(b[1] or 0)},
                     {"bucket": "31–90 days", "count": int(b[2] or 0)}, {"bucket": "90+ days", "count": int(b[3] or 0)}],
        "days": days,
    }


def risk(db: Session, account_id: int | None = None) -> dict[str, Any]:
    open_sub = _open(account_id).subquery()

    def matrix(column: str) -> list[dict[str, Any]]:
        rows = db.execute(select(open_sub.c[column], open_sub.c.severity, func.count())
                          .group_by(open_sub.c[column], open_sub.c.severity)).all()
        out: dict[str, dict[str, Any]] = {}
        for key, severity, count in rows:
            entry = out.setdefault(key, {"key": key, **{s: 0 for s in SEVERITIES}})
            entry[severity] = count
        for entry in out.values():
            entry["total"] = sum(entry[s] for s in SEVERITIES)
            entry["weighted"] = sum(entry[s] * SEVERITY_WEIGHTS_BY_NAME[s] for s in SEVERITIES)
        return sorted(out.values(), key=lambda e: -e["weighted"])

    categories = db.execute(
        select(SecurityRule.category, func.count()).join(open_sub, open_sub.c.security_rule_id == SecurityRule.id)
        .group_by(SecurityRule.category).order_by(func.count().desc())).all()
    top_rules = db.execute(
        select(open_sub.c.rule_id, open_sub.c.title, open_sub.c.severity, func.count())
        .group_by(open_sub.c.rule_id, open_sub.c.title, open_sub.c.severity)
        .order_by(func.count().desc()).limit(10)).all()
    stats = asset_service.stats(db, account_id)
    enc_stmt = select(Asset.service, Asset.encryption_status, func.count()).where(
        Asset.is_active.is_(True), Asset.encryption_status != "not_applicable").group_by(Asset.service, Asset.encryption_status)
    if account_id:
        enc_stmt = enc_stmt.where(Asset.cloud_account_id == account_id)
    enc: dict[str, dict[str, int]] = {}
    for service, status, count in db.execute(enc_stmt).all():
        enc.setdefault(service, {"encrypted": 0, "unencrypted": 0})[status] = count
    top_assets = db.scalars(
        select(Asset).where(Asset.is_active.is_(True), Asset.risk_score > 0,
                            *([Asset.cloud_account_id == account_id] if account_id else []))
        .order_by(Asset.risk_score.desc()).limit(15)).all()
    return {
        "by_service": matrix("service"),
        "by_region": matrix("region"),
        "by_category": [{"category": c, "count": n} for c, n in categories],
        "top_rules": [{"rule_id": r, "title": t, "severity": s, "count": n} for r, t, s, n in top_rules],
        "exposure_by_service": [{"service": s["service"], "public": s["public"], "total": s["count"]}
                                for s in stats["by_service"]],
        "encryption_by_service": [{"service": k, **v} for k, v in sorted(enc.items())],
        "top_risky_assets": [asset_service.summary(a) for a in top_assets],
        "severity_weights": {k.value: v for k, v in SEVERITY_WEIGHTS.items()},
    }


SEVERITY_WEIGHTS_BY_NAME = {k.value: v for k, v in SEVERITY_WEIGHTS.items()}
