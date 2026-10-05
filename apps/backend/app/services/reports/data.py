"""Assemble the data model shared by every report format."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from cloudaegis_engine.compliance.catalog import controls_for_rule
from cloudaegis_engine.rules import default_registry
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ACTIVE_STATUSES, CloudAccount, Finding, Scan
from app.services import assets as asset_service, compliance as compliance_service
from app.services.dashboard import SEVERITIES, SEVERITY_WEIGHTS_BY_NAME, combined_score
from app.services.findings import SEVERITY_ORDER
from app.services.scans import latest_completed_scans

EXEC_FINDING_LIMIT = 40
TECH_FINDING_LIMIT = 5000


def _previous_score(db: Session, scan: Scan) -> int | None:
    return db.scalar(select(Scan.security_score).where(
        Scan.cloud_account_id == scan.cloud_account_id, Scan.id < scan.id, Scan.security_score.is_not(None))
        .order_by(Scan.id.desc()).limit(1))


def _narrative(score: dict | None, counts: dict[str, int], previous: int | None, public: int,
               top_rules: list[dict], compliance: list[dict]) -> list[str]:
    if not score:
        return ["No completed scan data is available."]
    paragraphs = []
    s = score["score"]
    posture = "strong" if s >= 85 else "moderate" if s >= 70 else "weak" if s >= 50 else "poor"
    trend = ""
    if previous is not None:
        delta = s - previous
        trend = (f" This is an improvement of {delta} points since the previous assessment." if delta > 0 else
                 f" This is a decline of {abs(delta)} points since the previous assessment." if delta < 0 else
                 " The score is unchanged since the previous assessment.")
    paragraphs.append(
        f"The assessed environment has a security score of {s}/100, indicating a {posture} security posture.{trend} "
        f"{score['failed_checks']:,} of {score['total_checks']:,} configuration checks failed.")
    urgent = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
    paragraphs.append(
        f"There are {sum(counts.values()):,} open findings, of which {counts.get('CRITICAL', 0)} are critical and "
        f"{counts.get('HIGH', 0)} high severity. {public} assets are directly exposed to the internet."
        + (" Critical and high findings should be remediated first; they represent the most likely paths to a breach."
           if urgent else ""))
    if top_rules:
        names = "; ".join(f"{r['title']} ({r['count']})" for r in top_rules[:3])
        paragraphs.append(f"The largest contributors to risk are: {names}.")
    if compliance:
        comp = ", ".join(f"{c['short_name']} {c['score']}%" for c in compliance)
        paragraphs.append(f"Compliance alignment: {comp}.")
    return paragraphs


def build_report_data(db: Session, account_id: int | None, report_type: str, severities: list[str] | None,
                      title: str, generated_by: str | None = None) -> dict[str, Any]:
    scans = latest_completed_scans(db, account_id)
    score = combined_score(scans)
    stmt = select(Finding).where(Finding.status.in_(ACTIVE_STATUSES))
    if account_id:
        stmt = stmt.where(Finding.cloud_account_id == account_id)
    all_open = db.scalars(stmt.order_by(SEVERITY_ORDER, Finding.first_detected_at)).unique().all()
    counts = Counter(f.severity for f in all_open)
    selected = [f for f in all_open if not severities or f.severity in severities]
    if report_type == "executive":
        selected = [f for f in selected if f.severity in ("CRITICAL", "HIGH")][:EXEC_FINDING_LIMIT]
    else:
        selected = selected[:TECH_FINDING_LIMIT]

    weighted = Counter()
    titles = {}
    for f in all_open:
        weighted[f.rule_id] += SEVERITY_WEIGHTS_BY_NAME[f.severity] or 0.1
        titles[f.rule_id] = (f.title, f.severity)
    rule_counts = Counter(f.rule_id for f in all_open)
    top_rules = [{"rule_id": r, "title": titles[r][0], "severity": titles[r][1], "count": rule_counts[r]}
                 for r, _ in weighted.most_common(10)]
    registry = default_registry()
    recommendations = []
    for entry in top_rules[:8]:
        rule = registry.get(entry["rule_id"])
        if rule:
            recommendations.append({**entry, "remediation": rule.metadata.remediation,
                                    "steps": list(rule.metadata.remediation_steps)})

    asset_stats = asset_service.stats(db, account_id)
    compliance = compliance_service.overview(db, account_id)["frameworks"]
    previous = _previous_score(db, scans[0]) if len(scans) == 1 else None
    accounts = {a.id: a for a in db.scalars(select(CloudAccount)).all()}
    top_assets = asset_service.list_assets(db, _Page(), sort="risk", order="desc", account_id=account_id,
                                           has_findings=True)["items"]

    def finding_row(f: Finding) -> dict[str, Any]:
        return {
            "id": f.display_id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity, "status": f.status,
            "service": f.service, "region": f.region, "account": f.account.name if f.account else "",
            "account_id": f.account.account_identifier if f.account else "",
            "resource": f.asset.resource_uid if f.asset else "", "resource_name": f.asset.name if f.asset else "",
            "first_detected": f.first_detected_at.isoformat(), "last_detected": f.last_detected_at.isoformat(),
            "evidence": f.evidence, "remediation": f.rule.remediation if f.rule else "",
            "impact": f.rule.impact if f.rule else "",
            "compliance": [f"{fw.short_name} {c.control_id}" for fw, c in controls_for_rule(f.rule_id)],
        }

    return {
        "title": title,
        "report_type": report_type,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": generated_by,
        "scope": accounts[account_id].name if account_id and account_id in accounts else "All connected accounts",
        "simulated": any(accounts[s.cloud_account_id].is_demo for s in scans if s.cloud_account_id in accounts),
        "score": score,
        "previous_score": previous,
        "severity_counts": {s: counts.get(s, 0) for s in SEVERITIES},
        "executive_summary": _narrative(score, counts, previous, asset_stats["public"], top_rules, compliance),
        "assets": asset_stats,
        "top_risky_assets": top_assets[:15],
        "compliance": [{k: c[k] for k in ("key", "name", "short_name", "version", "score", "passed", "failed",
                                          "not_applicable", "total")} for c in compliance],
        "top_rules": top_rules,
        "recommendations": recommendations,
        "findings": [finding_row(f) for f in selected],
        "findings_included": len(selected),
        "findings_total_open": len(all_open),
        "scans": [{
            "id": s.id, "display_id": s.display_id, "account": accounts[s.cloud_account_id].name,
            "account_identifier": accounts[s.cloud_account_id].account_identifier,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            "duration_seconds": s.duration_seconds, "regions": s.regions, "services": s.services,
            "assets": s.assets_discovered, "checks": s.checks_evaluated, "status": s.status,
            "service_errors": s.service_errors,
        } for s in scans],
        "rules_evaluated": len(registry),
    }


class _Page:
    page = 1
    page_size = 15
    offset = 0
