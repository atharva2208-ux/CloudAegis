"""Scan lifecycle: queueing, execution, and persistence of engine output."""

from __future__ import annotations

import logging
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from cloudaegis_engine import ScanEngine, ScanOutput, Severity
from cloudaegis_engine.compliance import RuleStats, evaluate_all
from cloudaegis_engine.engine import ProgressSnapshot, ScanCancelled
from cloudaegis_engine.providers import ProviderError, create_provider
from cloudaegis_engine.rules import default_registry
from cloudaegis_engine.scoring import asset_risk_score, calculate_security_score
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.errors import AppError, ConflictError, NotFoundError
from app.models import (
    ACTIVE_SCAN_STATUSES,
    ACTIVE_STATUSES,
    FINISHED_OK,
    Asset,
    AssetRelationship,
    CloudAccount,
    Finding,
    FindingEvent,
    FindingStatus,
    Scan,
    ScanResult,
    ScanStatus,
    SecurityRule,
)
from app.services import audit, notifications, settings as app_settings
from app.services.accounts import provider_config
from app.services.context import SYSTEM, Actor

log = logging.getLogger("cloudaegis.scans")

PROGRESS_WRITE_INTERVAL = 0.75


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- Queueing ---------------------------------------------------------------
def create_scan(db: Session, account_id: int, actor: Actor, regions: list[str] | None = None,
                services: list[str] | None = None, trigger: str = "manual") -> Scan:
    account = db.get(CloudAccount, account_id)
    if account is None:
        raise NotFoundError("Cloud account not found")
    if account.status == "error":
        raise AppError("The account connection is failing; re-validate credentials before scanning",
                       code="account_unhealthy", status_code=409)
    running = db.scalar(select(Scan).where(Scan.cloud_account_id == account_id, Scan.status.in_(ACTIVE_SCAN_STATUSES)))
    if running:
        raise ConflictError(f"A scan is already in progress for this account ({running.display_id})")
    enabled = account.enabled_regions
    chosen_regions = sorted(set(regions)) if regions else enabled
    invalid = set(chosen_regions) - set(enabled)
    if invalid:
        raise AppError(f"Regions not enabled for this account: {', '.join(sorted(invalid))}",
                       code="validation_error", status_code=422)
    configured = app_settings.get(db, "scanning")["services"]
    chosen_services = app_settings.validate_services(services) if services else configured
    scan = Scan(cloud_account_id=account_id, status=ScanStatus.QUEUED.value, trigger=trigger,
                triggered_by_id=actor.user_id, regions=chosen_regions, services=chosen_services,
                progress={"phase": "queued", "services": [{"service": s, "status": "pending", "percent": 0,
                                                           "resources": 0, "findings": 0, "error": None}
                                                          for s in chosen_services],
                          "assets_discovered": 0, "assets_analyzed": 0})
    db.add(scan)
    db.flush()
    audit.record(db, actor, "scan.started", resource_type="scan", resource_id=scan.id,
                 details={"account": account.name, "regions": chosen_regions, "services": chosen_services})
    db.commit()
    db.refresh(scan)
    return scan


def request_cancel(db: Session, scan_id: int, actor: Actor) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise NotFoundError("Scan not found")
    if scan.status not in ACTIVE_SCAN_STATUSES:
        raise ConflictError("Only queued or running scans can be cancelled")
    scan.cancel_requested = True
    if scan.status == ScanStatus.QUEUED.value:
        scan.status = ScanStatus.CANCELLED.value
        scan.finished_at = _now()
    audit.record(db, actor, "scan.cancelled", resource_type="scan", resource_id=scan.id)
    db.commit()
    return scan


def recover_interrupted_scans(db: Session) -> int:
    """Mark scans orphaned by a process restart as failed."""
    result = db.execute(
        update(Scan).where(Scan.status.in_(ACTIVE_SCAN_STATUSES))
        .values(status=ScanStatus.FAILED.value, error_message="Interrupted by a service restart", finished_at=_now())
    )
    db.commit()
    return result.rowcount or 0


# --- Execution --------------------------------------------------------------
class _ProgressWriter:
    def __init__(self, scan_id: int) -> None:
        self.scan_id = scan_id
        self._last = 0.0

    def __call__(self, snapshot: ProgressSnapshot) -> None:
        now = time.monotonic()
        if snapshot.phase not in ("completed",) and now - self._last < PROGRESS_WRITE_INTERVAL:
            return
        self._last = now
        with SessionLocal() as db:
            db.execute(update(Scan).where(Scan.id == self.scan_id).values(
                progress=snapshot.as_dict(), assets_discovered=snapshot.assets_discovered,
                assets_analyzed=snapshot.assets_analyzed, updated_at=_now()))
            db.commit()

    def cancelled(self) -> bool:
        with SessionLocal() as db:
            return bool(db.scalar(select(Scan.cancel_requested).where(Scan.id == self.scan_id)))


def execute_scan(scan_id: int, provider_overrides: dict[str, Any] | None = None,
                 clock: datetime | None = None) -> None:
    """Run a queued scan end-to-end. Safe to call from any worker thread/process."""
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.status != ScanStatus.QUEUED.value:
            return
        account = db.get(CloudAccount, scan.cloud_account_id)
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = clock or _now()
        db.commit()
        kind, config = provider_config(account)
        config.update(provider_overrides or {})
        thresholds = app_settings.get(db, "thresholds")
        disabled = list(db.scalars(select(SecurityRule.rule_id).where(SecurityRule.enabled.is_(False))).all())
        regions, services = list(scan.regions), list(scan.services)

    writer = _ProgressWriter(scan_id)
    log.info("scan_started", extra={"scan_id": scan_id, "provider": kind, "regions": len(regions)})
    try:
        provider = create_provider(kind, config)
        engine = ScanEngine(provider, registry=default_registry().without(disabled), context_options=thresholds,
                            now=clock)
        output = engine.run(regions=regions, services=services, progress=writer, should_cancel=writer.cancelled)
    except ScanCancelled:
        _finish_without_results(scan_id, ScanStatus.CANCELLED, "Cancelled by user")
        return
    except ProviderError as exc:
        _finish_without_results(scan_id, ScanStatus.FAILED, str(exc))
        return
    except Exception:
        log.exception("scan_failed", extra={"scan_id": scan_id})
        _finish_without_results(scan_id, ScanStatus.FAILED, "Unexpected scanner error — see server logs")
        return

    if len(output.service_errors) == len(services) and services:
        _finish_without_results(scan_id, ScanStatus.FAILED,
                                "No service could be read: " + "; ".join(f"{k}: {v}" for k, v in output.service_errors.items()))
        return

    with SessionLocal() as db:
        try:
            persist_results(db, scan_id, output, clock=clock)
            db.commit()
        except Exception:
            db.rollback()
            log.exception("scan_persist_failed", extra={"scan_id": scan_id})
            _finish_without_results(scan_id, ScanStatus.FAILED, "Failed to store scan results")
            return
    log.info("scan_completed", extra={"scan_id": scan_id, "assets": len(output.inventory),
                                      "findings": len(output.failures), "duration": round(output.duration_seconds, 2)})


def _finish_without_results(scan_id: int, status: ScanStatus, message: str) -> None:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = status.value
        scan.error_message = message[:2000]
        scan.finished_at = _now()
        if scan.started_at:
            scan.duration_seconds = (scan.finished_at - scan.started_at).total_seconds()
        audit.record(db, SYSTEM, f"scan.{status.value.lower()}", resource_type="scan", resource_id=scan.id,
                     result="failure" if status is ScanStatus.FAILED else "success", details={"message": message})
        if status is ScanStatus.FAILED:
            notifications.notify_scan(db, scan, failed=True)
        db.commit()
    log.warning("scan_finished_without_results", extra={"scan_id": scan_id, "status": status.value})


# --- Persistence ------------------------------------------------------------
def persist_results(db: Session, scan_id: int, output: ScanOutput, clock: datetime | None = None) -> Scan:
    now = clock or _now()
    scan = db.get(Scan, scan_id)
    assert scan is not None
    account_id = scan.cloud_account_id
    rules = {r.rule_id: r for r in db.scalars(select(SecurityRule)).all()}
    scanned_services = set(scan.services) - set(output.service_errors)
    scanned_regions = set(scan.regions) | {"global"}

    # 1. Assets -----------------------------------------------------------------
    existing = {a.resource_uid: a for a in db.scalars(select(Asset).where(Asset.cloud_account_id == account_id))}
    assets: dict[str, Asset] = {}
    for resource in output.inventory:
        asset = existing.get(resource.uid)
        if asset is None:
            asset = Asset(cloud_account_id=account_id, resource_uid=resource.uid, first_seen_at=now)
            db.add(asset)
        asset.resource_type = resource.resource_type
        asset.service = resource.service
        asset.name = resource.name[:512]
        asset.region = resource.region
        asset.tags = resource.tags
        asset.properties = resource.properties
        asset.public_exposure = output.exposure.get(resource.uid, False)
        asset.encryption_status = output.encryption.get(resource.uid, "not_applicable")
        asset.last_seen_at = now
        asset.is_active = True
        asset.last_scan_id = scan_id
        assets[resource.uid] = asset
    # Resources no longer present in scanned scope are retired (kept for history).
    for uid, asset in existing.items():
        if uid not in assets and asset.service in scanned_services and asset.region in scanned_regions:
            asset.is_active = False
    db.flush()

    # 2. Relationships ----------------------------------------------------------
    scanned_ids = [a.id for a in assets.values()]
    if scanned_ids:
        db.execute(AssetRelationship.__table__.delete().where(AssetRelationship.source_asset_id.in_(scanned_ids)))
    edges = set()
    for resource in output.inventory:
        source = assets[resource.uid]
        for rel in resource.relationships:
            target = assets.get(rel.target_uid) or existing.get(rel.target_uid)
            if target is not None and target.id != source.id:
                edges.add((source.id, target.id, rel.kind))
    if edges:
        db.execute(AssetRelationship.__table__.insert(),
                   [{"source_asset_id": s, "target_asset_id": t, "kind": k} for s, t, k in edges])

    # 3. Findings ---------------------------------------------------------------
    current: dict[tuple[int, int], Finding] = {
        (f.asset_id, f.security_rule_id): f
        for f in db.scalars(select(Finding).where(Finding.cloud_account_id == account_id))
    }
    failing_keys: set[tuple[int, int]] = set()
    new_count = 0
    new_critical: list[Finding] = []
    for result in output.failures:
        rule = rules.get(result.rule_id)
        asset = assets.get(result.resource_uid)
        if rule is None or asset is None:
            continue
        key = (asset.id, rule.id)
        failing_keys.add(key)
        finding = current.get(key)
        if finding is None:
            finding = Finding(cloud_account_id=account_id, asset_id=asset.id, security_rule_id=rule.id,
                              rule_id=rule.rule_id, severity=rule.severity, service=rule.service, region=asset.region,
                              title=rule.title, first_detected_at=now, status_changed_at=now,
                              status=FindingStatus.OPEN.value)
            db.add(finding)
            db.flush()
            db.add(FindingEvent(finding_id=finding.id, event_type="detected", to_status=FindingStatus.OPEN.value,
                                scan_id=scan_id, created_at=now))
            current[key] = finding
            new_count += 1
            if rule.severity == Severity.CRITICAL.value:
                new_critical.append(finding)
        elif finding.status == FindingStatus.RESOLVED.value:
            db.add(FindingEvent(finding_id=finding.id, event_type="reopened", from_status=finding.status,
                                to_status=FindingStatus.OPEN.value, scan_id=scan_id, created_at=now,
                                note="Detected again by scan"))
            finding.status = FindingStatus.OPEN.value
            finding.status_changed_at = now
            finding.resolved_at = None
        finding.severity = rule.severity
        finding.title = rule.title
        finding.evidence = result.evidence
        finding.message = result.message
        finding.last_detected_at = now
        finding.last_scan_id = scan_id

    # A finding is closed only on positive evidence: its rule was re-evaluated
    # on the resource and passed, or the resource itself disappeared from a
    # scanned scope. Findings outside this scan's scope are left untouched.
    evaluated_keys: set[tuple[int, int]] = set()
    for result in output.results:
        rule, asset = rules.get(result.rule_id), assets.get(result.resource_uid)
        if rule is not None and asset is not None:
            evaluated_keys.add((asset.id, rule.id))
    retired_assets = {a.id for a in existing.values() if not a.is_active}
    resolved_count = 0
    for key, finding in current.items():
        if key in failing_keys or finding.status not in ACTIVE_STATUSES:
            continue
        if key in evaluated_keys:
            note = "Check passed in latest scan"
        elif finding.asset_id in retired_assets:
            note = "Resource no longer exists"
        else:
            continue
        previous = finding.status
        finding.status = FindingStatus.RESOLVED.value
        finding.resolved_at = now
        finding.status_changed_at = now
        db.add(FindingEvent(finding_id=finding.id, event_type="auto_resolved", from_status=previous,
                            to_status=FindingStatus.RESOLVED.value, scan_id=scan_id, created_at=now, note=note))
        resolved_count += 1
    db.flush()

    # 4. Per-rule stats ---------------------------------------------------------
    rows = []
    for rule_id, stats in output.rule_stats.items():
        if stats.evaluated and rule_id in rules:
            rows.append({"scan_id": scan_id, "security_rule_id": rules[rule_id].id, "rule_id": rule_id,
                         "evaluated": stats.evaluated, "failed": stats.failed})
    if rows:
        db.execute(ScanResult.__table__.insert(), rows)

    # 5. Asset risk & finding counts -------------------------------------------
    open_by_asset: dict[int, list[Severity]] = defaultdict(list)
    suppressed_keys = set()
    for key, finding in current.items():
        if finding.status in ACTIVE_STATUSES:
            open_by_asset[finding.asset_id].append(Severity(finding.severity))
        elif finding.status == FindingStatus.SUPPRESSED.value:
            suppressed_keys.add(key)
    for asset in assets.values():
        severities = open_by_asset.get(asset.id, [])
        asset.open_findings = len(severities)
        asset.risk_score = asset_risk_score(severities, asset.public_exposure)

    # 6. Score, counts and compliance ------------------------------------------
    sev_counts = Counter()
    score_inputs = []
    for result in output.results:
        rule = rules.get(result.rule_id)
        asset = assets.get(result.resource_uid)
        if rule is None or asset is None:
            continue
        failing = result.failed and (asset.id, rule.id) not in suppressed_keys
        if failing:
            sev_counts[rule.severity] += 1
        score_inputs.append((Severity(rule.severity), failing))
    breakdown = calculate_security_score(score_inputs)
    compliance = [f.as_dict() for f in evaluate_all({k: RuleStats(v.evaluated, v.failed)
                                                     for k, v in output.rule_stats.items()})]

    scan.status = ScanStatus.PARTIAL.value if output.service_errors else ScanStatus.COMPLETED.value
    scan.duration_seconds = round(output.duration_seconds, 2)
    scan.finished_at = (clock + timedelta(seconds=output.duration_seconds)) if clock else _now()
    scan.assets_discovered = len(output.inventory)
    scan.assets_analyzed = len(output.inventory)
    scan.checks_evaluated = len(output.results)
    scan.findings_total = sum(sev_counts.values())
    scan.findings_new = new_count
    scan.findings_resolved = resolved_count
    scan.critical_count = sev_counts.get("CRITICAL", 0)
    scan.high_count = sev_counts.get("HIGH", 0)
    scan.medium_count = sev_counts.get("MEDIUM", 0)
    scan.low_count = sev_counts.get("LOW", 0)
    scan.info_count = sev_counts.get("INFO", 0)
    scan.public_assets = sum(1 for a in assets.values() if a.public_exposure)
    scan.security_score = breakdown.score
    scan.score_breakdown = breakdown.as_dict()
    scan.compliance_summary = compliance
    scan.service_errors = output.service_errors
    scan.progress = {**(scan.progress or {}), "phase": "completed"}
    account = db.get(CloudAccount, account_id)
    account.last_scan_at = scan.finished_at
    audit.record(db, SYSTEM, "scan.completed", resource_type="scan", resource_id=scan.id,
                 details={"score": breakdown.score, "findings": scan.findings_total, "new": new_count,
                          "resolved": resolved_count, "partial": bool(output.service_errors)})
    notifications.notify_scan(db, scan, new_critical=new_critical)
    return scan


# --- Queries ----------------------------------------------------------------
def scan_out(scan: Scan) -> dict[str, Any]:
    return {
        "id": scan.id, "display_id": scan.display_id, "account_id": scan.cloud_account_id,
        "account_name": scan.account.name if scan.account else "", "is_demo": bool(scan.account and scan.account.is_demo),
        "status": scan.status, "trigger": scan.trigger,
        "triggered_by": scan.triggered_by.email if scan.triggered_by else ("system" if scan.trigger == "seed" else None),
        "regions": scan.regions or [], "services": scan.services or [], "progress": scan.progress or {},
        "assets_discovered": scan.assets_discovered, "assets_analyzed": scan.assets_analyzed,
        "checks_evaluated": scan.checks_evaluated, "findings_total": scan.findings_total,
        "findings_new": scan.findings_new, "findings_resolved": scan.findings_resolved,
        "severity_counts": {"CRITICAL": scan.critical_count, "HIGH": scan.high_count, "MEDIUM": scan.medium_count,
                            "LOW": scan.low_count, "INFO": scan.info_count},
        "public_assets": scan.public_assets, "security_score": scan.security_score,
        "score_breakdown": scan.score_breakdown or {}, "compliance_summary": scan.compliance_summary or [],
        "service_errors": scan.service_errors or {}, "error_message": scan.error_message,
        "queued_at": scan.queued_at, "started_at": scan.started_at, "finished_at": scan.finished_at,
        "duration_seconds": scan.duration_seconds,
    }


def latest_completed_scans(db: Session, account_id: int | None = None) -> list[Scan]:
    """Most recent successful scan per account."""
    sub = (select(Scan.cloud_account_id, func.max(Scan.id).label("max_id"))
           .where(Scan.status.in_(FINISHED_OK)).group_by(Scan.cloud_account_id))
    if account_id is not None:
        sub = sub.where(Scan.cloud_account_id == account_id)
    sub = sub.subquery()
    return list(db.scalars(select(Scan).join(sub, Scan.id == sub.c.max_id)).all())


def compare(db: Session, base_id: int, target_id: int) -> dict[str, Any]:
    base, target = db.get(Scan, base_id), db.get(Scan, target_id)
    if base is None or target is None:
        raise NotFoundError("Scan not found")
    if base.cloud_account_id != target.cloud_account_id:
        raise AppError("Scans must belong to the same account", code="validation_error", status_code=422)
    if base.status not in FINISHED_OK or target.status not in FINISHED_OK:
        raise AppError("Both scans must be completed", code="validation_error", status_code=422)
    if base.id > target.id:
        base, target = target, base
    sev = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    b_out, t_out = scan_out(base), scan_out(target)
    severity_delta = {s: t_out["severity_counts"][s] - b_out["severity_counts"][s] for s in sev}
    b_comp = {c["key"]: c for c in base.compliance_summary or []}
    compliance_delta = [
        {"key": c["key"], "short_name": c["short_name"], "base": b_comp.get(c["key"], {}).get("score"),
         "target": c["score"],
         "delta": round(c["score"] - b_comp[c["key"]]["score"], 1) if c["key"] in b_comp else None}
        for c in target.compliance_summary or []
    ]
    # Findings first detected after base and up to target = new; resolved in that window = resolved.
    new_rows = db.scalars(select(Finding).where(
        Finding.cloud_account_id == base.cloud_account_id,
        Finding.first_detected_at > base.finished_at, Finding.first_detected_at <= target.finished_at)
        .order_by(Finding.severity).limit(100)).all()
    resolved_rows = db.scalars(select(Finding).where(
        Finding.cloud_account_id == base.cloud_account_id, Finding.resolved_at.is_not(None),
        Finding.resolved_at > base.finished_at, Finding.resolved_at <= target.finished_at).limit(100)).all()

    def brief(f: Finding) -> dict[str, Any]:
        return {"id": f.id, "display_id": f.display_id, "rule_id": f.rule_id, "title": f.title,
                "severity": f.severity, "asset_name": f.asset.name if f.asset else ""}

    return {
        "base": b_out, "target": t_out,
        "score_delta": (target.security_score - base.security_score)
        if target.security_score is not None and base.security_score is not None else None,
        "severity_delta": severity_delta,
        "public_assets_delta": target.public_assets - base.public_assets,
        "assets_delta": target.assets_discovered - base.assets_discovered,
        "compliance_delta": compliance_delta,
        "new_findings": [brief(f) for f in new_rows],
        "resolved_findings": [brief(f) for f in resolved_rows],
    }
