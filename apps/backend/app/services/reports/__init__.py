"""Report generation (PDF / JSON / CSV)."""

from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AppError, NotFoundError
from app.models import CloudAccount, Report
from app.schemas.misc import ReportCreate
from app.services import audit
from app.services.context import Actor
from app.services.reports.data import build_report_data
from app.services.reports.exporters import to_csv, to_json
from app.services.reports.pdf import to_pdf

CONTENT_TYPES = {"pdf": "application/pdf", "json": "application/json", "csv": "text/csv"}


def report_out(r: Report) -> dict[str, Any]:
    return {
        "id": r.id, "title": r.title, "report_type": r.report_type, "format": r.format, "status": r.status,
        "account_id": r.cloud_account_id, "account_name": r.account.name if r.account else None, "scan_id": r.scan_id,
        "generated_by": r.generated_by.email if r.generated_by else None, "size_bytes": r.size_bytes,
        "sha256": r.sha256, "created_at": r.created_at,
    }


def generate(db: Session, data: ReportCreate, actor: Actor) -> Report:
    if data.account_id and db.get(CloudAccount, data.account_id) is None:
        raise NotFoundError("Cloud account not found")
    payload = build_report_data(db, data.account_id, data.report_type, data.severities, data.title,
                                generated_by=actor.email)
    if not payload["scans"]:
        raise AppError("No completed scan is available yet for this scope — run a scan first",
                       code="no_scan_data", status_code=409)
    if data.format == "pdf":
        content = to_pdf(payload)
    elif data.format == "json":
        content = to_json(payload)
    else:
        content = to_csv(payload)
    report = Report(title=data.title, report_type=data.report_type, format=data.format,
                    cloud_account_id=data.account_id, scan_id=payload["scans"][0]["id"],
                    generated_by_id=actor.user_id, parameters=data.model_dump(mode="json"),
                    size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest(), content=content)
    db.add(report)
    db.flush()
    audit.record(db, actor, "report.generated", resource_type="report", resource_id=report.id,
                 details={"title": data.title, "format": data.format, "type": data.report_type,
                          "account_id": data.account_id})
    db.commit()
    db.refresh(report)
    return report


def list_reports(db: Session, limit: int = 100) -> list[Report]:
    return list(db.scalars(select(Report).order_by(Report.created_at.desc()).limit(limit)).all())


def get_content(db: Session, report_id: int, actor: Actor) -> tuple[Report, bytes]:
    report = db.get(Report, report_id)
    if report is None or report.content is None:
        raise NotFoundError("Report not found")
    audit.record(db, actor, "report.downloaded", resource_type="report", resource_id=report.id)
    db.commit()
    return report, report.content


def delete(db: Session, report_id: int, actor: Actor) -> None:
    report = db.get(Report, report_id)
    if report is None:
        raise NotFoundError("Report not found")
    audit.record(db, actor, "report.deleted", resource_type="report", resource_id=report.id,
                 details={"title": report.title})
    db.delete(report)
    db.commit()
