from __future__ import annotations

import re

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, require
from app.core.database import get_db
from app.core.permissions import Perm
from app.schemas.common import Message
from app.schemas.misc import ReportCreate, ReportOut
from app.services import reports as report_service

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("", response_model=list[ReportOut])
def list_reports(_: AuthContext = Depends(require(Perm.REPORTS_READ)), db: Session = Depends(get_db)) -> list[dict]:
    return [report_service.report_out(r) for r in report_service.list_reports(db)]


@router.post("", response_model=ReportOut, status_code=201)
def generate(data: ReportCreate, ctx: AuthContext = Depends(require(Perm.REPORTS_GENERATE)),
             db: Session = Depends(get_db)) -> dict:
    return report_service.report_out(report_service.generate(db, data, ctx.actor))


@router.get("/{report_id}/download", response_class=Response)
def download(report_id: int, ctx: AuthContext = Depends(require(Perm.REPORTS_READ)),
             db: Session = Depends(get_db)) -> Response:
    report, content = report_service.get_content(db, report_id, ctx.actor)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", report.title).strip("-")[:80] or "report"
    filename = f"{safe}-{report.created_at:%Y%m%d-%H%M}.{report.format}"
    return Response(content=content, media_type=report_service.CONTENT_TYPES[report.format],
                    headers={"Content-Disposition": f'attachment; filename="{filename}"',
                             "X-Content-SHA256": report.sha256 or ""})


@router.delete("/{report_id}", response_model=Message)
def delete(report_id: int, ctx: AuthContext = Depends(require(Perm.REPORTS_GENERATE)),
           db: Session = Depends(get_db)) -> dict:
    report_service.delete(db, report_id, ctx.actor)
    return {"message": "Report deleted"}
