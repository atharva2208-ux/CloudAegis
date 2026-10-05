from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, page_params, require
from app.core.database import get_db
from app.core.errors import NotFoundError
from app.core.permissions import Perm
from app.models import ACTIVE_SCAN_STATUSES, Scan
from app.schemas.common import Page, PageParams, make_page
from app.schemas.scan import ScanComparison, ScanCreate, ScanOut
from app.services import scans as scan_service
from app.workers.queue import get_queue

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=Page[ScanOut])
def list_scans(params: PageParams = Depends(page_params), account_id: int | None = None,
               status: list[str] | None = Query(None), _: AuthContext = Depends(require(Perm.SCANS_READ)),
               db: Session = Depends(get_db)) -> dict:
    stmt = select(Scan)
    if account_id:
        stmt = stmt.where(Scan.cloud_account_id == account_id)
    if status:
        stmt = stmt.where(Scan.status.in_(status))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(Scan.queued_at.desc(), Scan.id.desc()).offset(params.offset)
                      .limit(params.page_size)).all()
    return make_page([scan_service.scan_out(s) for s in rows], total, params)


@router.get("/active", response_model=list[ScanOut])
def active(_: AuthContext = Depends(require(Perm.SCANS_READ)), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(select(Scan).where(Scan.status.in_(ACTIVE_SCAN_STATUSES)).order_by(Scan.queued_at)).all()
    return [scan_service.scan_out(s) for s in rows]


@router.post("", response_model=ScanOut, status_code=202, summary="Queue a background scan")
def start_scan(data: ScanCreate, ctx: AuthContext = Depends(require(Perm.SCANS_RUN)),
               db: Session = Depends(get_db)) -> dict:
    scan = scan_service.create_scan(db, data.account_id, ctx.actor, regions=data.regions, services=data.services)
    get_queue().enqueue(scan.id)
    return scan_service.scan_out(scan)


@router.get("/compare", response_model=ScanComparison)
def compare(base: int, target: int, _: AuthContext = Depends(require(Perm.SCANS_READ)),
            db: Session = Depends(get_db)) -> dict:
    return scan_service.compare(db, base, target)


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, _: AuthContext = Depends(require(Perm.SCANS_READ)), db: Session = Depends(get_db)) -> dict:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise NotFoundError("Scan not found")
    return scan_service.scan_out(scan)


@router.post("/{scan_id}/cancel", response_model=ScanOut)
def cancel(scan_id: int, ctx: AuthContext = Depends(require(Perm.SCANS_RUN)), db: Session = Depends(get_db)) -> dict:
    return scan_service.scan_out(scan_service.request_cancel(db, scan_id, ctx.actor))
