from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, page_params, require
from app.core.database import get_db
from app.core.permissions import Perm
from app.schemas.common import Message, Page, PageParams
from app.schemas.inventory import (
    BulkStatusUpdate,
    CommentRequest,
    FindingDetail,
    FindingFacets,
    FindingStatusT,
    FindingStatusUpdate,
    FindingSummary,
    Severity,
    TicketDraft,
    TicketRequest,
)
from app.services import findings as finding_service

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=Page[FindingSummary])
def list_findings(
    params: PageParams = Depends(page_params),
    q: str | None = Query(None, max_length=200),
    severity: list[Severity] | None = Query(None),
    status: list[FindingStatusT] | None = Query(None),
    service: list[str] | None = Query(None),
    region: list[str] | None = Query(None),
    rule_id: list[str] | None = Query(None),
    account_id: int | None = None,
    asset_id: int | None = None,
    framework: str | None = Query(None, max_length=32),
    control: str | None = Query(None, max_length=32),
    detected_from: datetime | None = None,
    detected_to: datetime | None = None,
    public_only: bool = False,
    sort: Literal["severity", "first_detected", "last_detected", "service", "region", "rule", "status", "title"] = "severity",
    order: Literal["asc", "desc"] = "asc",
    _: AuthContext = Depends(require(Perm.FINDINGS_READ)),
    db: Session = Depends(get_db),
) -> dict:
    return finding_service.list_findings(
        db, params, sort, order, q=q, severity=severity, status=status, service=service, region=region,
        rule_id=rule_id, account_id=account_id, asset_id=asset_id, framework=framework, control=control,
        detected_from=detected_from, detected_to=detected_to, public_only=public_only)


@router.get("/facets", response_model=FindingFacets)
def facets(account_id: int | None = None, status: list[FindingStatusT] | None = Query(None),
           _: AuthContext = Depends(require(Perm.FINDINGS_READ)), db: Session = Depends(get_db)) -> dict:
    return finding_service.facets(db, account_id, status)


@router.post("/bulk-status", response_model=Message)
def bulk_status(data: BulkStatusUpdate, ctx: AuthContext = Depends(require(Perm.FINDINGS_UPDATE)),
                db: Session = Depends(get_db)) -> dict:
    changed = finding_service.bulk_update(db, data.finding_ids, data.status, data.note, ctx.actor)
    return {"message": f"{changed} finding(s) updated"}


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: int, _: AuthContext = Depends(require(Perm.FINDINGS_READ)),
                db: Session = Depends(get_db)) -> dict:
    return finding_service.detail(db, finding_id)


@router.patch("/{finding_id}/status", response_model=FindingDetail)
def set_status(finding_id: int, data: FindingStatusUpdate, ctx: AuthContext = Depends(require(Perm.FINDINGS_UPDATE)),
               db: Session = Depends(get_db)) -> dict:
    finding_service.update_status(db, finding_id, data.status, data.note, ctx.actor)
    return finding_service.detail(db, finding_id)


@router.post("/{finding_id}/comments", response_model=FindingDetail)
def comment(finding_id: int, data: CommentRequest, ctx: AuthContext = Depends(require(Perm.FINDINGS_UPDATE)),
            db: Session = Depends(get_db)) -> dict:
    finding_service.add_comment(db, finding_id, data.note, ctx.actor)
    return finding_service.detail(db, finding_id)


@router.get("/{finding_id}/ticket-draft", response_model=TicketDraft,
            summary="Pre-filled ticket text for an external tracker")
def ticket_draft(finding_id: int, _: AuthContext = Depends(require(Perm.FINDINGS_READ)),
                 db: Session = Depends(get_db)) -> dict:
    return finding_service.ticket_draft(db, finding_id)


@router.post("/{finding_id}/ticket", response_model=FindingDetail, summary="Link an external ticket reference")
def link_ticket(finding_id: int, data: TicketRequest, ctx: AuthContext = Depends(require(Perm.FINDINGS_UPDATE)),
                db: Session = Depends(get_db)) -> dict:
    finding_service.link_ticket(db, finding_id, data.ticket_ref, data.note, ctx.actor)
    return finding_service.detail(db, finding_id)
