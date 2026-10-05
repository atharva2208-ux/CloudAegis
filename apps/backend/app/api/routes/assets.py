from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, page_params, require
from app.core.database import get_db
from app.core.permissions import Perm
from app.schemas.common import Page, PageParams
from app.schemas.inventory import AssetDetail, AssetStats, AssetSummary
from app.services import assets as asset_service

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=Page[AssetSummary])
def list_assets(
    params: PageParams = Depends(page_params),
    q: str | None = Query(None, max_length=200),
    account_id: int | None = None,
    service: list[str] | None = Query(None),
    region: list[str] | None = Query(None),
    resource_type: list[str] | None = Query(None),
    public: bool | None = None,
    encryption: Literal["encrypted", "unencrypted", "not_applicable"] | None = None,
    risk: list[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]] | None = Query(None),
    has_findings: bool | None = None,
    include_inactive: bool = False,
    sort: Literal["risk", "name", "service", "region", "findings", "last_seen", "type"] = "risk",
    order: Literal["asc", "desc"] = "desc",
    _: AuthContext = Depends(require(Perm.ASSETS_READ)),
    db: Session = Depends(get_db),
) -> dict:
    return asset_service.list_assets(db, params, sort, order, account_id=account_id, q=q, service=service,
                                     region=region, resource_type=resource_type, public=public, encryption=encryption,
                                     risk=risk, has_findings=has_findings, include_inactive=include_inactive)


@router.get("/stats", response_model=AssetStats)
def stats(account_id: int | None = None, _: AuthContext = Depends(require(Perm.ASSETS_READ)),
          db: Session = Depends(get_db)) -> dict:
    return asset_service.stats(db, account_id)


@router.get("/{asset_id}", response_model=AssetDetail)
def get_asset(asset_id: int, _: AuthContext = Depends(require(Perm.ASSETS_READ)), db: Session = Depends(get_db)) -> dict:
    return asset_service.detail(db, asset_id)
