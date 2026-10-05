"""Asset inventory queries."""

from __future__ import annotations

from typing import Any

from cloudaegis_engine.scoring import risk_level
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session, aliased

from app.core.errors import NotFoundError
from app.models import ACTIVE_STATUSES, Asset, AssetRelationship, Finding
from app.schemas.common import PageParams, make_page
from app.services.findings import SEVERITY_ORDER, summary as finding_summary

SORTS = {
    "risk": Asset.risk_score,
    "name": func.lower(Asset.name),
    "service": Asset.service,
    "region": Asset.region,
    "findings": Asset.open_findings,
    "last_seen": Asset.last_seen_at,
    "type": Asset.resource_type,
}

RISK_BANDS = {"CRITICAL": (70, 101), "HIGH": (40, 70), "MEDIUM": (15, 40), "LOW": (1, 15), "NONE": (0, 1)}


def summary(a: Asset) -> dict[str, Any]:
    return {
        "id": a.id, "name": a.name, "resource_uid": a.resource_uid, "resource_type": a.resource_type,
        "service": a.service, "region": a.region, "account_id": a.cloud_account_id,
        "account_name": a.account.name if a.account else "",
        "account_identifier": a.account.account_identifier if a.account else None,
        "public_exposure": a.public_exposure, "encryption_status": a.encryption_status, "risk_score": a.risk_score,
        "risk_level": risk_level(a.risk_score), "open_findings": a.open_findings, "last_seen_at": a.last_seen_at,
        "is_active": a.is_active,
    }


def _filtered(account_id: int | None, q: str | None, service: list[str] | None, region: list[str] | None,
              resource_type: list[str] | None, public: bool | None, encryption: str | None, risk: list[str] | None,
              has_findings: bool | None, include_inactive: bool):
    stmt = select(Asset)
    if not include_inactive:
        stmt = stmt.where(Asset.is_active.is_(True))
    if account_id:
        stmt = stmt.where(Asset.cloud_account_id == account_id)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(
            Asset.name.ilike(like), Asset.resource_uid.ilike(like),
            Asset.properties["public_ip"].as_string() == q.strip(), Asset.properties["private_ip"].as_string() == q.strip(),
        ))
    if service:
        stmt = stmt.where(Asset.service.in_(service))
    if region:
        stmt = stmt.where(Asset.region.in_(region))
    if resource_type:
        stmt = stmt.where(Asset.resource_type.in_(resource_type))
    if public is not None:
        stmt = stmt.where(Asset.public_exposure.is_(public))
    if encryption:
        stmt = stmt.where(Asset.encryption_status == encryption)
    if risk:
        stmt = stmt.where(or_(*[Asset.risk_score.between(RISK_BANDS[r][0], RISK_BANDS[r][1] - 1)
                                for r in risk if r in RISK_BANDS]))
    if has_findings is True:
        stmt = stmt.where(Asset.open_findings > 0)
    elif has_findings is False:
        stmt = stmt.where(Asset.open_findings == 0)
    return stmt


def list_assets(db: Session, params: PageParams, sort: str = "risk", order: str = "desc", *,
                account_id: int | None = None, q: str | None = None, service: list[str] | None = None,
                region: list[str] | None = None, resource_type: list[str] | None = None, public: bool | None = None,
                encryption: str | None = None, risk: list[str] | None = None, has_findings: bool | None = None,
                include_inactive: bool = False) -> dict:
    stmt = _filtered(account_id, q, service, region, resource_type, public, encryption, risk, has_findings,
                     include_inactive)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    column = SORTS.get(sort, Asset.risk_score)
    ordering = column.desc() if order == "desc" else column.asc()
    rows = db.scalars(stmt.order_by(ordering, Asset.id).offset(params.offset).limit(params.page_size)).all()
    return make_page([summary(a) for a in rows], total, params)


def stats(db: Session, account_id: int | None = None) -> dict[str, Any]:
    base = select(Asset).where(Asset.is_active.is_(True))
    if account_id:
        base = base.where(Asset.cloud_account_id == account_id)
    sub = base.subquery()
    by_service = db.execute(select(
        sub.c.service, func.count(), func.sum(case((sub.c.public_exposure.is_(True), 1), else_=0)),
        func.sum(case((sub.c.open_findings > 0, 1), else_=0)),
    ).group_by(sub.c.service).order_by(func.count().desc())).all()
    regions = db.execute(select(sub.c.region, func.count()).group_by(sub.c.region).order_by(func.count().desc())).all()
    types = db.execute(select(sub.c.resource_type, func.count()).group_by(sub.c.resource_type)
                       .order_by(func.count().desc())).all()
    enc = dict(db.execute(select(sub.c.encryption_status, func.count()).group_by(sub.c.encryption_status)).all())
    total = sum(r[1] for r in by_service)
    return {
        "total": total,
        "by_service": [{"service": s, "count": c, "public": int(p or 0), "with_findings": int(w or 0)}
                       for s, c, p, w in by_service],
        "public": sum(int(r[2] or 0) for r in by_service),
        "encrypted": enc.get("encrypted", 0),
        "unencrypted": enc.get("unencrypted", 0),
        "regions": [{"value": r, "count": c} for r, c in regions],
        "resource_types": [{"value": t, "count": c} for t, c in types],
    }


def detail(db: Session, asset_id: int) -> dict[str, Any]:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError("Asset not found")
    target = aliased(Asset)
    outbound = db.execute(select(AssetRelationship.kind, target).join(target, AssetRelationship.target_asset_id == target.id)
                          .where(AssetRelationship.source_asset_id == asset.id)).all()
    inbound = db.execute(select(AssetRelationship.kind, target).join(target, AssetRelationship.source_asset_id == target.id)
                         .where(AssetRelationship.target_asset_id == asset.id).limit(200)).all()
    findings = db.scalars(select(Finding).where(Finding.asset_id == asset.id)
                          .order_by(case((Finding.status.in_(ACTIVE_STATUSES), 0), else_=1), SEVERITY_ORDER)).unique().all()
    return {
        **summary(asset),
        "tags": asset.tags or {},
        "properties": asset.properties or {},
        "first_seen_at": asset.first_seen_at,
        "relationships": [
            {"id": t.id, "name": t.name, "service": t.service, "resource_type": t.resource_type, "kind": kind,
             "direction": "outbound"} for kind, t in outbound
        ] + [
            {"id": t.id, "name": t.name, "service": t.service, "resource_type": t.resource_type, "kind": kind,
             "direction": "inbound"} for kind, t in inbound
        ],
        "findings": [finding_summary(f) for f in findings],
    }
