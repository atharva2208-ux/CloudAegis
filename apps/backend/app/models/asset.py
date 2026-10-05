from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, utcnow


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("cloud_account_id", "resource_uid"),
        Index("ix_assets_account_service", "cloud_account_id", "service"),
        Index("ix_assets_risk", "risk_score"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    cloud_account_id: Mapped[int] = mapped_column(ForeignKey("cloud_accounts.id", ondelete="CASCADE"), index=True)
    resource_uid: Mapped[str] = mapped_column(Text)
    resource_type: Mapped[str] = mapped_column(String(64), index=True)
    service: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(512))
    region: Mapped[str] = mapped_column(String(32), index=True)
    tags: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # Provider-normalized configuration. Flexible by nature, hence JSON.
    properties: Mapped[dict[str, Any]] = mapped_column(default=dict)
    public_exposure: Mapped[bool] = mapped_column(default=False, index=True)
    encryption_status: Mapped[str] = mapped_column(String(16), default="not_applicable")
    risk_score: Mapped[int] = mapped_column(default=0)
    open_findings: Mapped[int] = mapped_column(default=0)
    is_active: Mapped[bool] = mapped_column(default=True, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), default=None)

    account = relationship("CloudAccount", lazy="joined")


class AssetRelationship(Base):
    __tablename__ = "asset_relationships"
    __table_args__ = (UniqueConstraint("source_asset_id", "target_asset_id", "kind"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source_asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    target_asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
