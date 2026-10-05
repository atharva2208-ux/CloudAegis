from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, utcnow


class ScanStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"  # completed, but one or more services could not be read
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


ACTIVE_SCAN_STATUSES = (ScanStatus.QUEUED.value, ScanStatus.RUNNING.value)
FINISHED_OK = (ScanStatus.COMPLETED.value, ScanStatus.PARTIAL.value)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    cloud_account_id: Mapped[int] = mapped_column(ForeignKey("cloud_accounts.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(16), default=ScanStatus.QUEUED.value, index=True)
    trigger: Mapped[str] = mapped_column(String(16), default="manual")  # manual | onboarding | seed
    triggered_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), default=None)
    regions: Mapped[list[Any]] = mapped_column(default=list)
    services: Mapped[list[Any]] = mapped_column(default=list)
    progress: Mapped[dict[str, Any]] = mapped_column(default=dict)
    cancel_requested: Mapped[bool] = mapped_column(default=False)
    assets_discovered: Mapped[int] = mapped_column(default=0)
    assets_analyzed: Mapped[int] = mapped_column(default=0)
    checks_evaluated: Mapped[int] = mapped_column(default=0)
    findings_total: Mapped[int] = mapped_column(default=0)
    findings_new: Mapped[int] = mapped_column(default=0)
    findings_resolved: Mapped[int] = mapped_column(default=0)
    critical_count: Mapped[int] = mapped_column(default=0)
    high_count: Mapped[int] = mapped_column(default=0)
    medium_count: Mapped[int] = mapped_column(default=0)
    low_count: Mapped[int] = mapped_column(default=0)
    info_count: Mapped[int] = mapped_column(default=0)
    public_assets: Mapped[int] = mapped_column(default=0)
    security_score: Mapped[int | None] = mapped_column(default=None)
    score_breakdown: Mapped[dict[str, Any]] = mapped_column(default=dict)
    compliance_summary: Mapped[list[Any]] = mapped_column(default=list)
    service_errors: Mapped[dict[str, Any]] = mapped_column(default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, default=None)
    queued_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    duration_seconds: Mapped[float | None] = mapped_column(default=None)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    account = relationship("CloudAccount", lazy="joined")
    triggered_by = relationship("User", lazy="joined")

    @property
    def display_id(self) -> str:
        return f"SCN-{self.id:06d}"


class ScanResult(Base):
    """Per-rule statistics for one scan; the basis for compliance history."""

    __tablename__ = "scan_results"
    __table_args__ = (UniqueConstraint("scan_id", "security_rule_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    security_rule_id: Mapped[int] = mapped_column(ForeignKey("security_rules.id", ondelete="CASCADE"))
    rule_id: Mapped[str] = mapped_column(String(16))
    evaluated: Mapped[int] = mapped_column(default=0)
    failed: Mapped[int] = mapped_column(default=0)
