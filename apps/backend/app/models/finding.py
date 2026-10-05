from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, utcnow


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


ACTIVE_STATUSES = (FindingStatus.OPEN.value, FindingStatus.ACKNOWLEDGED.value, FindingStatus.IN_PROGRESS.value)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("asset_id", "security_rule_id"),
        Index("ix_findings_status_severity", "status", "severity"),
        Index("ix_findings_account_status", "cloud_account_id", "status"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    cloud_account_id: Mapped[int] = mapped_column(ForeignKey("cloud_accounts.id", ondelete="CASCADE"))
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    security_rule_id: Mapped[int] = mapped_column(ForeignKey("security_rules.id", ondelete="CASCADE"))
    # Denormalised for fast filtering/sorting without joins.
    rule_id: Mapped[str] = mapped_column(String(16), index=True)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    service: Mapped[str] = mapped_column(String(32), index=True)
    region: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(255))
    message: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict[str, Any]] = mapped_column(default=dict)
    status: Mapped[str] = mapped_column(String(16), default=FindingStatus.OPEN.value)
    first_detected_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    last_detected_at: Mapped[datetime] = mapped_column(default=utcnow)
    status_changed_at: Mapped[datetime] = mapped_column(default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(default=None)
    suppression_reason: Mapped[str | None] = mapped_column(Text, default=None)
    ticket_ref: Mapped[str | None] = mapped_column(String(128), default=None)
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), default=None)
    last_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), default=None)

    asset = relationship("Asset", lazy="joined")
    rule = relationship("SecurityRule", lazy="joined")
    account = relationship("CloudAccount", lazy="joined")
    events: Mapped[list["FindingEvent"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="FindingEvent.created_at.desc()",
        lazy="select",  # loaded explicitly where needed; never in list queries
    )

    @property
    def display_id(self) -> str:
        return f"FND-{self.id:06d}"


class FindingEvent(Base):
    __tablename__ = "finding_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(32))  # detected | status_changed | reopened | auto_resolved | comment | ticket_linked
    from_status: Mapped[str | None] = mapped_column(String(16), default=None)
    to_status: Mapped[str | None] = mapped_column(String(16), default=None)
    note: Mapped[str | None] = mapped_column(Text, default=None)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), default=None)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), default=None)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    finding: Mapped[Finding] = relationship(back_populates="events")
    user = relationship("User", lazy="joined")
