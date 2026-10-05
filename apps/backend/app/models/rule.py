from __future__ import annotations

from typing import Any

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class SecurityRule(TimestampMixin, Base):
    """Catalog copy of a detection rule's metadata (synced from the engine)."""

    __tablename__ = "security_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(10), index=True)
    service: Mapped[str] = mapped_column(String(32), index=True)
    category: Mapped[str] = mapped_column(String(64))
    resource_type: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text)
    impact: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    remediation_steps: Mapped[list[Any]] = mapped_column(default=list)
    remediation_cli: Mapped[str | None] = mapped_column(Text, default=None)
    references: Mapped[list[Any]] = mapped_column(default=list)
    enabled: Mapped[bool] = mapped_column(default=True)
