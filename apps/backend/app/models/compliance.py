from __future__ import annotations

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class ComplianceFramework(Base):
    __tablename__ = "compliance_frameworks"
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(32), unique=True)
    name: Mapped[str] = mapped_column(String(128))
    short_name: Mapped[str] = mapped_column(String(32))
    version: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text, default="")

    controls: Mapped[list["ComplianceControl"]] = relationship(
        back_populates="framework", cascade="all, delete-orphan", order_by="ComplianceControl.position"
    )


class ComplianceControl(Base):
    __tablename__ = "compliance_controls"
    __table_args__ = (UniqueConstraint("framework_id", "control_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    framework_id: Mapped[int] = mapped_column(ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), index=True)
    control_id: Mapped[str] = mapped_column(String(32))
    section: Mapped[str] = mapped_column(String(128), default="")
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    position: Mapped[int] = mapped_column(default=0)

    framework: Mapped[ComplianceFramework] = relationship(back_populates="controls")
    mappings: Mapped[list["ComplianceMapping"]] = relationship(cascade="all, delete-orphan", lazy="selectin")

    @property
    def rule_ids(self) -> list[str]:
        return [m.rule_id for m in self.mappings]


class ComplianceMapping(Base):
    __tablename__ = "compliance_mappings"
    __table_args__ = (UniqueConstraint("control_id", "security_rule_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    control_id: Mapped[int] = mapped_column(ForeignKey("compliance_controls.id", ondelete="CASCADE"), index=True)
    security_rule_id: Mapped[int] = mapped_column(ForeignKey("security_rules.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(16))
