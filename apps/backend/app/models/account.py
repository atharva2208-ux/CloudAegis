from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class CloudAccount(TimestampMixin, Base):
    __tablename__ = "cloud_accounts"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    provider: Mapped[str] = mapped_column(String(16), default="aws")  # aws | demo
    account_identifier: Mapped[str | None] = mapped_column(String(32), index=True)
    auth_method: Mapped[str] = mapped_column(String(32))  # assume_role | temporary_credentials | demo
    role_arn: Mapped[str | None] = mapped_column(String(2048), default=None)
    # Fernet-encrypted JSON (external ID, temporary credentials). Never returned by the API.
    secret_payload: Mapped[str | None] = mapped_column(Text, default=None)
    credentials_expire_at: Mapped[datetime | None] = mapped_column(default=None)
    principal_arn: Mapped[str | None] = mapped_column(String(2048), default=None)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | connected | error
    status_message: Mapped[str | None] = mapped_column(String(500), default=None)
    is_demo: Mapped[bool] = mapped_column(default=False)
    default_region: Mapped[str] = mapped_column(String(32), default="us-east-1")
    last_validated_at: Mapped[datetime | None] = mapped_column(default=None)
    last_scan_at: Mapped[datetime | None] = mapped_column(default=None)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), default=None)

    regions: Mapped[list["CloudRegion"]] = relationship(
        back_populates="account", cascade="all, delete-orphan", lazy="selectin", order_by="CloudRegion.name"
    )

    @property
    def enabled_regions(self) -> list[str]:
        return [r.name for r in self.regions if r.enabled]

    @property
    def has_stored_secret(self) -> bool:
        return bool(self.secret_payload)


class CloudRegion(Base):
    __tablename__ = "cloud_regions"
    __table_args__ = (UniqueConstraint("cloud_account_id", "name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    cloud_account_id: Mapped[int] = mapped_column(ForeignKey("cloud_accounts.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(default=True)

    account: Mapped[CloudAccount] = relationship(back_populates="regions")
