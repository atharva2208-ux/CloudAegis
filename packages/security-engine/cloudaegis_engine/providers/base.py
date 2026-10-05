"""Cloud provider abstraction.

The scan engine only depends on :class:`CloudProvider`. Each provider
(AWS today; Azure and GCP later) translates its native APIs into
normalized :class:`~cloudaegis_engine.models.Resource` objects.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterator

from cloudaegis_engine.models import Resource


class ProviderError(Exception):
    """Raised for provider failures safe to show to users (no secrets)."""


class ServiceAccessError(ProviderError):
    """Discovery of one service failed (e.g. AccessDenied); the scan continues."""

    def __init__(self, service: str, message: str) -> None:
        super().__init__(f"{service}: {message}")
        self.service = service
        self.message = message


@dataclass
class ConnectionResult:
    ok: bool
    account_id: str | None = None
    principal_arn: str | None = None
    regions: list[str] = field(default_factory=list)
    message: str = ""
    warnings: list[str] = field(default_factory=list)


class CloudProvider(ABC):
    """Interface every cloud provider adapter implements."""

    provider_name: str = "abstract"

    @abstractmethod
    def validate_connection(self) -> ConnectionResult:
        """Verify credentials and return identity + enabled regions."""

    @abstractmethod
    def account_id(self) -> str:
        """Identifier of the account / subscription / project being scanned."""

    @abstractmethod
    def supported_services(self) -> list[str]:
        """Service labels this provider can discover, in discovery order."""

    @abstractmethod
    def discover_service(self, service: str, regions: list[str]) -> Iterator[Resource]:
        """Yield normalized resources for ``service`` across ``regions``.

        Implementations should raise :class:`ServiceAccessError` when the
        service cannot be read at all; per-resource errors should be
        tolerated and logged so one bad resource does not abort a scan.
        """
