"""Per-request actor context passed into services (for audit and authorization)."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from app.core.logging import request_id_ctx
from app.models import User


@dataclass(frozen=True)
class Actor:
    user: User | None
    ip_address: str | None = None
    user_agent: str | None = None
    request_id: str | None = None

    @property
    def user_id(self) -> int | None:
        return self.user.id if self.user else None

    @property
    def email(self) -> str | None:
        return self.user.email if self.user else None


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def actor_from_request(request: Request, user: User | None) -> Actor:
    return Actor(
        user=user,
        ip_address=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:255] or None,
        request_id=request_id_ctx.get(),
    )


SYSTEM = Actor(user=None, ip_address=None, user_agent="cloudaegis-worker")
