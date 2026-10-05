from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, Field, field_validator

from app.core.permissions import Role
from app.schemas.common import Schema


_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


def _email(value: str) -> str:
    value = value.strip().lower()
    if len(value) > 254 or not _EMAIL_RE.match(value):
        raise ValueError("Invalid email address")
    return value


# Syntactic validation only: internal domains such as *.local are legitimate here.
Email = Annotated[str, AfterValidator(_email)]


class LoginRequest(Schema):
    email: Email
    password: str = Field(min_length=1, max_length=128)


class UserOut(Schema):
    id: int
    email: str
    full_name: str
    role: str
    permissions: list[str]
    is_active: bool
    last_login_at: datetime | None = None
    created_at: datetime
    locked: bool = False
    failed_login_attempts: int = 0


class SessionOut(Schema):
    user: UserOut
    csrf_token: str
    expires_at: datetime
    idle_timeout_minutes: int


class ChangePasswordRequest(Schema):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class UserCreate(Schema):
    email: Email
    full_name: str = Field(min_length=2, max_length=120)
    role: Role
    password: str = Field(min_length=12, max_length=128)

    @field_validator("full_name")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class UserUpdate(Schema):
    full_name: str | None = Field(default=None, min_length=2, max_length=120)
    role: Role | None = None
    is_active: bool | None = None


class RoleOut(Schema):
    name: str
    description: str
    permissions: list[str]
