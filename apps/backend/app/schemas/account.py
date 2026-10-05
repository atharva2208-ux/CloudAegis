from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator

from app.schemas.common import Schema

ROLE_ARN_RE = re.compile(r"^arn:aws(-[a-z]+)*:iam::\d{12}:role/[\w+=,.@/-]{1,512}$")
REGION_RE = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d$")
EXTERNAL_ID_RE = re.compile(r"^[\w+=,.@:/-]{2,1224}$")


class AwsCredentialsIn(Schema):
    """Credential material. Accepted on write, never returned."""

    method: Literal["assume_role", "temporary_credentials"]
    role_arn: str | None = Field(default=None, max_length=2048)
    external_id: SecretStr | None = None
    access_key_id: str | None = Field(default=None, max_length=128)
    secret_access_key: SecretStr | None = None
    session_token: SecretStr | None = None

    @model_validator(mode="after")
    def _validate(self) -> "AwsCredentialsIn":
        if self.method == "assume_role":
            if not self.role_arn or not ROLE_ARN_RE.match(self.role_arn):
                raise ValueError("A valid IAM role ARN is required (arn:aws:iam::<account-id>:role/<name>)")
            if self.external_id and not EXTERNAL_ID_RE.match(self.external_id.get_secret_value()):
                raise ValueError("External ID contains invalid characters")
        else:
            if not (self.access_key_id and self.secret_access_key and self.session_token):
                raise ValueError("Temporary credentials need an access key ID, secret access key and session token")
            if not self.access_key_id.startswith("ASIA"):
                raise ValueError(
                    "Only temporary STS credentials (access key IDs starting with ASIA) are accepted. "
                    "Long-lived IAM user keys are not supported — use an IAM role instead."
                )
        return self

    def to_auth(self) -> dict:
        auth: dict = {"method": self.method}
        if self.method == "assume_role":
            auth["role_arn"] = self.role_arn
            if self.external_id:
                auth["external_id"] = self.external_id.get_secret_value()
        else:
            auth["access_key_id"] = self.access_key_id
            auth["secret_access_key"] = self.secret_access_key.get_secret_value()  # type: ignore[union-attr]
            auth["session_token"] = self.session_token.get_secret_value()  # type: ignore[union-attr]
        return auth


class ConnectionTestRequest(Schema):
    credentials: AwsCredentialsIn
    default_region: str = "us-east-1"

    @field_validator("default_region")
    @classmethod
    def _region(cls, v: str) -> str:
        if not REGION_RE.match(v):
            raise ValueError("Invalid AWS region")
        return v


class ConnectionTestResult(Schema):
    ok: bool
    account_id: str | None = None
    principal_arn: str | None = None
    regions: list[str] = []
    message: str
    warnings: list[str] = []


class AccountCreate(Schema):
    name: str = Field(min_length=2, max_length=100)
    credentials: AwsCredentialsIn
    default_region: str = "us-east-1"
    regions: list[str] = Field(default_factory=list, max_length=40)
    start_scan: bool = True

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^[\w .()\-]+$", v):
            raise ValueError("Name may contain letters, numbers, spaces and . ( ) - _")
        return v

    @field_validator("regions")
    @classmethod
    def _regions(cls, v: list[str]) -> list[str]:
        for region in v:
            if not REGION_RE.match(region):
                raise ValueError(f"Invalid AWS region: {region}")
        return sorted(set(v))


class DemoAccountCreate(Schema):
    name: str = Field(default="Demo Cloud Environment", min_length=2, max_length=100)
    start_scan: bool = True


class AccountUpdate(Schema):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    regions: list[str] | None = Field(default=None, max_length=40)
    credentials: AwsCredentialsIn | None = None

    @field_validator("regions")
    @classmethod
    def _regions(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        for region in v:
            if not REGION_RE.match(region) and region not in ("global",):
                raise ValueError(f"Invalid AWS region: {region}")
        return sorted(set(v))


class RegionOut(Schema):
    name: str
    enabled: bool


class AccountOut(Schema):
    id: int
    name: str
    provider: str
    account_identifier: str | None
    auth_method: str
    role_arn: str | None
    has_stored_secret: bool
    credentials_expire_at: datetime | None
    principal_arn: str | None
    status: str
    status_message: str | None
    is_demo: bool
    default_region: str
    regions: list[RegionOut]
    last_validated_at: datetime | None
    last_scan_at: datetime | None
    created_at: datetime
    asset_count: int = 0
    open_findings: int = 0
    security_score: int | None = None


class OnboardingGuide(Schema):
    trust_policy: dict
    permissions_policies: list[str]
    inline_policy: dict
    cloudformation_template: str
    platform_principal: str | None
    external_id_suggestion: str
