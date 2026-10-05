from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.schemas.common import Schema


class ReportCreate(Schema):
    title: str = Field(min_length=3, max_length=200)
    format: Literal["pdf", "json", "csv"] = "pdf"
    report_type: Literal["executive", "technical"] = "executive"
    account_id: int | None = None
    severities: list[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]] | None = None


class ReportOut(Schema):
    id: int
    title: str
    report_type: str
    format: str
    status: str
    account_id: int | None
    account_name: str | None
    scan_id: int | None
    generated_by: str | None
    size_bytes: int
    sha256: str | None
    created_at: datetime


class AuditLogOut(Schema):
    id: int
    timestamp: datetime
    user_email: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    result: str
    ip_address: str | None
    user_agent: str | None
    request_id: str | None
    details: dict[str, Any]


class NotificationOut(Schema):
    id: int
    kind: str
    severity: str
    title: str
    message: str
    link: str | None
    created_at: datetime
    read_at: datetime | None


class RuleOut(Schema):
    rule_id: str
    title: str
    severity: str
    service: str
    category: str
    resource_type: str
    description: str
    impact: str
    remediation: str
    remediation_steps: list[str]
    remediation_cli: str | None
    references: list[str]
    enabled: bool
    compliance: list[dict[str, str]]
    open_findings: int = 0


class RuleToggle(Schema):
    enabled: bool


class SettingsOut(Schema):
    thresholds: dict[str, int]
    scan_services: list[str]
    available_services: list[str]
    notify_on_critical: bool
    session_idle_minutes: int
    demo_mode: bool


class SettingsUpdate(Schema):
    thresholds: dict[str, int] | None = None
    scan_services: list[str] | None = None
    notify_on_critical: bool | None = None


class SearchHit(Schema):
    category: Literal["asset", "finding", "rule", "account", "region", "ip"]
    id: str
    title: str
    subtitle: str
    link: str


class SearchResults(Schema):
    query: str
    groups: dict[str, list[SearchHit]]
    total: int
