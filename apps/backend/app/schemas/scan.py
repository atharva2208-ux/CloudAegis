from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from app.schemas.common import Schema


class ScanCreate(Schema):
    account_id: int
    regions: list[str] | None = Field(default=None, max_length=40)
    services: list[str] | None = Field(default=None, max_length=20)


class ScanOut(Schema):
    id: int
    display_id: str
    account_id: int
    account_name: str
    is_demo: bool
    status: str
    trigger: str
    triggered_by: str | None
    regions: list[str]
    services: list[str]
    progress: dict[str, Any]
    assets_discovered: int
    assets_analyzed: int
    checks_evaluated: int
    findings_total: int
    findings_new: int
    findings_resolved: int
    severity_counts: dict[str, int]
    public_assets: int
    security_score: int | None
    score_breakdown: dict[str, Any]
    compliance_summary: list[dict[str, Any]]
    service_errors: dict[str, Any]
    error_message: str | None
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: float | None


class ScanComparison(Schema):
    base: ScanOut
    target: ScanOut
    score_delta: int | None
    severity_delta: dict[str, int]
    public_assets_delta: int
    assets_delta: int
    compliance_delta: list[dict[str, Any]]
    new_findings: list[dict[str, Any]]
    resolved_findings: list[dict[str, Any]]
