from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.schemas.common import Schema

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
FindingStatusT = Literal["OPEN", "ACKNOWLEDGED", "IN_PROGRESS", "RESOLVED", "SUPPRESSED"]


class AssetSummary(Schema):
    id: int
    name: str
    resource_uid: str
    resource_type: str
    service: str
    region: str
    account_id: int
    account_name: str
    account_identifier: str | None
    public_exposure: bool
    encryption_status: str
    risk_score: int
    risk_level: str
    open_findings: int
    last_seen_at: datetime
    is_active: bool


class RelatedAsset(Schema):
    id: int
    name: str
    service: str
    resource_type: str
    kind: str
    direction: Literal["outbound", "inbound"]


class AssetDetail(AssetSummary):
    tags: dict[str, Any]
    properties: dict[str, Any]
    first_seen_at: datetime
    relationships: list[RelatedAsset]
    findings: list["FindingSummary"]


class FindingSummary(Schema):
    id: int
    display_id: str
    rule_id: str
    title: str
    severity: Severity
    status: FindingStatusT
    service: str
    region: str
    category: str
    asset_id: int
    asset_name: str
    resource_uid: str
    resource_type: str
    account_id: int
    account_name: str
    first_detected_at: datetime
    last_detected_at: datetime
    public_exposure: bool
    ticket_ref: str | None = None


class FindingEventOut(Schema):
    id: int
    event_type: str
    from_status: str | None
    to_status: str | None
    note: str | None
    user: str | None
    scan_id: int | None
    created_at: datetime


class ComplianceRef(Schema):
    framework_key: str
    framework: str
    control_id: str
    title: str


class RemediationOut(Schema):
    summary: str
    steps: list[str]
    cli_example: str | None
    automated: bool = False


class FindingDetail(FindingSummary):
    description: str
    impact: str
    message: str
    evidence: dict[str, Any]
    remediation: RemediationOut
    references: list[str]
    compliance: list[ComplianceRef]
    suppression_reason: str | None
    resolved_at: datetime | None
    status_changed_at: datetime
    account_identifier: str | None
    events: list[FindingEventOut]


class FindingStatusUpdate(Schema):
    status: FindingStatusT
    note: str | None = Field(default=None, max_length=2000)


class BulkStatusUpdate(FindingStatusUpdate):
    finding_ids: list[int] = Field(min_length=1, max_length=500)


class TicketRequest(Schema):
    ticket_ref: str = Field(min_length=2, max_length=128, pattern=r"^[A-Za-z0-9_.#:/-]+$")
    note: str | None = Field(default=None, max_length=2000)


class TicketDraft(Schema):
    title: str
    body: str


class CommentRequest(Schema):
    note: str = Field(min_length=1, max_length=2000)


class FacetCount(Schema):
    value: str
    count: int


class FindingFacets(Schema):
    severity: list[FacetCount]
    status: list[FacetCount]
    service: list[FacetCount]
    region: list[FacetCount]
    rule: list[FacetCount]


class ServiceCount(Schema):
    service: str
    count: int
    public: int
    with_findings: int


class AssetStats(Schema):
    total: int
    by_service: list[ServiceCount]
    public: int
    encrypted: int
    unencrypted: int
    regions: list[FacetCount]
    resource_types: list[FacetCount]


AssetDetail.model_rebuild()
