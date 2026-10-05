"""Cloud account onboarding and management."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from cloudaegis_engine.providers import ProviderError, create_provider
from cloudaegis_engine.providers.aws.permissions import audit_policy_document
from cloudaegis_engine.providers.base import ConnectionResult
from cloudaegis_engine.providers.demo import DEMO_ACCOUNT_ID
from cloudaegis_engine.providers.demo.generator import DEMO_REGIONS
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError, ConflictError, NotFoundError
from app.core.security import decrypt_secret_payload, encrypt_secret_payload
from app.models import ACTIVE_SCAN_STATUSES, ACTIVE_STATUSES, Asset, CloudAccount, CloudRegion, Finding, Scan
from app.schemas.account import AccountCreate, AccountUpdate, AwsCredentialsIn, DemoAccountCreate
from app.services import audit
from app.services.context import Actor

log = logging.getLogger("cloudaegis.accounts")

TEMP_CREDENTIAL_ASSUMED_LIFETIME = timedelta(hours=12)


def _friendly(result: ConnectionResult) -> ConnectionResult:
    if not result.ok and "NoCredentials" in (result.message or ""):
        result.message = ("CloudAegis has no AWS identity of its own to assume the audit role with. Configure an "
                          "instance profile / task role (or AWS_PROFILE) for the backend, or use temporary credentials.")
    elif not result.ok and "AccessDenied" in (result.message or ""):
        result.message = ("Access denied while assuming the role. Check the role's trust policy, the external ID, "
                          "and that the CloudAegis principal is allowed to call sts:AssumeRole.")
    return result


def test_connection(credentials: AwsCredentialsIn, default_region: str) -> ConnectionResult:
    try:
        provider = create_provider("aws", {"auth": credentials.to_auth(), "default_region": default_region})
        return _friendly(provider.validate_connection())
    except ProviderError as exc:
        return ConnectionResult(ok=False, message=str(exc))


def provider_config(account: CloudAccount) -> tuple[str, dict[str, Any]]:
    if account.is_demo:
        # Mature posture for on-demand scans; simulated latency makes live progress visible.
        return "demo", {"account_id": account.account_identifier or DEMO_ACCOUNT_ID, "maturity": 0.62,
                        "pace_seconds": 9.0}
    auth: dict[str, Any] = {"method": account.auth_method}
    if account.auth_method == "assume_role":
        auth["role_arn"] = account.role_arn
    auth.update(decrypt_secret_payload(account.secret_payload))
    return "aws", {"auth": auth, "account_id": account.account_identifier, "default_region": account.default_region}


def _set_regions(account: CloudAccount, available: list[str], enabled: list[str]) -> None:
    enabled_set = set(enabled) if enabled else set(available)
    existing = {r.name: r for r in account.regions}
    for name in sorted(set(available) | enabled_set):
        region = existing.get(name)
        if region is None:
            account.regions.append(CloudRegion(name=name, enabled=name in enabled_set))
        else:
            region.enabled = name in enabled_set


def create_aws_account(db: Session, data: AccountCreate, actor: Actor) -> CloudAccount:
    result = test_connection(data.credentials, data.default_region)
    if not result.ok:
        audit.record_now(actor, "account.created", result="failure", resource_type="cloud_account",
                         details={"name": data.name, "reason": result.message})
        raise AppError(f"Connection validation failed: {result.message}", code="connection_failed", status_code=400)
    if db.scalar(select(CloudAccount).where(CloudAccount.account_identifier == result.account_id,
                                            CloudAccount.is_demo.is_(False))):
        raise ConflictError(f"AWS account {result.account_id} is already connected")
    auth = data.credentials.to_auth()
    secret = {k: v for k, v in auth.items() if k in ("external_id", "access_key_id", "secret_access_key", "session_token")}
    account = CloudAccount(
        name=data.name,
        provider="aws",
        account_identifier=result.account_id,
        auth_method=data.credentials.method,
        role_arn=data.credentials.role_arn if data.credentials.method == "assume_role" else None,
        secret_payload=encrypt_secret_payload(secret) if secret else None,
        credentials_expire_at=(datetime.now(timezone.utc) + TEMP_CREDENTIAL_ASSUMED_LIFETIME
                               if data.credentials.method == "temporary_credentials" else None),
        principal_arn=result.principal_arn,
        status="connected",
        status_message=result.message,
        default_region=data.default_region,
        last_validated_at=datetime.now(timezone.utc),
        created_by_id=actor.user_id,
    )
    _set_regions(account, result.regions, data.regions)
    db.add(account)
    db.flush()
    audit.record(db, actor, "account.created", resource_type="cloud_account", resource_id=account.id,
                 details={"name": account.name, "aws_account_id": account.account_identifier,
                          "auth_method": account.auth_method, "regions": account.enabled_regions})
    db.commit()
    db.refresh(account)
    return account


def create_demo_account(db: Session, data: DemoAccountCreate, actor: Actor) -> CloudAccount:
    if db.scalar(select(CloudAccount).where(CloudAccount.is_demo.is_(True))):
        raise ConflictError("The demo environment is already connected")
    account = CloudAccount(
        name=data.name, provider="demo", account_identifier=DEMO_ACCOUNT_ID, auth_method="demo", is_demo=True,
        status="connected", status_message="Simulated environment — no AWS API calls are made",
        principal_arn=f"arn:aws:sts::{DEMO_ACCOUNT_ID}:assumed-role/CloudAegisAudit/demo",
        last_validated_at=datetime.now(timezone.utc), created_by_id=actor.user_id,
    )
    _set_regions(account, list(DEMO_REGIONS), list(DEMO_REGIONS))
    db.add(account)
    db.flush()
    audit.record(db, actor, "account.created", resource_type="cloud_account", resource_id=account.id,
                 details={"name": account.name, "demo": True})
    db.commit()
    db.refresh(account)
    return account


def get_account(db: Session, account_id: int) -> CloudAccount:
    account = db.get(CloudAccount, account_id)
    if account is None:
        raise NotFoundError("Cloud account not found")
    return account


def update_account(db: Session, account_id: int, data: AccountUpdate, actor: Actor) -> CloudAccount:
    account = get_account(db, account_id)
    changes: dict[str, Any] = {}
    if data.name and data.name != account.name:
        changes["name"] = {"from": account.name, "to": data.name}
        account.name = data.name
    if data.regions is not None:
        known = {r.name for r in account.regions}
        unknown = set(data.regions) - known
        if unknown:
            raise AppError(f"Regions not available for this account: {', '.join(sorted(unknown))}",
                           code="validation_error", status_code=422)
        if not data.regions:
            raise AppError("Enable at least one region", code="validation_error", status_code=422)
        changes["regions"] = data.regions
        _set_regions(account, list(known), data.regions)
    if data.credentials is not None:
        if account.is_demo:
            raise AppError("The demo environment has no credentials", status_code=400)
        result = test_connection(data.credentials, account.default_region)
        if not result.ok:
            raise AppError(f"Connection validation failed: {result.message}", code="connection_failed")
        if result.account_id != account.account_identifier:
            raise AppError(f"Credentials belong to account {result.account_id}, expected "
                           f"{account.account_identifier}", code="account_mismatch")
        auth = data.credentials.to_auth()
        secret = {k: v for k, v in auth.items() if k in ("external_id", "access_key_id", "secret_access_key",
                                                         "session_token")}
        account.auth_method = data.credentials.method
        account.role_arn = data.credentials.role_arn if data.credentials.method == "assume_role" else None
        account.secret_payload = encrypt_secret_payload(secret) if secret else None
        account.status = "connected"
        account.status_message = result.message
        account.last_validated_at = datetime.now(timezone.utc)
        account.credentials_expire_at = (datetime.now(timezone.utc) + TEMP_CREDENTIAL_ASSUMED_LIFETIME
                                         if data.credentials.method == "temporary_credentials" else None)
        changes["credentials"] = "rotated"
    if changes:
        audit.record(db, actor, "account.updated", resource_type="cloud_account", resource_id=account.id,
                     details=changes)
    db.commit()
    db.refresh(account)
    return account


def revalidate(db: Session, account_id: int, actor: Actor) -> ConnectionResult:
    account = get_account(db, account_id)
    kind, config = provider_config(account)
    try:
        result = _friendly(create_provider(kind, config).validate_connection())
    except ProviderError as exc:
        result = ConnectionResult(ok=False, message=str(exc))
    account.status = "connected" if result.ok else "error"
    account.status_message = result.message
    account.last_validated_at = datetime.now(timezone.utc)
    if result.ok and result.regions:
        _set_regions(account, result.regions, account.enabled_regions)
    audit.record(db, actor, "account.validated", resource_type="cloud_account", resource_id=account.id,
                 result="success" if result.ok else "failure", details={"message": result.message})
    db.commit()
    return result


def delete_account(db: Session, account_id: int, actor: Actor) -> None:
    account = get_account(db, account_id)
    active = db.scalar(select(func.count(Scan.id)).where(Scan.cloud_account_id == account_id,
                                                         Scan.status.in_(ACTIVE_SCAN_STATUSES)))
    if active:
        raise ConflictError("Cancel the running scan before removing this account")
    audit.record(db, actor, "account.deleted", resource_type="cloud_account", resource_id=account.id,
                 details={"name": account.name, "aws_account_id": account.account_identifier})
    db.delete(account)
    db.commit()


def list_accounts(db: Session) -> list[dict[str, Any]]:
    accounts = db.scalars(select(CloudAccount).order_by(CloudAccount.is_demo.desc(), CloudAccount.name)).all()
    asset_counts = dict(db.execute(select(Asset.cloud_account_id, func.count(Asset.id))
                                   .where(Asset.is_active.is_(True)).group_by(Asset.cloud_account_id)).all())
    finding_counts = dict(db.execute(select(Finding.cloud_account_id, func.count(Finding.id))
                                     .where(Finding.status.in_(ACTIVE_STATUSES))
                                     .group_by(Finding.cloud_account_id)).all())
    out = []
    for account in accounts:
        latest = db.scalar(select(Scan.security_score).where(Scan.cloud_account_id == account.id,
                                                             Scan.security_score.is_not(None))
                           .order_by(Scan.finished_at.desc()).limit(1))
        out.append(account_out(account, asset_counts.get(account.id, 0), finding_counts.get(account.id, 0), latest))
    return out


def account_out(account: CloudAccount, assets: int = 0, findings: int = 0, score: int | None = None) -> dict:
    return {
        "id": account.id, "name": account.name, "provider": account.provider,
        "account_identifier": account.account_identifier, "auth_method": account.auth_method,
        "role_arn": account.role_arn, "has_stored_secret": account.has_stored_secret,
        "credentials_expire_at": account.credentials_expire_at, "principal_arn": account.principal_arn,
        "status": account.status, "status_message": account.status_message, "is_demo": account.is_demo,
        "default_region": account.default_region,
        "regions": [{"name": r.name, "enabled": r.enabled} for r in account.regions],
        "last_validated_at": account.last_validated_at, "last_scan_at": account.last_scan_at,
        "created_at": account.created_at, "asset_count": assets, "open_findings": findings,
        "security_score": score,
    }


def onboarding_guide() -> dict[str, Any]:
    settings = get_settings()
    principal = getattr(settings, "platform_aws_principal_arn", None) or "arn:aws:iam::<CLOUDAEGIS_ACCOUNT_ID>:root"
    external_id = f"cloudaegis-{uuid.uuid4().hex[:20]}"
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": principal},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
        }],
    }
    inline = audit_policy_document()
    template = f"""AWSTemplateFormatVersion: "2010-09-09"
Description: Read-only audit role for CloudAegis (no write permissions)
Parameters:
  ExternalId:
    Type: String
    Default: {external_id}
    NoEcho: true
Resources:
  CloudAegisAuditRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: CloudAegisAudit
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: "{principal}"
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                sts:ExternalId: !Ref ExternalId
      Policies:
        - PolicyName: CloudAegisReadOnlyAudit
          PolicyDocument: {json.dumps(inline)}
Outputs:
  RoleArn:
    Value: !GetAtt CloudAegisAuditRole.Arn
"""
    return {
        "trust_policy": trust,
        "permissions_policies": ["Inline: CloudAegisReadOnlyAudit (least privilege, recommended)",
                                 "Alternative: arn:aws:iam::aws:policy/SecurityAudit"],
        "inline_policy": inline,
        "cloudformation_template": template,
        "platform_principal": getattr(settings, "platform_aws_principal_arn", None),
        "external_id_suggestion": external_id,
    }
