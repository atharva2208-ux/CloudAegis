"""AWS session construction.

Supported authentication methods (long-lived access keys are deliberately
not supported):

``assume_role``
    CloudAegis' own identity (instance profile, ECS task role, or the
    default credential chain) calls ``sts:AssumeRole`` on a read-only
    audit role in the target account, optionally with an external ID.
    Credentials auto-refresh for long scans.

``temporary_credentials``
    STS session credentials (``ASIA...`` access key + session token)
    supplied by the operator. They expire on their own.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.config import Config
from botocore.credentials import RefreshableCredentials
from botocore.session import get_session

from cloudaegis_engine.providers.base import ProviderError

BOTO_CONFIG = Config(
    retries={"max_attempts": 8, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=30,
    user_agent_extra="CloudAegis/1.0",
)

ROLE_SESSION_NAME = "CloudAegisSecurityAudit"
ASSUME_ROLE_DURATION = 3600


def _assume_role_refresher(role_arn: str, external_id: str | None, base: boto3.Session):
    def refresh() -> dict[str, Any]:
        params: dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": ROLE_SESSION_NAME,
            "DurationSeconds": ASSUME_ROLE_DURATION,
        }
        if external_id:
            params["ExternalId"] = external_id
        creds = base.client("sts", config=BOTO_CONFIG).assume_role(**params)["Credentials"]
        expiry = creds["Expiration"]
        if isinstance(expiry, datetime):
            expiry = expiry.astimezone(timezone.utc).isoformat()
        return {
            "access_key": creds["AccessKeyId"],
            "secret_key": creds["SecretAccessKey"],
            "token": creds["SessionToken"],
            "expiry_time": expiry,
        }

    return refresh


def build_session(auth: dict[str, Any], default_region: str = "us-east-1") -> boto3.Session:
    method = auth.get("method")
    if method == "assume_role":
        role_arn = auth.get("role_arn")
        if not role_arn:
            raise ProviderError("role_arn is required for assume_role authentication")
        base = boto3.Session(region_name=default_region)
        refresher = _assume_role_refresher(role_arn, auth.get("external_id"), base)
        credentials = RefreshableCredentials.create_from_metadata(
            metadata=refresher(), refresh_using=refresher, method="sts-assume-role"
        )
        botocore_session = get_session()
        botocore_session._credentials = credentials  # documented pattern for refreshable creds
        botocore_session.set_config_variable("region", default_region)
        return boto3.Session(botocore_session=botocore_session)
    if method == "temporary_credentials":
        key = auth.get("access_key_id") or ""
        secret = auth.get("secret_access_key")
        token = auth.get("session_token")
        if not (key and secret and token):
            raise ProviderError("Temporary credentials require an access key ID, secret access key and session token")
        return boto3.Session(
            aws_access_key_id=key,
            aws_secret_access_key=secret,
            aws_session_token=token,
            region_name=default_region,
        )
    if method == "default_chain":
        # Used for local development and tests (e.g. moto, or an operator's
        # own short-lived SSO session). Not offered in the UI.
        return boto3.Session(region_name=default_region)
    raise ProviderError(f"Unsupported AWS authentication method: {method}")
