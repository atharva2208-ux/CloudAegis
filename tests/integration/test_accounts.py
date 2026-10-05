"""Cloud account onboarding: validation, secure credential handling, regions, deletion."""

from __future__ import annotations

import json
import logging

import boto3
import pytest

moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

pytestmark = pytest.mark.integration
ACCOUNT = "123456789012"
SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"
TOKEN = "IQoJb3JpZ2luX2VjEXAMPLESESSIONTOKENvalue1234567890"


@pytest.fixture
def aws():
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")


@pytest.fixture
def audit_role(aws):
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "sts:AssumeRole",
         "Condition": {"StringEquals": {"sts:ExternalId": "cloudaegis-test"}}}]}
    return aws.client("iam").create_role(RoleName="CloudAegisAudit", AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]


def _role_creds(arn):
    return {"method": "assume_role", "role_arn": arn, "external_id": "cloudaegis-test"}


def test_onboarding_guide_is_least_privilege(admin):
    guide = admin.get("/api/v1/accounts/onboarding-guide").json()
    statement = guide["trust_policy"]["Statement"][0]
    assert statement["Action"] == "sts:AssumeRole"
    assert "sts:ExternalId" in json.dumps(statement["Condition"])
    actions = guide["inline_policy"]["Statement"][0]["Action"]
    assert actions and all(a.split(":")[1].startswith(("Describe", "Get", "List")) for a in actions)
    assert "AWSTemplateFormatVersion" in guide["cloudformation_template"]


def test_test_connection_with_role(admin, audit_role):
    r = admin.post("/api/v1/accounts/test-connection", json={"credentials": _role_creds(audit_role), "default_region": "us-east-1"})
    assert r.status_code == 200
    result = r.json()
    assert result["ok"] and result["account_id"] == ACCOUNT
    assert "us-east-1" in result["regions"]


def test_create_account_never_returns_or_logs_secrets(admin, aws, caplog):
    creds = {"method": "temporary_credentials", "access_key_id": "ASIAEXAMPLEEXAMPLE12",
             "secret_access_key": SECRET, "session_token": TOKEN}
    with caplog.at_level(logging.DEBUG):
        r = admin.post("/api/v1/accounts", json={"name": "Sandbox account", "credentials": creds,
                                                  "default_region": "us-east-1", "regions": ["us-east-1"], "start_scan": False})
    assert r.status_code == 201, r.text
    body = r.text
    assert SECRET not in body and TOKEN not in body
    account = r.json()
    assert account["has_stored_secret"] is True
    assert account["auth_method"] == "temporary_credentials"
    listing = admin.get("/api/v1/accounts").text
    assert SECRET not in listing and TOKEN not in listing
    assert SECRET not in caplog.text and TOKEN not in caplog.text
    audit = admin.get("/api/v1/audit", params={"action": "account.created"}).text
    assert SECRET not in audit and TOKEN not in audit

    from sqlalchemy import text
    from app.core.database import engine

    with engine.connect() as conn:
        stored = conn.execute(text("SELECT secret_payload FROM cloud_accounts WHERE id = :i"), {"i": account["id"]}).scalar()
    assert stored and SECRET not in stored and TOKEN not in stored, "credentials must be encrypted at rest"
    admin.delete(f"/api/v1/accounts/{account['id']}")


def test_long_lived_keys_are_rejected(admin):
    creds = {"method": "temporary_credentials", "access_key_id": "AKIAIOSFODNN7EXAMPLE",
             "secret_access_key": SECRET, "session_token": TOKEN}
    r = admin.post("/api/v1/accounts/test-connection", json={"credentials": creds})
    assert r.status_code == 422
    assert "Long-lived" in json.dumps(r.json())


@pytest.mark.parametrize("arn", ["not-an-arn", "arn:aws:iam::12345:role/x", "arn:aws:s3:::bucket", "arn:aws:iam::123456789012:user/bob"])
def test_role_arn_is_validated(admin, arn):
    r = admin.post("/api/v1/accounts/test-connection", json={"credentials": {"method": "assume_role", "role_arn": arn}})
    assert r.status_code == 422


def test_failed_connection_blocks_creation(admin, aws, monkeypatch):
    from cloudaegis_engine.providers.aws import AWSProvider
    from cloudaegis_engine.providers.base import ConnectionResult

    monkeypatch.setattr(AWSProvider, "validate_connection",
                        lambda self: ConnectionResult(ok=False, message="Unable to authenticate: AccessDenied"))
    before = len(admin.get("/api/v1/accounts").json())
    creds = {"method": "assume_role", "role_arn": f"arn:aws:iam::{ACCOUNT}:role/NoTrust"}
    r = admin.post("/api/v1/accounts", json={"name": "Broken", "credentials": creds, "start_scan": False})
    assert r.status_code == 400
    assert "trust policy" in r.json()["error"]["message"]  # actionable guidance, not a raw AWS error
    assert len(admin.get("/api/v1/accounts").json()) == before


def test_account_lifecycle_with_role(admin, audit_role):
    r = admin.post("/api/v1/accounts", json={"name": "Production (role)", "credentials": _role_creds(audit_role),
                                              "default_region": "us-east-1", "regions": ["us-east-1", "eu-west-1"],
                                              "start_scan": False})
    assert r.status_code == 201, r.text
    account = r.json()
    assert account["role_arn"] == audit_role
    assert account["account_identifier"] == ACCOUNT
    assert {x["name"] for x in account["regions"] if x["enabled"]} == {"us-east-1", "eu-west-1"}
    assert "external_id" not in r.text.lower() or "cloudaegis-test" not in r.text

    renamed = admin.patch(f"/api/v1/accounts/{account['id']}", json={"name": "Production AWS", "regions": ["us-east-1"]})
    assert renamed.status_code == 200
    assert [x["name"] for x in renamed.json()["regions"] if x["enabled"]] == ["us-east-1"]
    assert admin.patch(f"/api/v1/accounts/{account['id']}", json={"regions": ["mars-1"]}).status_code == 422

    validated = admin.post(f"/api/v1/accounts/{account['id']}/validate").json()
    assert validated["ok"]

    deleted = admin.delete(f"/api/v1/accounts/{account['id']}")
    assert deleted.status_code == 200
    assert admin.get(f"/api/v1/accounts/{account['id']}").status_code == 404


def test_demo_environment_cannot_be_connected_twice(admin, demo_account):
    r = admin.post("/api/v1/accounts/demo", json={"name": "Another demo", "start_scan": False})
    assert r.status_code == 409


def test_demo_account_is_labelled_simulated(admin, demo_account):
    account = admin.get(f"/api/v1/accounts/{demo_account['id']}").json()
    assert account["is_demo"] is True
    assert "Simulated" in account["status_message"]
    assert account["has_stored_secret"] is False
