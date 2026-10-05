"""AWS provider adapter against moto-mocked AWS APIs.

These tests exercise the real boto3 collectors end to end: AWS resources are
created in moto, discovered by :class:`AWSProvider`, normalised, and then
evaluated by the rule engine. No AWS account or network access is needed.
"""

from __future__ import annotations

import json
from unittest import mock

import boto3
import pytest
from botocore.exceptions import ClientError

moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

from cloudaegis_engine.engine import ScanEngine  # noqa: E402
from cloudaegis_engine.providers import ProviderError  # noqa: E402
from cloudaegis_engine.providers.aws import AWSProvider  # noqa: E402
from cloudaegis_engine.providers.aws.session import build_session  # noqa: E402
from cloudaegis_engine.providers.base import ServiceAccessError  # noqa: E402

pytestmark = pytest.mark.aws
REGION = "us-east-1"
ACCOUNT = "123456789012"  # moto's default account


@pytest.fixture
def aws():
    with mock_aws():
        yield boto3.Session(region_name=REGION)


@pytest.fixture
def provider(aws):
    return AWSProvider({"method": "default_chain"}, default_region=REGION)


def failing(output, rule_id: str) -> set[str]:
    return {r.resource_uid for r in output.failures if r.rule_id == rule_id}


def passing(output, rule_id: str) -> set[str]:
    return {r.resource_uid for r in output.results if r.rule_id == rule_id and not r.failed}


# --- Connection ---------------------------------------------------------------
def test_validate_connection_returns_identity_and_regions(provider):
    result = provider.validate_connection()
    assert result.ok
    assert result.account_id == ACCOUNT
    assert result.principal_arn.startswith("arn:aws:")
    assert REGION in result.regions


def test_account_mismatch_is_rejected(aws):
    result = AWSProvider({"method": "default_chain"}, expected_account_id="999999999999").validate_connection()
    assert not result.ok
    assert "expected 999999999999" in result.message


def test_assume_role_session(aws):
    iam = aws.client("iam")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName="CloudAegisAudit", AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    provider = AWSProvider({"method": "assume_role", "role_arn": role["Arn"], "external_id": "ext-123"})
    result = provider.validate_connection()
    assert result.ok
    assert "assumed-role/CloudAegisAudit/CloudAegisSecurityAudit" in result.principal_arn


def test_temporary_credentials_session_requires_all_parts():
    with pytest.raises(ProviderError):
        build_session({"method": "temporary_credentials", "access_key_id": "ASIAXXXX"})
    with pytest.raises(ProviderError):
        build_session({"method": "long_lived_keys"})


# --- Discovery + rules ----------------------------------------------------------
def test_iam_user_without_mfa_and_admin_policy(aws, provider):
    iam = aws.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Sup3r-Secret-Pass!")
    admin = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    iam.put_user_policy(UserName="alice", PolicyName="break-glass", PolicyDocument=json.dumps(admin))
    iam.create_user(UserName="build-bot")  # programmatic-only user: console MFA rule not applicable
    output = ScanEngine(provider).run([REGION], services=["IAM"])
    alice = f"arn:aws:iam::{ACCOUNT}:user/alice"
    assert alice in failing(output, "IAM-003")  # console user without MFA
    assert alice in failing(output, "IAM-013")  # administrator without MFA
    assert alice in failing(output, "IAM-009")  # user holds administrative privileges
    assert f"arn:aws:iam::{ACCOUNT}:user/build-bot" not in failing(output, "IAM-003")


def test_iam_publicly_assumable_role(aws, provider):
    iam = aws.client("iam")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName="open-role", AssumeRolePolicyDocument=json.dumps(trust))
    output = ScanEngine(provider).run([REGION], services=["IAM"])
    assert f"arn:aws:iam::{ACCOUNT}:role/open-role" in failing(output, "IAM-010")


def test_s3_public_policy_and_missing_controls(aws, provider):
    s3 = aws.client("s3")
    s3.create_bucket(Bucket="public-site")
    s3.put_bucket_policy(Bucket="public-site", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::public-site/*"}]}))
    s3.create_bucket(Bucket="locked-down")
    s3.put_public_access_block(Bucket="locked-down", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_versioning(Bucket="locked-down", VersioningConfiguration={"Status": "Enabled"})
    output = ScanEngine(provider).run([REGION], services=["S3"])
    public, private = "arn:aws:s3:::public-site", "arn:aws:s3:::locked-down"
    assert public in failing(output, "S3-002")  # public bucket policy
    assert public in failing(output, "S3-005")  # versioning disabled
    assert private not in failing(output, "S3-002")
    assert private in passing(output, "S3-005")
    assert private in passing(output, "S3-007")  # bucket-level BPA enabled
    resources = {r.uid: r for r in output.inventory}
    assert output.exposure[public] is True
    assert resources[public].service == "S3"


def test_ec2_open_ssh_and_imdsv1_and_unencrypted_volume(aws, provider):
    ec2 = aws.client("ec2")
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName="ssh-open", Description="test", VpcId=vpc_id)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    ec2.run_instances(ImageId=image, MinCount=1, MaxCount=1, SecurityGroupIds=[sg],
                      MetadataOptions={"HttpTokens": "optional", "HttpEndpoint": "enabled"})
    ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8, Encrypted=False)
    output = ScanEngine(provider).run([REGION], services=["EC2"])
    assert any(uid.endswith(f"security-group/{sg}") for uid in failing(output, "EC2-002"))
    assert failing(output, "EC2-005"), "IMDSv1 instance should be flagged"
    assert failing(output, "EC2-006"), "unencrypted EBS volume should be flagged"


def test_kms_rotation_and_secrets_rotation(aws, provider):
    kms = aws.client("kms")
    key = kms.create_key(Description="app key")["KeyMetadata"]["Arn"]
    rotated = kms.create_key(Description="rotated")["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=rotated)
    aws.client("secretsmanager").create_secret(Name="db/password", SecretString="hunter2-not-collected")
    output = ScanEngine(provider).run([REGION], services=["KMS", "Secrets Manager"])
    assert key in failing(output, "KMS-001")
    assert any(rotated in uid for uid in passing(output, "KMS-001"))
    assert failing(output, "SM-001"), "secret without rotation should be flagged"
    # Secret values are never collected.
    blob = json.dumps([r.properties for r in output.inventory], default=str)
    assert "hunter2-not-collected" not in blob


def test_rds_public_unencrypted_instance(aws, provider):
    aws.client("rds").create_db_instance(
        DBInstanceIdentifier="orders-db", DBInstanceClass="db.t3.micro", Engine="postgres",
        MasterUsername="admin", MasterUserPassword="password123!", AllocatedStorage=20,
        PubliclyAccessible=True, StorageEncrypted=False, BackupRetentionPeriod=0)
    output = ScanEngine(provider).run([REGION], services=["RDS"])
    uid = next(r.uid for r in output.inventory if r.name == "orders-db")
    assert uid in failing(output, "RDS-001")
    assert uid in failing(output, "RDS-002")
    assert uid in failing(output, "RDS-003")


def test_cloudtrail_missing_is_flagged(aws, provider):
    # CT-001 is an account-level check: the account resource comes from IAM discovery.
    output = ScanEngine(provider).run([REGION], services=["IAM", "CloudTrail"])
    assert failing(output, "CT-001"), "an account without any trail must fail CT-001"


def test_full_scan_does_not_error_on_empty_account(provider):
    output = ScanEngine(provider).run([REGION])
    assert not output.rule_errors
    assert output.account_id == ACCOUNT


def test_access_denied_becomes_service_error(provider):
    denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "ListBuckets")

    def boom(ctx):
        raise denied
        yield  # pragma: no cover

    with mock.patch.dict("cloudaegis_engine.providers.aws.collectors.COLLECTORS", {"S3": boom}, clear=False):
        with pytest.raises(ServiceAccessError) as exc:
            list(provider.discover_service("S3", [REGION]))
    assert "AccessDenied" in exc.value.message
    assert "permissions" in exc.value.message
