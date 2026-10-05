"""Concise builders for rule unit tests.

Every builder returns a *compliant* baseline resource whose property names
and shapes mirror what the AWS collectors and the demo generator emit
(``providers/aws/collectors`` and ``providers/demo/generator.py``).
Tests override only the properties relevant to the case under test::

    bucket(versioning="Suspended")
    iam_user(access_keys=[access_key(created_days=120)])

``NOW`` is fixed so age-based rules are deterministic.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.models import CheckOutcome, Inventory, Relationship, Resource, RuleResult
from cloudaegis_engine.rules.base import Rule, RuleContext
from cloudaegis_engine.rules.registry import default_registry

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
ACCOUNT_ID = "123456789012"
EXTERNAL_ACCOUNT_ID = "210987654321"
REGION = "us-east-1"

ADMIN_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
READONLY_DOC = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": ["s3:Get*", "s3:List*", "ec2:Describe*"], "Resource": "*"}]}
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
READONLY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
BPA_ON = {"block_public_acls": True, "ignore_public_acls": True,
          "block_public_policy": True, "restrict_public_buckets": True}


# -- time ----------------------------------------------------------------------
def days_ago(days: int, hours: int = 0) -> str:
    """ISO-8601 timestamp ``days`` (+``hours``) before :data:`NOW`."""
    return (NOW - timedelta(days=days, hours=hours)).isoformat()


# -- evaluation helpers ------------------------------------------------------------
def rule(rule_id: str) -> Rule:
    found = default_registry().get(rule_id)
    assert found is not None, f"rule {rule_id} is not registered"
    return found


def context(*resources: Resource, **overrides: Any) -> RuleContext:
    return RuleContext(inventory=Inventory(resources), now=NOW, **overrides)


def evaluate(rule_id: str, resource: Resource, *related: Resource, **ctx_overrides: Any) -> RuleResult | None:
    """Evaluate ``rule_id`` against ``resource`` with ``related`` resources in the inventory."""
    r = rule(rule_id)
    assert r.resource_type == resource.resource_type, (
        f"{rule_id} targets {r.resource_type}, fixture is {resource.resource_type}")
    result = r.evaluate(resource, context(resource, *related, **ctx_overrides))
    if result is not None:
        assert result.rule_id == rule_id
        assert result.resource_uid == resource.uid
    return result


def assert_pass(result: RuleResult | None) -> RuleResult:
    assert result is not None, "expected PASS, rule returned None (not applicable)"
    assert result.outcome is CheckOutcome.PASS, f"expected PASS, got FAIL: {result.evidence}"
    return result


def assert_fail(result: RuleResult | None) -> RuleResult:
    assert result is not None, "expected FAIL, rule returned None (not applicable)"
    assert result.outcome is CheckOutcome.FAIL, f"expected FAIL, got PASS: {result.evidence}"
    assert result.message, "failed results must carry a message"
    return result


# -- generic -------------------------------------------------------------------------
def make(resource_type: str, uid: str, name: str, props: dict[str, Any], *, region: str = REGION,
         account_id: str = ACCOUNT_ID, tags: dict[str, str] | None = None,
         relationships: list[Relationship] | None = None) -> Resource:
    return Resource(uid=uid, resource_type=resource_type, service=rt.SERVICE_OF[resource_type], name=name,
                    region=region, account_id=account_id, properties=props, tags=tags or {},
                    relationships=relationships or [])


def drop(resource: Resource, *keys: str) -> Resource:
    """Remove properties entirely (a collector that could not read them omits the key)."""
    for key in keys:
        resource.properties.pop(key, None)
    return resource


def statement(effect: str = "Allow", **fields: Any) -> dict[str, Any]:
    return {"Effect": effect, **fields}


def policy_doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


# -- IAM -----------------------------------------------------------------------------
def account(account_id: str = ACCOUNT_ID, **props: Any) -> Resource:
    base = {
        "account_id": account_id,
        "root_mfa_enabled": True,
        "root_access_keys_present": False,
        "password_policy": {
            "minimum_length": 14, "require_symbols": True, "require_numbers": True,
            "require_uppercase": True, "require_lowercase": True,
            "max_password_age": 90, "password_reuse_prevention": 24,
        },
        "s3_public_access_block": dict(BPA_ON),
    }
    return make(rt.AWS_ACCOUNT, f"arn:aws:iam::{account_id}:root", f"AWS account {account_id}",
                {**base, **props}, region="global", account_id=account_id)


def access_key(key_id: str = "AKIAEXAMPLE0001", *, created_days: int = 10, last_used_days: int | None = 1,
               status: str = "Active") -> dict[str, Any]:
    return {
        "access_key_id": key_id,
        "status": status,
        "created_at": days_ago(created_days),
        "last_used_at": days_ago(last_used_days) if last_used_days is not None else None,
    }


def admin_doc_entry(name: str = "AdministratorAccess", source: str = "attached") -> dict[str, Any]:
    return {"name": name, "source": source, "document": ADMIN_DOC}


def iam_user(name: str = "alice.smith", **props: Any) -> Resource:
    base = {
        "user_name": name,
        "created_at": days_ago(400),
        "password_enabled": True,
        "password_last_used": days_ago(2),
        "mfa_enabled": True,
        "mfa_devices": 1,
        "access_keys": [],
        "groups": ["ReadOnly"],
        "attached_policies": [],
        "policy_documents": [{"name": "ReadOnlyAccess", "source": "group:ReadOnly", "document": READONLY_DOC}],
    }
    return make(rt.IAM_USER, f"arn:aws:iam::{ACCOUNT_ID}:user/{name}", name, {**base, **props}, region="global")


def service_trust(service: str = "lambda.amazonaws.com") -> dict[str, Any]:
    return policy_doc(statement(Principal={"Service": service}, Action="sts:AssumeRole"))


def iam_role(name: str = "orders-lambda-exec", **props: Any) -> Resource:
    base = {
        "role_name": name, "path": "/", "created_at": days_ago(300), "is_service_linked": False,
        "trust_policy": service_trust(),
        "last_used_at": days_ago(1),
        "attached_policies": [],
        "policy_documents": [{"name": "orders-access", "source": "inline", "document": policy_doc(
            statement(Action=["s3:GetObject", "s3:PutObject"], Resource="arn:aws:s3:::prod-orders-*/*"),
            statement(Action=["logs:CreateLogStream", "logs:PutLogEvents"], Resource="*"))}],
    }
    return make(rt.IAM_ROLE, f"arn:aws:iam::{ACCOUNT_ID}:role/{name}", name, {**base, **props}, region="global")


def iam_policy(name: str = "orders-service-policy", **props: Any) -> Resource:
    base = {
        "policy_name": name, "attachment_count": 2, "default_version": "v1",
        "document": policy_doc(statement(Action=["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"],
                                         Resource=f"arn:aws:dynamodb:*:{ACCOUNT_ID}:table/orders-*")),
        "created_at": days_ago(200),
    }
    return make(rt.IAM_POLICY, f"arn:aws:iam::{ACCOUNT_ID}:policy/{name}", name, {**base, **props}, region="global")


# -- S3 ------------------------------------------------------------------------------
def deny_insecure_transport(bucket_name: str) -> dict[str, Any]:
    return statement("Deny", Sid="DenyInsecureTransport", Principal="*", Action="s3:*",
                     Resource=[f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
                     Condition={"Bool": {"aws:SecureTransport": "false"}})


def owner_grant() -> dict[str, Any]:
    return {"grantee_type": "CanonicalUser", "grantee_uri": None, "permission": "FULL_CONTROL"}


def public_grant(uri: str = ALL_USERS_URI, permission: str = "READ") -> dict[str, Any]:
    return {"grantee_type": "Group", "grantee_uri": uri, "permission": permission}


def bucket(name: str = "prod-orders-data", account_id: str = ACCOUNT_ID, **props: Any) -> Resource:
    base = {
        "bucket_name": name,
        "created_at": days_ago(500),
        "public_access_block": dict(BPA_ON),
        "policy": policy_doc(deny_insecure_transport(name)),
        "policy_is_public": False,
        "acl_grants": [owner_grant()],
        "encryption": {"algorithm": "aws:kms", "kms_key_id": f"arn:aws:kms:{REGION}:{account_id}:key/demo-1"},
        "versioning": "Enabled",
        "mfa_delete": False,
        "logging_enabled": True,
        "logging_target": "shared-s3-access-logs",
        "object_ownership": "BucketOwnerEnforced",
    }
    return make(rt.S3_BUCKET, f"arn:aws:s3:::{name}", name, {**base, **props}, account_id=account_id)


# -- EC2 -----------------------------------------------------------------------------
def perm(protocol: str = "tcp", from_port: int | None = None, to_port: int | None = None, *,
         cidrs: list[str] | tuple[str, ...] = (), ipv6_cidrs: list[str] | tuple[str, ...] = (),
         source_groups: list[str] | tuple[str, ...] = ()) -> dict[str, Any]:
    """A normalized security-group permission (see collectors/ec2.normalize_permissions)."""
    if to_port is None and from_port is not None:
        to_port = from_port
    return {"protocol": protocol, "from_port": from_port, "to_port": to_port, "cidrs": list(cidrs),
            "ipv6_cidrs": list(ipv6_cidrs), "source_groups": list(source_groups)}


def internet(protocol: str, from_port: int | None = None, to_port: int | None = None) -> dict[str, Any]:
    return perm(protocol, from_port, to_port, cidrs=["0.0.0.0/0"])


ALL_TRAFFIC_OUT = perm("-1", cidrs=["0.0.0.0/0"])
HTTPS_OUT = perm("tcp", 443, cidrs=["0.0.0.0/0"])


def security_group(group_id: str = "sg-0123456789abcdef0", region: str = REGION, account_id: str = ACCOUNT_ID,
                   **props: Any) -> Resource:
    base = {
        "group_id": group_id, "group_name": "orders-app-sg", "vpc_id": "vpc-0aaaaaaaaaaaaaaa1", "is_default": False,
        "description": "app tier for orders",
        "ingress": [perm("tcp", 8080, cidrs=["10.0.0.0/8"])],
        "egress": [HTTPS_OUT],
        "attached_eni_count": 1,
    }
    return make(rt.EC2_SECURITY_GROUP, f"arn:aws:ec2:{region}:{account_id}:security-group/{group_id}",
                f"{props.get('group_name', base['group_name'])} ({group_id})", {**base, **props},
                region=region, account_id=account_id)


def instance(instance_id: str = "i-0123456789abcdef0", region: str = REGION, **props: Any) -> Resource:
    base = {
        "instance_id": instance_id, "instance_type": "t3.medium", "state": "running",
        "launch_time": days_ago(30), "public_ip": None, "private_ip": "10.0.1.15",
        "vpc_id": "vpc-0aaaaaaaaaaaaaaa1", "subnet_id": "subnet-0aaaaaaaaaaaaaaa1",
        "security_group_ids": ["sg-0123456789abcdef0"],
        "imds_http_tokens": "required", "imds_http_endpoint": "enabled",
        "iam_instance_profile": f"arn:aws:iam::{ACCOUNT_ID}:instance-profile/orders-ec2",
        "platform": "Linux/UNIX", "image_id": "ami-0aaaaaaaaaaaaaaa1",
    }
    return make(rt.EC2_INSTANCE, f"arn:aws:ec2:{region}:{ACCOUNT_ID}:instance/{instance_id}", "orders-app-001",
                {**base, **props}, region=region)


def volume(volume_id: str = "vol-0123456789abcdef0", **props: Any) -> Resource:
    base = {"volume_id": volume_id, "encrypted": True, "kms_key_id": None, "size_gb": 100,
            "volume_type": "gp3", "state": "in-use", "attached_instance_ids": ["i-0123456789abcdef0"]}
    return make(rt.EC2_VOLUME, f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:volume/{volume_id}", volume_id, {**base, **props})


def region_settings(region: str = REGION, **props: Any) -> Resource:
    base = {"ebs_encryption_by_default": True}
    return make(rt.EC2_REGION_SETTINGS, f"arn:aws:ec2:{region}:{ACCOUNT_ID}:region-settings",
                f"EC2 settings ({region})", {**base, **props}, region=region)


# -- VPC -----------------------------------------------------------------------------
def vpc(vpc_id: str = "vpc-0aaaaaaaaaaaaaaa1", **props: Any) -> Resource:
    base = {"vpc_id": vpc_id, "cidr_block": "10.8.0.0/16", "is_default": False, "flow_logs_enabled": True}
    return make(rt.VPC, f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:vpc/{vpc_id}", "prod-core-vpc", {**base, **props})


def subnet(subnet_id: str = "subnet-0aaaaaaaaaaaaaaa1", **props: Any) -> Resource:
    base = {"subnet_id": subnet_id, "vpc_id": "vpc-0aaaaaaaaaaaaaaa1", "cidr_block": "10.8.0.0/20",
            "availability_zone": f"{REGION}a", "map_public_ip_on_launch": False, "has_internet_route": True}
    return make(rt.VPC_SUBNET, f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:subnet/{subnet_id}", "prod-public-0",
                {**base, **props})


def nacl_entry(rule_number: int, action: str, cidr: str = "0.0.0.0/0", protocol: str = "-1",
               from_port: int | None = None, to_port: int | None = None, egress: bool = False) -> dict[str, Any]:
    if to_port is None and from_port is not None:
        to_port = from_port
    return {"rule_number": rule_number, "egress": egress, "protocol": protocol, "action": action,
            "cidr": cidr, "from_port": from_port, "to_port": to_port}


def default_nacl_entries() -> list[dict[str, Any]]:
    """AWS default NACL: allow all in/out, then the implicit ``*`` deny."""
    return [nacl_entry(100, "allow"), nacl_entry(32767, "deny"), nacl_entry(100, "allow", egress=True)]


def nacl(nacl_id: str = "acl-0aaaaaaaaaaaaaaa1", **props: Any) -> Resource:
    base = {
        "nacl_id": nacl_id, "vpc_id": "vpc-0aaaaaaaaaaaaaaa1", "is_default": True,
        "entries": [nacl_entry(10, "deny", protocol="6", from_port=22),
                    nacl_entry(20, "deny", protocol="6", from_port=3389)] + default_nacl_entries(),
        "subnet_ids": ["subnet-0aaaaaaaaaaaaaaa1"],
    }
    return make(rt.VPC_NETWORK_ACL, f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:network-acl/{nacl_id}", "prod-nacl",
                {**base, **props})


# -- RDS -----------------------------------------------------------------------------
def rds_instance(name: str = "prod-orders-db-01", region: str = REGION, **props: Any) -> Resource:
    base = {
        "db_instance_id": name, "engine": "postgres", "engine_version": "16.3",
        "instance_class": "db.r6g.large", "status": "available", "publicly_accessible": False,
        "storage_encrypted": True, "kms_key_id": f"arn:aws:kms:{region}:{ACCOUNT_ID}:key/rds",
        "backup_retention_period": 7, "log_exports": ["postgresql"],
        "security_group_ids": ["sg-0123456789abcdef0"], "deletion_protection": True, "multi_az": True,
        "endpoint": f"{name}.c0123456789.{region}.rds.amazonaws.com:5432", "created_at": days_ago(300),
    }
    return make(rt.RDS_INSTANCE, f"arn:aws:rds:{region}:{ACCOUNT_ID}:db:{name}", name, {**base, **props},
                region=region)


# -- CloudTrail ----------------------------------------------------------------------
def trail(name: str = "organization-trail", account_id: str = ACCOUNT_ID, **props: Any) -> Resource:
    bucket_name = props.get("s3_bucket_name", "shared-cloudtrail-logs")
    base = {
        "trail_name": name, "home_region": REGION, "is_multi_region": True, "is_organization_trail": False,
        "is_logging": True, "log_file_validation": True, "s3_bucket_name": bucket_name,
        "kms_key_id": f"arn:aws:kms:{REGION}:{account_id}:key/0123456789abcdef",
        "cloudwatch_log_group_arn": f"arn:aws:logs:{REGION}:{account_id}:log-group:cloudtrail:*",
        "include_global_events": True,
    }
    return make(rt.CLOUDTRAIL_TRAIL, f"arn:aws:cloudtrail:{REGION}:{account_id}:trail/{name}", name,
                {**base, **props}, account_id=account_id,
                relationships=[Relationship("logs_to", f"arn:aws:s3:::{bucket_name}")])


# -- Lambda --------------------------------------------------------------------------
def lambda_function(name: str = "orders-handler-001", **props: Any) -> Resource:
    base = {
        "function_name": name, "runtime": "python3.12", "package_type": "Zip",
        "role_arn": f"arn:aws:iam::{ACCOUNT_ID}:role/orders-lambda-exec",
        "function_url_auth_type": None, "resource_policy": None,
        "environment_variable_names": ["LOG_LEVEL", "TABLE_NAME"],
        "kms_key_arn": f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/0123456789abcdef",
        "last_modified": days_ago(20), "vpc_id": None,
    }
    return make(rt.LAMBDA_FUNCTION, f"arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:{name}", name,
                {**base, **props})


# -- KMS -----------------------------------------------------------------------------
def root_key_policy() -> dict[str, Any]:
    return policy_doc(statement(Sid="EnableRootPermissions", Principal={"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
                                Action="kms:*", Resource="*"))


def kms_key(key_id: str = "1234abcd-12ab-34cd-56ef-1234567890ab", **props: Any) -> Resource:
    base = {
        "key_id": key_id, "key_manager": "CUSTOMER", "key_state": "Enabled", "key_spec": "SYMMETRIC_DEFAULT",
        "key_usage": "ENCRYPT_DECRYPT", "rotation_enabled": True, "policy": root_key_policy(),
        "description": "orders encryption key", "deletion_date": None, "created_at": days_ago(400),
    }
    return make(rt.KMS_KEY, f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/{key_id}", "alias/orders-data",
                {**base, **props})


# -- Secrets Manager -----------------------------------------------------------------
def secret(name: str = "prod/orders/db-credentials", **props: Any) -> Resource:
    base = {
        "secret_name": name, "rotation_enabled": True, "rotation_days": 30,
        "last_rotated_at": days_ago(10), "last_changed_at": days_ago(10), "created_at": days_ago(400),
        "kms_key_id": f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/0123456789abcdef",
        "resource_policy": None,
    }
    return make(rt.SECRET, f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{name}-AbCdEf", name,
                {**base, **props})


# -- ECR -----------------------------------------------------------------------------
def ecr_repository(name: str = "orders/api", **props: Any) -> Resource:
    base = {
        "repository_name": name, "repository_uri": f"{ACCOUNT_ID}.dkr.ecr.{REGION}.amazonaws.com/{name}",
        "scan_on_push": True, "image_tag_mutability": "IMMUTABLE", "encryption_type": "AES256",
        "kms_key": None, "repository_policy": None, "created_at": days_ago(100),
    }
    return make(rt.ECR_REPOSITORY, f"arn:aws:ecr:{REGION}:{ACCOUNT_ID}:repository/{name}", name, {**base, **props})
