"""Derived posture attributes per asset: public exposure and encryption."""

from __future__ import annotations

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.checks import network, policy as pol
from cloudaegis_engine.models import Inventory, Resource
from cloudaegis_engine.rules.aws._helpers import bucket_public_reasons, internet_ingress

ENCRYPTED = "encrypted"
UNENCRYPTED = "unencrypted"
NOT_APPLICABLE = "not_applicable"


def is_publicly_exposed(resource: Resource, inventory: Inventory) -> bool:
    t = resource.resource_type
    p = resource.properties
    if t == rt.S3_BUCKET:
        return bool(bucket_public_reasons(resource, inventory))
    if t == rt.EC2_INSTANCE:
        return (
            p.get("state") == "running"
            and bool(p.get("public_ip"))
            and bool(internet_ingress(inventory, p.get("security_group_ids"), resource.region, resource.account_id))
        )
    if t == rt.RDS_INSTANCE:
        return bool(p.get("publicly_accessible"))
    if t == rt.LAMBDA_FUNCTION:
        return p.get("function_url_auth_type") == "NONE" or pol.is_public_policy(p.get("resource_policy"))
    if t == rt.ECR_REPOSITORY:
        return pol.is_public_policy(p.get("repository_policy"))
    if t == rt.KMS_KEY:
        return p.get("key_manager") == "CUSTOMER" and pol.is_public_policy(p.get("policy"))
    if t == rt.SECRET:
        return pol.is_public_policy(p.get("resource_policy"))
    if t == rt.IAM_ROLE:
        return any(
            pol.principal_is_wildcard(s.get("Principal"))
            and not pol.has_restricting_condition(s)
            and not pol.statement_has_condition_key(s, "sts:ExternalId")
            for s in pol.allow_statements(p.get("trust_policy"))
        )
    if t == rt.EC2_SECURITY_GROUP:
        return bool(p.get("attached_eni_count")) and bool(network.internet_exposed_ports(p.get("ingress")))
    if t == rt.VPC_SUBNET:
        return bool(p.get("map_public_ip_on_launch")) and bool(p.get("has_internet_route"))
    return False


def encryption_status(resource: Resource) -> str:
    t = resource.resource_type
    p = resource.properties
    if t == rt.S3_BUCKET:
        return ENCRYPTED if p.get("encryption") else UNENCRYPTED
    if t == rt.EC2_VOLUME:
        return ENCRYPTED if p.get("encrypted") else UNENCRYPTED
    if t == rt.RDS_INSTANCE:
        return ENCRYPTED if p.get("storage_encrypted") else UNENCRYPTED
    if t in (rt.SECRET, rt.ECR_REPOSITORY):
        return ENCRYPTED  # always encrypted at rest by the service
    return NOT_APPLICABLE
