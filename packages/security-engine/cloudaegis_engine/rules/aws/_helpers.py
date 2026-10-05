"""Cross-resource helpers shared by AWS rule packs and posture derivation."""

from __future__ import annotations

from typing import Any

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.checks import network, policy as pol
from cloudaegis_engine.models import Inventory, Resource

BPA_FLAGS = ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets")
PUBLIC_GRANTEE_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def account_resource(inventory: Inventory, account_id: str) -> Resource | None:
    for resource in inventory.of_type(rt.AWS_ACCOUNT):
        if resource.account_id == account_id:
            return resource
    return None


def effective_bpa(bucket: Resource, inventory: Inventory) -> dict[str, bool]:
    """Combine bucket-level and account-level S3 Block Public Access.

    A flag is effective if it is enabled at either level.
    """
    bucket_bpa = bucket.prop("public_access_block") or {}
    account = account_resource(inventory, bucket.account_id)
    account_bpa = (account.prop("s3_public_access_block") if account else None) or {}
    return {flag: bool(bucket_bpa.get(flag)) or bool(account_bpa.get(flag)) for flag in BPA_FLAGS}


def public_acl_grants(bucket: Resource) -> list[dict[str, Any]]:
    return [g for g in bucket.prop("acl_grants", []) or [] if g.get("grantee_uri") in PUBLIC_GRANTEE_URIS]


def bucket_public_reasons(bucket: Resource, inventory: Inventory) -> list[str]:
    """Reasons a bucket is effectively public, after Block Public Access."""
    bpa = effective_bpa(bucket, inventory)
    reasons: list[str] = []
    policy_public = bucket.prop("policy_is_public")
    if policy_public is None:
        policy_public = pol.is_public_policy(bucket.prop("policy"))
    if policy_public and not bpa["restrict_public_buckets"]:
        reasons.append("Bucket policy grants public access")
    if public_acl_grants(bucket) and not bpa["ignore_public_acls"]:
        reasons.append("Bucket ACL grants access to AllUsers/AuthenticatedUsers")
    return reasons


def security_groups(inventory: Inventory, group_ids: list[str] | None, region: str, account_id: str) -> list[Resource]:
    wanted = set(group_ids or ())
    return [
        sg
        for sg in inventory.of_type(rt.EC2_SECURITY_GROUP)
        if sg.prop("group_id") in wanted and sg.region == region and sg.account_id == account_id
    ]


def internet_ingress(inventory: Inventory, group_ids: list[str] | None, region: str, account_id: str) -> list[dict[str, Any]]:
    exposed: list[dict[str, Any]] = []
    for sg in security_groups(inventory, group_ids, region, account_id):
        for rule in network.internet_exposed_ports(sg.prop("ingress")):
            exposed.append({"SecurityGroup": sg.prop("group_id"), **rule})
    return exposed


def role_by_arn(inventory: Inventory, arn: str | None) -> Resource | None:
    if not arn:
        return None
    return inventory.get(arn)
