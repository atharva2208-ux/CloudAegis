"""S3 bucket discovery."""

from __future__ import annotations

from typing import Any, Iterator

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.models import Resource
from cloudaegis_engine.providers.aws.collectors import CollectorContext
from cloudaegis_engine.providers.aws.collectors._util import call, iso, policy_doc, tags_to_dict


def _bucket_region(s3: Any, name: str) -> str:
    location = call(s3.get_bucket_location, Bucket=name, default={}).get("LocationConstraint")
    if location in (None, ""):
        return "us-east-1"
    if location == "EU":
        return "eu-west-1"
    return location


def collect(ctx: CollectorContext) -> Iterator[Resource]:
    s3_global = ctx.client("s3", "us-east-1")
    buckets = s3_global.list_buckets().get("Buckets", [])
    selected = set(ctx.regions)
    for bucket in buckets:
        name = bucket["Name"]
        region = _bucket_region(s3_global, name)
        if selected and region not in selected:
            continue
        s3 = ctx.client("s3", region)

        bpa_raw = call(s3.get_public_access_block, Bucket=name, missing=("NoSuchPublicAccessBlockConfiguration",))
        bpa = None
        if bpa_raw:
            c = bpa_raw.get("PublicAccessBlockConfiguration", {})
            bpa = {
                "block_public_acls": c.get("BlockPublicAcls", False),
                "ignore_public_acls": c.get("IgnorePublicAcls", False),
                "block_public_policy": c.get("BlockPublicPolicy", False),
                "restrict_public_buckets": c.get("RestrictPublicBuckets", False),
            }
        policy_raw = call(s3.get_bucket_policy, Bucket=name, missing=("NoSuchBucketPolicy",))
        status = call(s3.get_bucket_policy_status, Bucket=name, missing=("NoSuchBucketPolicy",))
        acl = call(s3.get_bucket_acl, Bucket=name, default={})
        enc = call(s3.get_bucket_encryption, Bucket=name, missing=("ServerSideEncryptionConfigurationNotFoundError",))
        versioning = call(s3.get_bucket_versioning, Bucket=name, default={})
        logging = call(s3.get_bucket_logging, Bucket=name, default={})
        ownership = call(s3.get_bucket_ownership_controls, Bucket=name,
                         missing=("OwnershipControlsNotFoundError",), default={})
        tagging = call(s3.get_bucket_tagging, Bucket=name, missing=("NoSuchTagSet",), default={})

        encryption = None
        if enc:
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                default = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                encryption = {"algorithm": default.get("SSEAlgorithm"), "kms_key_id": default.get("KMSMasterKeyID")}

        grants = []
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            grants.append({
                "grantee_type": grantee.get("Type"),
                "grantee_uri": grantee.get("URI"),
                "permission": grant.get("Permission"),
            })

        ownership_rules = ownership.get("OwnershipControls", {}).get("Rules", [])
        log_cfg = logging.get("LoggingEnabled")

        yield Resource(
            uid=f"arn:{ctx.partition}:s3:::{name}",
            resource_type=rt.S3_BUCKET,
            service="S3",
            name=name,
            region=region,
            account_id=ctx.account_id,
            tags=tags_to_dict(tagging.get("TagSet")),
            properties={
                "bucket_name": name,
                "created_at": iso(bucket.get("CreationDate")),
                "public_access_block": bpa,
                "policy": policy_doc(policy_raw.get("Policy")) if policy_raw else None,
                # None => status unavailable; rules fall back to their own policy analysis.
                "policy_is_public": status.get("PolicyStatus", {}).get("IsPublic") if status else None,
                "acl_grants": grants,
                "encryption": encryption,
                "versioning": versioning.get("Status") or "Disabled",
                "mfa_delete": versioning.get("MFADelete") == "Enabled",
                "logging_enabled": bool(log_cfg),
                "logging_target": (log_cfg or {}).get("TargetBucket"),
                "object_ownership": ownership_rules[0].get("ObjectOwnership") if ownership_rules else None,
            },
        )
