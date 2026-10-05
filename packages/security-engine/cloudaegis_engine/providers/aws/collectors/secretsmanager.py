"""Secrets Manager discovery (metadata only — secret values are never read)."""

from __future__ import annotations

from typing import Iterator

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.models import Resource
from cloudaegis_engine.providers.aws.collectors import CollectorContext
from cloudaegis_engine.providers.aws.collectors._util import call, iso, policy_doc, tags_to_dict
from cloudaegis_engine.providers.aws.collectors.ec2 import _paginate


def collect(ctx: CollectorContext) -> Iterator[Resource]:
    for region in ctx.regions:
        sm = ctx.client("secretsmanager", region)
        for secret in _paginate(sm, "list_secrets", "SecretList"):
            policy = call(sm.get_resource_policy, SecretId=secret["ARN"], default={})
            rules = secret.get("RotationRules") or {}
            yield Resource(
                uid=secret["ARN"],
                resource_type=rt.SECRET,
                service="Secrets Manager",
                name=secret["Name"],
                region=region,
                account_id=ctx.account_id,
                tags=tags_to_dict(secret.get("Tags")),
                properties={
                    "secret_name": secret["Name"],
                    "rotation_enabled": bool(secret.get("RotationEnabled")),
                    "rotation_days": rules.get("AutomaticallyAfterDays"),
                    "last_rotated_at": iso(secret.get("LastRotatedDate")),
                    "last_changed_at": iso(secret.get("LastChangedDate")),
                    "created_at": iso(secret.get("CreatedDate")),
                    "kms_key_id": secret.get("KmsKeyId"),
                    "resource_policy": policy_doc(policy.get("ResourcePolicy")),
                },
            )
