"""KMS key discovery."""

from __future__ import annotations

from typing import Iterator

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.models import Resource
from cloudaegis_engine.providers.aws.collectors import CollectorContext
from cloudaegis_engine.providers.aws.collectors._util import call, iso, policy_doc
from cloudaegis_engine.providers.aws.collectors.ec2 import _paginate


def collect(ctx: CollectorContext) -> Iterator[Resource]:
    for region in ctx.regions:
        kms = ctx.client("kms", region)
        aliases = {}
        for alias in _paginate(kms, "list_aliases", "Aliases"):
            if alias.get("TargetKeyId"):
                aliases.setdefault(alias["TargetKeyId"], alias["AliasName"])
        for key in _paginate(kms, "list_keys", "Keys"):
            meta = call(kms.describe_key, KeyId=key["KeyId"], default={}).get("KeyMetadata")
            if not meta:
                continue
            customer = meta.get("KeyManager") == "CUSTOMER"
            symmetric = meta.get("KeySpec", meta.get("CustomerMasterKeySpec")) == "SYMMETRIC_DEFAULT"
            rotation = None
            if customer and symmetric and meta.get("KeyState") == "Enabled":
                rotation = call(kms.get_key_rotation_status, KeyId=key["KeyId"], default={}).get("KeyRotationEnabled")
            policy = None
            if customer:
                raw = call(kms.get_key_policy, KeyId=key["KeyId"], PolicyName="default", default={})
                policy = policy_doc(raw.get("Policy"))
            yield Resource(
                uid=meta["Arn"],
                resource_type=rt.KMS_KEY,
                service="KMS",
                name=aliases.get(key["KeyId"], key["KeyId"]),
                region=region,
                account_id=ctx.account_id,
                properties={
                    "key_id": key["KeyId"],
                    "key_manager": meta.get("KeyManager"),
                    "key_state": meta.get("KeyState"),
                    "key_spec": meta.get("KeySpec", meta.get("CustomerMasterKeySpec")),
                    "key_usage": meta.get("KeyUsage"),
                    "rotation_enabled": rotation,
                    "policy": policy,
                    "description": meta.get("Description"),
                    "deletion_date": iso(meta.get("DeletionDate")),
                    "created_at": iso(meta.get("CreationDate")),
                },
            )
