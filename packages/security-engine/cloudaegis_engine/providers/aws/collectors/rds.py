"""RDS DB instance discovery."""

from __future__ import annotations

from typing import Iterator

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.models import Relationship, Resource
from cloudaegis_engine.providers.aws.collectors import CollectorContext
from cloudaegis_engine.providers.aws.collectors._util import iso, tags_to_dict
from cloudaegis_engine.providers.aws.collectors.ec2 import _paginate


def collect(ctx: CollectorContext) -> Iterator[Resource]:
    for region in ctx.regions:
        rds = ctx.client("rds", region)
        for db in _paginate(rds, "describe_db_instances", "DBInstances"):
            sgs = [g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups", [])]
            endpoint = db.get("Endpoint") or {}
            yield Resource(
                uid=db["DBInstanceArn"],
                resource_type=rt.RDS_INSTANCE,
                service="RDS",
                name=db["DBInstanceIdentifier"],
                region=region,
                account_id=ctx.account_id,
                tags=tags_to_dict(db.get("TagList")),
                properties={
                    "db_instance_id": db["DBInstanceIdentifier"],
                    "engine": db.get("Engine"),
                    "engine_version": db.get("EngineVersion"),
                    "instance_class": db.get("DBInstanceClass"),
                    "status": db.get("DBInstanceStatus"),
                    "publicly_accessible": bool(db.get("PubliclyAccessible")),
                    "storage_encrypted": bool(db.get("StorageEncrypted")),
                    "kms_key_id": db.get("KmsKeyId"),
                    "backup_retention_period": db.get("BackupRetentionPeriod", 0),
                    "log_exports": db.get("EnabledCloudwatchLogsExports", []),
                    "security_group_ids": sgs,
                    "deletion_protection": bool(db.get("DeletionProtection")),
                    "multi_az": bool(db.get("MultiAZ")),
                    "endpoint": f"{endpoint.get('Address')}:{endpoint.get('Port')}" if endpoint else None,
                    "created_at": iso(db.get("InstanceCreateTime")),
                },
                relationships=[Relationship("protected_by", ctx.arn("ec2", region, f"security-group/{g}")) for g in sgs],
            )
