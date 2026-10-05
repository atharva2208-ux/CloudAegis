"""CloudTrail trail discovery."""

from __future__ import annotations

from typing import Iterator

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.models import Relationship, Resource
from cloudaegis_engine.providers.aws.collectors import CollectorContext
from cloudaegis_engine.providers.aws.collectors._util import call


def collect(ctx: CollectorContext) -> Iterator[Resource]:
    seen: set[str] = set()
    for region in ctx.regions:
        ct = ctx.client("cloudtrail", region)
        for trail in ct.describe_trails(includeShadowTrails=False).get("trailList", []):
            arn = trail["TrailARN"]
            if arn in seen:
                continue
            seen.add(arn)
            home = trail.get("HomeRegion", region)
            status = call(ctx.client("cloudtrail", home).get_trail_status, Name=arn, default={})
            bucket = trail.get("S3BucketName")
            yield Resource(
                uid=arn,
                resource_type=rt.CLOUDTRAIL_TRAIL,
                service="CloudTrail",
                name=trail["Name"],
                region=home,
                account_id=ctx.account_id,
                properties={
                    "trail_name": trail["Name"],
                    "home_region": home,
                    "is_multi_region": bool(trail.get("IsMultiRegionTrail")),
                    "is_organization_trail": bool(trail.get("IsOrganizationTrail")),
                    "is_logging": bool(status.get("IsLogging")),
                    "log_file_validation": bool(trail.get("LogFileValidationEnabled")),
                    "s3_bucket_name": bucket,
                    "kms_key_id": trail.get("KmsKeyId"),
                    "cloudwatch_log_group_arn": trail.get("CloudWatchLogsLogGroupArn"),
                    "include_global_events": bool(trail.get("IncludeGlobalServiceEvents")),
                },
                relationships=[Relationship("logs_to", f"arn:{ctx.partition}:s3:::{bucket}")] if bucket else [],
            )
