"""CloudTrail detection rules."""

from __future__ import annotations

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.models import Resource, RuleMetadata, RuleResult, Severity
from cloudaegis_engine.rules.aws import _refs
from cloudaegis_engine.rules.aws._helpers import bucket_public_reasons
from cloudaegis_engine.rules.base import Rule, RuleContext
from cloudaegis_engine.rules.registry import register


def _account_trails(ctx: RuleContext, account_id: str) -> list[Resource]:
    return [t for t in ctx.inventory.of_type(rt.CLOUDTRAIL_TRAIL) if t.account_id == account_id]


@register
class CloudTrailDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="CT-001",
        title="No active CloudTrail trail",
        severity=Severity.CRITICAL,
        service="CloudTrail",
        category="Logging & Monitoring",
        resource_type=rt.AWS_ACCOUNT,
        description="The account has no CloudTrail trail that is currently logging.",
        impact="Management API activity beyond the 90-day event history is not retained, preventing "
        "detection and forensic investigation of account compromise.",
        remediation="Create a multi-region trail that logs management events to a dedicated, "
        "access-restricted S3 bucket.",
        remediation_cli="aws cloudtrail create-trail --name org-trail --s3-bucket-name <bucket> "
        "--is-multi-region-trail --enable-log-file-validation && aws cloudtrail start-logging --name org-trail",
        references=(_refs.CLOUDTRAIL_BEST, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        trails = _account_trails(ctx, resource.account_id)
        logging = [t.name for t in trails if t.prop("is_logging")]
        return self.check(resource, not logging, {"Trails": [t.name for t in trails], "LoggingTrails": logging})


@register
class NoMultiRegionTrail(Rule):
    metadata = RuleMetadata(
        rule_id="CT-002",
        title="No multi-region CloudTrail trail",
        severity=Severity.HIGH,
        service="CloudTrail",
        category="Logging & Monitoring",
        resource_type=rt.AWS_ACCOUNT,
        description="CloudTrail is logging, but no active trail covers all regions.",
        impact="Activity in unmonitored regions — a common place for attackers to launch resources — "
        "is not recorded.",
        remediation="Convert the primary trail to a multi-region trail.",
        remediation_cli="aws cloudtrail update-trail --name <trail> --is-multi-region-trail",
        references=(_refs.CLOUDTRAIL_BEST, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        logging = [t for t in _account_trails(ctx, resource.account_id) if t.prop("is_logging")]
        if not logging:
            return None  # CT-001 reports the stronger condition
        multi = [t.name for t in logging if t.prop("is_multi_region")]
        return self.check(resource, not multi, {"LoggingTrails": [t.name for t in logging], "MultiRegionTrails": multi})


@register
class TrailLogValidationDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="CT-003",
        title="CloudTrail log file validation is disabled",
        severity=Severity.MEDIUM,
        service="CloudTrail",
        category="Logging & Monitoring",
        resource_type=rt.CLOUDTRAIL_TRAIL,
        description="The trail does not produce digest files for integrity validation.",
        impact="Tampering with or deleting log files cannot be detected, weakening forensic evidence.",
        remediation="Enable log file validation on the trail.",
        remediation_cli="aws cloudtrail update-trail --name <trail> --enable-log-file-validation",
        references=(_refs.CLOUDTRAIL_VALIDATION, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        enabled = bool(resource.prop("log_file_validation"))
        return self.check(resource, not enabled, {"LogFileValidationEnabled": enabled})


@register
class TrailNotKmsEncrypted(Rule):
    metadata = RuleMetadata(
        rule_id="CT-004",
        title="CloudTrail logs are not encrypted with KMS",
        severity=Severity.MEDIUM,
        service="CloudTrail",
        category="Logging & Monitoring",
        resource_type=rt.CLOUDTRAIL_TRAIL,
        description="The trail delivers log files without SSE-KMS encryption using a customer managed key.",
        impact="Anyone with read access to the log bucket can read sensitive API activity; key policies "
        "cannot add a second layer of access control.",
        remediation="Configure the trail with a customer managed KMS key.",
        remediation_cli="aws cloudtrail update-trail --name <trail> --kms-key-id <key-arn>",
        references=(_refs.CLOUDTRAIL_BEST, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        key = resource.prop("kms_key_id")
        return self.check(resource, not key, {"KmsKeyId": key})


@register
class TrailBucketPublic(Rule):
    metadata = RuleMetadata(
        rule_id="CT-005",
        title="CloudTrail destination bucket is publicly accessible",
        severity=Severity.CRITICAL,
        service="CloudTrail",
        category="Logging & Monitoring",
        resource_type=rt.CLOUDTRAIL_TRAIL,
        description="The S3 bucket receiving this trail's logs is publicly accessible.",
        impact="Audit logs reveal account structure and activity to attackers and may be altered or deleted.",
        remediation="Block public access on the log bucket and restrict its policy to the CloudTrail "
        "service principal and the security team.",
        references=(_refs.CLOUDTRAIL_BEST,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        bucket_name = resource.prop("s3_bucket_name")
        bucket = ctx.inventory.get(f"arn:aws:s3:::{bucket_name}") if bucket_name else None
        if bucket is None:
            return None  # bucket lives in another account or was not discovered
        reasons = bucket_public_reasons(bucket, ctx.inventory)
        return self.check(resource, bool(reasons), {"S3BucketName": bucket_name, "BucketPublicReasons": reasons})


@register
class TrailNoCloudWatchIntegration(Rule):
    metadata = RuleMetadata(
        rule_id="CT-006",
        title="CloudTrail trail is not integrated with CloudWatch Logs",
        severity=Severity.LOW,
        service="CloudTrail",
        category="Logging & Monitoring",
        resource_type=rt.CLOUDTRAIL_TRAIL,
        description="The trail does not send events to a CloudWatch Logs log group.",
        impact="Real-time metric filters and alarms on sensitive API calls (root login, policy changes) "
        "cannot be configured.",
        remediation="Configure a CloudWatch Logs log group and delivery role on the trail.",
        references=(_refs.CLOUDTRAIL_BEST,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        group = resource.prop("cloudwatch_log_group_arn")
        return self.check(resource, not group, {"CloudWatchLogsLogGroupArn": group})


@register
class TrailLoggingStopped(Rule):
    metadata = RuleMetadata(
        rule_id="CT-007",
        title="CloudTrail trail exists but logging is stopped",
        severity=Severity.HIGH,
        service="CloudTrail",
        category="Logging & Monitoring",
        resource_type=rt.CLOUDTRAIL_TRAIL,
        description="The trail is configured but IsLogging is false.",
        impact="Stopping a trail is a well-known defence-evasion technique; events are no longer recorded.",
        remediation="Restart logging and investigate who stopped the trail (StopLogging event).",
        remediation_cli="aws cloudtrail start-logging --name <trail>",
        references=(_refs.CLOUDTRAIL_BEST,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        logging = bool(resource.prop("is_logging"))
        return self.check(resource, not logging, {"IsLogging": logging})
