"""RDS detection rules."""

from __future__ import annotations

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.models import Resource, RuleMetadata, RuleResult, Severity
from cloudaegis_engine.rules.aws import _refs
from cloudaegis_engine.rules.aws._helpers import internet_ingress
from cloudaegis_engine.rules.base import Rule, RuleContext
from cloudaegis_engine.rules.registry import register


@register
class RdsPubliclyAccessible(Rule):
    metadata = RuleMetadata(
        rule_id="RDS-001",
        title="RDS instance is publicly accessible",
        severity=Severity.HIGH,
        service="RDS",
        category="Public Exposure",
        resource_type=rt.RDS_INSTANCE,
        description="The DB instance has PubliclyAccessible = true and resolves to a public IP address.",
        impact="The database endpoint can be reached from outside the VPC whenever security groups allow it.",
        remediation="Set PubliclyAccessible to false and connect through private networking.",
        remediation_cli="aws rds modify-db-instance --db-instance-identifier <id> --no-publicly-accessible --apply-immediately",
        references=(_refs.RDS_SECURITY, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        public = bool(resource.prop("publicly_accessible"))
        return self.check(resource, public, {"PubliclyAccessible": public, "Endpoint": resource.prop("endpoint")})


@register
class RdsStorageNotEncrypted(Rule):
    metadata = RuleMetadata(
        rule_id="RDS-002",
        title="RDS storage is not encrypted",
        severity=Severity.HIGH,
        service="RDS",
        category="Data Protection",
        resource_type=rt.RDS_INSTANCE,
        description="StorageEncrypted is false for the DB instance.",
        impact="Database files, automated backups, replicas and snapshots are stored unencrypted.",
        remediation="Encryption cannot be enabled in place: snapshot the instance, copy the snapshot with "
        "encryption, and restore a new encrypted instance.",
        references=(_refs.RDS_ENCRYPTION, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        encrypted = bool(resource.prop("storage_encrypted"))
        return self.check(resource, not encrypted, {"StorageEncrypted": encrypted})


@register
class RdsBackupsDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="RDS-003",
        title="RDS automated backups are disabled",
        severity=Severity.MEDIUM,
        service="RDS",
        category="Resilience",
        resource_type=rt.RDS_INSTANCE,
        description="BackupRetentionPeriod is 0, so automated backups and point-in-time recovery are off.",
        impact="Data loss from corruption, deletion or ransomware cannot be recovered.",
        remediation="Set a backup retention period of at least 7 days.",
        remediation_cli="aws rds modify-db-instance --db-instance-identifier <id> --backup-retention-period 7 --apply-immediately",
        references=(_refs.RDS_BACKUPS,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        retention = int(resource.prop("backup_retention_period") or 0)
        return self.check(resource, retention == 0, {"BackupRetentionPeriod": retention})


@register
class RdsSecurityGroupOpen(Rule):
    metadata = RuleMetadata(
        rule_id="RDS-004",
        title="Public RDS instance reachable from the internet",
        severity=Severity.CRITICAL,
        service="RDS",
        category="Public Exposure",
        resource_type=rt.RDS_INSTANCE,
        description="The instance is publicly accessible and one of its security groups allows inbound "
        "traffic from 0.0.0.0/0 or ::/0.",
        impact="The database is directly reachable from the internet and exposed to credential attacks "
        "and engine vulnerabilities.",
        remediation="Disable public accessibility and restrict security groups to application subnets.",
        references=(_refs.RDS_SECURITY,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        if not resource.prop("publicly_accessible"):
            return None
        exposed = internet_ingress(ctx.inventory, resource.prop("security_group_ids"), resource.region, resource.account_id)
        return self.check(resource, bool(exposed), {"PubliclyAccessible": True, "InternetIngress": exposed})


@register
class RdsLogExportsDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="RDS-005",
        title="RDS database logs are not exported",
        severity=Severity.LOW,
        service="RDS",
        category="Logging & Monitoring",
        resource_type=rt.RDS_INSTANCE,
        description="No database log types are published to CloudWatch Logs.",
        impact="Authentication failures, errors and audit events are not retained centrally for detection "
        "and investigation.",
        remediation="Enable CloudWatch Logs exports for the engine's audit/error/general logs.",
        references=(_refs.RDS_SECURITY,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        exports = resource.prop("log_exports") or []
        return self.check(resource, not exports, {"EnabledCloudwatchLogsExports": exports})


@register
class RdsDeletionProtectionDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="RDS-006",
        title="RDS deletion protection is disabled",
        severity=Severity.LOW,
        service="RDS",
        category="Resilience",
        resource_type=rt.RDS_INSTANCE,
        description="DeletionProtection is false for the DB instance.",
        impact="The database can be deleted by a single API call, whether by mistake or by an attacker.",
        remediation="Enable deletion protection on production databases.",
        remediation_cli="aws rds modify-db-instance --db-instance-identifier <id> --deletion-protection",
        references=(_refs.RDS_SECURITY,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        enabled = bool(resource.prop("deletion_protection"))
        return self.check(resource, not enabled, {"DeletionProtection": enabled})
