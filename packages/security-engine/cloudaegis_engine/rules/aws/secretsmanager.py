"""Secrets Manager detection rules."""

from __future__ import annotations

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.checks import policy as pol
from cloudaegis_engine.checks.timeutil import age_days
from cloudaegis_engine.models import Resource, RuleMetadata, RuleResult, Severity
from cloudaegis_engine.rules.aws import _refs
from cloudaegis_engine.rules.base import Rule, RuleContext
from cloudaegis_engine.rules.registry import register


@register
class SecretRotationDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="SM-001",
        title="Secret rotation is not enabled",
        severity=Severity.MEDIUM,
        service="Secrets Manager",
        category="Identity & Access",
        resource_type=rt.SECRET,
        description="Automatic rotation is not configured for the secret.",
        impact="Credentials remain valid indefinitely; leaked values stay usable until manually changed.",
        remediation="Configure a rotation Lambda and schedule (for example every 30–90 days).",
        remediation_cli="aws secretsmanager rotate-secret --secret-id <id> --rotation-lambda-arn <arn> "
        "--rotation-rules AutomaticallyAfterDays=30",
        references=(_refs.SM_ROTATION,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        enabled = bool(resource.prop("rotation_enabled"))
        return self.check(resource, not enabled, {"RotationEnabled": enabled})


@register
class PublicSecretPolicy(Rule):
    metadata = RuleMetadata(
        rule_id="SM-002",
        title="Secret resource policy allows any principal",
        severity=Severity.CRITICAL,
        service="Secrets Manager",
        category="Identity & Access",
        resource_type=rt.SECRET,
        description='The secret\'s resource policy grants access to "Principal": "*" without restricting conditions.',
        impact="The secret value may be retrievable by identities in any AWS account.",
        remediation="Remove the public statement; scope access to specific principals within the organization.",
        remediation_cli="aws secretsmanager delete-resource-policy --secret-id <id>",
        references=(_refs.SM_POLICIES,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        policy = resource.prop("resource_policy")
        if not policy:
            return None
        public = [pol.summarize_statement(s) for s in pol.public_statements(policy)]
        return self.check(resource, bool(public), {"PublicStatements": public})


@register
class SecretNotRecentlyRotated(Rule):
    metadata = RuleMetadata(
        rule_id="SM-003",
        title="Secret has not been rotated within 90 days",
        severity=Severity.LOW,
        service="Secrets Manager",
        category="Identity & Access",
        resource_type=rt.SECRET,
        description="Rotation is enabled, but the last successful rotation is older than the threshold.",
        impact="Rotation may be failing silently, leaving old credentials active.",
        remediation="Check the rotation Lambda's logs and trigger a rotation manually.",
        remediation_cli="aws secretsmanager rotate-secret --secret-id <id>",
        references=(_refs.SM_ROTATION,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        if not resource.prop("rotation_enabled"):
            return None
        last = resource.prop("last_rotated_at") or resource.prop("created_at")
        days = age_days(last, ctx.now)
        if days is None:
            return None
        return self.check(resource, days > ctx.secret_rotation_days,
                          {"DaysSinceRotation": days, "ThresholdDays": ctx.secret_rotation_days})


@register
class SecretUsesAwsManagedKey(Rule):
    metadata = RuleMetadata(
        rule_id="SM-004",
        title="Secret encrypted with the AWS managed key",
        severity=Severity.INFO,
        service="Secrets Manager",
        category="Data Protection",
        resource_type=rt.SECRET,
        description="The secret uses aws/secretsmanager rather than a customer managed KMS key.",
        impact="The secret cannot be shared cross-account and decryption access cannot be restricted "
        "through a key policy.",
        remediation="Re-encrypt the secret with a customer managed key where separation of duties is required.",
        references=(_refs.SM_POLICIES,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        key = resource.prop("kms_key_id")
        aws_managed = not key or str(key).endswith("alias/aws/secretsmanager")
        return self.check(resource, aws_managed, {"KmsKeyId": key or "aws/secretsmanager"})
