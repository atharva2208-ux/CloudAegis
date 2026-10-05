"""KMS detection rules."""

from __future__ import annotations

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.checks import policy as pol
from cloudaegis_engine.models import Resource, RuleMetadata, RuleResult, Severity
from cloudaegis_engine.rules.aws import _refs
from cloudaegis_engine.rules.base import Rule, RuleContext
from cloudaegis_engine.rules.registry import register


def _customer_key(resource: Resource) -> bool:
    return resource.prop("key_manager") == "CUSTOMER" and resource.prop("key_state") not in (
        "PendingDeletion", "PendingReplicaDeletion")


@register
class KeyRotationDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="KMS-001",
        title="KMS key rotation is disabled",
        severity=Severity.MEDIUM,
        service="KMS",
        category="Data Protection",
        resource_type=rt.KMS_KEY,
        description="Automatic rotation is not enabled for a customer managed symmetric encryption key.",
        impact="Key material is used indefinitely, increasing the impact of any key exposure and failing "
        "common cryptographic hygiene requirements.",
        remediation="Enable automatic key rotation.",
        remediation_cli="aws kms enable-key-rotation --key-id <key-id>",
        references=(_refs.KMS_ROTATION, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        if not _customer_key(resource) or resource.prop("key_spec") != "SYMMETRIC_DEFAULT":
            return None
        enabled = bool(resource.prop("rotation_enabled"))
        return self.check(resource, not enabled, {"KeyRotationEnabled": enabled, "KeySpec": "SYMMETRIC_DEFAULT"})


@register
class PublicKeyPolicy(Rule):
    metadata = RuleMetadata(
        rule_id="KMS-002",
        title="KMS key policy allows any principal",
        severity=Severity.CRITICAL,
        service="KMS",
        category="Data Protection",
        resource_type=rt.KMS_KEY,
        description='The key policy grants access to "Principal": "*" without restricting conditions '
        "such as kms:CallerAccount or aws:PrincipalOrgID.",
        impact="Principals in any AWS account may use the key to decrypt data or alter its policy.",
        remediation="Restrict the principal to specific account or role ARNs, or add a kms:CallerAccount condition.",
        references=(_refs.KMS_POLICIES,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        if resource.prop("key_manager") != "CUSTOMER":
            return None
        public = [pol.summarize_statement(s) for s in pol.public_statements(resource.prop("policy"))]
        return self.check(resource, bool(public), {"PublicStatements": public})


@register
class KeyPendingDeletion(Rule):
    metadata = RuleMetadata(
        rule_id="KMS-003",
        title="KMS key is scheduled for deletion",
        severity=Severity.INFO,
        service="KMS",
        category="Data Protection",
        resource_type=rt.KMS_KEY,
        description="A customer managed key is in the PendingDeletion state.",
        impact="When deletion completes, any data still encrypted under this key becomes permanently "
        "unrecoverable. Verify the deletion is intended.",
        remediation="Confirm no data depends on the key; otherwise cancel the deletion.",
        remediation_cli="aws kms cancel-key-deletion --key-id <key-id>",
        references=(_refs.KMS_POLICIES,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        if resource.prop("key_manager") != "CUSTOMER":
            return None
        pending = resource.prop("key_state") == "PendingDeletion"
        return self.check(resource, pending, {"KeyState": resource.prop("key_state"),
                                              "DeletionDate": resource.prop("deletion_date")})
