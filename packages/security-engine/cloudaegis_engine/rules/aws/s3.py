"""S3 detection rules."""

from __future__ import annotations

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.checks import policy as pol
from cloudaegis_engine.models import Resource, RuleMetadata, RuleResult, Severity
from cloudaegis_engine.rules.aws import _refs
from cloudaegis_engine.rules.aws._helpers import (
    BPA_FLAGS,
    bucket_public_reasons,
    effective_bpa,
    public_acl_grants,
)
from cloudaegis_engine.rules.base import Rule, RuleContext
from cloudaegis_engine.rules.registry import register

_BPA_CLI = (
    "aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration "
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
)


@register
class BucketPubliclyAccessible(Rule):
    metadata = RuleMetadata(
        rule_id="S3-001",
        title="S3 bucket is publicly accessible",
        severity=Severity.CRITICAL,
        service="S3",
        category="Public Exposure",
        resource_type=rt.S3_BUCKET,
        description="The bucket's policy or ACL grants access to anonymous or any authenticated AWS "
        "users, and Block Public Access does not neutralise the grant.",
        impact="Objects in the bucket may be listed, read or modified by anyone on the internet, "
        "leading to data breaches or content tampering.",
        remediation="Enable S3 Block Public Access and remove public statements and ACL grants. Serve "
        "intentionally public content through CloudFront with origin access control.",
        remediation_steps=(
            "Enable S3 Block Public Access on the bucket (and at the account level).",
            "Review the bucket policy and remove statements with Principal \"*\".",
            "Remove ACL grants to AllUsers and AuthenticatedUsers; set Object Ownership to BucketOwnerEnforced.",
        ),
        remediation_cli=_BPA_CLI,
        references=(_refs.S3_BPA, _refs.S3_SECURITY, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        reasons = bucket_public_reasons(resource, ctx.inventory)
        return self.check(resource, bool(reasons), {"PublicAccessReasons": reasons,
                                                     "EffectiveBlockPublicAccess": effective_bpa(resource, ctx.inventory)})


@register
class BucketPolicyPublic(Rule):
    metadata = RuleMetadata(
        rule_id="S3-002",
        title="S3 bucket policy allows public access",
        severity=Severity.HIGH,
        service="S3",
        category="Storage Security",
        resource_type=rt.S3_BUCKET,
        description='The bucket policy contains an Allow statement for "Principal": "*" without a '
        "condition restricting the caller.",
        impact="If Block Public Access is ever relaxed, the policy immediately exposes the bucket. Even "
        "with BPA enabled, the policy expresses an unsafe intent that should be removed.",
        remediation="Replace the wildcard principal with explicit account or role ARNs, or add an "
        "aws:SourceVpce / aws:PrincipalOrgID condition.",
        references=(_refs.S3_SECURITY,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        policy = resource.prop("policy")
        if not policy:
            return None
        public = [pol.summarize_statement(s) for s in pol.public_statements(policy)]
        return self.check(resource, bool(public), {"PublicStatements": public})


@register
class BucketPublicAcl(Rule):
    metadata = RuleMetadata(
        rule_id="S3-003",
        title="S3 bucket ACL grants public access",
        severity=Severity.HIGH,
        service="S3",
        category="Storage Security",
        resource_type=rt.S3_BUCKET,
        description="The bucket access control list grants permissions to the AllUsers or "
        "AuthenticatedUsers groups.",
        impact="ACL grants bypass bucket-policy review and can expose object listings or contents.",
        remediation="Remove the public grants and set Object Ownership to BucketOwnerEnforced to disable ACLs.",
        remediation_cli="aws s3api put-bucket-ownership-controls --bucket <bucket> "
        "--ownership-controls Rules=[{ObjectOwnership=BucketOwnerEnforced}]",
        references=(_refs.S3_SECURITY,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        grants = public_acl_grants(resource)
        return self.check(resource, bool(grants), {"PublicGrants": grants,
                                                   "ObjectOwnership": resource.prop("object_ownership")})


@register
class BucketEncryptionDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="S3-004",
        title="S3 bucket default encryption not configured",
        severity=Severity.MEDIUM,
        service="S3",
        category="Data Protection",
        resource_type=rt.S3_BUCKET,
        description="No default server-side encryption configuration was returned for the bucket.",
        impact="Objects may be stored without encryption at rest, failing data-protection requirements.",
        remediation="Configure default encryption with SSE-KMS using a customer managed key for sensitive data.",
        remediation_cli="aws s3api put-bucket-encryption --bucket <bucket> --server-side-encryption-configuration "
        "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'",
        references=(_refs.S3_ENCRYPTION,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        enc = resource.prop("encryption")
        return self.check(resource, not enc, {"ServerSideEncryptionConfiguration": enc or "None"})


@register
class BucketVersioningDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="S3-005",
        title="S3 bucket versioning is not enabled",
        severity=Severity.LOW,
        service="S3",
        category="Data Protection",
        resource_type=rt.S3_BUCKET,
        description="Versioning is disabled or suspended on the bucket.",
        impact="Accidental deletes, overwrites and ransomware-style encryption of objects cannot be rolled back.",
        remediation="Enable versioning and add lifecycle rules to expire noncurrent versions.",
        remediation_cli="aws s3api put-bucket-versioning --bucket <bucket> --versioning-configuration Status=Enabled",
        references=(_refs.S3_VERSIONING,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        status = resource.prop("versioning", "Disabled")
        return self.check(resource, status != "Enabled", {"VersioningStatus": status})


@register
class BucketLoggingDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="S3-006",
        title="S3 server access logging is disabled",
        severity=Severity.LOW,
        service="S3",
        category="Logging & Monitoring",
        resource_type=rt.S3_BUCKET,
        description="Server access logging is not configured for the bucket.",
        impact="Investigations cannot determine who accessed which objects and when.",
        remediation="Enable server access logging to a dedicated, access-restricted log bucket.",
        remediation_cli="aws s3api put-bucket-logging --bucket <bucket> --bucket-logging-status "
        "'{\"LoggingEnabled\":{\"TargetBucket\":\"<log-bucket>\",\"TargetPrefix\":\"<bucket>/\"}}'",
        references=(_refs.S3_LOGGING,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        enabled = bool(resource.prop("logging_enabled"))
        return self.check(resource, not enabled, {"LoggingEnabled": enabled})


@register
class BucketBlockPublicAccessDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="S3-007",
        title="S3 Block Public Access is not fully enabled",
        severity=Severity.HIGH,
        service="S3",
        category="Storage Security",
        resource_type=rt.S3_BUCKET,
        description="One or more of the four Block Public Access settings is off at both the bucket and "
        "account level.",
        impact="Without Block Public Access, a single policy or ACL change can expose the bucket to the internet.",
        remediation="Enable all four Block Public Access settings on the bucket or for the whole account.",
        remediation_cli=_BPA_CLI,
        references=(_refs.S3_BPA, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        bpa = effective_bpa(resource, ctx.inventory)
        disabled = [f for f in BPA_FLAGS if not bpa[f]]
        return self.check(resource, bool(disabled), {"DisabledSettings": disabled,
                                                     "BucketConfiguration": resource.prop("public_access_block")})


@register
class BucketPolicyAllowsInsecureTransport(Rule):
    metadata = RuleMetadata(
        rule_id="S3-008",
        title="S3 bucket policy does not enforce TLS",
        severity=Severity.MEDIUM,
        service="S3",
        category="Data Protection",
        resource_type=rt.S3_BUCKET,
        description="The bucket policy has no Deny statement for requests where aws:SecureTransport is false.",
        impact="Clients can read or write data over unencrypted HTTP, exposing it to interception.",
        remediation="Add a Deny statement for all principals when aws:SecureTransport is false.",
        references=(_refs.S3_SECURITY, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        enforced = pol.denies_insecure_transport(resource.prop("policy"))
        return self.check(resource, not enforced, {"SecureTransportEnforced": enforced,
                                                   "HasBucketPolicy": bool(resource.prop("policy"))})


@register
class AccountBlockPublicAccessDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="S3-009",
        title="Account-level S3 Block Public Access is not enabled",
        severity=Severity.MEDIUM,
        service="S3",
        category="Storage Security",
        resource_type=rt.AWS_ACCOUNT,
        description="The account-wide S3 Block Public Access configuration is missing or partially disabled.",
        impact="Each bucket must be protected individually; any new bucket may be made public by mistake.",
        remediation="Enable all four Block Public Access settings at the account level.",
        remediation_cli="aws s3control put-public-access-block --account-id <account-id> "
        "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
        "BlockPublicPolicy=true,RestrictPublicBuckets=true",
        references=(_refs.S3_BPA, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        if "s3_public_access_block" not in resource.properties:
            return None
        bpa = resource.prop("s3_public_access_block") or {}
        disabled = [f for f in BPA_FLAGS if not bpa.get(f)]
        return self.check(resource, bool(disabled), {"DisabledSettings": disabled})
