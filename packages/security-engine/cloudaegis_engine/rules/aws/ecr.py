"""ECR detection rules."""

from __future__ import annotations

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.checks import policy as pol
from cloudaegis_engine.models import Resource, RuleMetadata, RuleResult, Severity
from cloudaegis_engine.rules.aws import _refs
from cloudaegis_engine.rules.base import Rule, RuleContext
from cloudaegis_engine.rules.registry import register


@register
class ScanOnPushDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="ECR-001",
        title="ECR image scanning on push is disabled",
        severity=Severity.MEDIUM,
        service="ECR",
        category="Vulnerability Management",
        resource_type=rt.ECR_REPOSITORY,
        description="Images pushed to the repository are not automatically scanned for vulnerabilities.",
        impact="Images with known critical CVEs can be deployed without anyone being alerted.",
        remediation="Enable scan on push, or enable Amazon Inspector enhanced scanning for the registry.",
        remediation_cli="aws ecr put-image-scanning-configuration --repository-name <repo> "
        "--image-scanning-configuration scanOnPush=true",
        references=(_refs.ECR_SCANNING,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        enabled = bool(resource.prop("scan_on_push"))
        return self.check(resource, not enabled, {"ScanOnPush": enabled})


@register
class MutableImageTags(Rule):
    metadata = RuleMetadata(
        rule_id="ECR-002",
        title="ECR repository allows mutable image tags",
        severity=Severity.LOW,
        service="ECR",
        category="Vulnerability Management",
        resource_type=rt.ECR_REPOSITORY,
        description="Image tags in the repository can be overwritten.",
        impact="A deployed tag such as 'prod' can be silently replaced with a different, possibly "
        "malicious, image.",
        remediation="Set image tag mutability to IMMUTABLE and deploy by digest.",
        remediation_cli="aws ecr put-image-tag-mutability --repository-name <repo> --image-tag-mutability IMMUTABLE",
        references=(_refs.ECR_TAG_MUTABILITY,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        mutability = resource.prop("image_tag_mutability", "MUTABLE")
        return self.check(resource, mutability == "MUTABLE", {"ImageTagMutability": mutability})


@register
class PublicRepositoryPolicy(Rule):
    metadata = RuleMetadata(
        rule_id="ECR-003",
        title="ECR repository policy allows public access",
        severity=Severity.HIGH,
        service="ECR",
        category="Public Exposure",
        resource_type=rt.ECR_REPOSITORY,
        description='The repository policy grants actions to "Principal": "*" without restricting conditions.',
        impact="Anyone with an AWS account can pull images, exposing proprietary code and embedded "
        "secrets; push permissions would allow supply-chain attacks.",
        remediation="Restrict the repository policy to specific accounts or the organization.",
        remediation_cli="aws ecr delete-repository-policy --repository-name <repo>",
        references=(_refs.ECR_POLICIES,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        policy = resource.prop("repository_policy")
        if not policy:
            return None
        public = [pol.summarize_statement(s) for s in pol.public_statements(policy)]
        return self.check(resource, bool(public), {"PublicStatements": public})
