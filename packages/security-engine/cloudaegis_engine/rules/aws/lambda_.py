"""Lambda detection rules."""

from __future__ import annotations

import re

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.checks import policy as pol
from cloudaegis_engine.models import Resource, RuleMetadata, RuleResult, Severity
from cloudaegis_engine.rules.aws import _refs
from cloudaegis_engine.rules.aws._helpers import role_by_arn
from cloudaegis_engine.rules.aws.iam import principal_admin_sources
from cloudaegis_engine.rules.base import Rule, RuleContext
from cloudaegis_engine.rules.registry import register

# Runtimes past AWS end-of-support. Keep in sync with the Lambda runtime
# deprecation schedule; the list is intentionally conservative.
# Runtimes past their AWS Lambda deprecation date (status as of mid-2026; see
# https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html). Review on each release.
DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7", "python3.8", "python3.9",
    "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x", "nodejs12.x",
    "nodejs14.x", "nodejs16.x", "nodejs18.x",
    "java8", "go1.x", "provided", "ruby2.5", "ruby2.7", "ruby3.2",
    "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1", "dotnet6", "dotnet7",
}

SECRET_NAME_PATTERN = re.compile(
    r"(SECRET|PASSWORD|PASSWD|PWD|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL)", re.IGNORECASE
)


@register
class PublicFunctionUrl(Rule):
    metadata = RuleMetadata(
        rule_id="LAM-001",
        title="Lambda function URL allows unauthenticated access",
        severity=Severity.HIGH,
        service="Lambda",
        category="Public Exposure",
        resource_type=rt.LAMBDA_FUNCTION,
        description="The function has a URL with AuthType NONE, so anyone with the URL can invoke it.",
        impact="Unauthenticated invocation can expose data, trigger side effects, or run up cost "
        "(denial of wallet).",
        remediation="Set the function URL AuthType to AWS_IAM, or front the function with API Gateway and "
        "an authorizer.",
        remediation_cli="aws lambda update-function-url-config --function-name <fn> --auth-type AWS_IAM",
        references=(_refs.LAMBDA_URLS,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        auth = resource.prop("function_url_auth_type")
        if auth is None:
            return self.passed(resource, {"FunctionUrl": None})
        return self.check(resource, auth == "NONE", {"FunctionUrlAuthType": auth})


@register
class PublicFunctionPolicy(Rule):
    metadata = RuleMetadata(
        rule_id="LAM-002",
        title="Lambda resource policy allows public invocation",
        severity=Severity.HIGH,
        service="Lambda",
        category="Public Exposure",
        resource_type=rt.LAMBDA_FUNCTION,
        description='The function\'s resource-based policy grants access to "Principal": "*" without a '
        "source account or ARN condition.",
        impact="Any AWS account can invoke the function or, depending on the actions, read its configuration.",
        remediation="Remove the public statement or add aws:SourceAccount / aws:SourceArn conditions.",
        remediation_cli="aws lambda remove-permission --function-name <fn> --statement-id <sid>",
        references=(_refs.LAMBDA_RESOURCE_POLICY,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        policy = resource.prop("resource_policy")
        if not policy:
            return None
        public = [pol.summarize_statement(s) for s in pol.public_statements(policy)]
        return self.check(resource, bool(public), {"PublicStatements": public})


@register
class OverprivilegedExecutionRole(Rule):
    metadata = RuleMetadata(
        rule_id="LAM-003",
        title="Lambda execution role has administrative privileges",
        severity=Severity.HIGH,
        service="Lambda",
        category="Identity & Access",
        resource_type=rt.LAMBDA_FUNCTION,
        description="The function's execution role grants full administrative permissions.",
        impact="Any code-injection or dependency compromise in the function yields administrator access "
        "to the account.",
        remediation="Give each function a dedicated role scoped to the resources it uses.",
        references=(_refs.IAM_BEST_PRACTICES,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        role = role_by_arn(ctx.inventory, resource.prop("role_arn"))
        if role is None:
            return None
        sources = principal_admin_sources(role)
        return self.check(resource, bool(sources), {"ExecutionRole": role.name, "AdminPolicySources": sources})


@register
class EnvVarsWithoutCmk(Rule):
    metadata = RuleMetadata(
        rule_id="LAM-004",
        title="Lambda environment variables not encrypted with a customer managed key",
        severity=Severity.LOW,
        service="Lambda",
        category="Data Protection",
        resource_type=rt.LAMBDA_FUNCTION,
        description="The function defines environment variables but relies on the AWS managed key "
        "rather than a customer managed KMS key.",
        impact="Anyone allowed lambda:GetFunctionConfiguration can read the values; access cannot be "
        "separately controlled or audited through a key policy.",
        remediation="Configure a customer managed KMS key, and move secrets to Secrets Manager.",
        remediation_cli="aws lambda update-function-configuration --function-name <fn> --kms-key-arn <key-arn>",
        references=(_refs.LAMBDA_ENV,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        names = resource.prop("environment_variable_names") or []
        if not names:
            return None
        key = resource.prop("kms_key_arn")
        return self.check(resource, not key, {"VariableCount": len(names), "KMSKeyArn": key})


@register
class SecretsInEnvironment(Rule):
    metadata = RuleMetadata(
        rule_id="LAM-005",
        title="Lambda environment variable names suggest embedded secrets",
        severity=Severity.MEDIUM,
        service="Lambda",
        category="Data Protection",
        resource_type=rt.LAMBDA_FUNCTION,
        description="Environment variable names indicate credentials (PASSWORD, TOKEN, API_KEY, ...). "
        "Only variable names are inspected; values are never collected.",
        impact="Secrets in environment variables are visible to anyone who can read function "
        "configuration and are not rotated.",
        remediation="Store secrets in Secrets Manager or Parameter Store and retrieve them at runtime.",
        references=(_refs.LAMBDA_ENV, _refs.SM_ROTATION),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        names = resource.prop("environment_variable_names") or []
        if not names:
            return None
        suspicious = [n for n in names if SECRET_NAME_PATTERN.search(n)]
        return self.check(resource, bool(suspicious), {"SuspiciousVariableNames": suspicious})


@register
class DeprecatedRuntime(Rule):
    metadata = RuleMetadata(
        rule_id="LAM-006",
        title="Lambda function uses a deprecated runtime",
        severity=Severity.MEDIUM,
        service="Lambda",
        category="Vulnerability Management",
        resource_type=rt.LAMBDA_FUNCTION,
        description="The function runtime has reached end of support and no longer receives security patches.",
        impact="Known vulnerabilities in the language runtime remain unpatched.",
        remediation="Upgrade the function to a supported runtime version and redeploy.",
        references=(_refs.LAMBDA_RUNTIMES,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        runtime = resource.prop("runtime")
        if not runtime:
            return None  # container image functions have no managed runtime
        return self.check(resource, runtime in DEPRECATED_RUNTIMES, {"Runtime": runtime})
