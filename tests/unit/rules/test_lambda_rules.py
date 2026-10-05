"""Lambda rules LAM-001 .. LAM-006."""

from __future__ import annotations

import json

import pytest

from _factory import (
    ADMIN_ARN,
    ACCOUNT_ID,
    REGION,
    admin_doc_entry,
    assert_fail,
    assert_pass,
    evaluate,
    iam_role,
    lambda_function,
    policy_doc,
    statement,
)

FN_ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:orders-handler-001"


def invoke_stmt(principal, condition=None):
    stmt = statement(Sid="AllowInvoke", Principal=principal, Action="lambda:InvokeFunction", Resource=FN_ARN)
    if condition:
        stmt["Condition"] = condition
    return stmt


class TestPublicFunctionUrl:
    def test_pass_without_function_url(self):
        result = assert_pass(evaluate("LAM-001", lambda_function(function_url_auth_type=None)))
        assert result.evidence == {"FunctionUrl": None}

    def test_pass_iam_auth(self):
        result = assert_pass(evaluate("LAM-001", lambda_function(function_url_auth_type="AWS_IAM")))
        assert result.evidence == {"FunctionUrlAuthType": "AWS_IAM"}

    def test_fail_no_auth(self):
        result = assert_fail(evaluate("LAM-001", lambda_function(function_url_auth_type="NONE")))
        assert result.evidence == {"FunctionUrlAuthType": "NONE"}


class TestPublicFunctionPolicy:
    @pytest.mark.parametrize("stmt", [
        invoke_stmt({"Service": "apigateway.amazonaws.com"},
                    {"ArnLike": {"AWS:SourceArn": f"arn:aws:execute-api:{REGION}:{ACCOUNT_ID}:abc123/*"}}),
        invoke_stmt({"Service": "s3.amazonaws.com"}),
        # Principal * scoped to a source ARN (condition key matching is case-insensitive).
        invoke_stmt("*", {"ArnLike": {"AWS:SourceArn": f"arn:aws:execute-api:{REGION}:{ACCOUNT_ID}:abc123/*"}}),
        invoke_stmt("*", {"StringEquals": {"lambda:FunctionUrlAuthType": "AWS_IAM"}}),
        invoke_stmt({"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"}),
    ])
    def test_pass(self, stmt):
        result = assert_pass(evaluate("LAM-002", lambda_function(resource_policy=policy_doc(stmt))))
        assert result.evidence == {"PublicStatements": []}

    @pytest.mark.parametrize("principal", ["*", {"AWS": "*"}])
    def test_fail_public_invoke(self, principal):
        result = assert_fail(evaluate("LAM-002", lambda_function(resource_policy=policy_doc(invoke_stmt(principal)))))
        [public] = result.evidence["PublicStatements"]
        assert public["Sid"] == "AllowInvoke"
        assert public["Action"] == "lambda:InvokeFunction"

    def test_fail_policy_as_json_string(self):
        # lambda:GetPolicy returns the policy as a JSON string.
        policy = json.dumps(policy_doc(invoke_stmt("*")))
        assert_fail(evaluate("LAM-002", lambda_function(resource_policy=policy)))

    def test_not_applicable_without_policy(self):
        assert evaluate("LAM-002", lambda_function(resource_policy=None)) is None


class TestOverprivilegedExecutionRole:
    def test_pass_scoped_role(self):
        role = iam_role("orders-lambda-exec")
        result = assert_pass(evaluate("LAM-003", lambda_function(role_arn=role.uid), role))
        assert result.evidence == {"ExecutionRole": "orders-lambda-exec", "AdminPolicySources": []}

    @pytest.mark.parametrize("admin", [
        {"attached_policies": [{"name": "AdministratorAccess", "arn": ADMIN_ARN}]},
        {"policy_documents": [admin_doc_entry("inline-admin", "inline")]},
    ])
    def test_fail_admin_role(self, admin):
        role = iam_role("billing-lambda-exec", **admin)
        result = assert_fail(evaluate("LAM-003", lambda_function(role_arn=role.uid), role))
        assert result.evidence["ExecutionRole"] == "billing-lambda-exec"
        assert len(result.evidence["AdminPolicySources"]) == 1

    @pytest.mark.parametrize("role_arn", [None, f"arn:aws:iam::{ACCOUNT_ID}:role/not-discovered"])
    def test_not_applicable_when_role_unknown(self, role_arn):
        assert evaluate("LAM-003", lambda_function(role_arn=role_arn), iam_role()) is None


class TestEnvVarsWithoutCmk:
    def test_pass_with_cmk(self):
        assert_pass(evaluate("LAM-004", lambda_function()))

    def test_fail_without_cmk(self):
        fn = lambda_function(environment_variable_names=["LOG_LEVEL", "QUEUE_URL", "REGION"], kms_key_arn=None)
        result = assert_fail(evaluate("LAM-004", fn))
        assert result.evidence == {"VariableCount": 3, "KMSKeyArn": None}

    @pytest.mark.parametrize("names", [[], None])
    def test_not_applicable_without_variables(self, names):
        assert evaluate("LAM-004", lambda_function(environment_variable_names=names, kms_key_arn=None)) is None


class TestSecretsInEnvironment:
    @pytest.mark.parametrize("names", [["LOG_LEVEL", "TABLE_NAME"], ["BUCKET", "PREFIX"], ["FEATURE_FLAGS"]])
    def test_pass_benign_names(self, names):
        result = assert_pass(evaluate("LAM-005", lambda_function(environment_variable_names=names)))
        assert result.evidence == {"SuspiciousVariableNames": []}

    @pytest.mark.parametrize("names, suspicious", [
        (["DB_HOST", "DB_USER", "DB_PASSWORD"], ["DB_PASSWORD"]),
        (["STRIPE_API_KEY", "LOG_LEVEL"], ["STRIPE_API_KEY"]),
        (["SLACK_WEBHOOK_TOKEN", "CHANNEL"], ["SLACK_WEBHOOK_TOKEN"]),
        (["github_token"], ["github_token"]),
        (["AWS_SECRET_ACCESS_KEY", "APIKEY", "SIGNING_PRIVATE_KEY", "DB_PWD", "SERVICE_CREDENTIALS"],
         ["AWS_SECRET_ACCESS_KEY", "APIKEY", "SIGNING_PRIVATE_KEY", "DB_PWD", "SERVICE_CREDENTIALS"]),
    ])
    def test_fail_secret_like_names(self, names, suspicious):
        result = assert_fail(evaluate("LAM-005", lambda_function(environment_variable_names=names)))
        assert result.evidence == {"SuspiciousVariableNames": suspicious}

    def test_not_applicable_without_variables(self):
        assert evaluate("LAM-005", lambda_function(environment_variable_names=[])) is None


class TestDeprecatedRuntime:
    @pytest.mark.parametrize("runtime", ["python3.12", "python3.13", "nodejs20.x", "nodejs22.x", "java21",
                                         "provided.al2023"])
    def test_pass_supported(self, runtime):
        result = assert_pass(evaluate("LAM-006", lambda_function(runtime=runtime)))
        assert result.evidence == {"Runtime": runtime}

    @pytest.mark.parametrize("runtime", ["python2.7", "python3.7", "python3.8", "python3.9", "nodejs18.x", "nodejs16.x", "nodejs12.x",
                                         "go1.x", "java8", "dotnet6", "ruby2.7"])
    def test_fail_deprecated(self, runtime):
        result = assert_fail(evaluate("LAM-006", lambda_function(runtime=runtime)))
        assert result.evidence == {"Runtime": runtime}

    @pytest.mark.parametrize("runtime", [None, ""])
    def test_not_applicable_for_container_images(self, runtime):
        assert evaluate("LAM-006", lambda_function(runtime=runtime, package_type="Image")) is None
