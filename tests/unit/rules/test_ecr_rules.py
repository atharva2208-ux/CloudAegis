"""ECR rules ECR-001 .. ECR-003."""

from __future__ import annotations

import pytest

from _factory import (
    ACCOUNT_ID,
    EXTERNAL_ACCOUNT_ID,
    assert_fail,
    assert_pass,
    drop,
    ecr_repository,
    evaluate,
    policy_doc,
    statement,
)

PULL_ACTIONS = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]


class TestScanOnPush:
    def test_pass_enabled(self):
        assert_pass(evaluate("ECR-001", ecr_repository(scan_on_push=True)))

    def test_fail_disabled(self):
        result = assert_fail(evaluate("ECR-001", ecr_repository(scan_on_push=False)))
        assert result.evidence == {"ScanOnPush": False}


class TestMutableImageTags:
    def test_pass_immutable(self):
        result = assert_pass(evaluate("ECR-002", ecr_repository(image_tag_mutability="IMMUTABLE")))
        assert result.evidence == {"ImageTagMutability": "IMMUTABLE"}

    def test_fail_mutable(self):
        assert_fail(evaluate("ECR-002", ecr_repository(image_tag_mutability="MUTABLE")))

    def test_fail_defaults_to_mutable_when_unknown(self):
        result = assert_fail(evaluate("ECR-002", drop(ecr_repository(), "image_tag_mutability")))
        assert result.evidence == {"ImageTagMutability": "MUTABLE"}


class TestPublicRepositoryPolicy:
    @pytest.mark.parametrize("stmt", [
        statement(Sid="Pull", Principal={"AWS": f"arn:aws:iam::{EXTERNAL_ACCOUNT_ID}:root"}, Action=PULL_ACTIONS),
        statement(Sid="Pull", Principal="*", Action=PULL_ACTIONS,
                  Condition={"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}),
        statement(Sid="Pull", Principal={"Service": "lambda.amazonaws.com"}, Action=PULL_ACTIONS,
                  Condition={"StringLike": {"aws:SourceArn": f"arn:aws:lambda:*:{ACCOUNT_ID}:function:*"}}),
    ])
    def test_pass(self, stmt):
        result = assert_pass(evaluate("ECR-003", ecr_repository(repository_policy=policy_doc(stmt))))
        assert result.evidence == {"PublicStatements": []}

    @pytest.mark.parametrize("principal", ["*", {"AWS": "*"}])
    def test_fail_public_pull(self, principal):
        stmt = statement(Sid="Pull", Principal=principal, Action=PULL_ACTIONS)
        result = assert_fail(evaluate("ECR-003", ecr_repository(repository_policy=policy_doc(stmt))))
        assert result.evidence["PublicStatements"] == [
            {"Effect": "Allow", "Sid": "Pull", "Principal": principal, "Action": PULL_ACTIONS}]

    def test_not_applicable_without_policy(self):
        assert evaluate("ECR-003", ecr_repository(repository_policy=None)) is None
