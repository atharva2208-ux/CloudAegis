"""Secrets Manager rules SM-001 .. SM-004."""

from __future__ import annotations

import json

import pytest

from _factory import (
    ACCOUNT_ID,
    REGION,
    assert_fail,
    assert_pass,
    days_ago,
    evaluate,
    policy_doc,
    secret,
    statement,
)

GET_VALUE = statement(Principal={"AWS": "*"}, Action="secretsmanager:GetSecretValue", Resource="*")


class TestSecretRotationDisabled:
    def test_pass_rotation_enabled(self):
        result = assert_pass(evaluate("SM-001", secret()))
        assert result.evidence == {"RotationEnabled": True}

    def test_fail_rotation_disabled(self):
        result = assert_fail(evaluate("SM-001", secret(rotation_enabled=False, rotation_days=None,
                                                       last_rotated_at=None)))
        assert result.evidence == {"RotationEnabled": False}


class TestPublicSecretPolicy:
    @pytest.mark.parametrize("stmt", [
        statement(Principal={"AWS": f"arn:aws:iam::{ACCOUNT_ID}:role/orders-app"},
                  Action="secretsmanager:GetSecretValue", Resource="*"),
        {**GET_VALUE, "Condition": {"StringEquals": {"aws:PrincipalAccount": ACCOUNT_ID}}},
        {**GET_VALUE, "Effect": "Deny"},
    ])
    def test_pass(self, stmt):
        result = assert_pass(evaluate("SM-002", secret(resource_policy=policy_doc(stmt))))
        assert result.evidence == {"PublicStatements": []}

    @pytest.mark.parametrize("policy", [policy_doc(GET_VALUE), json.dumps(policy_doc(GET_VALUE)),
                                        policy_doc({**GET_VALUE, "Principal": "*"})])
    def test_fail_wildcard_principal(self, policy):
        result = assert_fail(evaluate("SM-002", secret(resource_policy=policy)))
        assert result.evidence["PublicStatements"][0]["Action"] == "secretsmanager:GetSecretValue"

    def test_not_applicable_without_policy(self):
        assert evaluate("SM-002", secret(resource_policy=None)) is None


class TestSecretNotRecentlyRotated:
    # Threshold is exclusive: "not rotated *within* 90 days" fails from day 91.
    @pytest.mark.parametrize("days, failed", [(1, False), (89, False), (90, False), (91, True), (300, True)])
    def test_threshold(self, days, failed):
        result = evaluate("SM-003", secret(last_rotated_at=days_ago(days)))
        (assert_fail if failed else assert_pass)(result)
        assert result.evidence == {"DaysSinceRotation": days, "ThresholdDays": 90}

    def test_falls_back_to_creation_date_when_never_rotated(self):
        result = assert_fail(evaluate("SM-003", secret(last_rotated_at=None, created_at=days_ago(150))))
        assert result.evidence["DaysSinceRotation"] == 150
        assert_pass(evaluate("SM-003", secret(last_rotated_at=None, created_at=days_ago(20))))

    def test_custom_threshold(self):
        s = secret(last_rotated_at=days_ago(45))
        assert_pass(evaluate("SM-003", s))
        result = assert_fail(evaluate("SM-003", s, secret_rotation_days=30))
        assert result.evidence["ThresholdDays"] == 30

    def test_not_applicable_when_rotation_disabled(self):
        assert evaluate("SM-003", secret(rotation_enabled=False, last_rotated_at=days_ago(900))) is None

    @pytest.mark.parametrize("bad_ts", [None, "", "not-a-date"])
    def test_not_applicable_without_usable_timestamp(self, bad_ts):
        assert evaluate("SM-003", secret(last_rotated_at=bad_ts, created_at=bad_ts)) is None


class TestSecretUsesAwsManagedKey:
    def test_pass_customer_managed_key(self):
        key = f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/0123456789abcdef"
        result = assert_pass(evaluate("SM-004", secret(kms_key_id=key)))
        assert result.evidence == {"KmsKeyId": key}

    @pytest.mark.parametrize("key, shown", [
        (None, "aws/secretsmanager"),
        ("alias/aws/secretsmanager", "alias/aws/secretsmanager"),
        (f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:alias/aws/secretsmanager",
         f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:alias/aws/secretsmanager"),
    ])
    def test_fail_aws_managed_key(self, key, shown):
        result = assert_fail(evaluate("SM-004", secret(kms_key_id=key)))
        assert result.evidence == {"KmsKeyId": shown}
