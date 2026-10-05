"""KMS rules KMS-001 .. KMS-003."""

from __future__ import annotations

import pytest

from _factory import (
    ACCOUNT_ID,
    NOW,
    assert_fail,
    assert_pass,
    evaluate,
    kms_key,
    policy_doc,
    root_key_policy,
    statement,
)

AWS_MANAGED = {"key_manager": "AWS", "policy": None, "description": "Default key managed by AWS"}
PUBLIC_USE = statement(Sid="AllowUse", Principal={"AWS": "*"}, Action=["kms:Decrypt", "kms:DescribeKey"], Resource="*")


class TestKeyRotation:
    def test_pass_rotation_enabled(self):
        result = assert_pass(evaluate("KMS-001", kms_key(rotation_enabled=True)))
        assert result.evidence == {"KeyRotationEnabled": True, "KeySpec": "SYMMETRIC_DEFAULT"}

    def test_fail_rotation_disabled(self):
        result = assert_fail(evaluate("KMS-001", kms_key(rotation_enabled=False)))
        assert result.evidence["KeyRotationEnabled"] is False

    @pytest.mark.parametrize("props", [
        AWS_MANAGED,
        {"key_spec": "RSA_2048", "key_usage": "SIGN_VERIFY"},
        {"key_spec": "HMAC_256", "key_usage": "GENERATE_VERIFY_MAC"},
        {"key_state": "PendingDeletion"},
        {"key_state": "PendingReplicaDeletion"},
    ])
    def test_not_applicable(self, props):
        assert evaluate("KMS-001", kms_key(rotation_enabled=False, **props)) is None


class TestPublicKeyPolicy:
    def test_pass_account_root_only(self):
        result = assert_pass(evaluate("KMS-002", kms_key(policy=root_key_policy())))
        assert result.evidence == {"PublicStatements": []}

    @pytest.mark.parametrize("condition", [
        {"StringEquals": {"kms:CallerAccount": ACCOUNT_ID}},
        {"StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com"}},
        {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
    ])
    def test_pass_wildcard_scoped_by_condition(self, condition):
        doc = policy_doc(*root_key_policy()["Statement"], {**PUBLIC_USE, "Condition": condition})
        assert_pass(evaluate("KMS-002", kms_key(policy=doc)))

    @pytest.mark.parametrize("principal", [{"AWS": "*"}, "*"])
    def test_fail_wildcard_principal(self, principal):
        doc = policy_doc(*root_key_policy()["Statement"], {**PUBLIC_USE, "Principal": principal})
        result = assert_fail(evaluate("KMS-002", kms_key(policy=doc)))
        [public] = result.evidence["PublicStatements"]
        assert public["Sid"] == "AllowUse"

    def test_not_applicable_for_aws_managed(self):
        assert evaluate("KMS-002", kms_key(**{**AWS_MANAGED, "policy": policy_doc(PUBLIC_USE)})) is None


class TestKeyPendingDeletion:
    def test_pass_enabled_key(self):
        result = assert_pass(evaluate("KMS-003", kms_key()))
        assert result.evidence == {"KeyState": "Enabled", "DeletionDate": None}

    def test_fail_pending_deletion(self):
        deletion = NOW.isoformat()
        result = assert_fail(evaluate("KMS-003", kms_key(key_state="PendingDeletion", deletion_date=deletion)))
        assert result.evidence == {"KeyState": "PendingDeletion", "DeletionDate": deletion}

    def test_disabled_key_is_not_pending_deletion(self):
        assert_pass(evaluate("KMS-003", kms_key(key_state="Disabled")))

    def test_not_applicable_for_aws_managed(self):
        assert evaluate("KMS-003", kms_key(key_state="PendingDeletion", **AWS_MANAGED)) is None
