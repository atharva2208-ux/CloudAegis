"""IAM rules IAM-001 .. IAM-015."""

from __future__ import annotations

import json

import pytest

from _factory import (
    ADMIN_ARN,
    ADMIN_DOC,
    ACCOUNT_ID,
    EXTERNAL_ACCOUNT_ID,
    access_key,
    account,
    admin_doc_entry,
    assert_fail,
    assert_pass,
    days_ago,
    drop,
    evaluate,
    iam_policy,
    iam_role,
    iam_user,
    policy_doc,
    statement,
)


# ---------------------------------------------------------------------------
# Account-level: IAM-001 root MFA, IAM-002 root keys
# ---------------------------------------------------------------------------
class TestRootMfa:
    def test_pass_when_root_mfa_enabled(self):
        result = assert_pass(evaluate("IAM-001", account(root_mfa_enabled=True)))
        assert result.evidence == {"AccountMFAEnabled": True}

    def test_fail_when_root_mfa_disabled(self):
        result = assert_fail(evaluate("IAM-001", account(root_mfa_enabled=False)))
        assert result.evidence == {"AccountMFAEnabled": False}

    def test_not_applicable_when_summary_unavailable(self):
        assert evaluate("IAM-001", drop(account(), "root_mfa_enabled")) is None


class TestRootAccessKeys:
    def test_pass_without_root_keys(self):
        result = assert_pass(evaluate("IAM-002", account(root_access_keys_present=False)))
        assert result.evidence == {"AccountAccessKeysPresent": 0}

    def test_fail_with_root_keys(self):
        result = assert_fail(evaluate("IAM-002", account(root_access_keys_present=True)))
        assert result.evidence == {"AccountAccessKeysPresent": 1}

    def test_not_applicable_when_summary_unavailable(self):
        assert evaluate("IAM-002", drop(account(), "root_access_keys_present")) is None


# ---------------------------------------------------------------------------
# IAM-003 console user without MFA
# ---------------------------------------------------------------------------
class TestConsoleUserWithoutMfa:
    def test_pass_console_user_with_mfa(self):
        result = assert_pass(evaluate("IAM-003", iam_user(mfa_enabled=True, mfa_devices=1)))
        assert result.evidence["MFAEnabled"] is True

    def test_fail_console_user_without_mfa(self):
        result = assert_fail(evaluate("IAM-003", iam_user(mfa_enabled=False, mfa_devices=0)))
        assert result.evidence == {"PasswordEnabled": True, "MFAEnabled": False, "MFADevices": 0}

    def test_not_applicable_for_programmatic_only_user(self):
        user = iam_user("svc-orders-deploy", password_enabled=False, password_last_used=None,
                        mfa_enabled=False, mfa_devices=0, access_keys=[access_key()])
        assert evaluate("IAM-003", user) is None


# ---------------------------------------------------------------------------
# IAM-004 unused access key (threshold: stale_credential_days, inclusive)
# ---------------------------------------------------------------------------
class TestUnusedAccessKey:
    @pytest.mark.parametrize("last_used_days, failed", [(0, False), (89, False), (90, True), (91, True), (400, True)])
    def test_threshold_on_last_use(self, last_used_days, failed):
        user = iam_user(access_keys=[access_key(created_days=500, last_used_days=last_used_days)])
        result = evaluate("IAM-004", user)
        if failed:
            assert_fail(result)
            [stale] = result.evidence["UnusedActiveKeys"]
            assert stale["DaysSinceLastUse"] == last_used_days
            assert stale["AccessKeyId"] == "AKIAEXAMPLE0001"
        else:
            assert_pass(result)
            assert result.evidence["UnusedActiveKeys"] == []
        assert result.evidence["ThresholdDays"] == 90

    def test_partial_day_rounds_down(self):
        # 89 days and 23 hours is still day 89 -> under the threshold.
        user = iam_user(access_keys=[access_key(created_days=500, last_used_days=None)])
        user.properties["access_keys"][0]["last_used_at"] = days_ago(89, hours=23)
        assert_pass(evaluate("IAM-004", user))

    def test_never_used_key_is_judged_by_creation_date(self):
        old = iam_user(access_keys=[access_key(created_days=120, last_used_days=None)])
        result = assert_fail(evaluate("IAM-004", old))
        assert result.evidence["UnusedActiveKeys"][0]["LastUsed"] == "never"
        assert result.evidence["UnusedActiveKeys"][0]["DaysSinceLastUse"] == 120

        fresh = iam_user(access_keys=[access_key(created_days=10, last_used_days=None)])
        assert_pass(evaluate("IAM-004", fresh))

    def test_inactive_keys_are_ignored(self):
        user = iam_user(access_keys=[
            access_key("AKIAOLD", created_days=900, last_used_days=800, status="Inactive"),
            access_key("AKIANEW", created_days=10, last_used_days=1),
        ])
        assert_pass(evaluate("IAM-004", user))

    def test_custom_threshold(self):
        user = iam_user(access_keys=[access_key(created_days=200, last_used_days=45)])
        assert_pass(evaluate("IAM-004", user))
        result = assert_fail(evaluate("IAM-004", user, stale_credential_days=30))
        assert result.evidence["ThresholdDays"] == 30

    @pytest.mark.parametrize("keys", [[], [access_key(status="Inactive", created_days=900, last_used_days=900)]])
    def test_not_applicable_without_active_keys(self, keys):
        assert evaluate("IAM-004", iam_user(access_keys=keys)) is None


# ---------------------------------------------------------------------------
# IAM-005 access key not rotated
# ---------------------------------------------------------------------------
class TestAccessKeyNotRotated:
    @pytest.mark.parametrize("created_days, failed", [(1, False), (89, False), (90, True), (365, True)])
    def test_threshold_on_key_age(self, created_days, failed):
        user = iam_user(access_keys=[access_key(created_days=created_days, last_used_days=0)])
        result = evaluate("IAM-005", user)
        if failed:
            assert_fail(result)
            [old] = result.evidence["KeysOverThreshold"]
            assert old["AgeDays"] == created_days
            assert old["Created"] == user.properties["access_keys"][0]["created_at"]
        else:
            assert_pass(result)

    def test_reports_only_the_old_key(self):
        user = iam_user(access_keys=[access_key("AKIAOLD", created_days=200), access_key("AKIANEW", created_days=5)])
        result = assert_fail(evaluate("IAM-005", user))
        assert [k["AccessKeyId"] for k in result.evidence["KeysOverThreshold"]] == ["AKIAOLD"]

    def test_custom_threshold(self):
        user = iam_user(access_keys=[access_key(created_days=100)])
        assert_pass(evaluate("IAM-005", user, stale_credential_days=180))

    def test_not_applicable_without_active_keys(self):
        user = iam_user(access_keys=[access_key(created_days=900, status="Inactive")])
        assert evaluate("IAM-005", user) is None


# ---------------------------------------------------------------------------
# IAM-006 / IAM-007 password policy
# ---------------------------------------------------------------------------
class TestNoPasswordPolicy:
    def test_pass_when_policy_configured(self):
        assert_pass(evaluate("IAM-006", account()))

    def test_fail_when_no_such_entity(self):
        result = assert_fail(evaluate("IAM-006", account(password_policy=None)))
        assert result.evidence == {"PasswordPolicy": "NoSuchEntity"}

    def test_not_applicable_when_not_collected(self):
        assert evaluate("IAM-006", drop(account(), "password_policy")) is None


class TestWeakPasswordPolicy:
    @staticmethod
    def _policy(**overrides):
        base = account().properties["password_policy"]
        return {**base, **overrides}

    def test_pass_at_exact_minimums(self):
        result = assert_pass(evaluate("IAM-007", account(password_policy=self._policy(
            minimum_length=14, password_reuse_prevention=24))))
        assert result.evidence["Weaknesses"] == []

    @pytest.mark.parametrize("overrides, expected", [
        ({"minimum_length": 13}, ["MinimumPasswordLength=13 (< 14)"]),
        ({"password_reuse_prevention": 23}, ["PasswordReusePrevention=23 (< 24)"]),
        ({"minimum_length": 8, "password_reuse_prevention": 5},
         ["MinimumPasswordLength=8 (< 14)", "PasswordReusePrevention=5 (< 24)"]),
        # AWS omits PasswordReusePrevention when reuse prevention is off.
        ({"password_reuse_prevention": None}, ["PasswordReusePrevention=0 (< 24)"]),
    ])
    def test_fail_on_weak_settings(self, overrides, expected):
        result = assert_fail(evaluate("IAM-007", account(password_policy=self._policy(**overrides))))
        assert result.evidence["Weaknesses"] == expected

    def test_not_applicable_without_policy(self):
        # IAM-006 reports the missing policy; IAM-007 must not double count it.
        assert evaluate("IAM-007", account(password_policy=None)) is None


# ---------------------------------------------------------------------------
# IAM-008 customer managed policy with full admin
# ---------------------------------------------------------------------------
class TestFullAdminCustomerPolicy:
    def test_pass_scoped_policy(self):
        result = assert_pass(evaluate("IAM-008", iam_policy()))
        assert result.evidence["AdminStatements"] == []

    @pytest.mark.parametrize("document", [
        ADMIN_DOC,
        policy_doc(statement(Action=["*"], Resource=["*"])),
        json.dumps(ADMIN_DOC),  # documents may arrive as JSON strings
        policy_doc(statement(Action="s3:GetObject", Resource="*"), statement(Sid="Admin", Action="*", Resource="*")),
    ])
    def test_fail_on_star_star(self, document):
        result = assert_fail(evaluate("IAM-008", iam_policy(document=document, attachment_count=3)))
        assert result.evidence["AttachmentCount"] == 3
        assert len(result.evidence["AdminStatements"]) == 1
        assert result.evidence["AdminStatements"][0]["Effect"] == "Allow"

    @pytest.mark.parametrize("document", [
        policy_doc(statement(Action="*", Resource="arn:aws:s3:::bucket/*")),
        policy_doc(statement("Deny", Action="*", Resource="*")),
        policy_doc(statement(Action="*", Resource="*", Condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}})),
    ])
    def test_pass_on_non_admin_variants(self, document):
        assert_pass(evaluate("IAM-008", iam_policy(document=document)))

    @pytest.mark.parametrize("count", [0, None])
    def test_not_applicable_when_unattached(self, count):
        assert evaluate("IAM-008", iam_policy(document=ADMIN_DOC, attachment_count=count)) is None


# ---------------------------------------------------------------------------
# IAM-009 user with admin privileges
# ---------------------------------------------------------------------------
class TestUserWithDirectAdmin:
    def test_pass_read_only_user(self):
        result = assert_pass(evaluate("IAM-009", iam_user()))
        assert result.evidence == {"AdminPolicySources": []}

    def test_fail_via_inline_or_attached_document(self):
        user = iam_user(policy_documents=[admin_doc_entry("break-glass", "inline")])
        result = assert_fail(evaluate("IAM-009", user))
        assert result.evidence["AdminPolicySources"] == ["break-glass"]

    def test_fail_via_group_policy_document(self):
        user = iam_user(groups=["Administrators"],
                        policy_documents=[admin_doc_entry("AdministratorAccess", "group:Administrators")])
        assert_fail(evaluate("IAM-009", user))

    @pytest.mark.parametrize("arn, name", [
        (ADMIN_ARN, "AdministratorAccess"),
        ("arn:aws:iam::aws:policy/IAMFullAccess", "IAMFullAccess"),
    ])
    def test_fail_via_managed_policy_arn_without_document(self, arn, name):
        user = iam_user(attached_policies=[{"name": name, "arn": arn}], policy_documents=[])
        result = assert_fail(evaluate("IAM-009", user))
        assert result.evidence["AdminPolicySources"] == [name]

    def test_source_is_not_duplicated(self):
        user = iam_user(attached_policies=[{"name": "AdministratorAccess", "arn": ADMIN_ARN}],
                        policy_documents=[admin_doc_entry()])
        result = assert_fail(evaluate("IAM-009", user))
        assert result.evidence["AdminPolicySources"] == ["AdministratorAccess"]


# ---------------------------------------------------------------------------
# IAM-010 publicly assumable role
# ---------------------------------------------------------------------------
def _trust(principal, condition=None):
    stmt = statement(Principal=principal, Action="sts:AssumeRole")
    if condition:
        stmt["Condition"] = condition
    return policy_doc(stmt)


class TestPubliclyAssumableRole:
    @pytest.mark.parametrize("trust", [
        _trust({"Service": "lambda.amazonaws.com"}),
        _trust({"AWS": f"arn:aws:iam::{EXTERNAL_ACCOUNT_ID}:root"}),
        _trust({"AWS": "*"}, {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}),
        _trust({"AWS": "*"}, {"StringEquals": {"sts:ExternalId": "ext-1234567"}}),
        _trust({"AWS": "*"}, {"ArnLike": {"aws:PrincipalArn": f"arn:aws:iam::{ACCOUNT_ID}:role/*"}}),
        policy_doc(statement("Deny", Principal="*", Action="sts:AssumeRole")),
    ])
    def test_pass(self, trust):
        result = assert_pass(evaluate("IAM-010", iam_role(trust_policy=trust)))
        assert result.evidence == {"PublicTrustStatements": []}

    @pytest.mark.parametrize("trust", [
        _trust({"AWS": "*"}),
        _trust("*"),
        _trust({"AWS": ["*", f"arn:aws:iam::{ACCOUNT_ID}:root"]}),
        # MFA-present is not a caller-scoping condition: any MFA'd principal anywhere qualifies.
        _trust({"AWS": "*"}, {"Bool": {"aws:MultiFactorAuthPresent": "true"}}),
        json.dumps(_trust({"AWS": "*"})),
    ])
    def test_fail(self, trust):
        result = assert_fail(evaluate("IAM-010", iam_role("partner-integration", trust_policy=trust)))
        [stmt] = result.evidence["PublicTrustStatements"]
        assert stmt["Action"] == "sts:AssumeRole"


# ---------------------------------------------------------------------------
# IAM-011 cross-account trust without external ID
# ---------------------------------------------------------------------------
class TestCrossAccountTrustWithoutExternalId:
    EXT_ROOT = f"arn:aws:iam::{EXTERNAL_ACCOUNT_ID}:root"

    @pytest.mark.parametrize("principal", [{"AWS": EXT_ROOT}, {"AWS": EXTERNAL_ACCOUNT_ID},
                                           {"AWS": f"arn:aws:iam::{EXTERNAL_ACCOUNT_ID}:role/vendor"}])
    def test_fail_external_principal_without_condition(self, principal):
        result = assert_fail(evaluate("IAM-011", iam_role(trust_policy=_trust(principal))))
        assert result.evidence["TrustedExternalPrincipals"] == [principal["AWS"]]

    @pytest.mark.parametrize("condition", [
        {"StringEquals": {"sts:ExternalId": "ext-1234567"}},
        {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
    ])
    def test_pass_with_protecting_condition(self, condition):
        result = assert_pass(evaluate("IAM-011", iam_role(trust_policy=_trust({"AWS": self.EXT_ROOT}, condition))))
        assert result.evidence["TrustedExternalPrincipals"] == [self.EXT_ROOT]

    def test_only_unprotected_statements_reported(self):
        other = "arn:aws:iam::998877665544:root"
        trust = policy_doc(
            statement(Principal={"AWS": self.EXT_ROOT}, Action="sts:AssumeRole",
                      Condition={"StringEquals": {"sts:ExternalId": "x"}}),
            statement(Principal={"AWS": other}, Action="sts:AssumeRole"),
        )
        result = assert_fail(evaluate("IAM-011", iam_role(trust_policy=trust)))
        assert result.evidence["TrustedExternalPrincipals"] == [other]

    @pytest.mark.parametrize("trust", [
        _trust({"Service": "lambda.amazonaws.com"}),
        _trust({"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"}),
        _trust({"AWS": "*"}),  # wildcard is IAM-010's concern
        _trust({"Federated": f"arn:aws:iam::{ACCOUNT_ID}:saml-provider/AWSSSO"}),
    ])
    def test_not_applicable_without_external_principals(self, trust):
        assert evaluate("IAM-011", iam_role(trust_policy=trust)) is None


# ---------------------------------------------------------------------------
# IAM-012 inactive user (threshold: unused_user_days, inclusive)
# ---------------------------------------------------------------------------
class TestUnusedIamUser:
    @pytest.mark.parametrize("last_login, failed", [(5, False), (89, False), (90, True), (200, True)])
    def test_threshold_on_console_activity(self, last_login, failed):
        result = evaluate("IAM-012", iam_user(password_last_used=days_ago(last_login)))
        (assert_fail if failed else assert_pass)(result)
        assert result.evidence["DaysSinceLastActivity"] == last_login
        assert result.evidence["ThresholdDays"] == 90

    def test_recent_key_use_counts_as_activity(self):
        user = iam_user(password_last_used=days_ago(300),
                        access_keys=[access_key(created_days=300, last_used_days=3)])
        result = assert_pass(evaluate("IAM-012", user))
        assert result.evidence["DaysSinceLastActivity"] == 3

    def test_never_used_user_fails(self):
        user = iam_user(password_last_used=None, access_keys=[access_key(created_days=200, last_used_days=None)])
        result = assert_fail(evaluate("IAM-012", user))
        assert result.evidence["DaysSinceLastActivity"] == "never"

    def test_custom_threshold(self):
        user = iam_user(password_last_used=days_ago(45))
        assert_fail(evaluate("IAM-012", user, unused_user_days=30))

    @pytest.mark.parametrize("created_days", [0, 30, 89])
    def test_not_applicable_for_new_users(self, created_days):
        user = iam_user(created_at=days_ago(created_days), password_last_used=None)
        assert evaluate("IAM-012", user) is None


# ---------------------------------------------------------------------------
# IAM-013 admin user without MFA
# ---------------------------------------------------------------------------
class TestPrivilegedUserWithoutMfa:
    ADMIN = {"attached_policies": [{"name": "AdministratorAccess", "arn": ADMIN_ARN}],
             "policy_documents": [admin_doc_entry()]}

    def test_fail_admin_console_user_without_mfa(self):
        result = assert_fail(evaluate("IAM-013", iam_user(mfa_enabled=False, mfa_devices=0, **self.ADMIN)))
        assert result.evidence == {"AdminPolicySources": ["AdministratorAccess"], "PasswordEnabled": True,
                                   "MFAEnabled": False}

    def test_pass_admin_with_mfa(self):
        assert_pass(evaluate("IAM-013", iam_user(mfa_enabled=True, **self.ADMIN)))

    def test_pass_admin_without_console_access(self):
        user = iam_user(password_enabled=False, mfa_enabled=False, **self.ADMIN)
        result = assert_pass(evaluate("IAM-013", user))
        assert result.evidence["PasswordEnabled"] is False

    def test_not_applicable_for_non_admin(self):
        assert evaluate("IAM-013", iam_user(mfa_enabled=False)) is None


# ---------------------------------------------------------------------------
# IAM-014 multiple active keys
# ---------------------------------------------------------------------------
class TestMultipleActiveAccessKeys:
    def test_pass_single_active_key(self):
        user = iam_user(access_keys=[access_key("AKIA1"), access_key("AKIA2", status="Inactive")])
        result = assert_pass(evaluate("IAM-014", user))
        assert result.evidence == {"ActiveAccessKeys": ["AKIA1"]}

    def test_fail_two_active_keys(self):
        user = iam_user(access_keys=[access_key("AKIA1"), access_key("AKIA2")])
        result = assert_fail(evaluate("IAM-014", user))
        assert result.evidence == {"ActiveAccessKeys": ["AKIA1", "AKIA2"]}

    def test_not_applicable_without_active_keys(self):
        assert evaluate("IAM-014", iam_user(access_keys=[])) is None


# ---------------------------------------------------------------------------
# IAM-015 privilege escalation
# ---------------------------------------------------------------------------
class TestPrivilegeEscalationPolicy:
    def test_pass_scoped_policy(self):
        result = assert_pass(evaluate("IAM-015", iam_policy()))
        assert result.evidence["EscalationActions"] == []

    @pytest.mark.parametrize("stmt, expected_subset", [
        (statement(Action=["iam:PassRole", "lambda:CreateFunction"], Resource="*"), {"iam:PassRole"}),
        (statement(Action="iam:CreatePolicyVersion", Resource="*"), {"iam:CreatePolicyVersion"}),
        (statement(Action="IAM:attachrolepolicy", Resource="*"), {"iam:AttachRolePolicy"}),  # case-insensitive
        (statement(Action="iam:Put*Policy", Resource="*"),
         {"iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy"}),
        (statement(Action="iam:*", Resource="*"), {"iam:CreateAccessKey", "iam:UpdateAssumeRolePolicy"}),
        (statement(NotAction=["s3:*", "ec2:*"], Resource="*"), {"iam:PassRole", "iam:CreateLoginProfile"}),
    ])
    def test_fail_on_escalation_actions(self, stmt, expected_subset):
        result = assert_fail(evaluate("IAM-015", iam_policy(document=policy_doc(stmt))))
        assert expected_subset <= set(result.evidence["EscalationActions"])
        assert result.evidence["Resource"] == "*"

    @pytest.mark.parametrize("stmt", [
        statement(Action="iam:PassRole", Resource=f"arn:aws:iam::{ACCOUNT_ID}:role/orders-lambda-exec"),
        statement("Deny", Action="iam:*", Resource="*"),
        statement(Action=["iam:Get*", "iam:List*"], Resource="*"),
    ])
    def test_pass_on_scoped_or_read_only_iam(self, stmt):
        assert_pass(evaluate("IAM-015", iam_policy(document=policy_doc(stmt))))

    def test_not_applicable_for_full_admin(self):
        # IAM-008 reports the stronger condition.
        assert evaluate("IAM-015", iam_policy(document=ADMIN_DOC)) is None

    def test_not_applicable_when_unattached(self):
        doc = policy_doc(statement(Action="iam:PassRole", Resource="*"))
        assert evaluate("IAM-015", iam_policy(document=doc, attachment_count=0)) is None
