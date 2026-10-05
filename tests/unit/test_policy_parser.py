"""checks/policy.py — IAM and resource-policy analysis helpers."""

from __future__ import annotations

import json

import pytest

from cloudaegis_engine.checks import policy as pol

OWN = "123456789012"
EXT = "210987654321"
ADMIN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(**fields):
    return {"Effect": "Allow", **fields}


def deny(**fields):
    return {"Effect": "Deny", **fields}


# ---------------------------------------------------------------------------
# Document loading and statement iteration
# ---------------------------------------------------------------------------
class TestLoadDocument:
    def test_dict_is_returned_as_is(self):
        assert pol.load_document(ADMIN) is ADMIN

    def test_json_string_is_parsed(self):
        assert pol.load_document(json.dumps(ADMIN)) == ADMIN

    @pytest.mark.parametrize("value", [None, "", "{not json", "[1, 2]", '"just a string"', 42, ["*"]])
    def test_invalid_inputs_return_none(self, value):
        assert pol.load_document(value) is None


class TestStatements:
    def test_single_statement_object_is_accepted(self):
        single = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}}
        assert list(pol.statements(single)) == [single["Statement"]]

    def test_non_dict_statements_are_skipped(self):
        assert list(pol.statements({"Statement": ["junk", None, allow(Action="s3:*")]})) == [allow(Action="s3:*")]

    @pytest.mark.parametrize("value", [None, {}, {"Version": "2012-10-17"}, "garbage"])
    def test_empty_or_invalid_documents_yield_nothing(self, value):
        assert list(pol.statements(value)) == []

    def test_allow_statements_filters_effect(self):
        d = doc(allow(Action="a:b"), deny(Action="c:d"))
        assert [s["Action"] for s in pol.allow_statements(d)] == ["a:b"]

    @pytest.mark.parametrize("field, value, expected", [
        ("Action", "s3:GetObject", ["s3:GetObject"]),
        ("Action", ["s3:GetObject", "s3:PutObject"], ["s3:GetObject", "s3:PutObject"]),
        ("Resource", "*", ["*"]),
        ("Resource", ["arn:aws:s3:::a", "arn:aws:s3:::a/*"], ["arn:aws:s3:::a", "arn:aws:s3:::a/*"]),
    ])
    def test_string_and_list_fields(self, field, value, expected):
        getter = pol.statement_actions if field == "Action" else pol.statement_resources
        assert getter(allow(**{field: value})) == expected

    def test_missing_fields_are_empty(self):
        assert pol.statement_actions(allow()) == []
        assert pol.statement_resources(allow()) == []

    def test_iter_documents(self):
        entries = [
            {"name": "inline-a", "document": ADMIN},
            {"name": "as-json", "document": json.dumps(ADMIN)},
            {"name": "empty", "document": None},
            {"document": ADMIN},
        ]
        assert [name for name, _ in pol.iter_documents(entries)] == ["inline-a", "as-json", "inline"]
        assert list(pol.iter_documents(None)) == []


# ---------------------------------------------------------------------------
# Action matching
# ---------------------------------------------------------------------------
class TestActionMatching:
    @pytest.mark.parametrize("pattern, action, expected", [
        ("*", "iam:PassRole", True),
        ("iam:*", "iam:PassRole", True),
        ("IAM:passrole", "iam:PassRole", True),
        ("iam:Pass*", "iam:PassRole", True),
        ("iam:Put?serPolicy", "iam:PutUserPolicy", True),
        ("iam:Get*", "iam:PassRole", False),
        ("s3:*", "iam:PassRole", False),
        ("iam:Pass", "iam:PassRole", False),  # no implicit prefix match
    ])
    def test_action_matches(self, pattern, action, expected):
        assert pol.action_matches(pattern, action) is expected

    def test_statement_allows_action_list(self):
        stmt = allow(Action=["s3:GetObject", "iam:Create*"], Resource="*")
        assert pol.statement_allows_action(stmt, "iam:CreateAccessKey")
        assert not pol.statement_allows_action(stmt, "iam:PassRole")

    def test_not_action_inverts_match(self):
        stmt = allow(NotAction=["iam:*", "organizations:*"], Resource="*")
        assert pol.statement_allows_action(stmt, "s3:DeleteBucket")
        assert not pol.statement_allows_action(stmt, "iam:PassRole")

    def test_not_action_string(self):
        stmt = allow(NotAction="iam:*", Resource="*")
        assert pol.statement_allows_action(stmt, "ec2:RunInstances")


# ---------------------------------------------------------------------------
# Admin detection
# ---------------------------------------------------------------------------
class TestAdminDetection:
    @pytest.mark.parametrize("stmt", [
        allow(Action="*", Resource="*"),
        allow(Action=["*"], Resource=["*"]),
        allow(Action=["s3:GetObject", "*"], Resource=["arn:aws:s3:::x", "*"]),
        allow(NotAction=[], Resource="*"),  # NotAction of nothing == everything
    ])
    def test_full_admin_statements(self, stmt):
        assert pol.is_full_admin_statement(stmt)

    @pytest.mark.parametrize("stmt", [
        deny(Action="*", Resource="*"),
        allow(Action="*", Resource="arn:aws:s3:::bucket/*"),
        allow(Action="s3:*", Resource="*"),
        allow(Action="*"),  # no Resource
        allow(Action="*", Resource="*", Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}),
        allow(NotAction=["iam:*"], Resource="*"),
    ])
    def test_non_admin_statements(self, stmt):
        assert not pol.is_full_admin_statement(stmt)

    def test_grants_full_admin_on_documents(self):
        assert pol.grants_full_admin(ADMIN)
        assert pol.grants_full_admin(json.dumps(ADMIN))
        assert pol.grants_full_admin(doc(allow(Action="s3:GetObject", Resource="*"), allow(Action="*", Resource="*")))
        assert not pol.grants_full_admin(doc(allow(Action="s3:*", Resource="*")))
        assert not pol.grants_full_admin(None)

    def test_wildcard_service_grants(self):
        d = doc(
            allow(Action=["iam:*", "s3:*", "ec2:Describe*"], Resource="*"),
            allow(Action="iam:*", Resource="*"),  # duplicate
            allow(Action="kms:*", Resource=f"arn:aws:kms:us-east-1:{OWN}:key/abc"),  # scoped
            deny(Action="sts:*", Resource="*"),
        )
        assert pol.wildcard_service_grants(d) == ["iam:*", "s3:*"]


# ---------------------------------------------------------------------------
# Privilege escalation
# ---------------------------------------------------------------------------
class TestEscalationActions:
    def test_specific_actions(self):
        d = doc(allow(Action=["iam:PassRole", "lambda:CreateFunction"], Resource="*"))
        assert pol.escalation_actions(d) == ["iam:PassRole"]

    def test_service_wildcard_returns_every_escalation_action_in_catalog_order(self):
        assert pol.escalation_actions(doc(allow(Action="iam:*", Resource="*"))) == list(pol.PRIVILEGE_ESCALATION_ACTIONS)

    def test_not_action_grants_escalation(self):
        hits = pol.escalation_actions(doc(allow(NotAction="s3:*", Resource="*")))
        assert hits == list(pol.PRIVILEGE_ESCALATION_ACTIONS)

    def test_not_action_excluding_iam_grants_none(self):
        assert pol.escalation_actions(doc(allow(NotAction="iam:*", Resource="*"))) == []

    def test_deduplicated_across_statements(self):
        d = doc(allow(Action="iam:PassRole", Resource="*"), allow(Action="iam:Pass*", Resource=["*"]))
        assert pol.escalation_actions(d) == ["iam:PassRole"]

    @pytest.mark.parametrize("d", [
        doc(allow(Action="iam:PassRole", Resource=f"arn:aws:iam::{OWN}:role/app")),
        doc(deny(Action="iam:*", Resource="*")),
        doc(allow(Action=["iam:Get*", "iam:List*"], Resource="*")),
        None,
    ])
    def test_no_escalation(self, d):
        assert pol.escalation_actions(d) == []

    def test_catalog_contains_well_known_paths(self):
        for action in ("iam:CreatePolicyVersion", "iam:AttachRolePolicy", "iam:PassRole", "iam:UpdateAssumeRolePolicy"):
            assert action in pol.PRIVILEGE_ESCALATION_ACTIONS


# ---------------------------------------------------------------------------
# Principals and conditions
# ---------------------------------------------------------------------------
class TestPrincipals:
    @pytest.mark.parametrize("principal", ["*", {"AWS": "*"}, {"AWS": ["*"]}, {"AWS": [f"arn:aws:iam::{OWN}:root", "*"]}])
    def test_wildcard(self, principal):
        assert pol.principal_is_wildcard(principal)

    @pytest.mark.parametrize("principal", [
        None, {"AWS": f"arn:aws:iam::{OWN}:root"}, {"AWS": OWN}, {"Service": "lambda.amazonaws.com"},
        {"Federated": "cognito-identity.amazonaws.com"},
    ])
    def test_not_wildcard(self, principal):
        assert not pol.principal_is_wildcard(principal)


class TestConditions:
    @pytest.mark.parametrize("condition", [
        {"ArnLike": {"aws:SourceArn": "arn:aws:execute-api:us-east-1:123456789012:abc/*"}},
        {"ArnLike": {"AWS:SourceArn": "arn:aws:sns:us-east-1:123456789012:topic"}},  # key is case-insensitive
        {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
        {"StringEquals": {"aws:SourceAccount": OWN}},
        {"StringEquals": {"aws:SourceVpce": "vpce-1"}},
        {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
        {"StringEquals": {"kms:CallerAccount": OWN}},
        {"ForAnyValue:StringLike": {"aws:PrincipalOrgPaths": "o-abc/r-1/*"}},
        {"Bool": {"aws:SecureTransport": "true"}, "StringEquals": {"aws:PrincipalAccount": OWN}},
    ])
    def test_restricting(self, condition):
        assert pol.has_restricting_condition(allow(Principal="*", Condition=condition))

    @pytest.mark.parametrize("condition", [
        None,
        {},
        {"Bool": {"aws:SecureTransport": "true"}},
        {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        {"StringEquals": {"sts:ExternalId": "abc"}},  # handled separately by IAM-010/011
        {"StringEquals": "malformed"},
        ["not", "a", "dict"],
    ])
    def test_not_restricting(self, condition):
        stmt = allow(Principal="*")
        if condition is not None:
            stmt["Condition"] = condition
        assert not pol.has_restricting_condition(stmt)

    def test_statement_has_condition_key_is_case_insensitive(self):
        stmt = allow(Condition={"StringEquals": {"STS:ExternalID": "x"}})
        assert pol.statement_has_condition_key(stmt, "sts:ExternalId")
        assert not pol.statement_has_condition_key(stmt, "aws:PrincipalOrgID")
        assert not pol.statement_has_condition_key(allow(), "sts:ExternalId")


class TestPublicStatements:
    PUBLIC = allow(Principal="*", Action="s3:GetObject", Resource="arn:aws:s3:::b/*")

    @pytest.mark.parametrize("d", [
        doc(PUBLIC),
        doc({**PUBLIC, "Principal": {"AWS": "*"}}),
        json.dumps(doc(PUBLIC)),
        doc({**PUBLIC, "Condition": {"Bool": {"aws:SecureTransport": "true"}}}),
    ])
    def test_public(self, d):
        assert pol.is_public_policy(d)
        assert len(pol.public_statements(d)) == 1

    @pytest.mark.parametrize("d", [
        doc({**PUBLIC, "Condition": {"StringEquals": {"aws:SourceAccount": OWN}}}),
        doc({**PUBLIC, "Condition": {"ArnLike": {"aws:SourceArn": "arn:aws:cloudfront::123456789012:distribution/E1"}}}),
        doc({**PUBLIC, "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}}),
        doc({**PUBLIC, "Effect": "Deny"}),
        doc({**PUBLIC, "Principal": {"Service": "cloudfront.amazonaws.com"}}),
        doc({**PUBLIC, "Principal": {"AWS": f"arn:aws:iam::{EXT}:root"}}),
        None,
        "",
    ])
    def test_not_public(self, d):
        assert not pol.is_public_policy(d)

    def test_only_public_statements_returned(self):
        restricted = {**self.PUBLIC, "Sid": "Scoped", "Condition": {"StringEquals": {"aws:SourceAccount": OWN}}}
        public = {**self.PUBLIC, "Sid": "Open"}
        assert [s["Sid"] for s in pol.public_statements(doc(restricted, public))] == ["Open"]


class TestExternalPrincipals:
    def test_collects_other_account_principals(self):
        d = doc(allow(Principal={"AWS": [
            f"arn:aws:iam::{EXT}:root",
            EXT,
            f"arn:aws:iam::{EXT}:role/vendor",
            f"arn:aws:sts::998877665544:assumed-role/ci/session",
            f"arn:aws:iam::{OWN}:root",
            OWN,
            "*",
        ]}, Action="sts:AssumeRole"))
        assert pol.external_principals(d, OWN) == [
            f"arn:aws:iam::{EXT}:root", EXT, f"arn:aws:iam::{EXT}:role/vendor",
            "arn:aws:sts::998877665544:assumed-role/ci/session"]

    def test_deduplicates_and_ignores_deny(self):
        d = doc(allow(Principal={"AWS": f"arn:aws:iam::{EXT}:root"}),
                allow(Principal={"AWS": f"arn:aws:iam::{EXT}:root"}),
                deny(Principal={"AWS": "arn:aws:iam::998877665544:root"}))
        assert pol.external_principals(d, OWN) == [f"arn:aws:iam::{EXT}:root"]

    @pytest.mark.parametrize("principal", [
        "*", {"AWS": "*"}, {"Service": "lambda.amazonaws.com"},
        {"Federated": f"arn:aws:iam::{EXT}:saml-provider/Okta"},  # only AWS principals are considered
        {"AWS": "not-an-arn"}, {"AWS": "12345"},
    ])
    def test_ignored_principals(self, principal):
        assert pol.external_principals(doc(allow(Principal=principal)), OWN) == []


# ---------------------------------------------------------------------------
# Insecure transport
# ---------------------------------------------------------------------------
class TestDeniesInsecureTransport:
    def _deny(self, condition):
        return deny(Principal="*", Action="s3:*", Resource=["arn:aws:s3:::b", "arn:aws:s3:::b/*"], Condition=condition)

    @pytest.mark.parametrize("condition", [
        {"Bool": {"aws:SecureTransport": "false"}},
        {"Bool": {"aws:SecureTransport": "False"}},
        {"Bool": {"aws:SecureTransport": False}},
        {"Bool": {"aws:SecureTransport": ["false"]}},
        {"BoolIfExists": {"aws:SecureTransport": "false"}},
        {"Bool": {"AWS:SecureTransport": "false"}},
    ])
    def test_detected(self, condition):
        assert pol.denies_insecure_transport(doc(self._deny(condition)))

    def test_detected_in_json_string_alongside_other_statements(self):
        d = doc(allow(Principal={"Service": "cloudtrail.amazonaws.com"}, Action="s3:PutObject", Resource="*"),
                self._deny({"Bool": {"aws:SecureTransport": "false"}}))
        assert pol.denies_insecure_transport(json.dumps(d))

    @pytest.mark.parametrize("d", [
        None,
        doc(),
        doc(allow(Principal="*", Action="s3:*", Resource="*", Condition={"Bool": {"aws:SecureTransport": "false"}})),
        doc(deny(Principal="*", Action="s3:*", Resource="*")),
        doc(deny(Principal="*", Action="s3:*", Resource="*", Condition={"Bool": {"aws:SecureTransport": "true"}})),
        doc(deny(Principal="*", Action="s3:*", Resource="*",
                 Condition={"StringNotEquals": {"aws:SecureTransport": "true"}})),
        doc(deny(Principal="*", Action="s3:*", Resource="*", Condition={"Bool": {"aws:MultiFactorAuthPresent": "false"}})),
    ])
    def test_not_detected(self, d):
        assert not pol.denies_insecure_transport(d)


def test_summarize_statement_keeps_only_present_keys():
    stmt = allow(Sid="S", Principal="*", Action="s3:GetObject", Resource="*", Extra="ignored")
    assert pol.summarize_statement(stmt) == {"Effect": "Allow", "Sid": "S", "Principal": "*",
                                             "Action": "s3:GetObject", "Resource": "*"}
    assert pol.summarize_statement(deny(NotAction="iam:*", Condition={"a": {}})) == {
        "Effect": "Deny", "NotAction": "iam:*", "Condition": {"a": {}}}


class TestConditionValuesMatter:
    """A restricting condition key only scopes access if its value is not itself 'everyone'."""

    def _stmt(self, condition):
        return {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*", "Condition": condition}

    @pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0", ["10.0.0.0/8", "0.0.0.0/0"]])
    def test_source_ip_any_is_not_restricting(self, cidr):
        assert not pol.has_restricting_condition(self._stmt({"IpAddress": {"aws:SourceIp": cidr}}))

    def test_wildcard_value_is_not_restricting(self):
        assert not pol.has_restricting_condition(self._stmt({"StringLike": {"aws:PrincipalOrgID": "*"}}))

    def test_specific_source_ip_restricts(self):
        assert pol.has_restricting_condition(self._stmt({"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}))

    def test_public_policy_with_open_source_ip_is_public(self):
        doc = {"Version": "2012-10-17", "Statement": [self._stmt({"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}})]}
        assert pol.is_public_policy(doc)
