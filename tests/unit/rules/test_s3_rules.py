"""S3 rules S3-001 .. S3-009."""

from __future__ import annotations

import pytest

from _factory import (
    ACCOUNT_ID,
    AUTH_USERS_URI,
    BPA_ON,
    EXTERNAL_ACCOUNT_ID,
    account,
    assert_fail,
    assert_pass,
    bucket,
    deny_insecure_transport,
    drop,
    evaluate,
    owner_grant,
    policy_doc,
    public_grant,
    statement,
)

BPA_FLAGS = ["block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"]
NAME = "marketing-site-static-assets"
PUBLIC_READ = statement(Sid="PublicRead", Principal="*", Action="s3:GetObject", Resource=f"arn:aws:s3:::{NAME}/*")
NO_ACCOUNT_BPA = account(s3_public_access_block=None)


def bpa(**flags):
    return {**{f: False for f in BPA_FLAGS}, **flags}


# ---------------------------------------------------------------------------
# S3-001 effective public access (policy/ACL after Block Public Access)
# ---------------------------------------------------------------------------
class TestBucketPubliclyAccessible:
    def test_pass_private_bucket(self):
        result = assert_pass(evaluate("S3-001", bucket(), account()))
        assert result.evidence["PublicAccessReasons"] == []
        assert result.evidence["EffectiveBlockPublicAccess"] == BPA_ON

    def test_fail_public_policy_without_bpa(self):
        b = bucket(NAME, public_access_block=None, policy=policy_doc(PUBLIC_READ), policy_is_public=True)
        result = assert_fail(evaluate("S3-001", b, NO_ACCOUNT_BPA))
        assert result.evidence["PublicAccessReasons"] == ["Bucket policy grants public access"]
        assert result.evidence["EffectiveBlockPublicAccess"] == bpa()

    def test_policy_publicity_is_computed_when_flag_missing(self):
        b = bucket(NAME, public_access_block=None, policy=policy_doc(PUBLIC_READ), policy_is_public=None)
        assert_fail(evaluate("S3-001", b, NO_ACCOUNT_BPA))

    @pytest.mark.parametrize("uri", [public_grant()["grantee_uri"], AUTH_USERS_URI])
    def test_fail_public_acl_without_bpa(self, uri):
        b = bucket(NAME, public_access_block=None, acl_grants=[owner_grant(), public_grant(uri)],
                   object_ownership="ObjectWriter")
        result = assert_fail(evaluate("S3-001", b, NO_ACCOUNT_BPA))
        assert result.evidence["PublicAccessReasons"] == ["Bucket ACL grants access to AllUsers/AuthenticatedUsers"]

    def test_fail_reports_both_reasons(self):
        b = bucket(NAME, public_access_block=None, policy=policy_doc(PUBLIC_READ), policy_is_public=True,
                   acl_grants=[owner_grant(), public_grant()])
        result = assert_fail(evaluate("S3-001", b, NO_ACCOUNT_BPA))
        assert len(result.evidence["PublicAccessReasons"]) == 2

    def test_bucket_restrict_public_buckets_neutralises_public_policy(self):
        b = bucket(NAME, public_access_block=bpa(restrict_public_buckets=True), policy_is_public=True)
        assert_pass(evaluate("S3-001", b, NO_ACCOUNT_BPA))

    def test_account_level_bpa_neutralises_public_policy_and_acl(self):
        b = bucket(NAME, public_access_block=None, policy_is_public=True, acl_grants=[public_grant()])
        result = assert_pass(evaluate("S3-001", b, account()))
        assert result.evidence["EffectiveBlockPublicAccess"] == BPA_ON

    def test_block_public_policy_alone_does_not_hide_existing_public_policy(self):
        # BlockPublicPolicy only prevents *new* public policies; RestrictPublicBuckets enforces.
        b = bucket(NAME, public_access_block=bpa(block_public_policy=True, block_public_acls=True),
                   policy_is_public=True)
        assert_fail(evaluate("S3-001", b, NO_ACCOUNT_BPA))

    def test_other_accounts_bpa_is_not_applied(self):
        b = bucket(NAME, public_access_block=None, policy_is_public=True)
        assert_fail(evaluate("S3-001", b, account(EXTERNAL_ACCOUNT_ID)))


# ---------------------------------------------------------------------------
# S3-002 bucket policy public
# ---------------------------------------------------------------------------
class TestBucketPolicyPublic:
    def test_pass_policy_without_public_statements(self):
        result = assert_pass(evaluate("S3-002", bucket()))
        assert result.evidence == {"PublicStatements": []}

    @pytest.mark.parametrize("stmt", [
        statement(Principal={"Service": "cloudtrail.amazonaws.com"}, Action="s3:PutObject",
                  Resource=f"arn:aws:s3:::{NAME}/AWSLogs/*",
                  Condition={"StringEquals": {"aws:SourceAccount": ACCOUNT_ID}}),
        statement(Principal="*", Action="s3:GetObject", Resource=f"arn:aws:s3:::{NAME}/*",
                  Condition={"StringEquals": {"aws:SourceVpce": "vpce-0123456789abcdef0"}}),
        statement(Principal="*", Action="s3:GetObject", Resource=f"arn:aws:s3:::{NAME}/*",
                  Condition={"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}),
        statement(Principal={"AWS": f"arn:aws:iam::{EXTERNAL_ACCOUNT_ID}:root"}, Action="s3:GetObject",
                  Resource=f"arn:aws:s3:::{NAME}/*"),
    ])
    def test_pass_restricted_statements(self, stmt):
        assert_pass(evaluate("S3-002", bucket(NAME, policy=policy_doc(stmt))))

    @pytest.mark.parametrize("principal", ["*", {"AWS": "*"}])
    def test_fail_public_statement(self, principal):
        stmt = {**PUBLIC_READ, "Principal": principal}
        result = assert_fail(evaluate("S3-002", bucket(NAME, policy=policy_doc(stmt, deny_insecure_transport(NAME)))))
        [public] = result.evidence["PublicStatements"]
        assert public["Sid"] == "PublicRead"
        assert public["Principal"] == principal

    def test_not_applicable_without_policy(self):
        assert evaluate("S3-002", bucket(policy=None)) is None


# ---------------------------------------------------------------------------
# S3-003 public ACL
# ---------------------------------------------------------------------------
class TestBucketPublicAcl:
    def test_pass_owner_only_acl(self):
        result = assert_pass(evaluate("S3-003", bucket()))
        assert result.evidence == {"PublicGrants": [], "ObjectOwnership": "BucketOwnerEnforced"}

    @pytest.mark.parametrize("grant", [public_grant(), public_grant(AUTH_USERS_URI, "WRITE")])
    def test_fail_public_grant(self, grant):
        result = assert_fail(evaluate("S3-003", bucket(acl_grants=[owner_grant(), grant],
                                                       object_ownership="ObjectWriter")))
        assert result.evidence["PublicGrants"] == [grant]
        assert result.evidence["ObjectOwnership"] == "ObjectWriter"

    def test_pass_when_acls_unavailable(self):
        assert_pass(evaluate("S3-003", bucket(acl_grants=None)))


# ---------------------------------------------------------------------------
# S3-004 .. S3-006 simple configuration flags
# ---------------------------------------------------------------------------
class TestBucketEncryption:
    @pytest.mark.parametrize("enc", [{"algorithm": "AES256", "kms_key_id": None},
                                     {"algorithm": "aws:kms", "kms_key_id": "arn:aws:kms:us-east-1:1:key/x"}])
    def test_pass_default_encryption(self, enc):
        result = assert_pass(evaluate("S3-004", bucket(encryption=enc)))
        assert result.evidence["ServerSideEncryptionConfiguration"] == enc

    def test_fail_without_encryption(self):
        result = assert_fail(evaluate("S3-004", bucket(encryption=None)))
        assert result.evidence == {"ServerSideEncryptionConfiguration": "None"}


class TestBucketVersioning:
    def test_pass_enabled(self):
        assert_pass(evaluate("S3-005", bucket(versioning="Enabled")))

    @pytest.mark.parametrize("status", ["Suspended", "Disabled"])
    def test_fail_not_enabled(self, status):
        result = assert_fail(evaluate("S3-005", bucket(versioning=status)))
        assert result.evidence == {"VersioningStatus": status}

    def test_fail_when_never_configured(self):
        result = assert_fail(evaluate("S3-005", drop(bucket(), "versioning")))
        assert result.evidence == {"VersioningStatus": "Disabled"}


class TestBucketLogging:
    def test_pass_enabled(self):
        assert_pass(evaluate("S3-006", bucket(logging_enabled=True)))

    def test_fail_disabled(self):
        result = assert_fail(evaluate("S3-006", bucket(logging_enabled=False)))
        assert result.evidence == {"LoggingEnabled": False}


# ---------------------------------------------------------------------------
# S3-007 bucket Block Public Access (effective, including account level)
# ---------------------------------------------------------------------------
class TestBucketBlockPublicAccess:
    def test_pass_bucket_level_all_on(self):
        result = assert_pass(evaluate("S3-007", bucket(), NO_ACCOUNT_BPA))
        assert result.evidence["DisabledSettings"] == []

    def test_pass_inherited_from_account(self):
        result = assert_pass(evaluate("S3-007", bucket(public_access_block=None), account()))
        assert result.evidence["BucketConfiguration"] is None

    def test_partial_bucket_settings_combined_with_account(self):
        partial = bpa(block_public_acls=True, ignore_public_acls=True)
        account_partial = account(s3_public_access_block=bpa(block_public_policy=True))
        result = assert_fail(evaluate("S3-007", bucket(public_access_block=partial), account_partial))
        assert result.evidence["DisabledSettings"] == ["restrict_public_buckets"]

    def test_fail_nothing_configured(self):
        result = assert_fail(evaluate("S3-007", bucket(public_access_block=None), NO_ACCOUNT_BPA))
        assert result.evidence["DisabledSettings"] == BPA_FLAGS

    def test_fail_without_account_resource_in_inventory(self):
        assert_fail(evaluate("S3-007", bucket(public_access_block=bpa(block_public_acls=True))))


# ---------------------------------------------------------------------------
# S3-008 secure transport
# ---------------------------------------------------------------------------
class TestBucketSecureTransport:
    @pytest.mark.parametrize("condition", [
        {"Bool": {"aws:SecureTransport": "false"}},
        {"Bool": {"aws:SecureTransport": False}},
        {"Bool": {"aws:SecureTransport": ["false"]}},
        {"BoolIfExists": {"aws:SecureTransport": "false"}},
    ])
    def test_pass_with_deny_insecure_transport(self, condition):
        stmt = {**deny_insecure_transport(NAME), "Condition": condition}
        result = assert_pass(evaluate("S3-008", bucket(NAME, policy=policy_doc(stmt))))
        assert result.evidence == {"SecureTransportEnforced": True, "HasBucketPolicy": True}

    def test_fail_without_policy(self):
        result = assert_fail(evaluate("S3-008", bucket(policy=None)))
        assert result.evidence == {"SecureTransportEnforced": False, "HasBucketPolicy": False}

    @pytest.mark.parametrize("stmts", [
        [PUBLIC_READ],
        # "Allow when SecureTransport is false" is the opposite of enforcement.
        [{**deny_insecure_transport(NAME), "Effect": "Allow"}],
        [{**deny_insecure_transport(NAME), "Condition": {"Bool": {"aws:SecureTransport": "true"}}}],
    ])
    def test_fail_policy_without_enforcement(self, stmts):
        result = assert_fail(evaluate("S3-008", bucket(NAME, policy=policy_doc(*stmts))))
        assert result.evidence["HasBucketPolicy"] is True


# ---------------------------------------------------------------------------
# S3-009 account-level Block Public Access
# ---------------------------------------------------------------------------
class TestAccountBlockPublicAccess:
    def test_pass_all_enabled(self):
        result = assert_pass(evaluate("S3-009", account()))
        assert result.evidence == {"DisabledSettings": []}

    def test_fail_not_configured(self):
        result = assert_fail(evaluate("S3-009", account(s3_public_access_block=None)))
        assert result.evidence == {"DisabledSettings": BPA_FLAGS}

    def test_fail_partially_configured(self):
        cfg = bpa(block_public_acls=True, ignore_public_acls=True, block_public_policy=True)
        result = assert_fail(evaluate("S3-009", account(s3_public_access_block=cfg)))
        assert result.evidence == {"DisabledSettings": ["restrict_public_buckets"]}

    def test_not_applicable_when_not_collected(self):
        assert evaluate("S3-009", drop(account(), "s3_public_access_block")) is None
