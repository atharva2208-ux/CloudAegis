"""CloudTrail rules CT-001 .. CT-007."""

from __future__ import annotations

import pytest

from _factory import (
    EXTERNAL_ACCOUNT_ID,
    account,
    assert_fail,
    assert_pass,
    bucket,
    evaluate,
    owner_grant,
    policy_doc,
    public_grant,
    statement,
    trail,
)

TRAIL_BUCKET = "shared-cloudtrail-logs"


# ---------------------------------------------------------------------------
# CT-001 / CT-002 account-level trail coverage
# ---------------------------------------------------------------------------
class TestCloudTrailDisabled:
    def test_pass_with_a_logging_trail(self):
        trails = [trail("organization-trail"), trail("legacy-audit-trail", is_logging=False)]
        result = assert_pass(evaluate("CT-001", account(), *trails))
        assert result.evidence == {"Trails": ["organization-trail", "legacy-audit-trail"],
                                   "LoggingTrails": ["organization-trail"]}

    def test_fail_without_trails(self):
        result = assert_fail(evaluate("CT-001", account()))
        assert result.evidence == {"Trails": [], "LoggingTrails": []}

    def test_fail_when_no_trail_is_logging(self):
        result = assert_fail(evaluate("CT-001", account(), trail(is_logging=False)))
        assert result.evidence["Trails"] == ["organization-trail"]

    def test_trails_of_other_accounts_are_ignored(self):
        foreign = trail("foreign-trail", account_id=EXTERNAL_ACCOUNT_ID)
        assert_fail(evaluate("CT-001", account(), foreign))


class TestNoMultiRegionTrail:
    def test_pass_with_logging_multi_region_trail(self):
        result = assert_pass(evaluate("CT-002", account(), trail(), trail("regional", is_multi_region=False)))
        assert result.evidence["MultiRegionTrails"] == ["organization-trail"]

    def test_fail_only_single_region_trails(self):
        result = assert_fail(evaluate("CT-002", account(), trail("ap-south-1-dev-trail", is_multi_region=False)))
        assert result.evidence == {"LoggingTrails": ["ap-south-1-dev-trail"], "MultiRegionTrails": []}

    def test_fail_when_multi_region_trail_is_stopped(self):
        trails = [trail("org", is_logging=False), trail("regional", is_multi_region=False)]
        result = assert_fail(evaluate("CT-002", account(), *trails))
        assert result.evidence["LoggingTrails"] == ["regional"]

    @pytest.mark.parametrize("trails", [[], [trail(is_logging=False)]])
    def test_not_applicable_without_logging_trails(self, trails):
        # CT-001 reports the stronger condition.
        assert evaluate("CT-002", account(), *trails) is None


# ---------------------------------------------------------------------------
# CT-003 .. CT-007 per-trail settings
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("rule_id, prop, good, bad, evidence_key", [
    ("CT-003", "log_file_validation", True, False, "LogFileValidationEnabled"),
    ("CT-004", "kms_key_id", "arn:aws:kms:us-east-1:123456789012:key/abc", None, "KmsKeyId"),
    ("CT-006", "cloudwatch_log_group_arn", "arn:aws:logs:us-east-1:123456789012:log-group:cloudtrail:*", None,
     "CloudWatchLogsLogGroupArn"),
    ("CT-007", "is_logging", True, False, "IsLogging"),
])
class TestTrailSettings:
    def test_pass(self, rule_id, prop, good, bad, evidence_key):
        result = assert_pass(evaluate(rule_id, trail(**{prop: good})))
        assert result.evidence == {evidence_key: good}

    def test_fail(self, rule_id, prop, good, bad, evidence_key):
        result = assert_fail(evaluate(rule_id, trail(**{prop: bad})))
        assert result.evidence == {evidence_key: bad}


# ---------------------------------------------------------------------------
# CT-005 trail bucket public (cross-resource)
# ---------------------------------------------------------------------------
class TestTrailBucketPublic:
    def test_pass_private_bucket(self):
        result = assert_pass(evaluate("CT-005", trail(), bucket(TRAIL_BUCKET), account()))
        assert result.evidence == {"S3BucketName": TRAIL_BUCKET, "BucketPublicReasons": []}

    def test_fail_public_bucket_policy(self):
        public = statement(Principal="*", Action="s3:GetObject", Resource=f"arn:aws:s3:::{TRAIL_BUCKET}/*")
        b = bucket(TRAIL_BUCKET, public_access_block=None, policy=policy_doc(public), policy_is_public=True)
        result = assert_fail(evaluate("CT-005", trail(), b, account(s3_public_access_block=None)))
        assert result.evidence["BucketPublicReasons"] == ["Bucket policy grants public access"]

    def test_fail_public_bucket_acl(self):
        b = bucket(TRAIL_BUCKET, public_access_block=None, acl_grants=[owner_grant(), public_grant()])
        assert_fail(evaluate("CT-005", trail(), b, account(s3_public_access_block=None)))

    def test_pass_when_account_bpa_blocks_public_policy(self):
        b = bucket(TRAIL_BUCKET, public_access_block=None, policy_is_public=True)
        assert_pass(evaluate("CT-005", trail(), b, account()))

    def test_not_applicable_when_bucket_not_in_inventory(self):
        # e.g. a central logging bucket in another account
        assert evaluate("CT-005", trail(), bucket("some-other-bucket")) is None

    def test_not_applicable_without_bucket_name(self):
        assert evaluate("CT-005", trail(s3_bucket_name=None), bucket(TRAIL_BUCKET)) is None
