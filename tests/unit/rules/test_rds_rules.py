"""RDS rules RDS-001 .. RDS-006."""

from __future__ import annotations

import pytest

from _factory import assert_fail, assert_pass, evaluate, internet, perm, rds_instance, security_group


class TestRdsPubliclyAccessible:
    def test_pass_private(self):
        db = rds_instance()
        result = assert_pass(evaluate("RDS-001", db))
        assert result.evidence == {"PubliclyAccessible": False, "Endpoint": db.prop("endpoint")}

    def test_fail_public(self):
        result = assert_fail(evaluate("RDS-001", rds_instance(publicly_accessible=True)))
        assert result.evidence["PubliclyAccessible"] is True


class TestRdsStorageEncryption:
    def test_pass_encrypted(self):
        assert_pass(evaluate("RDS-002", rds_instance(storage_encrypted=True)))

    def test_fail_unencrypted(self):
        result = assert_fail(evaluate("RDS-002", rds_instance(storage_encrypted=False, kms_key_id=None)))
        assert result.evidence == {"StorageEncrypted": False}


class TestRdsBackups:
    @pytest.mark.parametrize("days", [1, 7, 35])
    def test_pass_retention_configured(self, days):
        result = assert_pass(evaluate("RDS-003", rds_instance(backup_retention_period=days)))
        assert result.evidence == {"BackupRetentionPeriod": days}

    @pytest.mark.parametrize("value", [0, None])
    def test_fail_backups_disabled(self, value):
        result = assert_fail(evaluate("RDS-003", rds_instance(backup_retention_period=value)))
        assert result.evidence == {"BackupRetentionPeriod": 0}


class TestRdsSecurityGroupOpen:
    def test_fail_public_db_with_internet_ingress(self):
        sg = security_group(ingress=[perm("tcp", 5432, cidrs=["10.0.0.0/8"]), internet("tcp", 5432)])
        result = assert_fail(evaluate("RDS-004", rds_instance(publicly_accessible=True), sg))
        assert result.evidence["PubliclyAccessible"] is True
        assert result.evidence["InternetIngress"] == [
            {"SecurityGroup": "sg-0123456789abcdef0", "protocol": "tcp", "ports": "5432", "sources": ["0.0.0.0/0"]}]

    def test_pass_public_db_with_restricted_ingress(self):
        sg = security_group(ingress=[perm("tcp", 5432, cidrs=["10.0.0.0/8"])])
        result = assert_pass(evaluate("RDS-004", rds_instance(publicly_accessible=True), sg))
        assert result.evidence["InternetIngress"] == []

    def test_pass_when_open_group_is_in_another_region(self):
        sg = security_group(region="eu-west-1", ingress=[internet("tcp", 5432)])
        assert_pass(evaluate("RDS-004", rds_instance(publicly_accessible=True), sg))

    def test_not_applicable_for_private_db(self):
        sg = security_group(ingress=[internet("tcp", 5432)])
        assert evaluate("RDS-004", rds_instance(publicly_accessible=False), sg) is None


class TestRdsLogExports:
    @pytest.mark.parametrize("exports", [["postgresql"], ["error", "audit"]])
    def test_pass_exports_enabled(self, exports):
        assert_pass(evaluate("RDS-005", rds_instance(log_exports=exports)))

    @pytest.mark.parametrize("exports", [[], None])
    def test_fail_no_exports(self, exports):
        result = assert_fail(evaluate("RDS-005", rds_instance(log_exports=exports)))
        assert result.evidence == {"EnabledCloudwatchLogsExports": []}


class TestRdsDeletionProtection:
    def test_pass_enabled(self):
        assert_pass(evaluate("RDS-006", rds_instance(deletion_protection=True)))

    def test_fail_disabled(self):
        result = assert_fail(evaluate("RDS-006", rds_instance(deletion_protection=False)))
        assert result.evidence == {"DeletionProtection": False}
