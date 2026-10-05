"""EC2 rules EC2-001 .. EC2-008."""

from __future__ import annotations

import pytest

from _factory import (
    assert_fail,
    assert_pass,
    evaluate,
    instance,
    internet,
    perm,
    region_settings,
    security_group,
    volume,
)

SG_ID = "sg-0123456789abcdef0"
WEB = [perm("tcp", 80, cidrs=["0.0.0.0/0"], ipv6_cidrs=["::/0"]),
       perm("tcp", 443, cidrs=["0.0.0.0/0"], ipv6_cidrs=["::/0"])]
PUBLIC_IP = "54.12.34.56"


# ---------------------------------------------------------------------------
# EC2-001 public instance reachable on non-web ports
# ---------------------------------------------------------------------------
class TestPublicInstanceWithOpenIngress:
    def test_pass_private_instance(self):
        sg = security_group(ingress=[internet("tcp", 22)])
        result = assert_pass(evaluate("EC2-001", instance(public_ip=None), sg))
        assert result.evidence == {"PublicIp": None}

    def test_pass_public_web_tier(self):
        result = assert_pass(evaluate("EC2-001", instance(public_ip=PUBLIC_IP), security_group(ingress=WEB)))
        assert result.evidence["NonWebExposure"] == []
        assert {e["ports"] for e in result.evidence["InternetIngress"]} == {"80", "443"}

    def test_pass_public_instance_with_internal_only_ingress(self):
        sg = security_group(ingress=[perm("tcp", 22, cidrs=["203.0.113.0/24"])])
        result = assert_pass(evaluate("EC2-001", instance(public_ip=PUBLIC_IP), sg))
        assert result.evidence["InternetIngress"] == []

    @pytest.mark.parametrize("ingress, ports", [
        ([internet("tcp", 22)], "22"),
        ([internet("-1")], "all"),
        ([internet("tcp", 8000, 9999)], "8000-9999"),
        ([perm("tcp", 3389, ipv6_cidrs=["::/0"])], "3389"),
    ])
    def test_fail_public_instance_with_non_web_exposure(self, ingress, ports):
        sg = security_group(ingress=WEB + ingress)
        result = assert_fail(evaluate("EC2-001", instance(public_ip=PUBLIC_IP), sg))
        assert result.evidence["PublicIp"] == PUBLIC_IP
        [exposure] = result.evidence["NonWebExposure"]
        assert exposure["SecurityGroup"] == SG_ID
        assert exposure["ports"] == ports
        assert len(result.evidence["InternetIngress"]) == 3

    def test_considers_every_attached_group(self):
        web = security_group("sg-0000000000000web", ingress=WEB)
        ssh = security_group("sg-0000000000000ssh", ingress=[internet("tcp", 22)])
        inst = instance(public_ip=PUBLIC_IP, security_group_ids=[web.prop("group_id"), ssh.prop("group_id")])
        result = assert_fail(evaluate("EC2-001", inst, web, ssh))
        assert [e["SecurityGroup"] for e in result.evidence["NonWebExposure"]] == ["sg-0000000000000ssh"]

    def test_ignores_same_group_id_in_another_region(self):
        other_region_sg = security_group(region="eu-west-1", ingress=[internet("tcp", 22)])
        assert_pass(evaluate("EC2-001", instance(public_ip=PUBLIC_IP), other_region_sg))

    def test_ignores_unattached_groups(self):
        unrelated = security_group("sg-0ffffffffffffffff", ingress=[internet("tcp", 22)])
        assert_pass(evaluate("EC2-001", instance(public_ip=PUBLIC_IP), security_group(ingress=WEB), unrelated))

    @pytest.mark.parametrize("state", ["stopped", "terminated", "pending"])
    def test_not_applicable_unless_running(self, state):
        sg = security_group(ingress=[internet("tcp", 22)])
        assert evaluate("EC2-001", instance(state=state, public_ip=PUBLIC_IP), sg) is None


# ---------------------------------------------------------------------------
# EC2-002 SSH / EC2-003 RDP open to the internet
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("rule_id, port", [("EC2-002", 22), ("EC2-003", 3389)])
class TestAdminPortOpenToInternet:
    def test_fail_exact_port_ipv4(self, rule_id, port):
        sg = security_group(ingress=[internet("tcp", port)], attached_eni_count=4)
        result = assert_fail(evaluate(rule_id, sg))
        assert result.evidence == {
            "OffendingRules": [{"protocol": "tcp", "ports": str(port), "sources": ["0.0.0.0/0"]}],
            "Port": port, "AttachedInterfaces": 4,
        }

    def test_fail_ipv6_any(self, rule_id, port):
        result = assert_fail(evaluate(rule_id, security_group(ingress=[perm("tcp", port, ipv6_cidrs=["::/0"])])))
        assert result.evidence["OffendingRules"][0]["sources"] == ["::/0"]

    @pytest.mark.parametrize("ingress", [
        internet("tcp", 0, 65535),
        internet("tcp", 1, 5000),
        internet("6", 20, 4000),  # numeric protocol
        internet("-1"),
    ])
    def test_fail_ranges_covering_port(self, rule_id, port, ingress):
        assert_fail(evaluate(rule_id, security_group(ingress=[ingress])))

    @pytest.mark.parametrize("ingress", [
        perm("tcp", 22, cidrs=["203.0.113.0/24"]),
        perm("tcp", 3389, cidrs=["10.0.0.0/8"]),
        perm("-1", source_groups=["sg-0123456789abcdef0"]),
        internet("tcp", 443),
        internet("tcp", 23, 3388),  # just misses both ports
        internet("icmp", -1, -1),
    ])
    def test_pass_when_port_not_reachable_from_internet(self, rule_id, port, ingress):
        result = assert_pass(evaluate(rule_id, security_group(ingress=[ingress])))
        assert result.evidence["OffendingRules"] == []

    def test_pass_no_ingress(self, rule_id, port):
        assert_pass(evaluate(rule_id, security_group(ingress=[])))


# ---------------------------------------------------------------------------
# EC2-004 all traffic open to the internet
# ---------------------------------------------------------------------------
class TestAllTrafficOpenToInternet:
    @pytest.mark.parametrize("ingress", [
        internet("-1"),
        perm("-1", ipv6_cidrs=["::/0"]),
        internet("tcp", 0, 65535),
    ])
    def test_fail(self, ingress):
        result = assert_fail(evaluate("EC2-004", security_group(ingress=[ingress], attached_eni_count=2)))
        assert len(result.evidence["OffendingRules"]) == 1
        assert result.evidence["AttachedInterfaces"] == 2

    def test_fail_evidence_shape_for_all_protocols(self):
        result = assert_fail(evaluate("EC2-004", security_group(ingress=[internet("-1")])))
        assert result.evidence["OffendingRules"] == [{"protocol": "all", "ports": "all", "sources": ["0.0.0.0/0"]}]

    @pytest.mark.parametrize("ingress", [
        WEB,
        [perm("-1", source_groups=[SG_ID])],  # default-SG style self reference
        [perm("-1", cidrs=["10.0.0.0/8"])],
        [internet("tcp", 8000, 9999)],
    ])
    def test_pass(self, ingress):
        assert_pass(evaluate("EC2-004", security_group(ingress=ingress)))

    # Regression test for a fixed bug in checks/network.py.
    def test_icmp_all_types_is_not_all_traffic(self):
        assert_pass(evaluate("EC2-004", security_group(ingress=[internet("icmp", -1, -1)])))


# ---------------------------------------------------------------------------
# EC2-005 IMDSv1
# ---------------------------------------------------------------------------
class TestImdsV1:
    def test_pass_tokens_required(self):
        result = assert_pass(evaluate("EC2-005", instance(imds_http_tokens="required")))
        assert result.evidence == {"HttpTokens": "required", "HttpEndpoint": "enabled"}

    def test_pass_endpoint_disabled(self):
        result = assert_pass(evaluate("EC2-005", instance(imds_http_endpoint="disabled", imds_http_tokens="optional")))
        assert result.evidence == {"HttpEndpoint": "disabled"}

    @pytest.mark.parametrize("state", ["running", "stopped"])
    def test_fail_tokens_optional(self, state):
        result = assert_fail(evaluate("EC2-005", instance(state=state, imds_http_tokens="optional")))
        assert result.evidence["HttpTokens"] == "optional"

    def test_not_applicable_terminated(self):
        assert evaluate("EC2-005", instance(state="terminated", imds_http_tokens="optional")) is None


# ---------------------------------------------------------------------------
# EC2-006 / EC2-007 EBS encryption
# ---------------------------------------------------------------------------
class TestUnencryptedEbsVolume:
    def test_pass_encrypted(self):
        assert_pass(evaluate("EC2-006", volume(encrypted=True)))

    def test_fail_unencrypted(self):
        result = assert_fail(evaluate("EC2-006", volume(encrypted=False, size_gb=500)))
        assert result.evidence == {"Encrypted": False, "SizeGiB": 500, "AttachedTo": ["i-0123456789abcdef0"]}

    def test_fail_unattached_volume(self):
        result = assert_fail(evaluate("EC2-006", volume(encrypted=False, state="available", attached_instance_ids=[])))
        assert result.evidence["AttachedTo"] == []


class TestEbsEncryptionByDefault:
    def test_pass_enabled(self):
        assert_pass(evaluate("EC2-007", region_settings(ebs_encryption_by_default=True)))

    def test_fail_disabled(self):
        result = assert_fail(evaluate("EC2-007", region_settings(ebs_encryption_by_default=False)))
        assert result.evidence == {"EbsEncryptionByDefault": False}


# ---------------------------------------------------------------------------
# EC2-008 database ports open to the internet
# ---------------------------------------------------------------------------
class TestDatabasePortsOpen:
    @pytest.mark.parametrize("ingress, expected", [
        ([internet("tcp", 5432)], [{"port": 5432, "service": "PostgreSQL"}]),
        ([perm("tcp", 6379, ipv6_cidrs=["::/0"])], [{"port": 6379, "service": "Redis"}]),
        ([internet("tcp", 3306), internet("tcp", 27017)],
         [{"port": 3306, "service": "MySQL"}, {"port": 27017, "service": "MongoDB"}]),
        ([internet("tcp", 8000, 9999)], [{"port": 9200, "service": "Elasticsearch"}]),
    ])
    def test_fail(self, ingress, expected):
        result = assert_fail(evaluate("EC2-008", security_group(ingress=ingress)))
        assert result.evidence["ExposedDatabasePorts"] == expected

    @pytest.mark.parametrize("ingress", [
        [perm("tcp", 5432, cidrs=["10.0.0.0/8"])],
        WEB,
        [internet("tcp", 22)],
    ])
    def test_pass(self, ingress):
        result = assert_pass(evaluate("EC2-008", security_group(ingress=ingress)))
        assert result.evidence["ExposedDatabasePorts"] == []

    def test_not_applicable_when_all_traffic_open(self):
        # EC2-004 reports the broader exposure.
        assert evaluate("EC2-008", security_group(ingress=[internet("-1")])) is None
