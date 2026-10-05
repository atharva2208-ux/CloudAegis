"""VPC rules VPC-001 .. VPC-006."""

from __future__ import annotations

import pytest

from _factory import (
    ALL_TRAFFIC_OUT,
    HTTPS_OUT,
    assert_fail,
    assert_pass,
    default_nacl_entries,
    evaluate,
    internet,
    nacl,
    nacl_entry,
    perm,
    security_group,
    subnet,
    vpc,
)

SG_ID = "sg-0123456789abcdef0"


class TestFlowLogs:
    def test_pass_enabled(self):
        assert_pass(evaluate("VPC-001", vpc(flow_logs_enabled=True)))

    @pytest.mark.parametrize("is_default", [True, False])
    def test_fail_disabled(self, is_default):
        result = assert_fail(evaluate("VPC-001", vpc(flow_logs_enabled=False, is_default=is_default)))
        assert result.evidence == {"FlowLogsEnabled": False, "IsDefault": is_default}


# ---------------------------------------------------------------------------
# VPC-002 default security group must have no rules
# ---------------------------------------------------------------------------
class TestDefaultSecurityGroup:
    def _default_sg(self, **props):
        return security_group(group_name="default", is_default=True, attached_eni_count=0, **props)

    def test_pass_no_rules(self):
        result = assert_pass(evaluate("VPC-002", self._default_sg(ingress=[], egress=[])))
        assert result.evidence == {"InboundRules": 0, "OutboundRules": 0}

    def test_fail_aws_default_rules(self):
        # AWS creates the default SG with self-referencing ingress and all-traffic egress.
        sg = self._default_sg(ingress=[perm("-1", source_groups=[SG_ID])], egress=[ALL_TRAFFIC_OUT])
        result = assert_fail(evaluate("VPC-002", sg))
        assert result.evidence == {"InboundRules": 1, "OutboundRules": 1}

    def test_fail_egress_only(self):
        result = assert_fail(evaluate("VPC-002", self._default_sg(ingress=[], egress=[HTTPS_OUT])))
        assert result.evidence == {"InboundRules": 0, "OutboundRules": 1}

    def test_not_applicable_for_custom_groups(self):
        assert evaluate("VPC-002", security_group(is_default=False, ingress=[internet("-1")])) is None


# ---------------------------------------------------------------------------
# VPC-003 unrestricted egress on in-use custom groups
# ---------------------------------------------------------------------------
class TestUnrestrictedEgress:
    def test_pass_restricted_egress(self):
        result = assert_pass(evaluate("VPC-003", security_group(egress=[HTTPS_OUT])))
        assert result.evidence == {"OpenEgressRules": []}

    @pytest.mark.parametrize("egress", [[ALL_TRAFFIC_OUT], [perm("-1", ipv6_cidrs=["::/0"])]])
    def test_fail_all_traffic_egress(self, egress):
        result = assert_fail(evaluate("VPC-003", security_group(egress=egress, attached_eni_count=3)))
        assert len(result.evidence["OpenEgressRules"]) == 1

    def test_not_applicable_for_default_group(self):
        assert evaluate("VPC-003", security_group(is_default=True, egress=[ALL_TRAFFIC_OUT])) is None

    @pytest.mark.parametrize("count", [0, None])
    def test_not_applicable_when_unattached(self, count):
        assert evaluate("VPC-003", security_group(attached_eni_count=count, egress=[ALL_TRAFFIC_OUT])) is None


# ---------------------------------------------------------------------------
# VPC-004 public subnet auto-assigns public IPs
# ---------------------------------------------------------------------------
class TestPublicSubnetAutoAssignIp:
    @pytest.mark.parametrize("auto, igw", [(False, True), (True, False), (False, False)])
    def test_pass(self, auto, igw):
        result = assert_pass(evaluate("VPC-004", subnet(map_public_ip_on_launch=auto, has_internet_route=igw)))
        assert result.evidence == {"MapPublicIpOnLaunch": auto, "RouteToInternetGateway": igw}

    def test_fail(self):
        assert_fail(evaluate("VPC-004", subnet(map_public_ip_on_launch=True, has_internet_route=True)))


# ---------------------------------------------------------------------------
# VPC-005 NACL allows SSH/RDP from anywhere
# ---------------------------------------------------------------------------
class TestNaclAllowsAdminPorts:
    def test_pass_admin_ports_denied_before_default_allow(self):
        result = assert_pass(evaluate("VPC-005", nacl()))
        assert result.evidence == {"OffendingEntries": []}

    def test_fail_default_allow_all(self):
        result = assert_fail(evaluate("VPC-005", nacl(entries=default_nacl_entries())))
        offending = result.evidence["OffendingEntries"]
        assert sorted(e["port"] for e in offending) == [22, 3389]
        assert all(e["rule_number"] == 100 and e["cidr"] == "0.0.0.0/0" for e in offending)

    def test_fail_only_one_port_denied(self):
        entries = [nacl_entry(10, "deny", protocol="6", from_port=22)] + default_nacl_entries()
        result = assert_fail(evaluate("VPC-005", nacl(entries=entries)))
        assert [e["port"] for e in result.evidence["OffendingEntries"]] == [3389]

    def test_fail_explicit_tcp_allow(self):
        entries = [nacl_entry(50, "allow", protocol="6", from_port=3389), nacl_entry(32767, "deny")]
        result = assert_fail(evaluate("VPC-005", nacl(entries=entries)))
        assert result.evidence["OffendingEntries"] == [
            {"port": 3389, "rule_number": 50, "protocol": "6", "from_port": 3389, "to_port": 3389,
             "cidr": "0.0.0.0/0"}]

    def test_deny_with_higher_rule_number_does_not_shadow(self):
        entries = [nacl_entry(100, "allow"), nacl_entry(200, "deny", protocol="6", from_port=22),
                   nacl_entry(32767, "deny")]
        result = assert_fail(evaluate("VPC-005", nacl(entries=entries)))
        assert 22 in [e["port"] for e in result.evidence["OffendingEntries"]]

    def test_rule_number_order_not_list_order(self):
        entries = [nacl_entry(100, "allow"), nacl_entry(32767, "deny"),
                   nacl_entry(20, "deny", protocol="6", from_port=3389), nacl_entry(10, "deny", protocol="6", from_port=22)]
        assert_pass(evaluate("VPC-005", nacl(entries=entries)))

    def test_deny_range_shadows_contained_port_only(self):
        entries = [nacl_entry(10, "deny", protocol="6", from_port=0, to_port=1023)] + default_nacl_entries()
        result = assert_fail(evaluate("VPC-005", nacl(entries=entries)))
        assert [e["port"] for e in result.evidence["OffendingEntries"]] == [3389]

    def test_deny_for_narrow_cidr_does_not_shadow_internet_allow(self):
        entries = [nacl_entry(10, "deny", cidr="198.51.100.0/24")] + default_nacl_entries()
        assert_fail(evaluate("VPC-005", nacl(entries=entries)))

    @pytest.mark.parametrize("entries", [
        [nacl_entry(100, "allow", cidr="10.0.0.0/8"), nacl_entry(32767, "deny")],
        [nacl_entry(100, "allow", protocol="6", from_port=443), nacl_entry(32767, "deny")],
        [nacl_entry(100, "allow", protocol="17", from_port=0, to_port=65535), nacl_entry(32767, "deny")],
        [nacl_entry(100, "allow", egress=True), nacl_entry(32767, "deny")],
    ])
    def test_pass_when_admin_ports_unreachable(self, entries):
        assert_pass(evaluate("VPC-005", nacl(entries=entries)))

    def test_fail_ipv6_allow(self):
        entries = [nacl_entry(100, "allow", cidr="::/0"), nacl_entry(32768, "deny", cidr="::/0")]
        assert_fail(evaluate("VPC-005", nacl(entries=entries)))

    # Regression test for a fixed bug in checks/network.py.
    def test_ipv6_deny_does_not_shadow_ipv4_allow(self):
        entries = [nacl_entry(10, "deny", cidr="::/0", protocol="6", from_port=22),
                   nacl_entry(20, "deny", cidr="::/0", protocol="6", from_port=3389)] + default_nacl_entries()
        assert_fail(evaluate("VPC-005", nacl(entries=entries)))

    @pytest.mark.parametrize("subnets", [[], None])
    def test_not_applicable_when_not_associated(self, subnets):
        assert evaluate("VPC-005", nacl(entries=default_nacl_entries(), subnet_ids=subnets)) is None


# ---------------------------------------------------------------------------
# VPC-006 wide port ranges open to the internet (>= 100 ports, not all traffic)
# ---------------------------------------------------------------------------
class TestWidePortRange:
    @pytest.mark.parametrize("ingress, ports", [
        (internet("tcp", 8000, 9999), "8000-9999"),
        (internet("tcp", 1000, 1099), "1000-1099"),  # exactly 100 ports
        (perm("udp", 30000, 40000, ipv6_cidrs=["::/0"]), "30000-40000"),
    ])
    def test_fail(self, ingress, ports):
        result = assert_fail(evaluate("VPC-006", security_group(ingress=[ingress])))
        assert [r["ports"] for r in result.evidence["OffendingRules"]] == [ports]

    @pytest.mark.parametrize("ingress", [
        internet("tcp", 1000, 1098),  # 99 ports
        internet("tcp", 443),
        perm("tcp", 0, 65535, cidrs=["10.0.0.0/8"]),
        internet("-1"),  # all traffic is EC2-004's finding
    ])
    def test_pass(self, ingress):
        assert_pass(evaluate("VPC-006", security_group(ingress=[ingress])))
