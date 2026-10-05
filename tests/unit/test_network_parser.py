"""checks/network.py — security group and network ACL exposure analysis."""

from __future__ import annotations

import pytest

from cloudaegis_engine.checks import network
from cloudaegis_engine.checks.network import PermissionRule


def sg(protocol="tcp", from_port=None, to_port=None, cidrs=(), ipv6_cidrs=()):
    """A permission as emitted by collectors/ec2.normalize_permissions."""
    if to_port is None and from_port is not None:
        to_port = from_port
    return {"protocol": protocol, "from_port": from_port, "to_port": to_port, "cidrs": list(cidrs),
            "ipv6_cidrs": list(ipv6_cidrs), "source_groups": []}


def acl(rule_number, action, cidr="0.0.0.0/0", protocol="-1", from_port=None, to_port=None, egress=False):
    """A NACL entry as emitted by collectors/vpc.py."""
    if to_port is None and from_port is not None:
        to_port = from_port
    return {"rule_number": rule_number, "egress": egress, "protocol": protocol, "action": action, "cidr": cidr,
            "from_port": from_port, "to_port": to_port}


ANY4 = ["0.0.0.0/0"]
ANY6 = ["::/0"]


# ---------------------------------------------------------------------------
# PermissionRule
# ---------------------------------------------------------------------------
class TestPermissionRuleParsing:
    def test_from_dict_merges_ipv4_and_ipv6(self):
        rule = PermissionRule.from_dict(sg("tcp", 22, cidrs=["10.0.0.0/8"], ipv6_cidrs=ANY6))
        assert rule == PermissionRule("tcp", 22, 22, ("10.0.0.0/8", "::/0"))

    def test_from_dict_defaults(self):
        rule = PermissionRule.from_dict({})
        assert rule.protocol == "-1" and rule.cidrs == () and rule.from_port is None

    def test_numeric_protocol_is_stringified(self):
        assert PermissionRule.from_dict({"protocol": 6, "from_port": 22, "to_port": 22}).protocol == "6"

    @pytest.mark.parametrize("raw", [None, []])
    def test_parse_rules_empty(self, raw):
        assert network.parse_rules(raw) == []


class TestOpenToInternet:
    @pytest.mark.parametrize("cidrs, v6, expected", [
        (ANY4, (), True),
        ((), ANY6, True),
        (["10.0.0.0/8", "0.0.0.0/0"], (), True),
        (["10.0.0.0/8"], ["2001:db8::/32"], False),
        (["0.0.0.0/1"], (), False),  # only the exact "anywhere" CIDRs count
        ((), (), False),
    ])
    def test_open_to_internet(self, cidrs, v6, expected):
        assert PermissionRule.from_dict(sg("tcp", 22, cidrs=cidrs, ipv6_cidrs=v6)).open_to_internet is expected


class TestAllTraffic:
    @pytest.mark.parametrize("raw", [
        sg("-1"),
        sg("-1", 0, 0),
        sg("tcp", 0, 65535),
        sg("udp", 0, 65535),
        sg("tcp", None, None),
    ])
    def test_all_traffic(self, raw):
        assert PermissionRule.from_dict(raw).all_traffic

    @pytest.mark.parametrize("raw", [sg("tcp", 22), sg("tcp", 0, 1023), sg("tcp", 1, 65535), sg("icmp", 8, -1)])
    def test_not_all_traffic(self, raw):
        assert not PermissionRule.from_dict(raw).all_traffic

    # Regression test for a fixed bug in checks/network.py.
    @pytest.mark.parametrize("protocol", ["icmp", "icmpv6"])
    def test_all_icmp_types_is_not_all_traffic(self, protocol):
        assert not PermissionRule.from_dict(sg(protocol, -1, -1, cidrs=ANY4)).all_traffic


class TestCoversPort:
    @pytest.mark.parametrize("raw, port, expected", [
        (sg("-1"), 22, True),
        (sg("tcp", 22), 22, True),
        (sg("tcp", 22), 23, False),
        (sg("tcp", 20, 25), 20, True),  # inclusive lower bound
        (sg("tcp", 20, 25), 25, True),  # inclusive upper bound
        (sg("tcp", 20, 25), 26, False),
        (sg("6", 3389), 3389, True),
        (sg("udp", 3389), 3389, True),
        (sg("17", 0, 65535), 22, True),
        (sg("tcp", None, None), 3389, True),
        (sg("icmp", -1, -1), 22, False),
        (sg("icmpv6", -1, -1), 22, False),
        (sg("58", -1, -1), 22, False),
        (sg("50"), 22, False),  # ESP has no ports
    ])
    def test_covers_port(self, raw, port, expected):
        assert PermissionRule.from_dict(raw).covers_port(port) is expected


class TestPortSpanAndDescribe:
    @pytest.mark.parametrize("raw, span", [
        (sg("tcp", 22), 1),
        (sg("tcp", 8000, 9999), 2000),
        (sg("tcp", 0, 65535), 65536),
        (sg("-1"), 65536),
        (sg("tcp", 1024, None), 1),  # helper mirrors from_port when to_port missing
    ])
    def test_port_span(self, raw, span):
        assert PermissionRule.from_dict(raw).port_span == span

    @pytest.mark.parametrize("raw, expected", [
        (sg("-1", cidrs=ANY4), {"protocol": "all", "ports": "all", "sources": ["0.0.0.0/0"]}),
        (sg("tcp", 22, cidrs=["10.0.0.0/8", "0.0.0.0/0"]), {"protocol": "tcp", "ports": "22", "sources": ["0.0.0.0/0"]}),
        (sg("tcp", 8000, 9999, ipv6_cidrs=ANY6), {"protocol": "tcp", "ports": "8000-9999", "sources": ["::/0"]}),
        (sg("udp", 53, cidrs=["10.0.0.0/8"]), {"protocol": "udp", "ports": "53", "sources": ["10.0.0.0/8"]}),
    ])
    def test_describe(self, raw, expected):
        assert PermissionRule.from_dict(raw).describe() == expected


# ---------------------------------------------------------------------------
# Rule-list helpers
# ---------------------------------------------------------------------------
INGRESS = [
    sg("tcp", 80, cidrs=ANY4, ipv6_cidrs=ANY6),
    sg("tcp", 22, cidrs=["203.0.113.0/24"]),
    sg("tcp", 3389, ipv6_cidrs=ANY6),
    sg("tcp", 8000, 9999, cidrs=ANY4),
    sg("-1", cidrs=["10.0.0.0/8"]),
]


class TestRuleListHelpers:
    def test_internet_rules_for_admin_ports(self):
        assert network.internet_rules_for_port(INGRESS, 22) == []
        [rdp] = network.internet_rules_for_port(INGRESS, 3389)
        assert rdp.cidrs == ("::/0",)

    def test_internet_rules_for_port_in_range(self):
        [rule] = network.internet_rules_for_port(INGRESS, 9200)
        assert (rule.from_port, rule.to_port) == (8000, 9999)

    def test_internet_rules_for_port_handles_none(self):
        assert network.internet_rules_for_port(None, 22) == []

    def test_internet_all_traffic_rules(self):
        assert network.internet_all_traffic_rules(INGRESS) == []
        rules = network.internet_all_traffic_rules(INGRESS + [sg("-1", ipv6_cidrs=ANY6)])
        assert len(rules) == 1 and rules[0].protocol == "-1"

    @pytest.mark.parametrize("min_span, expected", [(100, ["8000-9999"]), (2000, ["8000-9999"]), (2001, [])])
    def test_internet_wide_range_rules(self, min_span, expected):
        rules = network.internet_wide_range_rules(INGRESS + [sg("-1", cidrs=ANY4)], min_span=min_span)
        assert [r.describe()["ports"] for r in rules] == expected

    def test_wide_range_default_threshold_boundary(self):
        assert network.internet_wide_range_rules([sg("tcp", 1000, 1099, cidrs=ANY4)])
        assert not network.internet_wide_range_rules([sg("tcp", 1000, 1098, cidrs=ANY4)])

    def test_internet_exposed_ports(self):
        assert network.internet_exposed_ports(INGRESS) == [
            {"protocol": "tcp", "ports": "80", "sources": ["0.0.0.0/0", "::/0"]},
            {"protocol": "tcp", "ports": "3389", "sources": ["::/0"]},
            {"protocol": "tcp", "ports": "8000-9999", "sources": ["0.0.0.0/0"]},
        ]

    def test_port_catalogs(self):
        assert network.ADMIN_PORTS == {22: "SSH", 3389: "RDP"}
        assert {3306, 5432, 6379, 27017, 1433} <= set(network.DATABASE_PORTS)


# ---------------------------------------------------------------------------
# Network ACLs
# ---------------------------------------------------------------------------
DEFAULT_ACL = [acl(100, "allow"), acl(32767, "deny"), acl(100, "allow", egress=True)]


class TestNaclAllowsInternetAdmin:
    @pytest.mark.parametrize("entries", [None, []])
    def test_empty(self, entries):
        assert network.nacl_allows_internet_admin(entries) == []

    def test_default_nacl_exposes_both_ports(self):
        result = network.nacl_allows_internet_admin(DEFAULT_ACL)
        assert result == [
            {"port": 22, "rule_number": 100, "protocol": "-1", "from_port": None, "to_port": None, "cidr": "0.0.0.0/0"},
            {"port": 3389, "rule_number": 100, "protocol": "-1", "from_port": None, "to_port": None,
             "cidr": "0.0.0.0/0"},
        ]

    def test_lower_numbered_deny_shadows_allow(self):
        entries = [acl(10, "deny", protocol="6", from_port=22), acl(20, "deny", protocol="6", from_port=3389)] + DEFAULT_ACL
        assert network.nacl_allows_internet_admin(entries) == []

    def test_evaluated_in_rule_number_order_regardless_of_list_order(self):
        entries = DEFAULT_ACL + [acl(5, "deny", protocol="6", from_port=0, to_port=65535)]
        assert network.nacl_allows_internet_admin(entries) == []

    def test_higher_numbered_deny_does_not_shadow(self):
        entries = [acl(100, "allow"), acl(110, "deny", protocol="6", from_port=22)]
        assert [e["port"] for e in network.nacl_allows_internet_admin(entries)] == [22, 3389]

    def test_missing_rule_number_sorts_last(self):
        entries = [{"egress": False, "protocol": "-1", "action": "allow", "cidr": "0.0.0.0/0"},
                   acl(10, "deny")]
        assert network.nacl_allows_internet_admin(entries) == []

    @pytest.mark.parametrize("entry, ports", [
        (acl(100, "allow", protocol="6", from_port=22), [22]),
        (acl(100, "allow", protocol="tcp", from_port=3389), [3389]),
        (acl(100, "allow", protocol="6", from_port=0, to_port=65535), [22, 3389]),
        (acl(100, "allow", protocol="6"), [22, 3389]),  # TCP without a port range
        (acl(100, "allow", cidr="::/0"), [22, 3389]),
    ])
    def test_allow_entries(self, entry, ports):
        result = network.nacl_allows_internet_admin([entry, acl(32767, "deny")])
        assert [e["port"] for e in result] == ports

    @pytest.mark.parametrize("entry", [
        acl(100, "allow", cidr="10.0.0.0/8"),
        acl(100, "allow", protocol="6", from_port=443),
        acl(100, "allow", protocol="17", from_port=3389),  # UDP
        acl(100, "allow", protocol="1"),  # ICMP
        acl(100, "allow", egress=True),
    ])
    def test_entries_that_do_not_expose_admin_ports(self, entry):
        assert network.nacl_allows_internet_admin([entry, acl(32767, "deny")]) == []

    def test_narrow_cidr_deny_is_skipped(self):
        entries = [acl(10, "deny", cidr="198.51.100.0/24", protocol="6", from_port=22)] + DEFAULT_ACL
        assert 22 in [e["port"] for e in network.nacl_allows_internet_admin(entries)]

    # Regression test for a fixed bug in checks/network.py.
    @pytest.mark.parametrize("deny_cidr, allow_cidr", [("::/0", "0.0.0.0/0"), ("0.0.0.0/0", "::/0")])
    def test_deny_for_one_ip_family_does_not_shadow_the_other(self, deny_cidr, allow_cidr):
        entries = [acl(10, "deny", cidr=deny_cidr, protocol="6", from_port=22), acl(100, "allow", cidr=allow_cidr)]
        assert 22 in [e["port"] for e in network.nacl_allows_internet_admin(entries)]
