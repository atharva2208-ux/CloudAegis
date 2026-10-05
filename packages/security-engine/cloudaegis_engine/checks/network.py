"""Network exposure analysis for security groups and network ACLs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

INTERNET_V4 = "0.0.0.0/0"
INTERNET_V6 = "::/0"
INTERNET_CIDRS = {INTERNET_V4, INTERNET_V6}

ICMP_PROTOCOLS = {"icmp", "1", "icmpv6", "58"}

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
DATABASE_PORTS = {
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


@dataclass(frozen=True)
class PermissionRule:
    protocol: str  # "-1" means all protocols
    from_port: int | None
    to_port: int | None
    cidrs: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PermissionRule":
        cidrs = tuple(data.get("cidrs", ())) + tuple(data.get("ipv6_cidrs", ()))
        return cls(
            protocol=str(data.get("protocol", "-1")),
            from_port=data.get("from_port"),
            to_port=data.get("to_port"),
            cidrs=cidrs,
        )

    @property
    def all_traffic(self) -> bool:
        if self.protocol == "-1":
            return True
        # For ICMP, -1/-1 means "all ICMP types and codes", not all traffic.
        if self.protocol in ICMP_PROTOCOLS:
            return False
        return self.from_port in (None, 0, -1) and self.to_port in (None, 65535, -1)

    @property
    def open_to_internet(self) -> bool:
        return any(c in INTERNET_CIDRS for c in self.cidrs)

    def covers_port(self, port: int) -> bool:
        if self.protocol == "-1":
            return True
        if self.protocol not in ("tcp", "6", "udp", "17"):
            return False
        if self.from_port is None or self.to_port is None:
            return True
        return self.from_port <= port <= self.to_port

    @property
    def port_span(self) -> int:
        if self.all_traffic:
            return 65536
        if self.from_port is None or self.to_port is None:
            return 65536
        return self.to_port - self.from_port + 1

    def describe(self) -> dict[str, Any]:
        if self.protocol == "-1":
            ports = "all"
        elif self.from_port == self.to_port:
            ports = str(self.from_port)
        else:
            ports = f"{self.from_port}-{self.to_port}"
        return {
            "protocol": "all" if self.protocol == "-1" else self.protocol,
            "ports": ports,
            "sources": [c for c in self.cidrs if c in INTERNET_CIDRS] or list(self.cidrs),
        }


def parse_rules(raw: Iterable[dict[str, Any]] | None) -> list[PermissionRule]:
    return [PermissionRule.from_dict(r) for r in raw or ()]


def internet_rules_for_port(raw: Iterable[dict[str, Any]] | None, port: int) -> list[PermissionRule]:
    return [r for r in parse_rules(raw) if r.open_to_internet and r.covers_port(port)]


def internet_all_traffic_rules(raw: Iterable[dict[str, Any]] | None) -> list[PermissionRule]:
    return [r for r in parse_rules(raw) if r.open_to_internet and r.all_traffic]


def internet_wide_range_rules(
    raw: Iterable[dict[str, Any]] | None, min_span: int = 100
) -> list[PermissionRule]:
    return [
        r
        for r in parse_rules(raw)
        if r.open_to_internet and not r.all_traffic and r.port_span >= min_span
    ]


def internet_exposed_ports(raw: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [r.describe() for r in parse_rules(raw) if r.open_to_internet]


def nacl_allows_internet_admin(entries: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Return NACL ingress allow entries that reach admin ports from anywhere.

    NACL rules are evaluated in rule-number order; a lower-numbered deny for
    the same traffic shadows a later allow, which this function honours.
    IPv4 and IPv6 traffic are evaluated independently: a deny for ``::/0``
    does not block IPv4 traffic from ``0.0.0.0/0`` and vice versa.
    """
    ordered = sorted(
        (e for e in entries or () if not e.get("egress")),
        key=lambda e: e.get("rule_number", 32767),
    )
    offending: list[dict[str, Any]] = []
    for port in ADMIN_PORTS:
        for family in (INTERNET_V4, INTERNET_V6):
            offending.extend(_first_nacl_match(ordered, port, family))
    return offending


def _first_nacl_match(ordered: list[dict[str, Any]], port: int, internet_cidr: str) -> list[dict[str, Any]]:
    """The first entry matching (port, address family) decides; return it if it allows."""
    for entry in ordered:
        if entry.get("cidr") != internet_cidr:
            continue
        protocol = str(entry.get("protocol", "-1"))
        from_port, to_port = entry.get("from_port"), entry.get("to_port")
        covers = protocol == "-1" or (
            protocol in ("6", "tcp")
            and (from_port is None or to_port is None or from_port <= port <= to_port)
        )
        if not covers:
            continue
        if entry.get("action") == "allow":
            return [{"port": port, **{k: entry.get(k) for k in (
                "rule_number", "protocol", "from_port", "to_port", "cidr")}}]
        return []  # first matching rule wins
    return []
