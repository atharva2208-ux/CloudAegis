"""VPC discovery: VPCs, subnets, route tables, gateways and network ACLs."""

from __future__ import annotations

from typing import Any, Iterator

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.models import Relationship, Resource
from cloudaegis_engine.providers.aws.collectors import CollectorContext
from cloudaegis_engine.providers.aws.collectors._util import name_from_tags, tags_to_dict
from cloudaegis_engine.providers.aws.collectors.ec2 import _paginate

INTERNET = {"0.0.0.0/0", "::/0"}


def _routes_to_igw(table: dict[str, Any]) -> bool:
    for route in table.get("Routes", []):
        dest = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")
        if dest in INTERNET and str(route.get("GatewayId", "")).startswith("igw-"):
            return True
    return False


def collect(ctx: CollectorContext) -> Iterator[Resource]:
    for region in ctx.regions:
        ec2 = ctx.client("ec2", region)
        flow_logs = _paginate(ec2, "describe_flow_logs", "FlowLogs")
        logged = {f.get("ResourceId") for f in flow_logs if f.get("FlowLogStatus", "ACTIVE") == "ACTIVE"}

        for vpc in _paginate(ec2, "describe_vpcs", "Vpcs"):
            tags = tags_to_dict(vpc.get("Tags"))
            yield Resource(
                uid=ctx.arn("ec2", region, f"vpc/{vpc['VpcId']}"),
                resource_type=rt.VPC,
                service="VPC",
                name=name_from_tags(tags, vpc["VpcId"]),
                region=region,
                account_id=ctx.account_id,
                tags=tags,
                properties={
                    "vpc_id": vpc["VpcId"],
                    "cidr_block": vpc.get("CidrBlock"),
                    "is_default": bool(vpc.get("IsDefault")),
                    "flow_logs_enabled": vpc["VpcId"] in logged,
                },
            )

        tables = _paginate(ec2, "describe_route_tables", "RouteTables")
        subnet_table: dict[str, dict[str, Any]] = {}
        main_table: dict[str, dict[str, Any]] = {}
        for table in tables:
            for assoc in table.get("Associations", []):
                if assoc.get("Main"):
                    main_table[table["VpcId"]] = table
                elif assoc.get("SubnetId"):
                    subnet_table[assoc["SubnetId"]] = table
            tags = tags_to_dict(table.get("Tags"))
            routes = [
                {
                    "destination": r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock") or r.get("DestinationPrefixListId"),
                    "target": r.get("GatewayId") or r.get("NatGatewayId") or r.get("TransitGatewayId")
                    or r.get("VpcPeeringConnectionId") or r.get("NetworkInterfaceId") or "local",
                }
                for r in table.get("Routes", [])
            ]
            yield Resource(
                uid=ctx.arn("ec2", region, f"route-table/{table['RouteTableId']}"),
                resource_type=rt.VPC_ROUTE_TABLE,
                service="VPC",
                name=name_from_tags(tags, table["RouteTableId"]),
                region=region,
                account_id=ctx.account_id,
                tags=tags,
                properties={
                    "route_table_id": table["RouteTableId"],
                    "vpc_id": table.get("VpcId"),
                    "routes": routes,
                    "subnet_ids": [a["SubnetId"] for a in table.get("Associations", []) if a.get("SubnetId")],
                    "is_main": any(a.get("Main") for a in table.get("Associations", [])),
                    "routes_to_internet_gateway": _routes_to_igw(table),
                },
            )

        for subnet in _paginate(ec2, "describe_subnets", "Subnets"):
            tags = tags_to_dict(subnet.get("Tags"))
            table = subnet_table.get(subnet["SubnetId"]) or main_table.get(subnet["VpcId"]) or {}
            yield Resource(
                uid=ctx.arn("ec2", region, f"subnet/{subnet['SubnetId']}"),
                resource_type=rt.VPC_SUBNET,
                service="VPC",
                name=name_from_tags(tags, subnet["SubnetId"]),
                region=region,
                account_id=ctx.account_id,
                tags=tags,
                properties={
                    "subnet_id": subnet["SubnetId"],
                    "vpc_id": subnet["VpcId"],
                    "cidr_block": subnet.get("CidrBlock"),
                    "availability_zone": subnet.get("AvailabilityZone"),
                    "map_public_ip_on_launch": bool(subnet.get("MapPublicIpOnLaunch")),
                    "has_internet_route": _routes_to_igw(table) if table else False,
                },
                relationships=[Relationship("in_vpc", ctx.arn("ec2", region, f"vpc/{subnet['VpcId']}"))],
            )

        for igw in _paginate(ec2, "describe_internet_gateways", "InternetGateways"):
            tags = tags_to_dict(igw.get("Tags"))
            vpcs = [a["VpcId"] for a in igw.get("Attachments", []) if a.get("VpcId")]
            yield Resource(
                uid=ctx.arn("ec2", region, f"internet-gateway/{igw['InternetGatewayId']}"),
                resource_type=rt.VPC_INTERNET_GATEWAY,
                service="VPC",
                name=name_from_tags(tags, igw["InternetGatewayId"]),
                region=region,
                account_id=ctx.account_id,
                tags=tags,
                properties={"igw_id": igw["InternetGatewayId"], "attached_vpc_ids": vpcs},
                relationships=[Relationship("attached_to", ctx.arn("ec2", region, f"vpc/{v}")) for v in vpcs],
            )

        for nat in _paginate(ec2, "describe_nat_gateways", "NatGateways"):
            tags = tags_to_dict(nat.get("Tags"))
            addresses = nat.get("NatGatewayAddresses", [])
            yield Resource(
                uid=ctx.arn("ec2", region, f"natgateway/{nat['NatGatewayId']}"),
                resource_type=rt.VPC_NAT_GATEWAY,
                service="VPC",
                name=name_from_tags(tags, nat["NatGatewayId"]),
                region=region,
                account_id=ctx.account_id,
                tags=tags,
                properties={
                    "nat_id": nat["NatGatewayId"],
                    "vpc_id": nat.get("VpcId"),
                    "subnet_id": nat.get("SubnetId"),
                    "state": nat.get("State"),
                    "public_ip": addresses[0].get("PublicIp") if addresses else None,
                },
            )

        for acl in _paginate(ec2, "describe_network_acls", "NetworkAcls"):
            tags = tags_to_dict(acl.get("Tags"))
            entries = []
            for e in acl.get("Entries", []):
                port_range = e.get("PortRange") or {}
                entries.append({
                    "rule_number": e.get("RuleNumber"),
                    "egress": bool(e.get("Egress")),
                    "protocol": str(e.get("Protocol", "-1")),
                    "action": e.get("RuleAction"),
                    "cidr": e.get("CidrBlock") or e.get("Ipv6CidrBlock"),
                    "from_port": port_range.get("From"),
                    "to_port": port_range.get("To"),
                })
            yield Resource(
                uid=ctx.arn("ec2", region, f"network-acl/{acl['NetworkAclId']}"),
                resource_type=rt.VPC_NETWORK_ACL,
                service="VPC",
                name=name_from_tags(tags, acl["NetworkAclId"]),
                region=region,
                account_id=ctx.account_id,
                tags=tags,
                properties={
                    "nacl_id": acl["NetworkAclId"],
                    "vpc_id": acl.get("VpcId"),
                    "is_default": bool(acl.get("IsDefault")),
                    "entries": entries,
                    "subnet_ids": [a["SubnetId"] for a in acl.get("Associations", []) if a.get("SubnetId")],
                },
            )
