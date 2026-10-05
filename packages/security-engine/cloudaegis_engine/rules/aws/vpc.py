"""VPC and network detection rules."""

from __future__ import annotations

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.checks import network
from cloudaegis_engine.models import Resource, RuleMetadata, RuleResult, Severity
from cloudaegis_engine.rules.aws import _refs
from cloudaegis_engine.rules.base import Rule, RuleContext
from cloudaegis_engine.rules.registry import register


@register
class FlowLogsDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="VPC-001",
        title="VPC flow logs are not enabled",
        severity=Severity.MEDIUM,
        service="VPC",
        category="Logging & Monitoring",
        resource_type=rt.VPC,
        description="No flow log is configured for the VPC.",
        impact="Network traffic cannot be analysed for exfiltration, lateral movement or incident scoping.",
        remediation="Enable flow logs (at least REJECT traffic) to CloudWatch Logs or S3.",
        remediation_cli="aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> "
        "--traffic-type ALL --log-destination-type s3 --log-destination <bucket-arn>",
        references=(_refs.VPC_FLOW_LOGS, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        enabled = bool(resource.prop("flow_logs_enabled"))
        return self.check(resource, not enabled, {"FlowLogsEnabled": enabled, "IsDefault": resource.prop("is_default")})


@register
class DefaultSecurityGroupAllowsTraffic(Rule):
    metadata = RuleMetadata(
        rule_id="VPC-002",
        title="Default security group allows traffic",
        severity=Severity.MEDIUM,
        service="VPC",
        category="Network Security",
        resource_type=rt.EC2_SECURITY_GROUP,
        description="The VPC's default security group has inbound or outbound rules.",
        impact="Resources launched without an explicit security group silently receive permissive "
        "connectivity.",
        remediation="Remove all rules from default security groups and assign purpose-built groups instead.",
        references=(_refs.EC2_SG, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        if not resource.prop("is_default"):
            return None
        ingress = resource.prop("ingress") or []
        egress = resource.prop("egress") or []
        return self.check(resource, bool(ingress or egress),
                          {"InboundRules": len(ingress), "OutboundRules": len(egress)})


@register
class UnrestrictedEgress(Rule):
    metadata = RuleMetadata(
        rule_id="VPC-003",
        title="Security group allows unrestricted outbound traffic",
        severity=Severity.LOW,
        service="VPC",
        category="Network Security",
        resource_type=rt.EC2_SECURITY_GROUP,
        description="An in-use, non-default security group allows all outbound traffic to 0.0.0.0/0.",
        impact="Compromised workloads can freely reach command-and-control servers and exfiltrate data.",
        remediation="Restrict egress to required destinations (VPC endpoints, proxies, specific ports).",
        references=(_refs.EC2_SG,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        if resource.prop("is_default") or not resource.prop("attached_eni_count"):
            return None
        rules = network.internet_all_traffic_rules(resource.prop("egress"))
        return self.check(resource, bool(rules), {"OpenEgressRules": [r.describe() for r in rules]})


@register
class PublicSubnetAutoAssignIp(Rule):
    metadata = RuleMetadata(
        rule_id="VPC-004",
        title="Subnet auto-assigns public IPs and routes to the internet",
        severity=Severity.MEDIUM,
        service="VPC",
        category="Public Exposure",
        resource_type=rt.VPC_SUBNET,
        description="MapPublicIpOnLaunch is enabled on a subnet whose route table has a route to an "
        "internet gateway.",
        impact="Every instance launched in the subnet is automatically internet-addressable, even when "
        "that was not intended.",
        remediation="Disable automatic public IP assignment and allocate public addresses explicitly where required.",
        remediation_cli="aws ec2 modify-subnet-attribute --subnet-id <subnet-id> --no-map-public-ip-on-launch",
        references=(_refs.EC2_SG,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        auto = bool(resource.prop("map_public_ip_on_launch"))
        igw = bool(resource.prop("has_internet_route"))
        return self.check(resource, auto and igw, {"MapPublicIpOnLaunch": auto, "RouteToInternetGateway": igw})


@register
class NaclAllowsAdminPorts(Rule):
    metadata = RuleMetadata(
        rule_id="VPC-005",
        title="Network ACL allows administration ports from the internet",
        severity=Severity.MEDIUM,
        service="VPC",
        category="Network Security",
        resource_type=rt.VPC_NETWORK_ACL,
        description="A NACL ingress rule allows SSH (22) or RDP (3389) from 0.0.0.0/0 or ::/0 before any deny.",
        impact="The subnet-level guardrail does not stop remote administration traffic from the internet.",
        remediation="Add deny entries for ports 22 and 3389 from 0.0.0.0/0 and ::/0 ahead of broad allow rules.",
        references=(_refs.VPC_NACL, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        if not resource.prop("subnet_ids"):
            return None
        offending = network.nacl_allows_internet_admin(resource.prop("entries"))
        return self.check(resource, bool(offending), {"OffendingEntries": offending})


@register
class WidePortRangeOpen(Rule):
    metadata = RuleMetadata(
        rule_id="VPC-006",
        title="Security group opens a wide port range to the internet",
        severity=Severity.HIGH,
        service="VPC",
        category="Network Security",
        resource_type=rt.EC2_SECURITY_GROUP,
        description="An inbound rule exposes 100 or more contiguous ports to 0.0.0.0/0 or ::/0.",
        impact="Broad ranges expose unintended services and make the attack surface hard to reason about.",
        remediation="Replace the range with the exact ports the application serves.",
        references=(_refs.EC2_SG,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        rules = network.internet_wide_range_rules(resource.prop("ingress"))
        return self.check(resource, bool(rules), {"OffendingRules": [r.describe() for r in rules]})
