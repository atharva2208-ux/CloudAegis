"""EC2 detection rules (instances, security groups, EBS)."""

from __future__ import annotations

from cloudaegis_engine import resource_types as rt
from cloudaegis_engine.checks import network
from cloudaegis_engine.models import Resource, RuleMetadata, RuleResult, Severity
from cloudaegis_engine.rules.aws import _refs
from cloudaegis_engine.rules.aws._helpers import internet_ingress
from cloudaegis_engine.rules.base import Rule, RuleContext
from cloudaegis_engine.rules.registry import register

# Exposure of only HTTP/HTTPS on a public instance is treated as intentional
# (web tier); anything else reachable from the internet is reported.
WEB_PORTS = {"80", "443"}

_REVOKE_CLI = (
    "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port {port} --cidr 0.0.0.0/0"
)


@register
class PublicInstanceWithOpenIngress(Rule):
    metadata = RuleMetadata(
        rule_id="EC2-001",
        title="Public EC2 instance exposes non-web services to the internet",
        severity=Severity.HIGH,
        service="EC2",
        category="Public Exposure",
        resource_type=rt.EC2_INSTANCE,
        description="A running instance has a public IP address and an attached security group that "
        "accepts traffic from 0.0.0.0/0 or ::/0 on ports other than HTTP (80) and HTTPS (443).",
        impact="The instance is directly reachable from the internet, exposing its services to scanning, "
        "exploitation and brute-force attacks.",
        remediation="Move the instance to a private subnet behind a load balancer or use Systems Manager "
        "Session Manager for administration. Restrict security group sources.",
        remediation_steps=(
            "Confirm whether the instance must be internet-facing.",
            "If not, remove the public IP / Elastic IP and place it in a private subnet.",
            "Restrict security group ingress to known CIDRs or load balancer security groups.",
        ),
        references=(_refs.EC2_SG, _refs.AWS_SECURITY_HUB_CONTROLS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        if resource.prop("state") != "running":
            return None
        public_ip = resource.prop("public_ip")
        if not public_ip:
            return self.passed(resource, {"PublicIp": None})
        exposed = internet_ingress(ctx.inventory, resource.prop("security_group_ids"), resource.region, resource.account_id)
        non_web = [e for e in exposed if e["ports"] not in WEB_PORTS]
        return self.check(resource, bool(non_web), {"PublicIp": public_ip, "InternetIngress": exposed,
                                                    "NonWebExposure": non_web})


class _SecurityGroupPortRule(Rule):
    port: int

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        rules = network.internet_rules_for_port(resource.prop("ingress"), self.port)
        return self.check(
            resource,
            bool(rules),
            {"OffendingRules": [r.describe() for r in rules], "Port": self.port,
             "AttachedInterfaces": resource.prop("attached_eni_count", 0)},
        )


@register
class SshOpenToInternet(_SecurityGroupPortRule):
    port = 22
    metadata = RuleMetadata(
        rule_id="EC2-002",
        title="Security group allows SSH from the internet",
        severity=Severity.HIGH,
        service="EC2",
        category="Network Security",
        resource_type=rt.EC2_SECURITY_GROUP,
        description="An inbound rule permits TCP port 22 from 0.0.0.0/0 or ::/0.",
        impact="SSH services are continuously brute-forced and targeted with exploits once exposed.",
        remediation="Remove the rule and use Session Manager, a bastion with restricted sources, or a VPN.",
        remediation_cli=_REVOKE_CLI.format(port=22),
        references=(_refs.EC2_SG, _refs.CIS_AWS),
    )


@register
class RdpOpenToInternet(_SecurityGroupPortRule):
    port = 3389
    metadata = RuleMetadata(
        rule_id="EC2-003",
        title="Security group allows RDP from the internet",
        severity=Severity.HIGH,
        service="EC2",
        category="Network Security",
        resource_type=rt.EC2_SECURITY_GROUP,
        description="An inbound rule permits TCP port 3389 from 0.0.0.0/0 or ::/0.",
        impact="Exposed RDP is one of the most common initial-access vectors for ransomware operators.",
        remediation="Remove the rule and use Fleet Manager / Session Manager or a VPN for remote desktop.",
        remediation_cli=_REVOKE_CLI.format(port=3389),
        references=(_refs.EC2_SG, _refs.CIS_AWS),
    )


@register
class AllTrafficOpenToInternet(Rule):
    metadata = RuleMetadata(
        rule_id="EC2-004",
        title="Security group allows all inbound traffic from the internet",
        severity=Severity.CRITICAL,
        service="EC2",
        category="Network Security",
        resource_type=rt.EC2_SECURITY_GROUP,
        description="An inbound rule allows all protocols and ports from 0.0.0.0/0 or ::/0.",
        impact="Every listening service on attached resources is exposed to the internet, including "
        "management and database ports.",
        remediation="Replace the rule with explicit ports and trusted source ranges or security groups.",
        references=(_refs.EC2_SG, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        rules = network.internet_all_traffic_rules(resource.prop("ingress"))
        return self.check(resource, bool(rules), {"OffendingRules": [r.describe() for r in rules],
                                                  "AttachedInterfaces": resource.prop("attached_eni_count", 0)})


@register
class ImdsV1Enabled(Rule):
    metadata = RuleMetadata(
        rule_id="EC2-005",
        title="EC2 instance allows IMDSv1",
        severity=Severity.MEDIUM,
        service="EC2",
        category="Compute Security",
        resource_type=rt.EC2_INSTANCE,
        description="The instance metadata service accepts IMDSv1 requests (HttpTokens = optional).",
        impact="SSRF vulnerabilities in applications on the instance can be used to steal the instance "
        "role's temporary credentials.",
        remediation="Require IMDSv2 session tokens on the instance and in launch templates.",
        remediation_cli="aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-endpoint enabled",
        references=(_refs.EC2_IMDS, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        if resource.prop("state") == "terminated":
            return None
        if resource.prop("imds_http_endpoint") == "disabled":
            return self.passed(resource, {"HttpEndpoint": "disabled"})
        tokens = resource.prop("imds_http_tokens")
        return self.check(resource, tokens != "required", {"HttpTokens": tokens, "HttpEndpoint": resource.prop("imds_http_endpoint")})


@register
class UnencryptedEbsVolume(Rule):
    metadata = RuleMetadata(
        rule_id="EC2-006",
        title="EBS volume is not encrypted",
        severity=Severity.MEDIUM,
        service="EC2",
        category="Data Protection",
        resource_type=rt.EC2_VOLUME,
        description="The EBS volume is not encrypted at rest.",
        impact="Snapshots shared or copied from this volume expose data in plaintext; regulatory "
        "requirements for encryption at rest are not met.",
        remediation="Create an encrypted snapshot copy and restore an encrypted volume; enable EBS "
        "encryption by default for the region.",
        remediation_steps=(
            "Create a snapshot of the volume.",
            "Copy the snapshot with --encrypted and a KMS key.",
            "Create a new volume from the encrypted snapshot and swap it in during a maintenance window.",
        ),
        references=(_refs.EBS_ENCRYPTION, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        encrypted = bool(resource.prop("encrypted"))
        return self.check(resource, not encrypted, {"Encrypted": encrypted, "SizeGiB": resource.prop("size_gb"),
                                                    "AttachedTo": resource.prop("attached_instance_ids", [])})


@register
class EbsEncryptionByDefaultDisabled(Rule):
    metadata = RuleMetadata(
        rule_id="EC2-007",
        title="EBS encryption by default is disabled",
        severity=Severity.LOW,
        service="EC2",
        category="Data Protection",
        resource_type=rt.EC2_REGION_SETTINGS,
        description="New EBS volumes in this region are not encrypted automatically.",
        impact="Engineers must remember to request encryption for every volume; mistakes leave data unencrypted.",
        remediation="Enable EBS encryption by default in every region in use.",
        remediation_cli="aws ec2 enable-ebs-encryption-by-default --region <region>",
        references=(_refs.EBS_ENCRYPTION, _refs.CIS_AWS),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        enabled = bool(resource.prop("ebs_encryption_by_default"))
        return self.check(resource, not enabled, {"EbsEncryptionByDefault": enabled})


@register
class DatabasePortsOpenToInternet(Rule):
    metadata = RuleMetadata(
        rule_id="EC2-008",
        title="Security group exposes database ports to the internet",
        severity=Severity.HIGH,
        service="EC2",
        category="Network Security",
        resource_type=rt.EC2_SECURITY_GROUP,
        description="An inbound rule allows common database or cache ports (MySQL, PostgreSQL, MSSQL, "
        "MongoDB, Redis, Elasticsearch...) from the internet.",
        impact="Data stores are exposed to credential attacks and to exploitation of unauthenticated "
        "services such as default Redis or Elasticsearch deployments.",
        remediation="Restrict database ports to application-tier security groups only.",
        references=(_refs.EC2_SG,),
    )

    def evaluate(self, resource: Resource, ctx: RuleContext) -> RuleResult | None:
        if network.internet_all_traffic_rules(resource.prop("ingress")):
            return None  # EC2-004 covers the broader exposure
        exposed = [
            {"port": port, "service": name}
            for port, name in network.DATABASE_PORTS.items()
            if network.internet_rules_for_port(resource.prop("ingress"), port)
        ]
        return self.check(resource, bool(exposed), {"ExposedDatabasePorts": exposed,
                                                    "AttachedInterfaces": resource.prop("attached_eni_count", 0)})
