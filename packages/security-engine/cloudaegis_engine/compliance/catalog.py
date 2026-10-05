"""Compliance framework catalog.

Each framework is a list of controls; each control lists the detection
rules that provide evidence for it. Frameworks are plain data so a new
framework (PCI DSS, ISO 27001, SOC 2...) is added by appending a
``Framework`` definition — no engine changes required.

Control identifiers follow the published framework numbering. CIS
benchmark text is licensed by the Center for Internet Security; only
identifiers and short paraphrased titles are reproduced here.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Control:
    control_id: str
    title: str
    description: str
    rule_ids: tuple[str, ...]
    section: str = ""


@dataclass(frozen=True)
class Framework:
    key: str
    name: str
    short_name: str
    version: str
    description: str
    controls: tuple[Control, ...] = field(default_factory=tuple)

    def control(self, control_id: str) -> Control | None:
        return next((c for c in self.controls if c.control_id == control_id), None)

    def rule_ids(self) -> set[str]:
        return {r for c in self.controls for r in c.rule_ids}


def _c(control_id: str, section: str, title: str, description: str, *rule_ids: str) -> Control:
    return Control(control_id=control_id, section=section, title=title, description=description, rule_ids=rule_ids)


CIS_AWS = Framework(
    key="cis-aws",
    name="CIS AWS Foundations Benchmark",
    short_name="CIS AWS",
    version="3.0.0",
    description="Prescriptive configuration baseline for AWS accounts published by the Center for "
    "Internet Security, covering identity, storage, logging and networking.",
    controls=(
        _c("1.4", "Identity and Access Management", "No root user access keys exist",
           "The root user must not have programmatic access keys.", "IAM-002"),
        _c("1.5", "Identity and Access Management", "MFA is enabled for the root user",
           "The root user must be protected by multi-factor authentication.", "IAM-001"),
        _c("1.8", "Identity and Access Management", "Password policy requires a minimum length of 14",
           "IAM password policy enforces long passwords.", "IAM-006", "IAM-007"),
        _c("1.9", "Identity and Access Management", "Password policy prevents password reuse",
           "IAM password policy prevents reuse of recent passwords.", "IAM-006", "IAM-007"),
        _c("1.10", "Identity and Access Management", "MFA is enabled for all console users",
           "Every IAM user with a console password has MFA.", "IAM-003", "IAM-013"),
        _c("1.12", "Identity and Access Management", "Unused credentials are disabled",
           "Credentials unused for the inactivity window are disabled.", "IAM-004", "IAM-012"),
        _c("1.13", "Identity and Access Management", "Only one active access key per user",
           "Users do not hold multiple active access keys.", "IAM-014"),
        _c("1.14", "Identity and Access Management", "Access keys are rotated every 90 days",
           "Active access keys are rotated regularly.", "IAM-005"),
        _c("1.15", "Identity and Access Management", "Users receive permissions only through groups",
           "Administrative permissions are not attached directly to users.", "IAM-009"),
        _c("1.16", "Identity and Access Management", "No policies grant full *:* administrative privileges",
           "Attached customer managed policies do not allow all actions on all resources.", "IAM-008"),
        _c("2.1.1", "Storage", "S3 bucket policies deny HTTP requests",
           "Bucket policies require TLS.", "S3-008"),
        _c("2.1.4", "Storage", "S3 Block Public Access is enabled",
           "Block Public Access is enabled at bucket and account level.", "S3-001", "S3-007", "S3-009"),
        _c("2.2.1", "Storage", "EBS volume encryption is enabled",
           "EBS encryption by default is enabled and volumes are encrypted.", "EC2-006", "EC2-007"),
        _c("2.3.1", "Storage", "RDS storage encryption is enabled",
           "RDS instances encrypt data at rest.", "RDS-002"),
        _c("2.3.3", "Storage", "RDS instances are not publicly accessible",
           "RDS instances are not reachable from the internet.", "RDS-001", "RDS-004"),
        _c("3.1", "Logging", "CloudTrail is enabled in all regions",
           "A multi-region trail is actively logging.", "CT-001", "CT-002", "CT-007"),
        _c("3.2", "Logging", "CloudTrail log file validation is enabled",
           "Trails produce integrity digest files.", "CT-003"),
        _c("3.5", "Logging", "CloudTrail logs are encrypted with KMS CMKs",
           "Trail log files use SSE-KMS with a customer managed key.", "CT-004"),
        _c("3.6", "Logging", "Rotation is enabled for customer managed symmetric keys",
           "Customer managed KMS keys rotate automatically.", "KMS-001"),
        _c("3.7", "Logging", "VPC flow logging is enabled in all VPCs",
           "Every VPC records flow logs.", "VPC-001"),
        _c("5.1", "Networking", "No NACL allows ingress from 0.0.0.0/0 to admin ports",
           "Network ACLs block remote administration from the internet.", "VPC-005"),
        _c("5.2", "Networking", "No security group allows ingress from 0.0.0.0/0 to admin ports",
           "Security groups block SSH/RDP from the internet.", "EC2-002", "EC2-003", "EC2-004"),
        _c("5.4", "Networking", "The default security group restricts all traffic",
           "Default security groups have no rules.", "VPC-002"),
        _c("5.6", "Networking", "EC2 metadata service requires IMDSv2",
           "Instances require session tokens for metadata access.", "EC2-005"),
    ),
)

AWS_WAF_SECURITY = Framework(
    key="aws-wa-security",
    name="AWS Well-Architected Framework — Security Pillar",
    short_name="AWS Security",
    version="2024",
    description="Best-practice questions from the Security Pillar of the AWS Well-Architected Framework.",
    controls=(
        _c("SEC01", "Security foundations", "Operate workloads securely",
           "Protect the root user and separate administrative duties.", "IAM-001", "IAM-002"),
        _c("SEC02", "Identity and access management", "Manage identities for people and machines",
           "Use strong sign-in, temporary credentials and credential rotation.",
           "IAM-003", "IAM-004", "IAM-005", "IAM-006", "IAM-007", "IAM-012", "IAM-013", "IAM-014",
           "SM-001", "SM-003"),
        _c("SEC03", "Identity and access management", "Manage permissions for people and machines",
           "Grant least privilege and reduce permissions continuously.",
           "IAM-008", "IAM-009", "IAM-010", "IAM-011", "IAM-015", "LAM-003", "SM-002"),
        _c("SEC04", "Detection", "Detect and investigate security events",
           "Capture logs centrally and analyse them.",
           "CT-001", "CT-002", "CT-003", "CT-005", "CT-006", "CT-007", "VPC-001", "S3-006", "RDS-005"),
        _c("SEC05", "Infrastructure protection", "Protect network resources",
           "Control traffic at all layers.",
           "EC2-001", "EC2-002", "EC2-003", "EC2-004", "EC2-008", "VPC-002", "VPC-003", "VPC-004",
           "VPC-005", "VPC-006", "RDS-001", "RDS-004", "LAM-001", "LAM-002"),
        _c("SEC06", "Infrastructure protection", "Protect compute resources",
           "Reduce attack surface and manage vulnerabilities.",
           "EC2-005", "LAM-006", "ECR-001", "ECR-002"),
        _c("SEC07", "Data protection", "Classify and control access to data",
           "Prevent unintended public access to data stores.",
           "S3-001", "S3-002", "S3-003", "S3-007", "S3-009", "ECR-003", "LAM-005"),
        _c("SEC08", "Data protection", "Protect data at rest",
           "Encrypt data at rest and manage keys.",
           "S3-004", "EC2-006", "EC2-007", "RDS-002", "CT-004", "KMS-001", "KMS-002", "KMS-003",
           "LAM-004", "SM-004"),
        _c("SEC09", "Data protection", "Protect data in transit",
           "Enforce encryption in transit.", "S3-008"),
        _c("SEC10", "Incident response", "Anticipate, respond to, and recover from incidents",
           "Keep recoverable copies of data and protect them from deletion.",
           "S3-005", "RDS-003", "RDS-006"),
    ),
)

NIST_CSF = Framework(
    key="nist-csf",
    name="NIST Cybersecurity Framework",
    short_name="NIST CSF",
    version="2.0",
    description="Outcome-based subcategories from the NIST Cybersecurity Framework 2.0 mapped to "
    "technical cloud configuration checks.",
    controls=(
        _c("PR.AA-01", "Protect — Identity Management, Authentication and Access Control",
           "Identities and credentials are managed",
           "Credentials for authorized users and services are issued, managed and revoked.",
           "IAM-002", "IAM-004", "IAM-005", "IAM-012", "IAM-014", "SM-001", "SM-003"),
        _c("PR.AA-03", "Protect — Identity Management, Authentication and Access Control",
           "Users, services and hardware are authenticated",
           "Strong authentication is enforced.", "IAM-001", "IAM-003", "IAM-006", "IAM-007", "IAM-013",
           "LAM-001"),
        _c("PR.AA-05", "Protect — Identity Management, Authentication and Access Control",
           "Access permissions follow least privilege",
           "Permissions are defined, managed and enforced with least privilege.",
           "IAM-008", "IAM-009", "IAM-010", "IAM-011", "IAM-015", "LAM-002", "LAM-003", "SM-002",
           "KMS-002", "ECR-003"),
        _c("PR.DS-01", "Protect — Data Security", "Data-at-rest is protected",
           "Confidentiality and integrity of data at rest are protected.",
           "S3-001", "S3-002", "S3-003", "S3-004", "S3-007", "S3-009", "EC2-006", "EC2-007", "RDS-002",
           "KMS-001", "LAM-004", "LAM-005", "SM-004"),
        _c("PR.DS-02", "Protect — Data Security", "Data-in-transit is protected",
           "Confidentiality and integrity of data in transit are protected.", "S3-008"),
        _c("PR.DS-11", "Protect — Data Security", "Backups of data are maintained",
           "Backups are created, protected and tested.", "S3-005", "RDS-003", "RDS-006", "KMS-003"),
        _c("PR.PS-02", "Protect — Platform Security", "Software is maintained",
           "Software is patched and end-of-life software is replaced.", "LAM-006", "EC2-005"),
        _c("PR.PS-04", "Protect — Platform Security", "Log records are generated",
           "Logs are generated and made available for continuous monitoring.",
           "CT-001", "CT-002", "CT-003", "CT-004", "CT-007", "S3-006", "RDS-005", "VPC-001"),
        _c("PR.IR-01", "Protect — Technology Infrastructure Resilience",
           "Networks are protected from unauthorized access",
           "Networks and environments are protected from unauthorized logical access.",
           "EC2-001", "EC2-002", "EC2-003", "EC2-004", "EC2-008", "VPC-002", "VPC-003", "VPC-004",
           "VPC-005", "VPC-006", "RDS-001", "RDS-004"),
        _c("DE.CM-01", "Detect — Continuous Monitoring", "Networks are monitored",
           "Networks and network services are monitored for adverse events.", "VPC-001", "CT-006", "CT-005"),
        _c("ID.RA-01", "Identify — Risk Assessment", "Vulnerabilities in assets are identified",
           "Vulnerabilities in assets are identified, validated and recorded.", "ECR-001", "ECR-002"),
    ),
)

FRAMEWORKS: tuple[Framework, ...] = (CIS_AWS, AWS_WAF_SECURITY, NIST_CSF)


def get_framework(key: str) -> Framework | None:
    return next((f for f in FRAMEWORKS if f.key == key), None)


def controls_for_rule(rule_id: str) -> list[tuple[Framework, Control]]:
    return [(f, c) for f in FRAMEWORKS for c in f.controls if rule_id in c.rule_ids]
