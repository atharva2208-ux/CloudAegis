"""Canonical normalized resource type identifiers.

Providers must emit these identifiers; rules target them. Adding a service
means adding a type here, a collector in the provider, and a rule pack.
"""

AWS_ACCOUNT = "aws.account"
IAM_USER = "aws.iam.user"
IAM_GROUP = "aws.iam.group"
IAM_ROLE = "aws.iam.role"
IAM_POLICY = "aws.iam.policy"
S3_BUCKET = "aws.s3.bucket"
EC2_INSTANCE = "aws.ec2.instance"
EC2_SECURITY_GROUP = "aws.ec2.security_group"
EC2_VOLUME = "aws.ec2.volume"
EC2_REGION_SETTINGS = "aws.ec2.region_settings"
EC2_NETWORK_INTERFACE = "aws.ec2.network_interface"
VPC = "aws.vpc.vpc"
VPC_SUBNET = "aws.vpc.subnet"
VPC_ROUTE_TABLE = "aws.vpc.route_table"
VPC_INTERNET_GATEWAY = "aws.vpc.internet_gateway"
VPC_NAT_GATEWAY = "aws.vpc.nat_gateway"
VPC_NETWORK_ACL = "aws.vpc.network_acl"
RDS_INSTANCE = "aws.rds.instance"
CLOUDTRAIL_TRAIL = "aws.cloudtrail.trail"
LAMBDA_FUNCTION = "aws.lambda.function"
ECR_REPOSITORY = "aws.ecr.repository"
KMS_KEY = "aws.kms.key"
SECRET = "aws.secretsmanager.secret"

# Human-readable service label for each resource type (used for grouping).
SERVICE_OF = {
    AWS_ACCOUNT: "IAM",
    IAM_USER: "IAM",
    IAM_GROUP: "IAM",
    IAM_ROLE: "IAM",
    IAM_POLICY: "IAM",
    S3_BUCKET: "S3",
    EC2_INSTANCE: "EC2",
    EC2_SECURITY_GROUP: "EC2",
    EC2_VOLUME: "EC2",
    EC2_REGION_SETTINGS: "EC2",
    EC2_NETWORK_INTERFACE: "EC2",
    VPC: "VPC",
    VPC_SUBNET: "VPC",
    VPC_ROUTE_TABLE: "VPC",
    VPC_INTERNET_GATEWAY: "VPC",
    VPC_NAT_GATEWAY: "VPC",
    VPC_NETWORK_ACL: "VPC",
    RDS_INSTANCE: "RDS",
    CLOUDTRAIL_TRAIL: "CloudTrail",
    LAMBDA_FUNCTION: "Lambda",
    ECR_REPOSITORY: "ECR",
    KMS_KEY: "KMS",
    SECRET: "Secrets Manager",
}

# Discovery order — the scan progress UI reports progress per service.
SERVICE_ORDER = ["IAM", "S3", "EC2", "VPC", "RDS", "CloudTrail", "Lambda", "ECR", "KMS", "Secrets Manager"]
