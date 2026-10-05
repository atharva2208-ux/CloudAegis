"""The exact read-only IAM actions the AWS collectors call.

Used to generate the least-privilege audit role policy shown during
onboarding. Keep this list in sync with the collectors (a unit test
checks every action is read-only: Describe/Get/List).
"""

REQUIRED_ACTIONS: tuple[str, ...] = (
    "sts:GetCallerIdentity",
    "ec2:DescribeRegions",
    # IAM
    "iam:GetAccountSummary",
    "iam:GetAccountPasswordPolicy",
    "iam:GetAccountAuthorizationDetails",
    "iam:ListUsers",
    "iam:GetLoginProfile",
    "iam:ListMFADevices",
    "iam:ListAccessKeys",
    "iam:GetAccessKeyLastUsed",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    # S3
    "s3:GetAccountPublicAccessBlock",
    "s3:ListAllMyBuckets",
    "s3:GetBucketLocation",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketPolicy",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketAcl",
    "s3:GetEncryptionConfiguration",
    "s3:GetBucketVersioning",
    "s3:GetBucketLogging",
    "s3:GetBucketOwnershipControls",
    "s3:GetBucketTagging",
    # EC2 / VPC
    "ec2:DescribeInstances",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeVolumes",
    "ec2:GetEbsEncryptionByDefault",
    "ec2:DescribeVpcs",
    "ec2:DescribeFlowLogs",
    "ec2:DescribeSubnets",
    "ec2:DescribeRouteTables",
    "ec2:DescribeInternetGateways",
    "ec2:DescribeNatGateways",
    "ec2:DescribeNetworkAcls",
    # RDS
    "rds:DescribeDBInstances",
    # CloudTrail
    "cloudtrail:DescribeTrails",
    "cloudtrail:GetTrailStatus",
    # Lambda
    "lambda:ListFunctions",
    "lambda:GetFunctionUrlConfig",
    "lambda:GetPolicy",
    # ECR
    "ecr:DescribeRepositories",
    "ecr:GetRepositoryPolicy",
    # KMS
    "kms:ListKeys",
    "kms:ListAliases",
    "kms:DescribeKey",
    "kms:GetKeyRotationStatus",
    "kms:GetKeyPolicy",
    # Secrets Manager (metadata only — GetSecretValue is deliberately absent)
    "secretsmanager:ListSecrets",
    "secretsmanager:GetResourcePolicy",
)


def audit_policy_document() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CloudAegisReadOnlyAudit",
                "Effect": "Allow",
                "Action": list(REQUIRED_ACTIONS),
                "Resource": "*",
            }
        ],
    }
