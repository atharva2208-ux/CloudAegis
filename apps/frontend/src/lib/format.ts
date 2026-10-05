import type { Severity } from "@/types/api";

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: "#E5484D",
  HIGH: "#F76B15",
  MEDIUM: "#9E8CFC",
  LOW: "#3B9EFF",
  INFO: "#7E7E87",
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFO: "Info",
};

export const STATUS_LABEL: Record<string, string> = {
  OPEN: "Open",
  ACKNOWLEDGED: "Acknowledged",
  IN_PROGRESS: "In progress",
  RESOLVED: "Resolved",
  SUPPRESSED: "Suppressed",
};

const numberFmt = new Intl.NumberFormat("en-US");
export const num = (n: number | null | undefined) => (n == null ? "—" : numberFmt.format(n));

export function pct(n: number | null | undefined, digits = 0): string {
  return n == null ? "—" : `${n.toFixed(digits)}%`;
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString("en-GB", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function shortDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-GB", { month: "short", day: "numeric" });
}

export function relative(iso: string | null | undefined): string {
  if (!iso) return "never";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 45) return "just now";
  if (diff < 3600) return plural(Math.max(1, Math.round(diff / 60)), "minute") + " ago";
  if (diff < 86400) return plural(Math.round(diff / 3600), "hour") + " ago";
  if (diff < 2592000) return plural(Math.round(diff / 86400), "day") + " ago";
  return plural(Math.round(diff / 2592000), "month") + " ago";
}

export function plural(n: number, word: string): string {
  return `${num(n)} ${word}${n === 1 ? "" : "s"}`;
}

export function duration(seconds: number | null | undefined): string {
  if (seconds == null) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const m = Math.floor(seconds / 60);
  return `${m}m ${Math.round(seconds % 60)}s`;
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function resourceTypeLabel(t: string): string {
  const map: Record<string, string> = {
    "aws.account": "Account",
    "aws.iam.user": "IAM user",
    "aws.iam.group": "IAM group",
    "aws.iam.role": "IAM role",
    "aws.iam.policy": "IAM policy",
    "aws.s3.bucket": "S3 bucket",
    "aws.ec2.instance": "EC2 instance",
    "aws.ec2.security_group": "Security group",
    "aws.ec2.volume": "EBS volume",
    "aws.ec2.region_settings": "Region settings",
    "aws.ec2.network_interface": "Network interface",
    "aws.vpc.vpc": "VPC",
    "aws.vpc.subnet": "Subnet",
    "aws.vpc.route_table": "Route table",
    "aws.vpc.internet_gateway": "Internet gateway",
    "aws.vpc.nat_gateway": "NAT gateway",
    "aws.vpc.network_acl": "Network ACL",
    "aws.rds.instance": "RDS instance",
    "aws.cloudtrail.trail": "CloudTrail trail",
    "aws.lambda.function": "Lambda function",
    "aws.ecr.repository": "ECR repository",
    "aws.kms.key": "KMS key",
    "aws.secretsmanager.secret": "Secret",
  };
  return map[t] ?? t;
}

export function humanizeAction(action: string): string {
  const [resource, verb] = action.split(".");
  const v = (verb ?? "").replace(/_/g, " ");
  return `${resource.charAt(0).toUpperCase()}${resource.slice(1)} ${v}`.trim();
}
