import { z } from "zod";
import type { AwsCredentials } from "@/services";

/** Client-side mirrors of the API's validation rules. The server remains the authority. */

export const ROLE_ARN_RE = /^arn:aws(-[a-z]+)*:iam::\d{12}:role\/[\w+=,.@/-]{1,512}$/;
export const REGION_RE = /^[a-z]{2}(-gov)?-[a-z]+-\d$/;
const EXTERNAL_ID_RE = /^[\w+=,.@:/-]{2,1224}$/;

export const AWS_REGIONS = [
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "ca-central-1",
  "eu-west-1",
  "eu-west-2",
  "eu-west-3",
  "eu-central-1",
  "eu-north-1",
  "ap-south-1",
  "ap-southeast-1",
  "ap-southeast-2",
  "ap-northeast-1",
  "ap-northeast-2",
  "sa-east-1",
];

export const credentialsShape = {
  method: z.enum(["assume_role", "temporary_credentials"]),
  role_arn: z.string().trim().optional(),
  external_id: z.string().trim().optional(),
  access_key_id: z.string().trim().optional(),
  secret_access_key: z.string().trim().optional(),
  session_token: z.string().trim().optional(),
};

interface CredentialValues {
  method: "assume_role" | "temporary_credentials";
  role_arn?: string;
  external_id?: string;
  access_key_id?: string;
  secret_access_key?: string;
  session_token?: string;
}

export function refineCredentials(v: CredentialValues, ctx: z.RefinementCtx) {
  const fail = (path: string, message: string) => ctx.addIssue({ code: z.ZodIssueCode.custom, path: [path], message });
  if (v.method === "assume_role") {
    if (!v.role_arn || !ROLE_ARN_RE.test(v.role_arn))
      fail("role_arn", "Enter a role ARN like arn:aws:iam::123456789012:role/CloudAegisAudit");
    if (v.external_id && !EXTERNAL_ID_RE.test(v.external_id))
      fail("external_id", "External ID may contain letters, digits and + = , . @ : / - _");
  } else {
    if (!v.access_key_id || !/^ASIA[A-Z0-9]{12,124}$/.test(v.access_key_id))
      fail("access_key_id", "Temporary STS access keys start with ASIA. Long-lived IAM user keys (AKIA…) are not accepted.");
    if (!v.secret_access_key || v.secret_access_key.length < 16) fail("secret_access_key", "Secret access key is required");
    if (!v.session_token || v.session_token.length < 20) fail("session_token", "Session token is required for temporary credentials");
  }
}

export const credentialsSchema = z.object(credentialsShape).superRefine(refineCredentials);

export type CredentialsForm = z.infer<typeof credentialsSchema>;

/** Convert form values to the API payload, sending only the fields for the chosen method. */
export function toCredentials(v: CredentialValues): AwsCredentials {
  return v.method === "assume_role"
    ? { method: "assume_role", role_arn: v.role_arn, external_id: v.external_id || undefined }
    : {
        method: "temporary_credentials",
        access_key_id: v.access_key_id,
        secret_access_key: v.secret_access_key,
        session_token: v.session_token,
      };
}

export const accountNameSchema = z
  .string()
  .trim()
  .min(2, "Use at least 2 characters")
  .max(100, "Use at most 100 characters")
  .regex(/^[\w .()-]+$/, "Letters, numbers, spaces and . ( ) - _ only");

export const passwordSchema = z
  .string()
  .min(12, "Use at least 12 characters")
  .max(128, "Use at most 128 characters")
  .refine(
    (v) => [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(v)).length >= 3,
    "Use at least three of: lowercase, uppercase, digits, symbols",
  );

