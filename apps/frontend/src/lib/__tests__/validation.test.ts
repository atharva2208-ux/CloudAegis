import { describe, expect, it } from "vitest";
import { accountNameSchema, credentialsSchema, passwordSchema, toCredentials } from "@/lib/validation";

describe("credential validation", () => {
  it("accepts a valid role ARN with external ID", () => {
    const r = credentialsSchema.safeParse({ method: "assume_role", role_arn: "arn:aws:iam::123456789012:role/CloudAegisAudit", external_id: "abc-123" });
    expect(r.success).toBe(true);
  });

  it.each(["arn:aws:iam::12345:role/x", "arn:aws:s3:::bucket", "arn:aws:iam::123456789012:user/bob", ""])("rejects role ARN %s", (arn) => {
    const r = credentialsSchema.safeParse({ method: "assume_role", role_arn: arn });
    expect(r.success).toBe(false);
  });

  it("rejects long-lived access keys", () => {
    const r = credentialsSchema.safeParse({
      method: "temporary_credentials",
      access_key_id: "AKIAIOSFODNN7EXAMPLE",
      secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      session_token: "IQoJb3JpZ2luX2VjEXAMPLE-session-token",
    });
    expect(r.success).toBe(false);
    if (!r.success) expect(r.error.issues[0].message).toMatch(/AKIA/);
  });

  it("only sends fields for the chosen method", () => {
    expect(toCredentials({ method: "assume_role", role_arn: "arn", external_id: "", access_key_id: "ASIA" })).toEqual({
      method: "assume_role",
      role_arn: "arn",
      external_id: undefined,
    });
  });
});

describe("other schemas", () => {
  it("validates account names", () => {
    expect(accountNameSchema.safeParse("Production AWS").success).toBe(true);
    expect(accountNameSchema.safeParse("<script>").success).toBe(false);
  });

  it("mirrors the server password policy", () => {
    expect(passwordSchema.safeParse("short").success).toBe(false);
    expect(passwordSchema.safeParse("alllowercaseletters").success).toBe(false);
    expect(passwordSchema.safeParse("Correct-Horse-Battery").success).toBe(true);
  });
});
