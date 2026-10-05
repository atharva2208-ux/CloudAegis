import { useFormContext } from "react-hook-form";
import { KeyRound, ShieldCheck, TriangleAlert } from "lucide-react";
import { cn } from "@/lib/cn";
import type { CredentialsForm } from "@/lib/validation";

export function FieldError({ message }: { message?: string }) {
  if (!message) return null;
  return (
    <p className="mt-1 text-[12px] text-[#FF8589]" role="alert">
      {message}
    </p>
  );
}

function MethodCard({
  value,
  title,
  description,
  icon,
  recommended,
}: {
  value: CredentialsForm["method"];
  title: string;
  description: string;
  icon: React.ReactNode;
  recommended?: boolean;
}) {
  const { register, watch } = useFormContext<CredentialsForm>();
  const active = watch("method") === value;
  return (
    <label
      className={cn(
        "flex cursor-pointer gap-3 rounded-panel border p-3.5 transition-colors",
        active ? "border-accent/70 bg-accent-dim/20" : "border-line hover:border-line-strong",
      )}
    >
      <input type="radio" value={value} className="mt-1 accent-[#F5A524]" {...register("method")} />
      <span className="min-w-0">
        <span className="flex items-center gap-2 text-[13.5px] font-medium">
          {icon}
          {title}
          {recommended && <span className="rounded-control bg-ok/15 px-1.5 py-0.5 text-[11px] font-normal text-ok">Recommended</span>}
        </span>
        <span className="mt-1 block text-[12.5px] text-muted">{description}</span>
      </span>
    </label>
  );
}

export function MethodPicker() {
  return (
    <div className="grid gap-2.5 md:grid-cols-2">
      <MethodCard
        value="assume_role"
        recommended
        icon={<ShieldCheck className="h-4 w-4 text-ok" aria-hidden />}
        title="IAM role"
        description="CloudAegis assumes a read-only cross-account role with an external ID. No long-lived secrets are stored."
      />
      <MethodCard
        value="temporary_credentials"
        icon={<KeyRound className="h-4 w-4 text-muted" aria-hidden />}
        title="Temporary credentials"
        description="Paste short-lived STS credentials (ASIA…). Useful for one-off assessments; they expire within hours."
      />
    </div>
  );
}

/** Credential inputs for the selected method. Secrets use password inputs and autocomplete is disabled. */
export function CredentialFields() {
  const {
    register,
    watch,
    formState: { errors },
  } = useFormContext<CredentialsForm>();
  const method = watch("method");

  if (method === "assume_role") {
    return (
      <div className="grid gap-4">
        <div>
          <label className="field-label" htmlFor="role_arn">
            Role ARN
          </label>
          <input
            id="role_arn"
            className="input mono"
            placeholder="arn:aws:iam::123456789012:role/CloudAegisAudit"
            autoComplete="off"
            spellCheck={false}
            {...register("role_arn")}
          />
          <FieldError message={errors.role_arn?.message} />
        </div>
        <div>
          <label className="field-label" htmlFor="external_id">
            External ID
          </label>
          <input id="external_id" className="input mono" autoComplete="off" spellCheck={false} {...register("external_id")} />
          <p className="mt-1 text-[12px] text-faint">
            Must match the <span className="mono">sts:ExternalId</span> condition in the role's trust policy. It prevents the confused-deputy problem.
          </p>
          <FieldError message={errors.external_id?.message} />
        </div>
      </div>
    );
  }
  return (
    <div className="grid gap-4">
      <div className="flex gap-2.5 rounded-control border border-sev-medium/40 bg-sev-medium/10 px-3 py-2.5 text-[12.5px]">
        <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0 text-sev-medium" aria-hidden />
        <span>
          Only temporary credentials from <span className="mono">aws sts get-session-token</span> or{" "}
          <span className="mono">assume-role</span> are accepted. They are encrypted at rest and never shown again. Prefer an IAM role for continuous scanning.
        </span>
      </div>
      <div>
        <label className="field-label" htmlFor="access_key_id">
          Access key ID
        </label>
        <input id="access_key_id" className="input mono" placeholder="ASIA…" autoComplete="off" spellCheck={false} {...register("access_key_id")} />
        <FieldError message={errors.access_key_id?.message} />
      </div>
      <div>
        <label className="field-label" htmlFor="secret_access_key">
          Secret access key
        </label>
        <input id="secret_access_key" type="password" className="input mono" autoComplete="new-password" {...register("secret_access_key")} />
        <FieldError message={errors.secret_access_key?.message} />
      </div>
      <div>
        <label className="field-label" htmlFor="session_token">
          Session token
        </label>
        <textarea id="session_token" className="input mono h-20 resize-y py-2" autoComplete="off" spellCheck={false} {...register("session_token")} />
        <FieldError message={errors.session_token?.message} />
      </div>
    </div>
  );
}
