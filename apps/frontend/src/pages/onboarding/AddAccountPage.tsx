import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { FormProvider, useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Check, CheckCircle2, FlaskConical, TriangleAlert, XCircle } from "lucide-react";
import { accountsApi } from "@/services";
import { Button } from "@/components/ui/button";
import { KeyValue, PageHeader, Panel } from "@/components/ui/misc";
import { InlineError } from "@/components/ui/states";
import { useToast } from "@/components/ui/toast";
import { CredentialFields, FieldError, MethodPicker } from "@/components/accounts/CredentialFields";
import { RoleSetupGuide } from "@/components/accounts/RoleSetupGuide";
import { AUTH_LABEL } from "@/components/accounts/AccountStatus";
import { cn } from "@/lib/cn";
import { AWS_REGIONS, accountNameSchema, credentialsShape, refineCredentials, toCredentials } from "@/lib/validation";
import type { ConnectionResult } from "@/types/api";

const schema = z
  .object({ name: accountNameSchema, default_region: z.string().min(1), ...credentialsShape })
  .superRefine(refineCredentials);
type FormValues = z.infer<typeof schema>;

const STEPS = ["Account", "Credentials", "Validate", "Review"] as const;

function Stepper({ step }: { step: number }) {
  return (
    <ol className="mb-5 flex flex-wrap items-center gap-2 text-[12.5px]" aria-label="Progress">
      {STEPS.map((label, i) => (
        <li key={label} className="flex items-center gap-2" aria-current={i === step ? "step" : undefined}>
          <span
            className={cn(
              "flex h-6 w-6 items-center justify-center rounded-[1px] border text-[12px] tabular-nums",
              i < step && "border-ok/50 bg-ok/15 text-ok",
              i === step && "border-accent bg-accent-dim/40 text-ink",
              i > step && "border-line text-faint",
            )}
          >
            {i < step ? <Check className="h-3.5 w-3.5" aria-hidden /> : i + 1}
          </span>
          <span className={i === step ? "text-ink" : "text-muted"}>{label}</span>
          {i < STEPS.length - 1 && <span className="mx-1 h-px w-8 bg-line" aria-hidden />}
        </li>
      ))}
    </ol>
  );
}

function ConnectionOutcome({ result }: { result: ConnectionResult }) {
  return (
    <div
      className={cn(
        "rounded-panel border p-4",
        result.ok ? "border-ok/40 bg-ok/[0.07]" : "border-sev-critical/40 bg-sev-critical/[0.07]",
      )}
      role="status"
    >
      <p className="flex items-center gap-2 text-[13.5px] font-medium">
        {result.ok ? <CheckCircle2 className="h-4 w-4 text-ok" aria-hidden /> : <XCircle className="h-4 w-4 text-sev-critical" aria-hidden />}
        {result.message}
      </p>
      {result.ok && (
        <dl className="mt-3 grid gap-3 sm:grid-cols-2">
          <KeyValue label="AWS account" mono>
            {result.account_id}
          </KeyValue>
          <KeyValue label="Authenticated as" mono>
            {result.principal_arn}
          </KeyValue>
        </dl>
      )}
      {result.warnings.length > 0 && (
        <ul className="mt-3 space-y-1 text-[12.5px] text-sev-medium">
          {result.warnings.map((w) => (
            <li key={w} className="flex gap-2">
              <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
              {w}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function AddAccountPage() {
  const [step, setStep] = useState(0);
  const [result, setResult] = useState<ConnectionResult | null>(null);
  const [regions, setRegions] = useState<string[]>([]);
  const [startScan, setStartScan] = useState(true);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const toast = useToast();
  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    mode: "onTouched",
    defaultValues: { name: "", method: "assume_role", default_region: "us-east-1", external_id: "" },
  });
  const { register, handleSubmit, trigger, getValues, watch, formState, setValue } = form;
  // Pre-fill a unique external ID so the generated trust policy and the form agree.
  const guide = useQuery({ queryKey: ["onboarding-guide"], queryFn: accountsApi.guide, staleTime: Infinity });
  useEffect(() => {
    if (guide.data && !getValues("external_id")) setValue("external_id", guide.data.external_id_suggestion);
  }, [guide.data, getValues, setValue]);

  const test = useMutation({
    mutationFn: () => {
      const v = getValues();
      return accountsApi.test(toCredentials(v), v.default_region);
    },
    onSuccess: (r) => {
      setResult(r);
      if (r.ok) setRegions(r.regions.length ? r.regions : [getValues("default_region")]);
    },
  });

  const create = useMutation({
    mutationFn: (v: FormValues) =>
      accountsApi.create({ name: v.name, credentials: toCredentials(v), default_region: v.default_region, regions, start_scan: startScan }),
    onSuccess: (account) => {
      queryClient.invalidateQueries({ queryKey: ["accounts"] });
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      toast.success(`${account.name} connected${startScan ? " — first scan queued" : ""}`);
      navigate(`/accounts/${account.id}`);
    },
  });

  const demo = useMutation({
    mutationFn: () => accountsApi.createDemo(getValues("name") || "Demo Cloud Environment"),
    onSuccess: (account) => {
      queryClient.invalidateQueries({ queryKey: ["accounts"] });
      toast.success("Simulated environment connected — first scan queued");
      navigate(`/accounts/${account.id}`);
    },
  });

  const next = async () => {
    const fields: (keyof FormValues)[][] = [
      ["name", "method"],
      ["role_arn", "external_id", "access_key_id", "secret_access_key", "session_token", "default_region"],
    ];
    if (step < 2 && !(await trigger(fields[step]))) return;
    if (step === 1) {
      setResult(null);
      test.reset();
    }
    setStep((s) => s + 1);
  };

  const method = watch("method");
  const values = watch();

  return (
    <>
      <Link to="/accounts" className="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-muted hover:text-ink">
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Accounts
      </Link>
      <PageHeader title="Connect an AWS account" description="CloudAegis only needs read-only access. Credentials are encrypted at rest and never displayed after they are saved." />
      <Stepper step={step} />

      <FormProvider {...form}>
        <form onSubmit={handleSubmit((v) => create.mutate(v))} className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px]" noValidate>
          <div className="min-w-0 space-y-4">
            {step === 0 && (
              <Panel title="Account details" bodyClassName="space-y-5 p-5">
                <div className="max-w-md">
                  <label className="field-label" htmlFor="name">
                    Friendly name
                  </label>
                  <input id="name" className="input" placeholder="Production AWS" {...register("name")} />
                  <FieldError message={formState.errors.name?.message} />
                </div>
                <div>
                  <p className="field-label">Authentication method</p>
                  <MethodPicker />
                </div>
              </Panel>
            )}

            {step === 1 && (
              <Panel title={method === "assume_role" ? "Audit role" : "Temporary credentials"} bodyClassName="space-y-5 p-5">
                <CredentialFields />
                <div className="max-w-xs">
                  <label className="field-label" htmlFor="default_region">
                    Home region
                  </label>
                  <select id="default_region" className="input" {...register("default_region")}>
                    {AWS_REGIONS.map((r) => (
                      <option key={r}>{r}</option>
                    ))}
                  </select>
                  <p className="mt-1 text-[12px] text-faint">Used for STS and global services. All enabled regions are discovered in the next step.</p>
                </div>
              </Panel>
            )}

            {step === 2 && (
              <Panel title="Validate connection" bodyClassName="space-y-4 p-5">
                <p className="text-[13px] text-muted">
                  CloudAegis calls <span className="mono">sts:GetCallerIdentity</span> and <span className="mono">ec2:DescribeRegions</span>, then samples a few read-only permissions.
                </p>
                <Button type="button" variant="primary" loading={test.isPending} onClick={() => test.mutate()}>
                  Test connection
                </Button>
                <InlineError error={test.error} />
                {result && <ConnectionOutcome result={result} />}
                {result?.ok && (
                  <div>
                    <p className="field-label">Regions to scan ({regions.length} selected)</p>
                    <div className="flex flex-wrap gap-1.5">
                      {result.regions.map((r) => (
                        <button
                          key={r}
                          type="button"
                          aria-pressed={regions.includes(r)}
                          onClick={() => setRegions((cur) => (cur.includes(r) ? cur.filter((x) => x !== r) : [...cur, r]))}
                          className={cn(
                            "h-7 rounded-control border px-2.5 text-[12.5px]",
                            regions.includes(r) ? "border-accent/60 bg-accent-dim/40" : "border-line text-muted hover:border-line-strong",
                          )}
                        >
                          {r}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </Panel>
            )}

            {step === 3 && (
              <Panel title="Review" bodyClassName="space-y-4 p-5">
                <dl className="grid gap-4 sm:grid-cols-2">
                  <KeyValue label="Name">{values.name}</KeyValue>
                  <KeyValue label="Authentication">{AUTH_LABEL[values.method]}</KeyValue>
                  <KeyValue label="AWS account" mono>
                    {result?.account_id}
                  </KeyValue>
                  {values.method === "assume_role" ? (
                    <KeyValue label="Role ARN" mono>
                      {values.role_arn}
                    </KeyValue>
                  ) : (
                    <KeyValue label="Access key ID" mono>
                      {values.access_key_id?.slice(0, 8)}••••••••
                    </KeyValue>
                  )}
                  <KeyValue label="Regions">{regions.join(", ")}</KeyValue>
                  <KeyValue label="Home region">{values.default_region}</KeyValue>
                </dl>
                <label className="flex items-center gap-2 text-[13px]">
                  <input type="checkbox" className="accent-[#F5A524]" checked={startScan} onChange={(e) => setStartScan(e.target.checked)} />
                  Discover resources and run the first security scan now
                </label>
                <InlineError error={create.error} />
              </Panel>
            )}

            <div className="flex items-center justify-between">
              <Button type="button" variant="ghost" disabled={step === 0} onClick={() => setStep((s) => s - 1)}>
                Back
              </Button>
              {step < 3 ? (
                <Button type="button" variant="primary" onClick={next} disabled={step === 2 && !(result?.ok && regions.length)}>
                  Continue
                </Button>
              ) : (
                <Button type="submit" variant="primary" loading={create.isPending}>
                  Connect account
                </Button>
              )}
            </div>
          </div>

          <aside className="space-y-4">
            {step === 1 && method === "assume_role" ? (
              <Panel title="Create the audit role" bodyClassName="p-4">
                <RoleSetupGuide externalId={values.external_id} />
              </Panel>
            ) : (
              <Panel title="How CloudAegis accesses AWS" bodyClassName="space-y-3 p-4 text-[12.5px] text-muted">
                <p>Every API call is read-only: the platform never creates, modifies or deletes cloud resources.</p>
                <p>Role assumption with an external ID is the recommended model. Each scan receives fresh one-hour session credentials.</p>
                <p>Long-lived IAM user access keys are rejected by design.</p>
              </Panel>
            )}
            <Panel title="No AWS account handy?" bodyClassName="p-4">
              <p className="mb-3 text-[12.5px] text-muted">
                Connect the simulated environment to explore the platform with realistic resources and findings. It is clearly labelled and makes no AWS calls.
              </p>
              <Button type="button" size="sm" loading={demo.isPending} onClick={() => demo.mutate()}>
                <FlaskConical className="h-3.5 w-3.5" aria-hidden /> Connect simulated environment
              </Button>
              <InlineError error={demo.error} />
            </Panel>
          </aside>
        </form>
      </FormProvider>
    </>
  );
}
