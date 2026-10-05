import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { FormProvider, useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, KeyRound, Radar, RefreshCw, Trash2 } from "lucide-react";
import { accountsApi, scansApi } from "@/services";
import { PERMS, useAuth } from "@/stores/auth";
import { useScope } from "@/stores/scope";
import { KeyValue, Panel } from "@/components/ui/misc";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { DemoBadge } from "@/components/ui/badges";
import { ErrorState, InlineError, LoadingRows } from "@/components/ui/states";
import { useToast } from "@/components/ui/toast";
import { AUTH_LABEL, AccountStatus } from "@/components/accounts/AccountStatus";
import { CredentialFields, MethodPicker } from "@/components/accounts/CredentialFields";
import { ScanTable, ScoreValue } from "@/components/scans/ScanTable";
import { ScanProgress } from "@/components/scans/ScanProgress";
import { StartScanDialog } from "@/components/scans/StartScanDialog";
import { cn } from "@/lib/cn";
import { errorMessage } from "@/lib/api";
import { dateTime, num, relative } from "@/lib/format";
import { credentialsSchema, toCredentials, type CredentialsForm } from "@/lib/validation";
import type { CloudAccount } from "@/types/api";

function RotateCredentialsDialog({ account, open, onOpenChange }: { account: CloudAccount; open: boolean; onOpenChange: (o: boolean) => void }) {
  const form = useForm<CredentialsForm>({
    resolver: zodResolver(credentialsSchema),
    defaultValues: { method: account.auth_method === "temporary_credentials" ? "temporary_credentials" : "assume_role", role_arn: account.role_arn ?? "" },
  });
  const queryClient = useQueryClient();
  const toast = useToast();
  const m = useMutation({
    mutationFn: (v: CredentialsForm) => accountsApi.update(account.id, { credentials: toCredentials(v) }),
    onSuccess: (a) => {
      queryClient.setQueryData(["account", account.id], a);
      queryClient.invalidateQueries({ queryKey: ["accounts"] });
      toast.success("Credentials replaced and validated");
      form.reset();
      onOpenChange(false);
    },
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      width="max-w-2xl"
      title="Update credentials"
      description="New credentials are validated before they replace the stored ones. Existing secrets are never displayed."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" loading={m.isPending} onClick={form.handleSubmit((v) => m.mutate(v))}>
            Validate and save
          </Button>
        </>
      }
    >
      <FormProvider {...form}>
        <div className="space-y-4">
          <MethodPicker />
          <CredentialFields />
          <InlineError error={m.error} />
        </div>
      </FormProvider>
    </Dialog>
  );
}

function DeleteDialog({ account, open, onOpenChange }: { account: CloudAccount; open: boolean; onOpenChange: (o: boolean) => void }) {
  const [confirm, setConfirm] = useState("");
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const toast = useToast();
  const m = useMutation({
    mutationFn: () => accountsApi.remove(account.id),
    onSuccess: (r) => {
      queryClient.invalidateQueries();
      toast.success(r.message);
      navigate("/accounts");
    },
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={`Remove ${account.name}?`}
      description="Stored credentials, discovered assets, findings and scan history for this account are permanently deleted. Nothing in AWS is changed."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="danger" loading={m.isPending} disabled={confirm !== account.name} onClick={() => m.mutate()}>
            Remove account
          </Button>
        </>
      }
    >
      <label className="field-label" htmlFor="confirm-name">
        Type <span className="mono text-ink">{account.name}</span> to confirm
      </label>
      <input id="confirm-name" className="input" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
      <div className="mt-3">
        <InlineError error={m.error} />
      </div>
    </Dialog>
  );
}

function RegionsPanel({ account, canManage }: { account: CloudAccount; canManage: boolean }) {
  const [enabled, setEnabled] = useState<string[]>([]);
  const queryClient = useQueryClient();
  const toast = useToast();
  useEffect(() => setEnabled(account.regions.filter((r) => r.enabled).map((r) => r.name)), [account]);
  const dirty = enabled.slice().sort().join() !== account.regions.filter((r) => r.enabled).map((r) => r.name).sort().join();
  const save = useMutation({
    mutationFn: () => accountsApi.update(account.id, { regions: enabled }),
    onSuccess: (a) => {
      queryClient.setQueryData(["account", account.id], a);
      queryClient.invalidateQueries({ queryKey: ["accounts"] });
      toast.success("Scan regions updated");
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  return (
    <Panel
      title={`Regions (${enabled.length} of ${account.regions.length} scanned)`}
      actions={
        canManage &&
        dirty && (
          <Button size="sm" variant="primary" loading={save.isPending} disabled={!enabled.length} onClick={() => save.mutate()}>
            Save regions
          </Button>
        )
      }
      bodyClassName="flex flex-wrap gap-1.5 p-4"
    >
      {account.regions.map((r) => {
        const on = enabled.includes(r.name);
        return (
          <button
            key={r.name}
            type="button"
            disabled={!canManage}
            aria-pressed={on}
            onClick={() => setEnabled((cur) => (on ? cur.filter((x) => x !== r.name) : [...cur, r.name]))}
            className={cn(
              "h-7 rounded-control border px-2.5 text-[12.5px] disabled:cursor-default",
              on ? "border-accent/60 bg-accent-dim/40 text-ink" : "border-line text-faint hover:border-line-strong",
            )}
          >
            {r.name}
          </button>
        );
      })}
    </Panel>
  );
}

export default function AccountDetailPage() {
  const id = Number(useParams().id);
  const { can } = useAuth();
  const { setAccountId } = useScope();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [scanOpen, setScanOpen] = useState(false);
  const [rotateOpen, setRotateOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);

  const { data: account, error, isLoading, refetch } = useQuery({ queryKey: ["account", id], queryFn: () => accountsApi.get(id) });
  const scans = useQuery({
    queryKey: ["scans", { account_id: id, page_size: 10 }],
    queryFn: () => scansApi.list({ account_id: id, page_size: 10 }),
    refetchInterval: (q) => (q.state.data?.items.some((s) => s.status === "QUEUED" || s.status === "RUNNING") ? 2000 : false),
  });
  const active = scans.data?.items.find((s) => s.status === "QUEUED" || s.status === "RUNNING");
  useEffect(() => {
    if (!active && scans.data) queryClient.invalidateQueries({ queryKey: ["account", id] });
  }, [active, scans.data, id, queryClient]);

  const validate = useMutation({
    mutationFn: () => accountsApi.validate(id),
    onSuccess: (r) => {
      queryClient.invalidateQueries({ queryKey: ["account", id] });
      queryClient.invalidateQueries({ queryKey: ["accounts"] });
      if (r.ok) toast.success(r.message);
      else toast.error(r.message);
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  if (isLoading) return <LoadingRows rows={8} />;
  if (error || !account) return <div className="panel"><ErrorState error={error} onRetry={refetch} /></div>;
  const canManage = can(PERMS.accountsManage);

  return (
    <>
      <Link to="/accounts" className="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-muted hover:text-ink">
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Accounts
      </Link>
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2.5 text-[20px] font-semibold">
            {account.name} {account.is_demo && <DemoBadge />}
          </h1>
          <div className="mt-1.5 flex flex-wrap items-center gap-3">
            <span className="mono text-faint">{account.account_identifier}</span>
            <AccountStatus status={account.status} />
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="ghost" onClick={() => setAccountId(account.id)}>
            View posture for this account
          </Button>
          {canManage && (
            <Button loading={validate.isPending} onClick={() => validate.mutate()}>
              <RefreshCw className="h-3.5 w-3.5" aria-hidden /> Re-validate
            </Button>
          )}
          {can(PERMS.scansRun) && (
            <Button variant="primary" onClick={() => setScanOpen(true)} disabled={!!active || account.status === "error"}>
              <Radar className="h-3.5 w-3.5" aria-hidden /> Run scan
            </Button>
          )}
        </div>
      </div>

      {account.status === "error" && account.status_message && (
        <div className="mb-4 rounded-panel border border-sev-critical/40 bg-sev-critical/10 px-4 py-3 text-[13px] text-[#FF8589]" role="alert">
          {account.status_message}
        </div>
      )}

      <div className="panel mb-4 grid grid-cols-2 sm:grid-cols-4 sm:divide-x sm:divide-line">
        <div className="p-4">
          <p className="text-[12px] text-faint">Security score</p>
          <p className="mt-1.5 text-[22px] font-semibold">
            <ScoreValue score={account.security_score} />
          </p>
        </div>
        <div className="p-4">
          <p className="text-[12px] text-faint">Assets</p>
          <p className="mt-1.5 text-[22px] font-semibold tabular-nums">{num(account.asset_count)}</p>
        </div>
        <div className="p-4">
          <p className="text-[12px] text-faint">Open findings</p>
          <p className="mt-1.5 text-[22px] font-semibold tabular-nums">{num(account.open_findings)}</p>
        </div>
        <div className="p-4">
          <p className="text-[12px] text-faint">Last scan</p>
          <p className="mt-2.5 text-[13px]">{relative(account.last_scan_at)}</p>
        </div>
      </div>

      {active && (
        <Panel title={`Scan ${active.display_id} in progress`} className="mb-4" bodyClassName="p-4">
          <ScanProgress scan={active} />
        </Panel>
      )}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="min-w-0 space-y-4">
          <Panel
            title="Scan history"
            actions={
              <Link to={`/scans?account_id=${account.id}`} className="link text-[12.5px]">
                All scans
              </Link>
            }
          >
            {scans.isLoading ? (
              <LoadingRows rows={3} />
            ) : scans.data?.items.length ? (
              <ScanTable scans={scans.data.items} showAccount={false} />
            ) : (
              <p className="p-6 text-center text-[13px] text-faint">No scans yet.</p>
            )}
          </Panel>
          <RegionsPanel account={account} canManage={canManage} />
        </div>

        <aside className="space-y-4">
          <Panel
            title="Connection"
            actions={
              canManage &&
              !account.is_demo && (
                <Button size="sm" variant="ghost" onClick={() => setRotateOpen(true)}>
                  <KeyRound className="h-3.5 w-3.5" aria-hidden /> Update credentials
                </Button>
              )
            }
            bodyClassName="p-4"
          >
            <dl className="grid gap-3">
              <KeyValue label="Authentication">{AUTH_LABEL[account.auth_method] ?? account.auth_method}</KeyValue>
              {account.role_arn && (
                <KeyValue label="Role ARN" mono>
                  {account.role_arn}
                </KeyValue>
              )}
              <KeyValue label="Authenticated principal" mono>
                {account.principal_arn ?? "—"}
              </KeyValue>
              <KeyValue label="Stored secret">
                {account.has_stored_secret ? "Encrypted at rest · never displayed" : account.is_demo ? "None (simulated)" : "None"}
              </KeyValue>
              {account.credentials_expire_at && <KeyValue label="Credentials expire">{dateTime(account.credentials_expire_at)}</KeyValue>}
              <KeyValue label="Last validated">{dateTime(account.last_validated_at)}</KeyValue>
              <KeyValue label="Home region">{account.default_region}</KeyValue>
              <KeyValue label="Connected">{dateTime(account.created_at)}</KeyValue>
              {account.status_message && account.status !== "error" && <KeyValue label="Status">{account.status_message}</KeyValue>}
            </dl>
          </Panel>
          {canManage && (
            <Panel title="Danger zone" bodyClassName="p-4">
              <p className="mb-3 text-[12.5px] text-muted">Disconnect this account and delete its data from CloudAegis.</p>
              <Button variant="danger" size="sm" onClick={() => setDeleteOpen(true)}>
                <Trash2 className="h-3.5 w-3.5" aria-hidden /> Remove account
              </Button>
            </Panel>
          )}
        </aside>
      </div>

      <StartScanDialog open={scanOpen} onOpenChange={setScanOpen} defaultAccountId={account.id} />
      {!account.is_demo && <RotateCredentialsDialog account={account} open={rotateOpen} onOpenChange={setRotateOpen} />}
      <DeleteDialog account={account} open={deleteOpen} onOpenChange={setDeleteOpen} />
    </>
  );
}
