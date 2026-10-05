import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { InlineError } from "@/components/ui/states";
import { platformApi, scansApi } from "@/services";
import { useScope } from "@/stores/scope";
import { useToast } from "@/components/ui/toast";
import { cn } from "@/lib/cn";

function ChipToggle({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "h-7 rounded-control border px-2.5 text-[12.5px]",
        active ? "border-accent/60 bg-accent-dim/40 text-ink" : "border-line text-muted hover:border-line-strong",
      )}
    >
      {children}
    </button>
  );
}

export function StartScanDialog({ open, onOpenChange, defaultAccountId }: { open: boolean; onOpenChange: (o: boolean) => void; defaultAccountId?: number }) {
  const { accounts, accountId } = useScope();
  const [selected, setSelected] = useState<number | undefined>(defaultAccountId ?? accountId ?? accounts[0]?.id);
  const account = accounts.find((a) => a.id === selected);
  const { data: settings } = useQuery({ queryKey: ["settings"], queryFn: platformApi.settings, enabled: open });
  const [regions, setRegions] = useState<string[]>([]);
  const [services, setServices] = useState<string[]>([]);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const toast = useToast();

  useEffect(() => {
    if (open) setSelected(defaultAccountId ?? accountId ?? accounts[0]?.id);
  }, [open, defaultAccountId, accountId, accounts]);
  useEffect(() => setRegions(account?.regions.filter((r) => r.enabled).map((r) => r.name) ?? []), [account]);
  useEffect(() => setServices(settings?.scan_services ?? []), [settings]);

  const start = useMutation({
    mutationFn: () => scansApi.start(selected!, regions, services),
    onSuccess: (scan) => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      toast.success(`Scan ${scan.display_id} started`);
      onOpenChange(false);
      navigate(`/scans/${scan.id}`);
    },
  });

  const toggle = (list: string[], set: (v: string[]) => void, value: string) =>
    set(list.includes(value) ? list.filter((v) => v !== value) : [...list, value]);

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Run a security scan"
      description="Scans use read-only API calls. Nothing in your cloud account is changed."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" loading={start.isPending} disabled={!selected || !regions.length || !services.length} onClick={() => start.mutate()}>
            Start scan
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div>
          <label className="field-label" htmlFor="scan-account">
            Account
          </label>
          <select id="scan-account" className="input" value={selected ?? ""} onChange={(e) => setSelected(Number(e.target.value))}>
            {accounts.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} ({a.account_identifier})
              </option>
            ))}
          </select>
        </div>
        {account && (
          <div>
            <p className="field-label">Regions</p>
            <div className="flex flex-wrap gap-1.5">
              {account.regions
                .filter((r) => r.enabled)
                .map((r) => (
                  <ChipToggle key={r.name} active={regions.includes(r.name)} onClick={() => toggle(regions, setRegions, r.name)}>
                    {r.name}
                  </ChipToggle>
                ))}
            </div>
          </div>
        )}
        {settings && (
          <div>
            <p className="field-label">Services</p>
            <div className="flex flex-wrap gap-1.5">
              {settings.available_services.map((s) => (
                <ChipToggle key={s} active={services.includes(s)} onClick={() => toggle(services, setServices, s)}>
                  {s}
                </ChipToggle>
              ))}
            </div>
            <p className="mt-2 text-[12px] text-faint">
              Some checks combine data across services (for example, CloudTrail log buckets), so scanning all services gives the most accurate results.
            </p>
          </div>
        )}
        <InlineError error={start.error} />
      </div>
    </Dialog>
  );
}
