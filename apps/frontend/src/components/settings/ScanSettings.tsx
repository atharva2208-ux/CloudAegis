import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { platformApi } from "@/services";
import { Panel } from "@/components/ui/misc";
import { Button } from "@/components/ui/button";
import { ErrorState, InlineError, LoadingRows } from "@/components/ui/states";
import { useToast } from "@/components/ui/toast";
import { cn } from "@/lib/cn";
import { Switch } from "./RulesSettings";

const THRESHOLDS: { key: string; label: string; help: string; min: number; max: number }[] = [
  { key: "stale_credential_days", label: "Access key rotation (days)", help: "Access keys unused or older than this are flagged (IAM-004, IAM-005).", min: 30, max: 365 },
  { key: "unused_user_days", label: "Unused IAM user (days)", help: "Users with no console or key activity for this long are flagged.", min: 30, max: 365 },
  { key: "secret_rotation_days", label: "Secret rotation (days)", help: "Secrets not rotated within this window are flagged.", min: 7, max: 365 },
];

export function ScanSettings() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const { data, error, isLoading, refetch } = useQuery({ queryKey: ["settings"], queryFn: platformApi.settings });
  const [services, setServices] = useState<string[]>([]);
  const [thresholds, setThresholds] = useState<Record<string, number>>({});
  const [notify, setNotify] = useState(true);
  useEffect(() => {
    if (data) {
      setServices(data.scan_services);
      setThresholds(data.thresholds);
      setNotify(data.notify_on_critical);
    }
  }, [data]);
  const save = useMutation({
    mutationFn: () => platformApi.updateSettings({ scan_services: services, thresholds, notify_on_critical: notify }),
    onSuccess: (s) => {
      queryClient.setQueryData(["settings"], s);
      toast.success("Settings saved. They apply from the next scan.");
    },
  });

  if (isLoading) return <LoadingRows rows={5} />;
  if (error || !data) return <ErrorState error={error} onRetry={refetch} />;
  const invalid = THRESHOLDS.some((t) => !(thresholds[t.key] >= t.min && thresholds[t.key] <= t.max)) || !services.length;

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel title="Default scan coverage" bodyClassName="p-4">
        <p className="mb-3 text-[12.5px] text-muted">Services included when a scan is started without an explicit selection.</p>
        <div className="flex flex-wrap gap-1.5">
          {data.available_services.map((s) => {
            const on = services.includes(s);
            return (
              <button
                key={s}
                type="button"
                aria-pressed={on}
                onClick={() => setServices((cur) => (on ? cur.filter((x) => x !== s) : [...cur, s]))}
                className={cn("h-7 rounded-control border px-2.5 text-[12.5px]", on ? "border-accent/60 bg-accent-dim/40" : "border-line text-muted hover:border-line-strong")}
              >
                {s}
              </button>
            );
          })}
        </div>
      </Panel>
      <Panel title="Detection thresholds" bodyClassName="space-y-4 p-4">
        {THRESHOLDS.map((t) => (
          <div key={t.key} className="grid grid-cols-[minmax(0,1fr)_100px] items-center gap-3">
            <label htmlFor={t.key} className="text-[13px]">
              {t.label}
              <span className="block text-[12px] text-faint">{t.help}</span>
            </label>
            <input
              id={t.key}
              type="number"
              min={t.min}
              max={t.max}
              className="input text-right tabular-nums"
              value={thresholds[t.key] ?? ""}
              onChange={(e) => setThresholds((cur) => ({ ...cur, [t.key]: Number(e.target.value) }))}
            />
          </div>
        ))}
      </Panel>
      <Panel title="Notifications" bodyClassName="flex items-center justify-between gap-4 p-4">
        <span className="text-[13px]">
          Notify when a scan detects new critical findings
          <span className="block text-[12px] text-faint">Shown in the notification centre for all users with findings access.</span>
        </span>
        <Switch checked={notify} onChange={setNotify} label="Notify on critical findings" />
      </Panel>
      <Panel title="Platform" bodyClassName="space-y-2 p-4 text-[13px]">
        <p>
          Demo mode: <span className="text-muted">{data.demo_mode ? "enabled — simulated environment available" : "disabled"}</span>
        </p>
        <p>
          Session idle timeout: <span className="text-muted">{data.session_idle_minutes} minutes</span>
        </p>
        <p className="text-[12px] text-faint">These are set through environment variables at deploy time.</p>
      </Panel>
      <div className="lg:col-span-2">
        <InlineError error={save.error} />
        <Button variant="primary" className="mt-2" loading={save.isPending} disabled={invalid} onClick={() => save.mutate()}>
          Save settings
        </Button>
      </div>
    </div>
  );
}
