import { Fragment, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronRight, ExternalLink } from "lucide-react";
import { platformApi } from "@/services";
import { PERMS, useAuth } from "@/stores/auth";
import { CodeBlock } from "@/components/ui/misc";
import { MultiFilter, SearchInput } from "@/components/ui/filters";
import { SeverityBadge } from "@/components/ui/badges";
import { ErrorState, LoadingRows } from "@/components/ui/states";
import { useToast } from "@/components/ui/toast";
import { cn } from "@/lib/cn";
import { errorMessage } from "@/lib/api";
import { SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL, num, resourceTypeLabel } from "@/lib/format";
import type { Rule } from "@/types/api";

function Switch({ checked, onChange, disabled, label }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; label: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={(e) => {
        e.stopPropagation();
        onChange(!checked);
      }}
      className={cn(
        "relative h-5 w-9 shrink-0 rounded-[1px] border transition-colors disabled:cursor-not-allowed disabled:opacity-60",
        checked ? "border-accent bg-accent/80" : "border-line-strong bg-raised",
      )}
    >
      <span className={cn("absolute top-0.5 h-3.5 w-3.5 rounded-[1px] bg-ink transition-[left]", checked ? "left-[18px]" : "left-0.5")} />
    </button>
  );
}

function RuleDetail({ r }: { r: Rule }) {
  return (
    <div className="grid gap-4 py-2 md:grid-cols-2">
      <div className="space-y-3 text-[13px]">
        <div>
          <p className="text-[12px] text-faint">Description</p>
          <p>{r.description}</p>
        </div>
        <div>
          <p className="text-[12px] text-faint">Impact</p>
          <p>{r.impact}</p>
        </div>
        <div>
          <p className="text-[12px] text-faint">Applies to</p>
          <p>{resourceTypeLabel(r.resource_type)}</p>
        </div>
        <div>
          <p className="text-[12px] text-faint">Compliance</p>
          <p className="flex flex-wrap gap-1.5">
            {r.compliance.map((c) => (
              <span key={`${c.framework}${c.control_id}`} className="rounded-control border border-line px-1.5 py-0.5 text-[12px] text-muted">
                {c.framework} {c.control_id}
              </span>
            ))}
          </p>
        </div>
      </div>
      <div className="space-y-3 text-[13px]">
        <div>
          <p className="text-[12px] text-faint">Remediation</p>
          <ol className="list-decimal space-y-1 pl-5 text-muted">
            {r.remediation_steps.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ol>
        </div>
        {r.remediation_cli && <CodeBlock code={r.remediation_cli} />}
        <div className="flex flex-wrap gap-3">
          {r.references.map((ref) => (
            <a key={ref} href={ref} target="_blank" rel="noopener noreferrer" className="link inline-flex items-center gap-1 text-[12.5px]">
              <ExternalLink className="h-3 w-3" aria-hidden /> {new URL(ref).hostname}
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}

export function RulesSettings() {
  const { can } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [q, setQ] = useState("");
  const [services, setServices] = useState<string[]>([]);
  const [severities, setSeverities] = useState<string[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const { data, error, isLoading, refetch } = useQuery({ queryKey: ["rules"], queryFn: platformApi.rules });
  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => platformApi.toggleRule(id, enabled),
    onSuccess: (r) => {
      queryClient.setQueryData<Rule[]>(["rules"], (old) => old?.map((x) => (x.rule_id === r.rule_id ? r : x)));
      toast.success(`${r.rule_id} ${r.enabled ? "enabled" : "disabled"}. Takes effect from the next scan.`);
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  const filtered = useMemo(() => {
    const needle = q.toLowerCase();
    return (data ?? []).filter(
      (r) =>
        (!services.length || services.includes(r.service)) &&
        (!severities.length || severities.includes(r.severity)) &&
        (!needle || `${r.rule_id} ${r.title} ${r.category}`.toLowerCase().includes(needle)),
    );
  }, [data, q, services, severities]);

  if (isLoading) return <LoadingRows />;
  if (error || !data) return <ErrorState error={error} onRetry={refetch} />;
  const serviceOptions = [...new Set(data.map((r) => r.service))].map((s) => ({ value: s, label: s, count: data.filter((r) => r.service === s).length }));
  const canManage = can(PERMS.settingsManage);
  const enabled = data.filter((r) => r.enabled).length;

  return (
    <>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <SearchInput value={q} onChange={setQ} placeholder="Search rules" className="w-full sm:w-64" />
        <MultiFilter label="Service" options={serviceOptions} selected={services} onChange={setServices} />
        <MultiFilter
          label="Severity"
          options={SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABEL[s], color: SEVERITY_COLOR[s] }))}
          selected={severities}
          onChange={setSeverities}
        />
        <span className="ml-auto text-[12.5px] text-faint">
          {enabled} of {data.length} rules enabled
        </span>
      </div>
      <div className="panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th className="w-8" />
                <th>Rule</th>
                <th>Service</th>
                <th>Category</th>
                <th>Severity</th>
                <th className="text-right">Open findings</th>
                <th className="text-right">Enabled</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r) => (
                <Fragment key={r.rule_id}>
                  <tr className="cursor-pointer" onClick={() => setOpen(open === r.rule_id ? null : r.rule_id)}>
                    <td>
                      <ChevronRight className={cn("h-4 w-4 text-faint transition-transform", open === r.rule_id && "rotate-90")} aria-hidden />
                    </td>
                    <td className={cn("min-w-[280px]", !r.enabled && "opacity-60")}>
                      {r.title}
                      <span className="mono block text-faint">{r.rule_id}</span>
                    </td>
                    <td className="text-muted">{r.service}</td>
                    <td className="whitespace-nowrap text-muted">{r.category}</td>
                    <td>
                      <SeverityBadge severity={r.severity} />
                    </td>
                    <td className="text-right tabular-nums">
                      {r.open_findings ? (
                        <Link to={`/findings?rule_id=${r.rule_id}`} className="link" onClick={(e) => e.stopPropagation()}>
                          {num(r.open_findings)}
                        </Link>
                      ) : (
                        <span className="text-faint">0</span>
                      )}
                    </td>
                    <td className="text-right">
                      <Switch
                        checked={r.enabled}
                        disabled={!canManage || toggle.isPending}
                        label={`${r.enabled ? "Disable" : "Enable"} ${r.rule_id}`}
                        onChange={(v) => toggle.mutate({ id: r.rule_id, enabled: v })}
                      />
                    </td>
                  </tr>
                  {open === r.rule_id && (
                    <tr>
                      <td />
                      <td colSpan={6} className="bg-canvas/40">
                        <RuleDetail r={r} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

export { Switch };
