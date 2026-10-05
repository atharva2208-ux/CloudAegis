import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, ChevronRight } from "lucide-react";
import { complianceApi } from "@/services";
import { useScope } from "@/stores/scope";
import { useUrlState } from "@/hooks/useUrlState";
import { Panel } from "@/components/ui/misc";
import { SearchInput } from "@/components/ui/filters";
import { SeverityBadge } from "@/components/ui/badges";
import { EmptyState, ErrorState, LoadingRows } from "@/components/ui/states";
import { ComplianceRing, ControlStatus } from "@/components/compliance/ControlStatus";
import { CompactFindingList } from "@/components/findings/CompactFindingList";
import { ScoreTrendChart } from "@/components/charts";
import { cn } from "@/lib/cn";
import { num, relative } from "@/lib/format";
import type { ControlResult } from "@/types/api";

const FILTERS = [
  { value: "", label: "All" },
  { value: "FAIL", label: "Failed" },
  { value: "PASS", label: "Passed" },
  { value: "NOT_APPLICABLE", label: "Not applicable" },
] as const;

function ControlFindings({ frameworkKey, controlId }: { frameworkKey: string; controlId: string }) {
  const { accountId } = useScope();
  const { data, isLoading, error } = useQuery({
    queryKey: ["control-findings", frameworkKey, controlId, accountId],
    queryFn: () => complianceApi.controlFindings(frameworkKey, controlId, accountId),
  });
  if (isLoading) return <LoadingRows rows={3} />;
  if (error) return <ErrorState error={error} />;
  return (
    <>
      <CompactFindingList findings={(data ?? []).slice(0, 25)} showResource empty="No open findings for this control." />
      {(data?.length ?? 0) > 25 && (
        <p className="px-4 py-2.5 text-[12.5px]">
          <Link className="link" to={`/findings?framework=${frameworkKey}&control=${encodeURIComponent(controlId)}`}>
            View all {num(data!.length)} findings
          </Link>
        </p>
      )}
    </>
  );
}

function ControlRow({ c, frameworkKey, open, onToggle }: { c: ControlResult; frameworkKey: string; open: boolean; onToggle: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (open) ref.current?.scrollIntoView({ block: "nearest" });
    // only on first open
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <div ref={ref} className="border-b border-line last:border-b-0">
      <button
        className="grid w-full grid-cols-[20px_72px_minmax(0,1fr)_120px_120px] items-center gap-3 px-4 py-3 text-left hover:bg-raised/50"
        onClick={onToggle}
        aria-expanded={open}
      >
        <ChevronRight className={cn("h-4 w-4 text-faint transition-transform", open && "rotate-90")} aria-hidden />
        <span className="mono text-[12.5px] text-muted">{c.control_id}</span>
        <span className="min-w-0">
          <span className="block text-[13.5px]">{c.title}</span>
          <span className="block truncate text-[12px] text-faint">{c.description}</span>
        </span>
        <ControlStatus status={c.status} />
        <span className="text-right text-[12.5px] tabular-nums text-muted">
          {c.status === "NOT_APPLICABLE" ? "no resources" : `${num(c.failed_resources)} / ${num(c.evaluated_resources)} failing`}
        </span>
      </button>
      {open && (
        <div className="border-t border-line bg-canvas/40">
          <div className="px-4 py-3 pl-[52px]">
            <p className="mb-2 text-[12px] font-medium text-faint">Mapped checks</p>
            <div className="overflow-x-auto rounded-control border border-line">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Severity</th>
                    <th className="text-right">Evaluated</th>
                    <th className="text-right">Failed</th>
                    <th>Remediation</th>
                  </tr>
                </thead>
                <tbody>
                  {c.rules.map((r) => (
                    <tr key={r.rule_id}>
                      <td className="min-w-[220px]">
                        <Link to={`/findings?rule_id=${r.rule_id}`} className="hover:text-accent-strong">
                          {r.title}
                        </Link>
                        <span className="mono block text-faint">{r.rule_id}</span>
                      </td>
                      <td>
                        <SeverityBadge severity={r.severity} />
                      </td>
                      <td className="text-right tabular-nums">{num(r.evaluated)}</td>
                      <td className={cn("text-right tabular-nums", r.failed > 0 && "text-[#FF8589]")}>{num(r.failed)}</td>
                      <td className="min-w-[260px] text-[12.5px] text-muted">{r.remediation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          {c.status === "FAIL" && (
            <div className="pb-2 pl-[36px]">
              <p className="px-4 pb-1 text-[12px] font-medium text-faint">Related findings</p>
              <ControlFindings frameworkKey={frameworkKey} controlId={c.control_id} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function FrameworkDetailPage() {
  const { key = "" } = useParams();
  const { accountId } = useScope();
  const url = useUrlState();
  const [q, setQ] = useState("");
  const focus = url.get("control");
  const [expanded, setExpanded] = useState<string[]>(focus ? [focus] : []);
  const status = url.get("status") ?? "";
  const { data, error, isLoading, refetch } = useQuery({
    queryKey: ["framework", key, accountId],
    queryFn: () => complianceApi.framework(key, accountId),
  });

  const sections = useMemo(() => {
    const out = new Map<string, ControlResult[]>();
    const needle = q.trim().toLowerCase();
    (data?.controls ?? [])
      .filter((c) => !status || c.status === status)
      .filter((c) => !needle || `${c.control_id} ${c.title} ${c.description}`.toLowerCase().includes(needle))
      .forEach((c) => out.set(c.section, [...(out.get(c.section) ?? []), c]));
    return [...out.entries()];
  }, [data, status, q]);

  if (isLoading) return <LoadingRows rows={10} />;
  if (error || !data) return <div className="panel"><ErrorState error={error} onRetry={refetch} /></div>;
  const toggle = (id: string) => setExpanded((cur) => (cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]));
  const counts: Record<string, number> = { "": data.controls.length, FAIL: data.failed, PASS: data.passed, NOT_APPLICABLE: data.not_applicable };

  return (
    <>
      <Link to="/compliance" className="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-muted hover:text-ink">
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Frameworks
      </Link>
      <div className="mb-4 grid gap-4 lg:grid-cols-[minmax(0,1fr)_420px]">
        <div className="panel flex gap-5 p-5">
          <ComplianceRing value={data.score} size={96} />
          <div className="min-w-0">
            <h1 className="text-[20px] font-semibold">{data.name}</h1>
            <p className="mt-0.5 text-[12.5px] text-faint">
              Version {data.version}
              {data.as_of && ` · assessed ${relative(data.as_of)}`}
            </p>
            <p className="mt-2 text-[13px] text-muted">{data.description}</p>
            <div className="mt-3 flex gap-5 text-[13px]">
              <span>
                <span className="font-semibold tabular-nums text-ok">{data.passed}</span> <span className="text-muted">passed</span>
              </span>
              <span>
                <span className="font-semibold tabular-nums text-[#FF8589]">{data.failed}</span> <span className="text-muted">failed</span>
              </span>
              <span>
                <span className="font-semibold tabular-nums">{data.not_applicable}</span> <span className="text-muted">not applicable</span>
              </span>
            </div>
          </div>
        </div>
        <Panel title="Compliance over time" bodyClassName="p-3">
          {data.trend.length > 1 ? <ScoreTrendChart data={data.trend} height={140} /> : <p className="p-6 text-center text-[13px] text-faint">Trend appears after two scans.</p>}
        </Panel>
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="inline-flex rounded-control border border-line p-0.5" role="tablist" aria-label="Control status">
          {FILTERS.map((f) => (
            <button
              key={f.value}
              role="tab"
              aria-selected={status === f.value}
              onClick={() => url.update({ status: f.value })}
              className={cn("h-7 rounded-[4px] px-2.5 text-[12.5px]", status === f.value ? "bg-raised text-ink" : "text-muted hover:text-ink")}
            >
              {f.label} <span className="tabular-nums text-faint">{counts[f.value]}</span>
            </button>
          ))}
        </div>
        <SearchInput value={q} onChange={setQ} placeholder="Search controls" className="w-full sm:w-64" />
      </div>

      {sections.length === 0 ? (
        <div className="panel">
          <EmptyState title="No controls match" description="Change the status filter or search text." />
        </div>
      ) : (
        <div className="space-y-4">
          {sections.map(([section, controls]) => (
            <Panel key={section} title={section} actions={<span className="text-[12px] text-faint">{controls.length} controls</span>}>
              {controls.map((c) => (
                <ControlRow key={c.control_id} c={c} frameworkKey={key} open={expanded.includes(c.control_id)} onToggle={() => toggle(c.control_id)} />
              ))}
            </Panel>
          ))}
        </div>
      )}
    </>
  );
}
