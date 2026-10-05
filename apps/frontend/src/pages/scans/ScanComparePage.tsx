import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, ArrowRight, Minus, TrendingDown, TrendingUp } from "lucide-react";
import { scansApi } from "@/services";
import { useUrlState } from "@/hooks/useUrlState";
import { PageHeader, Panel } from "@/components/ui/misc";
import { EmptyState, ErrorState, LoadingRows } from "@/components/ui/states";
import { SeverityBadge } from "@/components/ui/badges";
import { ScoreValue } from "@/components/scans/ScanTable";
import { cn } from "@/lib/cn";
import { SEVERITIES, SEVERITY_LABEL, dateTime, num } from "@/lib/format";
import type { BriefFinding } from "@/types/api";

/** Coloured delta where "good" depends on the metric: score up is good, findings up is bad. */
function Delta({ value, higherIsBetter = false, suffix = "" }: { value: number | null; higherIsBetter?: boolean; suffix?: string }) {
  if (value == null) return <span className="text-faint">—</span>;
  if (value === 0)
    return (
      <span className="inline-flex items-center gap-1 text-faint">
        <Minus className="h-3.5 w-3.5" aria-hidden /> 0
      </span>
    );
  const good = higherIsBetter ? value > 0 : value < 0;
  const Icon = value > 0 ? TrendingUp : TrendingDown;
  return (
    <span className={cn("inline-flex items-center gap-1 tabular-nums", good ? "text-ok" : "text-sev-critical")}>
      <Icon className="h-3.5 w-3.5" aria-hidden />
      {value > 0 ? "+" : ""}
      {Number.isInteger(value) ? value : value.toFixed(1)}
      {suffix}
    </span>
  );
}

function Row({ label, from, to, delta, higherIsBetter }: { label: string; from: React.ReactNode; to: React.ReactNode; delta: number | null; higherIsBetter?: boolean }) {
  return (
    <tr>
      <td className="text-muted">{label}</td>
      <td className="text-right tabular-nums">{from}</td>
      <td className="w-8 text-center text-faint">
        <ArrowRight className="inline h-3.5 w-3.5" aria-hidden />
      </td>
      <td className="tabular-nums">{to}</td>
      <td className="text-right">
        <Delta value={delta} higherIsBetter={higherIsBetter} />
      </td>
    </tr>
  );
}

function FindingList({ items, empty }: { items: BriefFinding[]; empty: string }) {
  if (!items.length) return <p className="p-4 text-[13px] text-faint">{empty}</p>;
  return (
    <ul className="max-h-[420px] divide-y divide-line overflow-y-auto">
      {items.map((f) => (
        <li key={f.id} className="flex items-start gap-3 px-4 py-2.5">
          <SeverityBadge severity={f.severity} className="w-[72px] shrink-0" />
          <div className="min-w-0">
            <Link to={`/findings/${f.id}`} className="block text-[13px] hover:text-accent-strong">
              {f.title}
            </Link>
            <span className="mono block truncate text-faint">
              {f.rule_id} · {f.asset_name}
            </span>
          </div>
        </li>
      ))}
    </ul>
  );
}

export default function ScanComparePage() {
  const url = useUrlState();
  const base = Number(url.get("base"));
  const target = Number(url.get("target"));
  const valid = base > 0 && target > 0 && base !== target;
  const scans = useQuery({
    queryKey: ["scans", { page_size: 100, status: ["COMPLETED", "PARTIAL"] }],
    queryFn: () => scansApi.list({ page_size: 100, status: ["COMPLETED", "PARTIAL"] }),
  });
  const { data, error, isLoading, refetch } = useQuery({
    queryKey: ["scan-compare", base, target],
    queryFn: () => scansApi.compare(base, target),
    enabled: valid,
  });

  const picker = (key: "base" | "target", value: number) => (
    <select className="input h-8 w-auto min-w-[260px] pr-8" aria-label={key === "base" ? "Baseline scan" : "Comparison scan"} value={value || ""} onChange={(e) => url.update({ [key]: e.target.value })}>
      <option value="">Select scan</option>
      {scans.data?.items.map((s) => (
        <option key={s.id} value={s.id}>
          {s.display_id} · {s.account_name} · {dateTime(s.finished_at)} · score {s.security_score ?? "—"}
        </option>
      ))}
    </select>
  );

  return (
    <>
      <Link to="/scans" className="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-muted hover:text-ink">
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Scans
      </Link>
      <PageHeader title="Security posture comparison" description="How posture changed between two scans: score, findings by severity, exposure and compliance." />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        {picker("base", base)}
        <ArrowRight className="h-4 w-4 text-faint" aria-hidden />
        {picker("target", target)}
      </div>

      {!valid ? (
        <div className="panel">
          <EmptyState title="Choose two different scans" description="Pick a baseline (earlier) scan and the scan to compare it with." />
        </div>
      ) : isLoading ? (
        <LoadingRows rows={8} />
      ) : error || !data ? (
        <div className="panel">
          <ErrorState error={error} onRetry={refetch} />
        </div>
      ) : (
        <>
          <div className="panel mb-4 grid gap-0 sm:grid-cols-3 sm:divide-x sm:divide-line">
            <div className="p-5">
              <p className="text-[12px] text-faint">Previous score · {data.base.display_id}</p>
              <p className="mt-2 text-[34px] font-semibold leading-none">
                <ScoreValue score={data.base.security_score} />
              </p>
            </div>
            <div className="p-5">
              <p className="text-[12px] text-faint">Current score · {data.target.display_id}</p>
              <p className="mt-2 text-[34px] font-semibold leading-none">
                <ScoreValue score={data.target.security_score} />
              </p>
            </div>
            <div className="p-5">
              <p className="text-[12px] text-faint">{(data.score_delta ?? 0) >= 0 ? "Improvement" : "Regression"}</p>
              <p className="mt-2 text-[34px] font-semibold leading-none">
                <Delta value={data.score_delta} higherIsBetter />
              </p>
            </div>
          </div>

          <div className="mb-4 grid gap-4 lg:grid-cols-2">
            <Panel title="Findings and exposure">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Metric</th>
                    <th className="text-right">{data.base.display_id}</th>
                    <th />
                    <th>{data.target.display_id}</th>
                    <th className="text-right">Change</th>
                  </tr>
                </thead>
                <tbody>
                  {SEVERITIES.filter((s) => s !== "INFO").map((s) => (
                    <Row
                      key={s}
                      label={`${SEVERITY_LABEL[s]} findings`}
                      from={num(data.base.severity_counts?.[s] ?? 0)}
                      to={num(data.target.severity_counts?.[s] ?? 0)}
                      delta={data.severity_delta[s] ?? 0}
                    />
                  ))}
                  <Row label="Public assets" from={num(data.base.public_assets)} to={num(data.target.public_assets)} delta={data.public_assets_delta} />
                  <Row label="Total assets" from={num(data.base.assets_discovered)} to={num(data.target.assets_discovered)} delta={null} />
                </tbody>
              </table>
            </Panel>
            <Panel title="Compliance">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Framework</th>
                    <th className="text-right">Before</th>
                    <th />
                    <th>After</th>
                    <th className="text-right">Change</th>
                  </tr>
                </thead>
                <tbody>
                  {data.compliance_delta.map((c) => (
                    <Row
                      key={c.key}
                      label={c.short_name}
                      from={c.base == null ? "—" : `${c.base.toFixed(1)}%`}
                      to={`${c.target.toFixed(1)}%`}
                      delta={c.delta == null ? null : Math.round(c.delta * 10) / 10}
                      higherIsBetter
                    />
                  ))}
                </tbody>
              </table>
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Panel title={`New findings (${data.new_findings.length})`}>
              <FindingList items={data.new_findings} empty="No new findings between these scans." />
            </Panel>
            <Panel title={`Resolved findings (${data.resolved_findings.length})`}>
              <FindingList items={data.resolved_findings} empty="No findings were resolved between these scans." />
            </Panel>
          </div>
        </>
      )}
    </>
  );
}
