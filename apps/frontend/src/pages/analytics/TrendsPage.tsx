import { useQuery } from "@tanstack/react-query";
import { TrendingUp } from "lucide-react";
import { platformApi } from "@/services";
import { useScope } from "@/stores/scope";
import { useUrlState } from "@/hooks/useUrlState";
import { PageHeader, Panel, Stat } from "@/components/ui/misc";
import { EmptyState, ErrorState, LoadingPanel } from "@/components/ui/states";
import { MultiLineChart, NewResolvedChart, ScoreTrendChart, SeverityTrendChart, SimpleBars } from "@/components/charts";
import { SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL, num } from "@/lib/format";

const RANGES = [
  { value: 30, label: "30 days" },
  { value: 90, label: "90 days" },
  { value: 180, label: "180 days" },
  { value: 365, label: "1 year" },
];
const COMPLIANCE_COLORS = ["#F5A524", "#3B9EFF", "#3DD68C", "#9E8CFC"];

function hours(h: number | null): string {
  if (h == null) return "—";
  if (h < 48) return `${h.toFixed(0)} h`;
  return `${(h / 24).toFixed(1)} d`;
}

export default function TrendsPage() {
  const { accountId } = useScope();
  const url = useUrlState();
  const days = Number(url.get("days") ?? 90);
  const { data, error, isLoading, refetch } = useQuery({
    queryKey: ["trends", accountId, days],
    queryFn: () => platformApi.trends(accountId, days),
  });

  const header = (
    <PageHeader
      title="Security trends"
      description="How posture, findings and compliance have moved across completed scans."
      actions={
        <div className="inline-flex rounded-control border border-line p-0.5" role="tablist" aria-label="Time range">
          {RANGES.map((r) => (
            <button
              key={r.value}
              role="tab"
              aria-selected={days === r.value}
              onClick={() => url.update({ days: r.value })}
              className={`h-7 rounded-[4px] px-2.5 text-[12.5px] ${days === r.value ? "bg-raised text-ink" : "text-muted hover:text-ink"}`}
            >
              {r.label}
            </button>
          ))}
        </div>
      }
    />
  );

  if (isLoading)
    return (
      <>
        {header}
        <div className="grid gap-4 lg:grid-cols-2">
          <LoadingPanel />
          <LoadingPanel />
        </div>
      </>
    );
  if (error || !data)
    return (
      <>
        {header}
        <div className="panel">
          <ErrorState error={error} onRetry={refetch} />
        </div>
      </>
    );
  if (!data.scans.length)
    return (
      <>
        {header}
        <div className="panel">
          <EmptyState icon={<TrendingUp className="h-7 w-7" />} title="No scans in this period" description="Trends appear once scans have completed in the selected range." />
        </div>
      </>
    );

  const first = data.scans[0];
  const last = data.scans[data.scans.length - 1];
  const frameworks = Object.keys(last.compliance ?? {});
  // Flatten for charts: per-scan numeric series without the nested compliance map.
  const series = data.scans.map(({ compliance: _c, ...rest }) => rest);
  const compliance = data.scans.map((s) => ({ date: s.date, ...s.compliance }));
  const exposure = data.scans.map((s) => ({ date: s.date, public: s.public_assets, assets: s.assets }));
  const delta = last.score - first.score;

  return (
    <>
      {header}
      <div className="panel mb-4 grid grid-cols-2 gap-y-4 p-5 md:grid-cols-5">
        <Stat label="Current score" value={last.score} sub={`${delta >= 0 ? "+" : ""}${delta} over ${data.scans.length} scans`} />
        <Stat label="Open findings" value={num(last.total)} sub={`${first.total - last.total >= 0 ? "−" : "+"}${num(Math.abs(first.total - last.total))} since ${first.display_id}`} />
        <Stat label="Critical open" value={num(last.CRITICAL)} tone={SEVERITY_COLOR.CRITICAL} sub={`${num(first.CRITICAL)} at start of period`} />
        <Stat label="MTTR · critical" value={hours(data.mttr.CRITICAL?.hours ?? null)} sub={`${num(data.mttr.CRITICAL?.resolved ?? 0)} resolved`} />
        <Stat label="MTTR · high" value={hours(data.mttr.HIGH?.hours ?? null)} sub={`${num(data.mttr.HIGH?.resolved ?? 0)} resolved`} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Security score" bodyClassName="p-4">
          <ScoreTrendChart data={series} height={230} />
        </Panel>
        <Panel title="Open findings by severity" bodyClassName="p-4">
          <SeverityTrendChart data={series} height={230} />
        </Panel>
        <Panel title="New vs resolved per scan" bodyClassName="p-4">
          <NewResolvedChart data={series.slice(1)} height={230} />
        </Panel>
        <Panel title="Compliance by framework" bodyClassName="p-4">
          <MultiLineChart
            data={compliance}
            domain={[0, 100]}
            height={230}
            lines={frameworks.map((f, i) => ({ key: f, name: f, color: COMPLIANCE_COLORS[i % COMPLIANCE_COLORS.length] }))}
          />
        </Panel>
        <Panel title="Internet-exposed assets" bodyClassName="p-4">
          <MultiLineChart data={exposure} height={230} lines={[{ key: "public", name: "Public assets", color: SEVERITY_COLOR.HIGH }]} />
        </Panel>
        <Panel title="Age of open findings" bodyClassName="p-4">
          <SimpleBars data={data.open_age} dataKey="count" categoryKey="bucket" name="Open findings" height={230} />
        </Panel>
      </div>

      <Panel title="Mean time to remediate" className="mt-4">
        <table className="data-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th className="text-right">Findings resolved</th>
              <th className="text-right">Mean time to resolve</th>
            </tr>
          </thead>
          <tbody>
            {SEVERITIES.map((s) => (
              <tr key={s}>
                <td style={{ color: SEVERITY_COLOR[s] }}>{SEVERITY_LABEL[s]}</td>
                <td className="text-right tabular-nums">{num(data.mttr[s]?.resolved ?? 0)}</td>
                <td className="text-right tabular-nums">{hours(data.mttr[s]?.hours ?? null)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="px-4 py-2.5 text-[12px] text-faint">Measured from first detection to resolution for findings resolved in the selected period.</p>
      </Panel>
    </>
  );
}
