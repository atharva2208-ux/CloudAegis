import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ClipboardCheck } from "lucide-react";
import { complianceApi } from "@/services";
import { useScope } from "@/stores/scope";
import { PageHeader, Panel } from "@/components/ui/misc";
import { EmptyState, ErrorState, LoadingPanel } from "@/components/ui/states";
import { ComplianceRing } from "@/components/compliance/ControlStatus";
import { MultiLineChart } from "@/components/charts";
import { relative } from "@/lib/format";
import type { FrameworkOverview } from "@/types/api";

const LINE_COLORS = ["#F5A524", "#3B9EFF", "#3DD68C", "#9E8CFC", "#F76B15"];

function FrameworkCard({ f }: { f: FrameworkOverview }) {
  const assessed = f.passed + f.failed;
  return (
    <Link to={`/compliance/${f.key}`} className="panel group flex flex-col p-5 transition-colors hover:border-line-strong">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="text-[15px] font-semibold group-hover:text-accent-strong">{f.short_name}</p>
          <p className="mt-0.5 text-[12px] text-faint">
            {f.name} · v{f.version}
          </p>
        </div>
        <ComplianceRing value={f.score} />
      </div>
      <p className="mt-3 line-clamp-2 text-[12.5px] text-muted">{f.description}</p>
      <div className="mt-4 grid grid-cols-3 gap-2 border-t border-line pt-3 text-[12px]">
        <div>
          <p className="text-faint">Passed</p>
          <p className="mt-0.5 text-[15px] font-semibold tabular-nums text-ok">{f.passed}</p>
        </div>
        <div>
          <p className="text-faint">Failed</p>
          <p className="mt-0.5 text-[15px] font-semibold tabular-nums text-[#FF8589]">{f.failed}</p>
        </div>
        <div>
          <p className="text-faint">Not applicable</p>
          <p className="mt-0.5 text-[15px] font-semibold tabular-nums text-muted">{f.not_applicable}</p>
        </div>
      </div>
      <p className="mt-3 text-[11.5px] text-faint">
        {assessed} of {f.total} controls assessed. The percentage is resource-weighted: the share of evaluated resources that satisfy each control.
      </p>
    </Link>
  );
}

export default function FrameworksPage() {
  const { accountId } = useScope();
  const { data, error, isLoading, refetch } = useQuery({
    queryKey: ["compliance", accountId],
    queryFn: () => complianceApi.frameworks(accountId),
  });

  // Merge per-framework trends into one series keyed by scan.
  const trend = (() => {
    if (!data) return [];
    const byScan = new Map<number, Record<string, number | string>>();
    data.frameworks.forEach((f) =>
      f.trend.forEach((p) => {
        const row = byScan.get(p.scan_id) ?? { date: p.date };
        row[f.key] = p.score;
        byScan.set(p.scan_id, row);
      }),
    );
    return [...byScan.entries()].sort((a, b) => a[0] - b[0]).map(([, v]) => v);
  })();

  return (
    <>
      <PageHeader
        title="Compliance frameworks"
        description="Rule results mapped to framework controls. Each control passes only when every related check passes on every applicable resource."
        meta={data?.as_of ? <span className="text-[12.5px] text-faint">Assessed {relative(data.as_of)}</span> : undefined}
      />
      {isLoading ? (
        <div className="grid gap-4 lg:grid-cols-3">
          <LoadingPanel />
          <LoadingPanel />
          <LoadingPanel />
        </div>
      ) : error || !data ? (
        <div className="panel">
          <ErrorState error={error} onRetry={refetch} />
        </div>
      ) : !data.assessed ? (
        <div className="panel">
          <EmptyState
            icon={<ClipboardCheck className="h-7 w-7" />}
            title="No compliance assessment yet"
            description="Compliance is calculated from scan results. Run a scan to assess your accounts against each framework."
          />
        </div>
      ) : (
        <>
          <div className="mb-4 grid gap-4 lg:grid-cols-3">
            {data.frameworks.map((f) => (
              <FrameworkCard key={f.key} f={f} />
            ))}
          </div>
          {trend.length > 1 && (
            <Panel title="Compliance trend" bodyClassName="p-4">
              <MultiLineChart
                data={trend}
                domain={[0, 100]}
                lines={data.frameworks.map((f, i) => ({ key: f.key, name: f.short_name, color: LINE_COLORS[i % LINE_COLORS.length] }))}
              />
            </Panel>
          )}
        </>
      )}
    </>
  );
}
