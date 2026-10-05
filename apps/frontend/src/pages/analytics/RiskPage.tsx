import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { platformApi } from "@/services";
import { useScope } from "@/stores/scope";
import { PageHeader, Panel } from "@/components/ui/misc";
import { ErrorState, LoadingPanel } from "@/components/ui/states";
import { ExposureMark, RiskMeter, SeverityBadge } from "@/components/ui/badges";
import { StackedSeverityBars } from "@/components/charts";
import { num, resourceTypeLabel } from "@/lib/format";

function Ratio({ label, part, total, tone }: { label: string; part: number; total: number; tone: string }) {
  const pct = total ? (part / total) * 100 : 0;
  return (
    <div className="grid grid-cols-[96px_minmax(0,1fr)_80px] items-center gap-3 py-1.5 text-[13px]">
      <span className="text-muted">{label}</span>
      <div className="h-1.5 overflow-hidden rounded-[1px] bg-line">
        <div className="h-full rounded-[1px]" style={{ width: `${pct}%`, background: tone }} />
      </div>
      <span className="text-right text-[12.5px] tabular-nums text-muted">
        {num(part)} / {num(total)}
      </span>
    </div>
  );
}

export default function RiskPage() {
  const { accountId } = useScope();
  const { data, error, isLoading, refetch } = useQuery({ queryKey: ["risk", accountId], queryFn: () => platformApi.risk(accountId) });

  const header = (
    <PageHeader
      title="Risk analytics"
      description="Where open risk is concentrated. Weighted risk multiplies each open finding by its severity weight."
    />
  );
  if (isLoading)
    return (
      <>
        {header}
        <div className="grid gap-4 lg:grid-cols-2">
          <LoadingPanel height="h-80" />
          <LoadingPanel height="h-80" />
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

  const w = data.severity_weights;
  const maxCategory = Math.max(1, ...data.by_category.map((c) => c.count));

  return (
    <>
      {header}
      <p className="mb-4 text-[12.5px] text-faint">
        Severity weights: critical {w.CRITICAL} · high {w.HIGH} · medium {w.MEDIUM} · low {w.LOW} · info {w.INFO}
      </p>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Open findings by service" bodyClassName="p-4">
          <StackedSeverityBars data={data.by_service} categoryKey="key" />
        </Panel>
        <Panel title="Open findings by region" bodyClassName="p-4">
          <StackedSeverityBars data={data.by_region} categoryKey="key" />
        </Panel>

        <Panel title="Weighted risk ranking">
          <table className="data-table">
            <thead>
              <tr>
                <th>Service</th>
                <th className="text-right">Open</th>
                <th className="text-right">Weighted risk</th>
                <th className="text-right">Share</th>
              </tr>
            </thead>
            <tbody>
              {(() => {
                const total = data.by_service.reduce((a, s) => a + s.weighted, 0) || 1;
                return [...data.by_service]
                  .sort((a, b) => b.weighted - a.weighted)
                  .map((s) => (
                    <tr key={s.key}>
                      <td>
                        <Link to={`/findings?service=${s.key}`} className="hover:text-accent-strong">
                          {s.key}
                        </Link>
                      </td>
                      <td className="text-right tabular-nums">{num(s.total)}</td>
                      <td className="text-right tabular-nums">{num(s.weighted)}</td>
                      <td className="text-right tabular-nums text-muted">{((s.weighted / total) * 100).toFixed(1)}%</td>
                    </tr>
                  ));
              })()}
            </tbody>
          </table>
        </Panel>

        <Panel title="Findings by category" bodyClassName="p-4">
          {data.by_category.map((c) => (
            <div key={c.category} className="grid grid-cols-[160px_minmax(0,1fr)_48px] items-center gap-3 py-1.5 text-[13px]">
              <span className="truncate text-muted">{c.category}</span>
              <div className="h-1.5 overflow-hidden rounded-[1px] bg-line">
                <div className="h-full rounded-[1px] bg-accent" style={{ width: `${(c.count / maxCategory) * 100}%` }} />
              </div>
              <span className="text-right tabular-nums">{num(c.count)}</span>
            </div>
          ))}
        </Panel>

        <Panel title="Internet exposure by service" bodyClassName="p-4">
          {data.exposure_by_service.filter((e) => e.total).map((e) => (
            <Ratio key={e.service} label={e.service} part={e.public} total={e.total} tone="#F76B15" />
          ))}
        </Panel>
        <Panel title="Encryption coverage by service" bodyClassName="p-4">
          {data.encryption_by_service.map((e) => (
            <Ratio key={e.service} label={e.service} part={e.encrypted} total={e.encrypted + e.unencrypted} tone="#3DD68C" />
          ))}
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Panel title="Most frequent failing rules">
          <table className="data-table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Severity</th>
                <th className="text-right">Open</th>
              </tr>
            </thead>
            <tbody>
              {data.top_rules.map((r) => (
                <tr key={r.rule_id}>
                  <td>
                    <Link to={`/findings?rule_id=${r.rule_id}`} className="hover:text-accent-strong">
                      {r.title}
                    </Link>
                    <span className="mono block text-faint">{r.rule_id}</span>
                  </td>
                  <td>
                    <SeverityBadge severity={r.severity} />
                  </td>
                  <td className="text-right tabular-nums">{num(r.count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
        <Panel title="Highest-risk assets">
          <table className="data-table">
            <thead>
              <tr>
                <th>Asset</th>
                <th>Exposure</th>
                <th>Risk</th>
                <th className="text-right">Findings</th>
              </tr>
            </thead>
            <tbody>
              {data.top_risky_assets.map((a) => (
                <tr key={a.id}>
                  <td className="max-w-[260px]">
                    <Link to={`/assets/${a.id}`} className="block truncate hover:text-accent-strong">
                      {a.name}
                    </Link>
                    <span className="text-[12px] text-faint">
                      {resourceTypeLabel(a.resource_type)} · {a.region}
                    </span>
                  </td>
                  <td>
                    <ExposureMark exposed={a.public_exposure} />
                  </td>
                  <td>
                    <RiskMeter score={a.risk_score} level={a.risk_level} />
                  </td>
                  <td className="text-right tabular-nums">{a.open_findings}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>
    </>
  );
}
