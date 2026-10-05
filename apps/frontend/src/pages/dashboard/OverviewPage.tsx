import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Building2, Radar } from "lucide-react";
import { platformApi } from "@/services";
import { useScope } from "@/stores/scope";
import { PERMS, useAuth } from "@/stores/auth";
import { Button } from "@/components/ui/button";
import { PageHeader, Panel } from "@/components/ui/misc";
import { EmptyState, ErrorState, LoadingPanel, Skeleton } from "@/components/ui/states";
import { DemoBadge, ExposureMark, RiskMeter, SeverityBadge } from "@/components/ui/badges";
import { ScorePanel, postureLabel } from "@/components/dashboard/ScorePanel";
import type { DashboardSummary } from "@/types/api";
import { ScanProgress } from "@/components/scans/ScanProgress";
import { StartScanDialog } from "@/components/scans/StartScanDialog";
import { CoverageBar, ScoreTrendChart, SeverityDonut, SeverityTrendChart, StackedSeverityBars } from "@/components/charts";
import { SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL, num, relative, resourceTypeLabel } from "@/lib/format";

function Kpi({ label, value, sub, tone, to }: { label: string; value: ReactNode; sub?: ReactNode; tone?: string; to?: string }) {
  const body = (
    <>
      <p className="eyebrow">{label}</p>
      <p className="mt-2 font-mono text-[28px] font-medium leading-none tabular-nums" style={tone ? { color: tone } : undefined}>
        {value}
      </p>
      {sub && <p className="mt-2 text-[12px] text-muted">{sub}</p>}
    </>
  );
  return to ? (
    <Link to={to} className="block px-4 py-4 transition-colors hover:bg-raised">
      {body}
    </Link>
  ) : (
    <div className="px-4 py-4">{body}</div>
  );
}

function KpiStrip({ data }: { data: DashboardSummary }) {
  // Prefer the API's previous score; fall back to the trend so "all accounts" scope still shows movement.
  const trend = data.score_trend;
  const previous = data.previous_score ?? (trend.length > 1 ? trend[trend.length - 2].score : null);
  const delta = previous == null || !data.score ? null : data.score.score - previous;
  const band = data.score ? postureLabel(data.score.score) : null;
  return (
    <section className="panel grid grid-cols-2 divide-line sm:grid-cols-3 sm:divide-x xl:grid-cols-6" aria-label="Key posture metrics">
      <div className="border-l-2 border-accent">
        <Kpi
          label="Security score"
          value={
            <>
              {data.score?.score ?? "—"}
              <span className="text-[14px] text-faint"> /100</span>
            </>
          }
          tone={band?.color}
          sub={delta == null ? "first assessment" : delta === 0 ? "unchanged since previous scan" : `${delta > 0 ? "▲ +" : "▼ "}${delta} since previous scan`}
        />
      </div>
      <Kpi label="Critical" value={num(data.severity_counts.CRITICAL)} tone={SEVERITY_COLOR.CRITICAL} sub="open findings" to="/findings?severity=CRITICAL" />
      <Kpi label="High" value={num(data.severity_counts.HIGH)} tone={SEVERITY_COLOR.HIGH} sub="open findings" to="/findings?severity=HIGH" />
      <Kpi label="Open findings" value={num(data.open_findings)} sub="all severities" to="/findings" />
      <Kpi label="Assets" value={num(data.assets)} sub={`${num(data.public_assets)} internet-exposed`} to="/assets" />
      <Kpi label="Last scan" value={<span className="text-[18px]">{relative(data.last_scan_at)}</span>} sub={`${data.accounts_scanned} account${data.accounts_scanned === 1 ? "" : "s"} assessed`} to="/scans" />
    </section>
  );
}

export default function OverviewPage() {
  const { accountId, accounts, current } = useScope();
  const { can } = useAuth();
  const [scanOpen, setScanOpen] = useState(false);
  const { data, error, isLoading, refetch } = useQuery({
    queryKey: ["dashboard", accountId],
    queryFn: () => platformApi.dashboard(accountId),
    refetchInterval: (q) => (q.state.data?.active_scans.length ? 2000 : 60_000),
  });

  const header = (
    <PageHeader
      title="Cloud security posture"
      description={current ? `${current.name} · AWS ${current.account_identifier}` : `All connected accounts (${accounts.length})`}
      meta={
        data?.last_scan_at ? (
          <>
            {current?.is_demo && <DemoBadge />}
            <span className="text-[12.5px] text-faint">Last scan {relative(data.last_scan_at)}</span>
          </>
        ) : undefined
      }
      actions={
        can(PERMS.scansRun) && accounts.length > 0 ? (
          <Button variant="primary" onClick={() => setScanOpen(true)}>
            <Radar className="h-4 w-4" aria-hidden /> Run scan
          </Button>
        ) : undefined
      }
    />
  );

  if (isLoading)
    return (
      <>
        {header}
        <div className="grid gap-4 lg:grid-cols-3">
          <Skeleton className="h-56 lg:col-span-2" />
          <Skeleton className="h-56" />
          <Skeleton className="h-64 lg:col-span-3" />
        </div>
      </>
    );
  if (error)
    return (
      <>
        {header}
        <div className="panel">
          <ErrorState error={error} onRetry={refetch} />
        </div>
      </>
    );
  if (!data) return null;

  if (accounts.length === 0)
    return (
      <>
        {header}
        <div className="panel">
          <EmptyState
            icon={<Building2 className="h-7 w-7" />}
            title="Connect your first cloud account"
            description="CloudAegis assesses AWS accounts through a read-only audit role. You can also explore the simulated demo environment."
            action={
              can(PERMS.accountsManage) && (
                <Link to="/accounts/new">
                  <Button variant="primary">Add an account</Button>
                </Link>
              )
            }
          />
        </div>
      </>
    );

  return (
    <>
      {header}
      <StartScanDialog open={scanOpen} onOpenChange={setScanOpen} />

      {data.active_scans.map((scan) => (
        <Panel
          key={scan.id}
          className="mb-4 border-accent/40"
          title={`Scan ${scan.display_id} in progress`}
          actions={<Link to={`/scans/${scan.id}`} className="link text-[12.5px]">View scan</Link>}
          bodyClassName="p-4"
        >
          <ScanProgress scan={scan} />
        </Panel>
      ))}

      {!data.score ? (
        <div className="panel">
          <EmptyState
            icon={<Radar className="h-7 w-7" />}
            title="No completed scans yet"
            description="Run a scan to discover assets and evaluate them against the detection rules."
            action={can(PERMS.scansRun) && <Button variant="primary" onClick={() => setScanOpen(true)}>Run first scan</Button>}
          />
        </div>
      ) : (
        <div className="space-y-4">
          <KpiStrip data={data} />

          <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)_minmax(0,0.9fr)]">
            <ScorePanel score={data.score} />
            <Panel title="Risk distribution" actions={<Link to="/findings" className="link text-[12px]">All findings</Link>} bodyClassName="flex items-center gap-5 p-4">
              <SeverityDonut counts={data.severity_counts} size={148} />
              <ul className="flex-1 space-y-1">
                {SEVERITIES.map((s) => (
                  <li key={s}>
                    <Link to={`/findings?severity=${s}&status=OPEN&status=ACKNOWLEDGED&status=IN_PROGRESS`} className="flex items-center justify-between px-1.5 py-1 text-[13px] hover:bg-raised">
                      <span className="flex items-center gap-2">
                        <span className="h-2.5 w-2.5" style={{ background: SEVERITY_COLOR[s] }} />
                        {SEVERITY_LABEL[s]}
                      </span>
                      <span className="font-mono tabular-nums">{num(data.severity_counts[s])}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </Panel>
            <Panel title="Control coverage" bodyClassName="space-y-4 p-4">
              <CoverageBar label="Encryption at rest" value={data.encryption.coverage} covered={data.encryption.encrypted} total={data.encryption.encrypted + data.encryption.unencrypted} />
              <CoverageBar label="MFA on console users" value={data.mfa.coverage} covered={data.mfa.covered} total={data.mfa.total} />
              <div>
                <div className="flex items-baseline justify-between">
                  <span className="text-[12.5px] text-muted">Internet-exposed assets</span>
                  <span className="font-mono text-[13px] tabular-nums text-sev-high">{num(data.public_assets)}</span>
                </div>
                <p className="mt-1 text-[11.5px] text-faint">
                  {data.public_by_service.slice(0, 4).map((p) => `${p.service} ${p.count}`).join(" · ") || "None"}
                </p>
              </div>
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Panel title="Security score trend" bodyClassName="p-4 pt-3">
              {data.score_trend.length > 1 ? <ScoreTrendChart data={data.score_trend} /> : <p className="py-16 text-center text-[13px] text-muted">The trend appears after the second scan.</p>}
            </Panel>
            <Panel title="Findings over time" bodyClassName="p-4 pt-3">
              <SeverityTrendChart data={data.findings_trend} height={200} />
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Panel title="Open findings by service" bodyClassName="p-4">
              <StackedSeverityBars data={data.findings_by_service} categoryKey="service" />
            </Panel>
            <Panel title="Compliance" actions={<Link to="/compliance" className="link text-[12.5px]">Frameworks</Link>} bodyClassName="divide-y divide-line">
              {data.compliance.map((f) => (
                <Link key={f.key} to={`/compliance/${f.key}`} className="block px-4 py-3.5 hover:bg-raised/50">
                  <div className="flex items-baseline justify-between">
                    <span className="text-[13px]">{f.name}</span>
                    <span className="text-[17px] font-semibold tabular-nums">{f.score.toFixed(1)}%</span>
                  </div>
                  <div className="mt-2 h-1.5 overflow-hidden rounded-[1px] bg-line">
                    <div className="h-full rounded-[1px] bg-accent" style={{ width: `${f.score}%` }} />
                  </div>
                  <p className="mt-1.5 text-[12px] text-faint">
                    Resource compliance · {f.passed} of {f.total} controls fully passing{f.not_applicable ? ` · ${f.not_applicable} not applicable` : ""}
                  </p>
                </Link>
              ))}
            </Panel>
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <Panel title="Top risky assets" className="xl:col-span-2" actions={<Link to="/assets?sort=risk" className="link text-[12.5px]">All assets</Link>} bodyClassName="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Asset</th>
                    <th>Type</th>
                    <th>Region</th>
                    <th>Exposure</th>
                    <th className="text-right">Findings</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {data.top_risky_assets.map((a) => (
                    <tr key={a.id}>
                      <td className="max-w-[260px]">
                        <Link to={`/assets/${a.id}`} className="block truncate hover:text-accent-strong">{a.name}</Link>
                      </td>
                      <td className="whitespace-nowrap text-muted">{resourceTypeLabel(a.resource_type)}</td>
                      <td className="whitespace-nowrap text-muted">{a.region}</td>
                      <td><ExposureMark exposed={a.public_exposure} /></td>
                      <td className="text-right tabular-nums">{a.open_findings}</td>
                      <td><RiskMeter score={a.risk_score} level={a.risk_level} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
            <Panel title="Recently detected" actions={<Link to="/findings?sort=first_detected&order=desc" className="link text-[12.5px]">View all</Link>}>
              <ul className="divide-y divide-line">
                {data.recent_findings.map((f) => (
                  <li key={f.id}>
                    <Link to={`/findings/${f.id}`} className="block px-4 py-3 hover:bg-raised/50">
                      <div className="flex items-center justify-between gap-2">
                        <SeverityBadge severity={f.severity} />
                        <span className="text-[11.5px] text-faint">{relative(f.first_detected_at)}</span>
                      </div>
                      <p className="mt-1 text-[13px] leading-snug">{f.title}</p>
                      <p className="mt-0.5 truncate text-[12px] text-faint">{f.asset_name}</p>
                    </Link>
                  </li>
                ))}
              </ul>
            </Panel>
          </div>
        </div>
      )}
      {isLoading && <LoadingPanel />}
    </>
  );
}
