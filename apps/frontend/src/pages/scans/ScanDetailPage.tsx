import { useEffect } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, GitCompareArrows, OctagonX } from "lucide-react";
import { scansApi } from "@/services";
import { PERMS, useAuth } from "@/stores/auth";
import { KeyValue, Panel, ProgressBar } from "@/components/ui/misc";
import { Button } from "@/components/ui/button";
import { DemoBadge, ScanStatusBadge } from "@/components/ui/badges";
import { ErrorState, LoadingRows } from "@/components/ui/states";
import { useToast } from "@/components/ui/toast";
import { ScanProgress } from "@/components/scans/ScanProgress";
import { ScorePanel } from "@/components/dashboard/ScorePanel";
import { errorMessage } from "@/lib/api";
import { SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL, dateTime, duration, num } from "@/lib/format";
import type { ScoreBreakdown } from "@/types/api";

export default function ScanDetailPage() {
  const id = Number(useParams().id);
  const { can } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const { data: scan, error, isLoading, refetch } = useQuery({
    queryKey: ["scan", id],
    queryFn: () => scansApi.get(id),
    refetchInterval: (q) => (q.state.data && ["QUEUED", "RUNNING"].includes(q.state.data.status) ? 1500 : false),
  });
  const running = !!scan && ["QUEUED", "RUNNING"].includes(scan.status);

  // Previous completed scan of the same account, for one-click comparison.
  const history = useQuery({
    queryKey: ["scans", { account_id: scan?.account_id, page_size: 50, status: ["COMPLETED", "PARTIAL"] }],
    queryFn: () => scansApi.list({ account_id: scan!.account_id, page_size: 50, status: ["COMPLETED", "PARTIAL"] }),
    enabled: !!scan && !running,
  });
  const previous = history.data?.items.find((s) => s.id < id);

  useEffect(() => {
    if (scan && !running) {
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["findings"] });
    }
  }, [running, scan, queryClient]);

  const cancel = useMutation({
    mutationFn: () => scansApi.cancel(id),
    onSuccess: (s) => {
      queryClient.setQueryData(["scan", id], s);
      toast.success("Cancellation requested");
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  if (isLoading) return <LoadingRows rows={8} />;
  if (error || !scan) return <div className="panel"><ErrorState error={error} onRetry={refetch} /></div>;
  const breakdown = "score" in scan.score_breakdown ? (scan.score_breakdown as ScoreBreakdown) : null;
  const services = scan.progress.services ?? [];
  const errors = Object.entries(scan.service_errors ?? {});

  return (
    <>
      <Link to="/scans" className="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-muted hover:text-ink">
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Scans
      </Link>
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-3 text-[20px] font-semibold">
            <span className="mono text-[18px]">{scan.display_id}</span>
            <ScanStatusBadge status={scan.status} />
            {scan.is_demo && <DemoBadge />}
          </h1>
          <p className="mt-1.5 text-[13px] text-muted">
            <Link to={`/accounts/${scan.account_id}`} className="link">
              {scan.account_name}
            </Link>{" "}
            · started {dateTime(scan.started_at ?? scan.queued_at)}
            {scan.triggered_by && ` by ${scan.triggered_by}`}
          </p>
        </div>
        <div className="flex gap-2">
          {previous && (
            <Link to={`/scans/compare?base=${previous.id}&target=${scan.id}`}>
              <Button>
                <GitCompareArrows className="h-4 w-4" aria-hidden /> Compare with {previous.display_id}
              </Button>
            </Link>
          )}
          {running && can(PERMS.scansRun) && (
            <Button variant="danger" loading={cancel.isPending} onClick={() => cancel.mutate()}>
              <OctagonX className="h-4 w-4" aria-hidden /> Cancel scan
            </Button>
          )}
        </div>
      </div>

      {scan.error_message && (
        <div className="mb-4 rounded-panel border border-sev-critical/40 bg-sev-critical/10 px-4 py-3 text-[13px] text-[#FF8589]" role="alert">
          {scan.error_message}
        </div>
      )}

      {running ? (
        <Panel title="Live progress" className="mb-4" bodyClassName="p-5">
          <ScanProgress scan={scan} />
        </Panel>
      ) : (
        <>
          {breakdown && (
            <div className="mb-4">
              <ScorePanel score={breakdown} previous={previous?.security_score ?? null} />
            </div>
          )}
          <div className="panel mb-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 lg:divide-x lg:divide-line">
            <div className="p-4">
              <p className="text-[12px] text-faint">Duration</p>
              <p className="mt-1.5 text-[18px] font-semibold tabular-nums">{duration(scan.duration_seconds)}</p>
            </div>
            <div className="p-4">
              <p className="text-[12px] text-faint">Assets</p>
              <p className="mt-1.5 text-[18px] font-semibold tabular-nums">{num(scan.assets_discovered)}</p>
            </div>
            <div className="p-4">
              <p className="text-[12px] text-faint">Checks evaluated</p>
              <p className="mt-1.5 text-[18px] font-semibold tabular-nums">{num(scan.checks_evaluated)}</p>
            </div>
            <div className="p-4">
              <p className="text-[12px] text-faint">Open findings</p>
              <p className="mt-1.5 text-[18px] font-semibold tabular-nums">{num(scan.findings_total)}</p>
            </div>
            <div className="p-4">
              <p className="text-[12px] text-faint">New / resolved</p>
              <p className="mt-1.5 text-[18px] font-semibold tabular-nums">
                <span className="text-sev-high">+{scan.findings_new}</span> <span className="text-faint">/</span>{" "}
                <span className="text-ok">−{scan.findings_resolved}</span>
              </p>
            </div>
            <div className="p-4">
              <p className="text-[12px] text-faint">Public assets</p>
              <p className="mt-1.5 text-[18px] font-semibold tabular-nums">{num(scan.public_assets)}</p>
            </div>
          </div>
        </>
      )}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="min-w-0 space-y-4">
          <Panel title="Services">
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Service</th>
                    <th>Status</th>
                    <th className="text-right">Resources</th>
                    <th className="text-right">Findings</th>
                    <th className="w-1/3">Progress</th>
                  </tr>
                </thead>
                <tbody>
                  {services.map((s) => (
                    <tr key={s.service}>
                      <td>
                        <Link to={`/findings?service=${s.service}`} className="hover:text-accent-strong">
                          {s.service}
                        </Link>
                      </td>
                      <td className="text-muted">
                        {s.status === "failed" ? <span className="text-sev-critical" title={s.error ?? undefined}>Failed</span> : s.status}
                      </td>
                      <td className="text-right tabular-nums">{num(s.resources)}</td>
                      <td className="text-right tabular-nums">{num(s.findings)}</td>
                      <td>
                        <ProgressBar value={s.percent} tone={s.status === "failed" ? "fail" : s.status === "completed" ? "ok" : "accent"} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
          {errors.length > 0 && (
            <Panel title="Collection errors" bodyClassName="divide-y divide-line">
              {errors.map(([svc, msg]) => (
                <div key={svc} className="px-4 py-2.5 text-[13px]">
                  <span className="font-medium">{svc}</span> <span className="text-muted">{msg}</span>
                </div>
              ))}
              <p className="px-4 py-2.5 text-[12px] text-faint">
                Rules for services that could not be collected are skipped, not counted as passing. Check the audit role's permissions.
              </p>
            </Panel>
          )}
        </div>
        <aside className="space-y-4">
          {!running && (
            <Panel title="Findings by severity" bodyClassName="space-y-2 p-4">
              {SEVERITIES.map((s) => (
                <Link key={s} to={`/findings?severity=${s}`} className="flex items-center gap-3 text-[13px] hover:text-accent-strong">
                  <span className="h-3 w-[3px] rounded-[1px]" style={{ background: SEVERITY_COLOR[s] }} aria-hidden />
                  <span className="flex-1">{SEVERITY_LABEL[s]}</span>
                  <span className="tabular-nums">{num(scan.severity_counts?.[s] ?? 0)}</span>
                </Link>
              ))}
            </Panel>
          )}
          {scan.compliance_summary.length > 0 && (
            <Panel title="Compliance at this scan" bodyClassName="space-y-3 p-4">
              {scan.compliance_summary.map((c) => (
                <Link key={c.key} to={`/compliance/${c.key}`} className="block hover:text-accent-strong">
                  <div className="flex items-baseline justify-between text-[13px]">
                    <span>{c.short_name}</span>
                    <span className="tabular-nums">{c.score.toFixed(1)}%</span>
                  </div>
                  <ProgressBar value={c.score} className="mt-1.5" tone={c.score >= 85 ? "ok" : "accent"} />
                </Link>
              ))}
            </Panel>
          )}
          <Panel title="Scope" bodyClassName="grid gap-3 p-4">
            <KeyValue label="Regions">{scan.regions.join(", ")}</KeyValue>
            <KeyValue label="Services">{scan.services.join(", ")}</KeyValue>
            <KeyValue label="Queued">{dateTime(scan.queued_at)}</KeyValue>
            <KeyValue label="Finished">{dateTime(scan.finished_at)}</KeyValue>
          </Panel>
        </aside>
      </div>
    </>
  );
}
