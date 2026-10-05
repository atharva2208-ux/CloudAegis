import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { GitCompareArrows, Radar } from "lucide-react";
import { scansApi } from "@/services";
import { useUrlState } from "@/hooks/useUrlState";
import { useScope } from "@/stores/scope";
import { PERMS, useAuth } from "@/stores/auth";
import { PageHeader, Panel } from "@/components/ui/misc";
import { MultiFilter } from "@/components/ui/filters";
import { Pagination } from "@/components/ui/pagination";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingRows } from "@/components/ui/states";
import { ScanTable } from "@/components/scans/ScanTable";
import { ScanProgress } from "@/components/scans/ScanProgress";
import { StartScanDialog } from "@/components/scans/StartScanDialog";

const STATUSES = ["QUEUED", "RUNNING", "COMPLETED", "PARTIAL", "FAILED", "CANCELLED"];

export default function ScansPage() {
  const url = useUrlState(["status"]);
  const { accountId: scopeAccount, accounts } = useScope();
  const { can } = useAuth();
  const navigate = useNavigate();
  const [scanOpen, setScanOpen] = useState(false);
  const [selected, setSelected] = useState<number[]>([]);
  const accountId = url.get("account_id") ? Number(url.get("account_id")) : scopeAccount;

  const params = {
    account_id: accountId,
    status: url.getAll("status"),
    page: Number(url.get("page") ?? 1),
    page_size: Number(url.get("page_size") ?? 25),
  };
  const { data, error, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["scans", params],
    queryFn: () => scansApi.list(params),
    placeholderData: keepPreviousData,
  });
  const active = useQuery({
    queryKey: ["scans", "active"],
    queryFn: scansApi.active,
    refetchInterval: (q) => (q.state.data?.length ? 1500 : 15_000),
  });
  const activeScans = (active.data ?? []).filter((s) => !accountId || s.account_id === accountId);

  const compare = () => {
    const ordered = [...selected].sort((a, b) => a - b);
    navigate(`/scans/compare?base=${ordered[0]}&target=${ordered[1]}`);
  };

  return (
    <>
      <PageHeader
        title="Scans"
        description="Each scan discovers resources with read-only API calls, evaluates every enabled rule and records a posture snapshot."
        actions={
          <>
            <Button disabled={selected.length !== 2} onClick={compare} title="Select two completed scans to compare">
              <GitCompareArrows className="h-4 w-4" aria-hidden /> Compare{selected.length ? ` (${selected.length}/2)` : ""}
            </Button>
            {can(PERMS.scansRun) && accounts.length > 0 && (
              <Button variant="primary" onClick={() => setScanOpen(true)}>
                <Radar className="h-4 w-4" aria-hidden /> Run scan
              </Button>
            )}
          </>
        }
      />

      {activeScans.map((s) => (
        <Panel key={s.id} className="mb-4" title={`${s.display_id} · ${s.status === "QUEUED" ? "Queued" : "Running"}`} bodyClassName="p-4">
          <ScanProgress scan={s} />
        </Panel>
      ))}

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <select
          className="input h-8 w-auto pr-8"
          aria-label="Account"
          value={accountId ?? ""}
          onChange={(e) => url.update({ account_id: e.target.value })}
        >
          <option value="">All accounts</option>
          {accounts.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </select>
        <MultiFilter
          label="Status"
          selected={url.getAll("status")}
          onChange={(v) => url.update({ status: v })}
          options={STATUSES.map((s) => ({ value: s, label: s.charAt(0) + s.slice(1).toLowerCase() }))}
        />
        <span className="ml-auto text-[12.5px] text-faint">Tick two completed scans to compare posture.</span>
      </div>

      <div className="panel overflow-hidden">
        {isLoading ? (
          <LoadingRows />
        ) : error ? (
          <ErrorState error={error} onRetry={refetch} />
        ) : !data?.items.length ? (
          <EmptyState icon={<Radar className="h-7 w-7" />} title="No scans yet" description="Run a scan to discover resources and evaluate security rules." />
        ) : (
          <div className={isFetching ? "opacity-70" : undefined}>
            <ScanTable
              scans={data.items}
              selectable
              selected={selected}
              onToggle={(id) => setSelected((cur) => (cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]))}
            />
          </div>
        )}
        {data && data.total > 0 && (
          <div className="border-t border-line">
            <Pagination
              page={data.page}
              pages={data.pages}
              total={data.total}
              pageSize={data.page_size}
              onPage={(p) => url.update({ page: p }, false)}
              onPageSize={(s) => url.update({ page_size: s })}
            />
          </div>
        )}
      </div>
      <StartScanDialog open={scanOpen} onOpenChange={setScanOpen} />
    </>
  );
}
