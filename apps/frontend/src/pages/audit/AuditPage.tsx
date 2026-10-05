import { Fragment, useEffect, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ChevronRight, ScrollText } from "lucide-react";
import { platformApi } from "@/services";
import { useUrlState } from "@/hooks/useUrlState";
import { useDebounce } from "@/hooks/useDebounce";
import { PageHeader } from "@/components/ui/misc";
import { SearchInput } from "@/components/ui/filters";
import { Pagination } from "@/components/ui/pagination";
import { Button } from "@/components/ui/button";
import { JsonTree } from "@/components/ui/json";
import { EmptyState, ErrorState, LoadingRows } from "@/components/ui/states";
import { cn } from "@/lib/cn";
import { dateTime, humanizeAction } from "@/lib/format";
import type { AuditLog } from "@/types/api";

const RESULT_STYLE: Record<AuditLog["result"], string> = {
  success: "text-ok",
  failure: "text-[#FF8589]",
  denied: "text-sev-high",
};

const RANGES = [
  { value: "", label: "Any time" },
  { value: "1", label: "Last 24 hours" },
  { value: "7", label: "Last 7 days" },
  { value: "30", label: "Last 30 days" },
];

export default function AuditPage() {
  const url = useUrlState();
  const [q, setQ] = useState(url.get("q") ?? "");
  const [open, setOpen] = useState<number | null>(null);
  const debounced = useDebounce(q, 300);
  useEffect(() => {
    if ((url.get("q") ?? "") !== debounced) url.update({ q: debounced });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debounced]);

  const days = url.get("days");
  const params = {
    q: url.get("q"),
    action: url.get("action"),
    user: url.get("user"),
    result: url.get("result"),
    since: days ? new Date(Date.now() - Number(days) * 86400_000).toISOString().slice(0, 16) + ":00Z" : undefined,
    page: Number(url.get("page") ?? 1),
    page_size: Number(url.get("page_size") ?? 50),
  };
  const { data, error, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["audit", params],
    queryFn: () => platformApi.audit(params),
    placeholderData: keepPreviousData,
  });
  const { data: facets } = useQuery({ queryKey: ["audit-facets"], queryFn: platformApi.auditFacets });
  const hasFilters = ["q", "action", "user", "result", "days"].some((k) => url.params.has(k));

  const select = (key: string, label: string, options: string[], format: (v: string) => string = (v) => v) => (
    <select className="input h-8 w-auto max-w-[220px] pr-8" aria-label={label} value={url.get(key) ?? ""} onChange={(e) => url.update({ [key]: e.target.value })}>
      <option value="">{label}</option>
      {options.map((o) => (
        <option key={o} value={o}>
          {format(o)}
        </option>
      ))}
    </select>
  );

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Append-only record of security-relevant activity: sign-ins, account changes, scans, finding decisions, reports and administration."
      />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <SearchInput value={q} onChange={setQ} placeholder="Search resource, IP or request ID" className="w-full sm:w-72" />
        {select("action", "Any action", facets?.actions ?? [], humanizeAction)}
        {select("user", "Any user", facets?.users ?? [])}
        {select("result", "Any result", facets?.results ?? [], (v) => v.charAt(0).toUpperCase() + v.slice(1))}
        <select className="input h-8 w-auto pr-8" aria-label="Time range" value={days ?? ""} onChange={(e) => url.update({ days: e.target.value })}>
          {RANGES.map((r) => (
            <option key={r.value} value={r.value}>
              {r.label}
            </option>
          ))}
        </select>
        {hasFilters && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setQ("");
              url.clear();
            }}
          >
            Reset filters
          </Button>
        )}
      </div>
      <div className="panel overflow-hidden">
        {isLoading ? (
          <LoadingRows />
        ) : error ? (
          <ErrorState error={error} onRetry={refetch} />
        ) : !data?.items.length ? (
          <EmptyState icon={<ScrollText className="h-7 w-7" />} title="No audit events match" description="Adjust or reset the filters." />
        ) : (
          <div className={cn("overflow-x-auto", isFetching && "opacity-70")}>
            <table className="data-table">
              <thead>
                <tr>
                  <th className="w-8" />
                  <th>Timestamp</th>
                  <th>User</th>
                  <th>Action</th>
                  <th>Resource</th>
                  <th>IP address</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((e) => (
                  <Fragment key={e.id}>
                    <tr className="cursor-pointer" onClick={() => setOpen(open === e.id ? null : e.id)}>
                      <td>
                        <button aria-label="Toggle details" aria-expanded={open === e.id} className="text-faint hover:text-ink">
                          <ChevronRight className={cn("h-4 w-4 transition-transform", open === e.id && "rotate-90")} />
                        </button>
                      </td>
                      <td className="whitespace-nowrap tabular-nums text-muted">{dateTime(e.timestamp)}</td>
                      <td className="whitespace-nowrap">{e.user_email ?? <span className="text-faint">system</span>}</td>
                      <td className="whitespace-nowrap">
                        {humanizeAction(e.action)}
                        <span className="mono block text-faint">{e.action}</span>
                      </td>
                      <td className="mono max-w-[260px] truncate text-muted" title={`${e.resource_type ?? ""} ${e.resource_id ?? ""}`}>
                        {e.resource_type ? `${e.resource_type}/${e.resource_id ?? ""}` : "—"}
                      </td>
                      <td className="mono whitespace-nowrap text-muted">{e.ip_address ?? "—"}</td>
                      <td className={cn("whitespace-nowrap capitalize", RESULT_STYLE[e.result])}>{e.result}</td>
                    </tr>
                    {open === e.id && (
                      <tr>
                        <td />
                        <td colSpan={6} className="bg-canvas/40">
                          <div className="grid gap-3 py-1 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
                            <div>
                              <p className="mb-1 text-[12px] text-faint">Details</p>
                              <JsonTree data={e.details} />
                            </div>
                            <dl className="space-y-2 text-[12.5px]">
                              <div>
                                <dt className="text-faint">Request ID</dt>
                                <dd className="mono">{e.request_id ?? "—"}</dd>
                              </div>
                              <div>
                                <dt className="text-faint">User agent</dt>
                                <dd className="break-all text-muted">{e.user_agent ?? "—"}</dd>
                              </div>
                            </dl>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
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
    </>
  );
}
