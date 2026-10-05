import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck, Ticket } from "lucide-react";
import { findingsApi, platformApi } from "@/services";
import { useUrlState } from "@/hooks/useUrlState";
import { useDebounce } from "@/hooks/useDebounce";
import { useScope } from "@/stores/scope";
import { PERMS, useAuth } from "@/stores/auth";
import { PageHeader } from "@/components/ui/misc";
import { MultiFilter, SearchInput, SortHeader } from "@/components/ui/filters";
import { Pagination } from "@/components/ui/pagination";
import { EmptyState, ErrorState, LoadingRows } from "@/components/ui/states";
import { ExposureMark, SeverityBadge, StatusBadge } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { StatusDialog } from "@/components/findings/StatusActions";
import { useToast } from "@/components/ui/toast";
import { SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL, STATUS_LABEL, relative, resourceTypeLabel } from "@/lib/format";
import { errorMessage } from "@/lib/api";
import type { FindingStatus } from "@/types/api";

const ACTIVE: FindingStatus[] = ["OPEN", "ACKNOWLEDGED", "IN_PROGRESS"];
const ALL_STATUSES: FindingStatus[] = ["OPEN", "ACKNOWLEDGED", "IN_PROGRESS", "RESOLVED", "SUPPRESSED"];
const FRAMEWORKS = [
  { value: "cis-aws", label: "CIS AWS" },
  { value: "aws-wa-security", label: "AWS Security" },
  { value: "nist-csf", label: "NIST CSF" },
];
const DATE_RANGES = [
  { value: "", label: "Any time" },
  { value: "1", label: "Last 24 hours" },
  { value: "7", label: "Last 7 days" },
  { value: "30", label: "Last 30 days" },
];

export default function FindingsPage() {
  const url = useUrlState(["severity", "status", "service", "region", "rule_id"]);
  const { accountId } = useScope();
  const { can } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [q, setQ] = useState(url.get("q") ?? "");
  const debouncedQ = useDebounce(q, 300);
  const [selected, setSelected] = useState<number[]>([]);
  const [bulkStatus, setBulkStatus] = useState<FindingStatus | null>(null);

  useEffect(() => {
    if ((url.get("q") ?? "") !== debouncedQ) url.update({ q: debouncedQ });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedQ]);

  const status = url.getAll("status").length ? (url.getAll("status") as FindingStatus[]) : ACTIVE;
  const page = Number(url.get("page") ?? 1);
  const pageSize = Number(url.get("page_size") ?? 25);
  const sort = url.get("sort") ?? "severity";
  const order = (url.get("order") as "asc" | "desc") ?? (sort === "severity" ? "asc" : "desc");
  const days = url.get("days");
  const detectedFrom = useMemo(
    () => (days ? new Date(Date.now() - Number(days) * 86400_000).toISOString() : undefined),
    [days],
  );

  const params = {
    q: url.get("q"),
    severity: url.getAll("severity"),
    status,
    service: url.getAll("service"),
    region: url.getAll("region"),
    rule_id: url.getAll("rule_id"),
    framework: url.get("framework"),
    control: url.get("control"),
    public_only: url.get("public_only") === "true" || undefined,
    detected_from: detectedFrom,
    account_id: accountId,
    page,
    page_size: pageSize,
    sort,
    order,
  };

  const { data, error, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["findings", params],
    queryFn: () => findingsApi.list(params),
    placeholderData: keepPreviousData,
  });
  const { data: facets } = useQuery({ queryKey: ["finding-facets", accountId], queryFn: () => findingsApi.facets(accountId) });
  const { data: rules } = useQuery({ queryKey: ["rules"], queryFn: platformApi.rules, staleTime: 300_000 });

  useEffect(() => setSelected([]), [data]);

  const bulk = useMutation({
    mutationFn: ({ status: s, note }: { status: FindingStatus; note: string }) => findingsApi.bulkStatus(selected, s, note),
    onSuccess: (res) => {
      toast.success(res.message);
      setBulkStatus(null);
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["finding-facets"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  const facetCount = (key: keyof NonNullable<typeof facets>, value: string) =>
    facets?.[key].find((f) => f.value === value)?.count;

  const hasFilters = ["q", "severity", "service", "region", "rule_id", "framework", "days", "public_only", "status"].some((k) => url.params.has(k));
  const items = data?.items ?? [];
  const allSelected = items.length > 0 && selected.length === items.length;
  const canUpdate = can(PERMS.findingsUpdate);

  return (
    <>
      <PageHeader
        title="Findings"
        description="Misconfigurations and risky settings detected across your cloud accounts. Filters are kept in the URL, so you can share a view."
      />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <SearchInput value={q} onChange={setQ} placeholder="Search title, rule, resource or FND-ID" className="w-full sm:w-80" />
        <MultiFilter
          label="Severity"
          selected={url.getAll("severity")}
          onChange={(v) => url.update({ severity: v })}
          options={SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABEL[s], color: SEVERITY_COLOR[s], count: facetCount("severity", s) }))}
        />
        <MultiFilter
          label="Status"
          selected={status}
          onChange={(v) => url.update({ status: v.length ? v : ALL_STATUSES })}
          options={ALL_STATUSES.map((s) => ({ value: s, label: STATUS_LABEL[s], count: facetCount("status", s) }))}
        />
        <MultiFilter
          label="Service"
          selected={url.getAll("service")}
          onChange={(v) => url.update({ service: v })}
          options={(facets?.service ?? []).map((f) => ({ value: f.value, label: f.value, count: f.count }))}
        />
        <MultiFilter
          label="Region"
          selected={url.getAll("region")}
          onChange={(v) => url.update({ region: v })}
          options={(facets?.region ?? []).map((f) => ({ value: f.value, label: f.value, count: f.count }))}
        />
        <MultiFilter
          label="Rule"
          searchable
          selected={url.getAll("rule_id")}
          onChange={(v) => url.update({ rule_id: v })}
          options={(rules ?? []).map((r) => ({ value: r.rule_id, label: `${r.rule_id} ${r.title}`, count: facetCount("rule", r.rule_id) }))}
        />
        <select
          className="input h-8 w-auto pr-8"
          aria-label="Compliance framework"
          value={url.get("framework") ?? ""}
          onChange={(e) => url.update({ framework: e.target.value, control: undefined })}
        >
          <option value="">Any framework</option>
          {FRAMEWORKS.map((f) => (
            <option key={f.value} value={f.value}>
              {f.label}
              {url.get("control") && url.get("framework") === f.value ? ` ${url.get("control")}` : ""}
            </option>
          ))}
        </select>
        <select className="input h-8 w-auto pr-8" aria-label="Detected" value={days ?? ""} onChange={(e) => url.update({ days: e.target.value })}>
          {DATE_RANGES.map((d) => (
            <option key={d.value} value={d.value}>
              {d.label}
            </option>
          ))}
        </select>
        <label className="inline-flex h-8 items-center gap-2 rounded-control border border-line px-2.5 text-[12.5px] text-muted">
          <input type="checkbox" className="accent-[#F5A524]" checked={url.get("public_only") === "true"} onChange={(e) => url.update({ public_only: e.target.checked })} />
          Internet-exposed only
        </label>
        {hasFilters && (
          <Button variant="ghost" size="sm" onClick={() => { setQ(""); url.clear(); }}>
            Reset filters
          </Button>
        )}
      </div>

      {canUpdate && selected.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2 rounded-panel border border-accent/40 bg-accent-dim/20 px-4 py-2 text-[13px]">
          <span className="mr-2">{selected.length} selected</span>
          <Button size="sm" onClick={() => setBulkStatus("ACKNOWLEDGED")}>Acknowledge</Button>
          <Button size="sm" onClick={() => setBulkStatus("IN_PROGRESS")}>Mark in progress</Button>
          <Button size="sm" onClick={() => setBulkStatus("RESOLVED")}>Mark resolved</Button>
          <Button size="sm" variant="danger" onClick={() => setBulkStatus("SUPPRESSED")}>Suppress</Button>
          <Button size="sm" variant="ghost" onClick={() => setSelected([])}>Clear</Button>
        </div>
      )}

      <div className="panel overflow-hidden">
        {isLoading ? (
          <LoadingRows />
        ) : error ? (
          <ErrorState error={error} onRetry={refetch} />
        ) : items.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck className="h-7 w-7" />}
            title={hasFilters ? "No findings match these filters" : "No open findings"}
            description={hasFilters ? "Adjust or reset the filters to widen the search." : "Every check passed in the latest scan, or no scan has run yet."}
          />
        ) : (
          <div className={`overflow-x-auto ${isFetching ? "opacity-70" : ""}`}>
            <table className="data-table">
              <thead>
                <tr>
                  {canUpdate && (
                    <th className="w-9">
                      <input
                        type="checkbox"
                        aria-label="Select all on this page"
                        className="accent-[#F5A524]"
                        checked={allSelected}
                        onChange={() => setSelected(allSelected ? [] : items.map((f) => f.id))}
                      />
                    </th>
                  )}
                  <SortHeader label="Severity" field="severity" sort={sort} order={order} onSort={(s, o) => url.update({ sort: s, order: o })} />
                  <SortHeader label="Finding" field="title" sort={sort} order={order} onSort={(s, o) => url.update({ sort: s, order: o })} />
                  <th>Resource</th>
                  <SortHeader label="Service" field="service" sort={sort} order={order} onSort={(s, o) => url.update({ sort: s, order: o })} />
                  <SortHeader label="Region" field="region" sort={sort} order={order} onSort={(s, o) => url.update({ sort: s, order: o })} />
                  <SortHeader label="Status" field="status" sort={sort} order={order} onSort={(s, o) => url.update({ sort: s, order: o })} />
                  <SortHeader label="First detected" field="first_detected" sort={sort} order={order} onSort={(s, o) => url.update({ sort: s, order: o })} />
                </tr>
              </thead>
              <tbody>
                {items.map((f) => (
                  <tr key={f.id}>
                    {canUpdate && (
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`Select ${f.display_id}`}
                          className="accent-[#F5A524]"
                          checked={selected.includes(f.id)}
                          onChange={() => setSelected((s) => (s.includes(f.id) ? s.filter((x) => x !== f.id) : [...s, f.id]))}
                        />
                      </td>
                    )}
                    <td className="whitespace-nowrap"><SeverityBadge severity={f.severity} /></td>
                    <td className="min-w-[280px] max-w-[420px]">
                      <Link to={`/findings/${f.id}`} className="block text-ink hover:text-accent-strong">
                        {f.title}
                      </Link>
                      <span className="mono text-faint">
                        {f.display_id} {f.rule_id}
                      </span>
                      {f.ticket_ref && (
                        <span className="ml-2 inline-flex items-center gap-1 text-[12px] text-muted">
                          <Ticket className="h-3 w-3" aria-hidden />
                          {f.ticket_ref}
                        </span>
                      )}
                    </td>
                    <td className="max-w-[280px]">
                      <Link to={`/assets/${f.asset_id}`} className="block truncate hover:text-accent-strong" title={f.resource_uid}>
                        {f.asset_name}
                      </Link>
                      <span className="flex items-center gap-2 text-[12px] text-faint">
                        {resourceTypeLabel(f.resource_type)}
                        {f.public_exposure && <ExposureMark exposed />}
                      </span>
                    </td>
                    <td className="whitespace-nowrap text-muted">{f.service}</td>
                    <td className="whitespace-nowrap text-muted">{f.region}</td>
                    <td><StatusBadge status={f.status} /></td>
                    <td className="whitespace-nowrap text-muted" title={f.first_detected_at}>{relative(f.first_detected_at)}</td>
                  </tr>
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

      <StatusDialog
        status={bulkStatus}
        count={selected.length}
        onClose={() => setBulkStatus(null)}
        onConfirm={(note) => bulkStatus && bulk.mutate({ status: bulkStatus, note })}
        pending={bulk.isPending}
        error={bulk.error}
      />
    </>
  );
}
