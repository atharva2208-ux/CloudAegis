import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Boxes } from "lucide-react";
import { assetsApi } from "@/services";
import { useUrlState } from "@/hooks/useUrlState";
import { useDebounce } from "@/hooks/useDebounce";
import { useScope } from "@/stores/scope";
import { PageHeader } from "@/components/ui/misc";
import { MultiFilter, SearchInput, SortHeader } from "@/components/ui/filters";
import { Pagination } from "@/components/ui/pagination";
import { EmptyState, ErrorState, LoadingRows, Skeleton } from "@/components/ui/states";
import { EncryptionMark, ExposureMark, RiskMeter } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";
import { SEVERITY_COLOR, num, relative, resourceTypeLabel } from "@/lib/format";
import type { AssetStats } from "@/types/api";

const RISK_OPTIONS = [
  { value: "CRITICAL", label: "Critical", color: SEVERITY_COLOR.CRITICAL },
  { value: "HIGH", label: "High", color: SEVERITY_COLOR.HIGH },
  { value: "MEDIUM", label: "Medium", color: SEVERITY_COLOR.MEDIUM },
  { value: "LOW", label: "Low", color: SEVERITY_COLOR.LOW },
  { value: "NONE", label: "No open findings", color: "#38383E" },
];

function ServiceStrip({ stats, active, onSelect }: { stats?: AssetStats; active: string[]; onSelect: (s: string) => void }) {
  if (!stats)
    return (
      <div className="panel mb-4 flex gap-6 p-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-20" />
        ))}
      </div>
    );
  return (
    <div className="panel mb-4 overflow-x-auto">
      <div className="flex min-w-max divide-x divide-line">
        <div className="px-5 py-3">
          <p className="text-[12px] text-faint">Total assets</p>
          <p className="mt-1 text-[22px] font-semibold tabular-nums">{num(stats.total)}</p>
          <p className="mt-0.5 text-[12px] text-muted">
            <span className="text-sev-high">{num(stats.public)}</span> internet-exposed
          </p>
        </div>
        {stats.by_service.map((s) => (
          <button
            key={s.service}
            onClick={() => onSelect(s.service)}
            aria-pressed={active.includes(s.service)}
            className={cn(
              "px-4 py-3 text-left transition-colors hover:bg-raised/60",
              active.includes(s.service) && "bg-accent-dim/25 shadow-[inset_0_-2px_0_#F5A524]",
            )}
          >
            <p className="text-[12px] text-faint">{s.service}</p>
            <p className="mt-1 text-[18px] font-semibold tabular-nums">{num(s.count)}</p>
            <p className="mt-0.5 text-[11.5px] text-muted">
              {num(s.with_findings)} with findings{s.public ? ` · ${num(s.public)} public` : ""}
            </p>
          </button>
        ))}
      </div>
    </div>
  );
}

export default function AssetsPage() {
  const url = useUrlState(["service", "region", "resource_type", "risk"]);
  const { accountId } = useScope();
  const [q, setQ] = useState(url.get("q") ?? "");
  const debouncedQ = useDebounce(q, 300);
  useEffect(() => {
    if ((url.get("q") ?? "") !== debouncedQ) url.update({ q: debouncedQ });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedQ]);

  const sort = url.get("sort") ?? "risk";
  const order = (url.get("order") as "asc" | "desc") ?? "desc";
  const params = {
    q: url.get("q"),
    service: url.getAll("service"),
    region: url.getAll("region"),
    resource_type: url.getAll("resource_type"),
    risk: url.getAll("risk"),
    public: url.get("public") === "true" ? true : undefined,
    encryption: url.get("encryption"),
    account_id: accountId,
    page: Number(url.get("page") ?? 1),
    page_size: Number(url.get("page_size") ?? 25),
    sort,
    order,
  };
  const { data, error, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["assets", params],
    queryFn: () => assetsApi.list(params),
    placeholderData: keepPreviousData,
  });
  const { data: stats } = useQuery({ queryKey: ["asset-stats", accountId], queryFn: () => assetsApi.stats(accountId) });
  const onSort = (s: string, o: "asc" | "desc") => url.update({ sort: s, order: o });
  const services = url.getAll("service");
  const hasFilters = ["q", "service", "region", "resource_type", "risk", "public", "encryption"].some((k) => url.params.has(k));

  return (
    <>
      <PageHeader
        title="Asset inventory"
        description="Every cloud resource discovered by the latest scans, with exposure, encryption and risk derived from open findings."
      />
      <ServiceStrip
        stats={stats}
        active={services}
        onSelect={(s) => url.update({ service: services.includes(s) ? services.filter((x) => x !== s) : [...services, s] })}
      />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <SearchInput value={q} onChange={setQ} placeholder="Search name, ARN, resource ID or IP" className="w-full sm:w-80" />
        <MultiFilter
          label="Service"
          selected={services}
          onChange={(v) => url.update({ service: v })}
          options={(stats?.by_service ?? []).map((s) => ({ value: s.service, label: s.service, count: s.count }))}
        />
        <MultiFilter
          label="Type"
          searchable
          selected={url.getAll("resource_type")}
          onChange={(v) => url.update({ resource_type: v })}
          options={(stats?.resource_types ?? []).map((t) => ({ value: t.value, label: resourceTypeLabel(t.value), count: t.count }))}
        />
        <MultiFilter
          label="Region"
          selected={url.getAll("region")}
          onChange={(v) => url.update({ region: v })}
          options={(stats?.regions ?? []).map((r) => ({ value: r.value, label: r.value, count: r.count }))}
        />
        <MultiFilter label="Risk" selected={url.getAll("risk")} onChange={(v) => url.update({ risk: v })} options={RISK_OPTIONS} />
        <select
          className="input h-8 w-auto pr-8"
          aria-label="Encryption"
          value={url.get("encryption") ?? ""}
          onChange={(e) => url.update({ encryption: e.target.value })}
        >
          <option value="">Any encryption</option>
          <option value="encrypted">Encrypted</option>
          <option value="unencrypted">Unencrypted</option>
          <option value="not_applicable">Not applicable</option>
        </select>
        <label className="inline-flex h-8 items-center gap-2 rounded-control border border-line px-2.5 text-[12.5px] text-muted">
          <input
            type="checkbox"
            className="accent-[#F5A524]"
            checked={url.get("public") === "true"}
            onChange={(e) => url.update({ public: e.target.checked })}
          />
          Internet-exposed only
        </label>
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
          <EmptyState
            icon={<Boxes className="h-7 w-7" />}
            title={hasFilters ? "No assets match these filters" : "No assets discovered yet"}
            description={hasFilters ? "Adjust or reset the filters." : "Connect a cloud account and run a scan to build the inventory."}
            action={!hasFilters ? <Link to="/accounts" className="link text-[13px]">Go to accounts</Link> : undefined}
          />
        ) : (
          <div className={cn("overflow-x-auto", isFetching && "opacity-70")}>
            <table className="data-table">
              <thead>
                <tr>
                  <SortHeader label="Name" field="name" sort={sort} order={order} onSort={onSort} />
                  <SortHeader label="Type" field="type" sort={sort} order={order} onSort={onSort} />
                  <SortHeader label="Region" field="region" sort={sort} order={order} onSort={onSort} />
                  <th>Account</th>
                  <th>Exposure</th>
                  <th>Encryption</th>
                  <SortHeader label="Risk" field="risk" sort={sort} order={order} onSort={onSort} />
                  <SortHeader label="Findings" field="findings" sort={sort} order={order} onSort={onSort} />
                  <SortHeader label="Last scanned" field="last_seen" sort={sort} order={order} onSort={onSort} />
                </tr>
              </thead>
              <tbody>
                {data.items.map((a) => (
                  <tr key={a.id}>
                    <td className="max-w-[320px]">
                      <Link to={`/assets/${a.id}`} className="block truncate text-ink hover:text-accent-strong">
                        {a.name}
                      </Link>
                      <span className="mono block truncate text-faint" title={a.resource_uid}>
                        {a.resource_uid}
                      </span>
                    </td>
                    <td className="whitespace-nowrap text-muted">{resourceTypeLabel(a.resource_type)}</td>
                    <td className="whitespace-nowrap text-muted">{a.region}</td>
                    <td className="whitespace-nowrap text-muted">{a.account_name}</td>
                    <td>
                      <ExposureMark exposed={a.public_exposure} />
                    </td>
                    <td>
                      <EncryptionMark status={a.encryption_status} />
                    </td>
                    <td>
                      <RiskMeter score={a.risk_score} level={a.risk_level} />
                    </td>
                    <td className="tabular-nums">
                      {a.open_findings ? (
                        <Link to={`/findings?q=${encodeURIComponent(a.resource_uid)}`} className="link">
                          {a.open_findings}
                        </Link>
                      ) : (
                        <span className="text-faint">0</span>
                      )}
                    </td>
                    <td className="whitespace-nowrap text-muted">{relative(a.last_seen_at)}</td>
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
    </>
  );
}
