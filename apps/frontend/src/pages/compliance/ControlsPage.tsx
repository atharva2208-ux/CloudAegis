import { useState } from "react";
import { Link } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ListChecks } from "lucide-react";
import { complianceApi } from "@/services";
import { useScope } from "@/stores/scope";
import { useUrlState } from "@/hooks/useUrlState";
import { useDebounce } from "@/hooks/useDebounce";
import { PageHeader } from "@/components/ui/misc";
import { SearchInput } from "@/components/ui/filters";
import { EmptyState, ErrorState, LoadingRows } from "@/components/ui/states";
import { ControlStatus } from "@/components/compliance/ControlStatus";
import { ProgressBar } from "@/components/ui/misc";
import { num } from "@/lib/format";

export default function ControlsPage() {
  const { accountId } = useScope();
  const url = useUrlState();
  const [q, setQ] = useState("");
  const debounced = useDebounce(q, 250);
  const params = { account_id: accountId, framework: url.get("framework"), status: url.get("status"), q: debounced || undefined };
  const { data, error, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["controls", params],
    queryFn: () => complianceApi.controls(params),
    placeholderData: keepPreviousData,
  });

  return (
    <>
      <PageHeader title="Controls" description="Every control across all frameworks, with the resources it was evaluated against." />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <SearchInput value={q} onChange={setQ} placeholder="Search control ID or title" className="w-full sm:w-72" />
        <select className="input h-8 w-auto pr-8" aria-label="Framework" value={url.get("framework") ?? ""} onChange={(e) => url.update({ framework: e.target.value })}>
          <option value="">All frameworks</option>
          <option value="cis-aws">CIS AWS Foundations</option>
          <option value="aws-wa-security">AWS Well-Architected Security</option>
          <option value="nist-csf">NIST CSF 2.0</option>
        </select>
        <select className="input h-8 w-auto pr-8" aria-label="Status" value={url.get("status") ?? ""} onChange={(e) => url.update({ status: e.target.value })}>
          <option value="">Any status</option>
          <option value="FAIL">Failed</option>
          <option value="PASS">Passed</option>
          <option value="NOT_APPLICABLE">Not applicable</option>
        </select>
        {data && <span className="ml-auto text-[12.5px] text-faint">{num(data.length)} controls</span>}
      </div>
      <div className="panel overflow-hidden">
        {isLoading ? (
          <LoadingRows />
        ) : error ? (
          <ErrorState error={error} onRetry={refetch} />
        ) : !data?.length ? (
          <EmptyState icon={<ListChecks className="h-7 w-7" />} title="No controls match" description="Adjust the filters, or run a scan if nothing has been assessed yet." />
        ) : (
          <div className={isFetching ? "overflow-x-auto opacity-70" : "overflow-x-auto"}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Framework</th>
                  <th>Control</th>
                  <th>Section</th>
                  <th>Status</th>
                  <th className="w-40">Resource compliance</th>
                  <th className="text-right">Failing</th>
                </tr>
              </thead>
              <tbody>
                {data.map((c) => (
                  <tr key={`${c.framework_key}-${c.control_id}`}>
                    <td className="whitespace-nowrap text-muted">{c.framework}</td>
                    <td className="min-w-[280px]">
                      <Link to={`/compliance/${c.framework_key}?control=${encodeURIComponent(c.control_id)}`} className="hover:text-accent-strong">
                        <span className="mono mr-2 text-muted">{c.control_id}</span>
                        {c.title}
                      </Link>
                    </td>
                    <td className="text-[12.5px] text-muted">{c.section}</td>
                    <td className="whitespace-nowrap">
                      <ControlStatus status={c.status} />
                    </td>
                    <td>
                      {c.compliance == null ? (
                        <span className="text-faint">—</span>
                      ) : (
                        <div className="flex items-center gap-2">
                          <ProgressBar value={c.compliance} tone={c.compliance === 100 ? "ok" : "accent"} />
                          <span className="w-12 text-right text-[12px] tabular-nums text-muted">{c.compliance.toFixed(0)}%</span>
                        </div>
                      )}
                    </td>
                    <td className="text-right tabular-nums">
                      {c.failed_resources ? `${num(c.failed_resources)} / ${num(c.evaluated_resources)}` : <span className="text-faint">0</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
