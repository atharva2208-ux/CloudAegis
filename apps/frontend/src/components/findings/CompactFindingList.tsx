import { Link } from "react-router-dom";
import { SeverityBadge, StatusBadge } from "@/components/ui/badges";
import { relative } from "@/lib/format";
import type { FindingSummary } from "@/types/api";

/** Dense findings table used inside detail pages (asset, control, account). */
export function CompactFindingList({
  findings,
  showResource = false,
  empty = "No findings",
}: {
  findings: FindingSummary[];
  showResource?: boolean;
  empty?: string;
}) {
  if (!findings.length) return <p className="px-4 py-6 text-center text-[13px] text-faint">{empty}</p>;
  return (
    <div className="overflow-x-auto">
      <table className="data-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Finding</th>
            {showResource && <th>Resource</th>}
            <th>Status</th>
            <th>Last detected</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.id}>
              <td className="whitespace-nowrap">
                <SeverityBadge severity={f.severity} />
              </td>
              <td className="min-w-[260px]">
                <Link to={`/findings/${f.id}`} className="block text-ink hover:text-accent-strong">
                  {f.title}
                </Link>
                <span className="mono text-faint">
                  {f.display_id} {f.rule_id}
                </span>
              </td>
              {showResource && (
                <td className="max-w-[260px]">
                  <Link to={`/assets/${f.asset_id}`} className="block truncate hover:text-accent-strong" title={f.resource_uid}>
                    {f.asset_name}
                  </Link>
                  <span className="text-[12px] text-faint">
                    {f.service} · {f.region}
                  </span>
                </td>
              )}
              <td>
                <StatusBadge status={f.status} />
              </td>
              <td className="whitespace-nowrap text-muted">{relative(f.last_detected_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
