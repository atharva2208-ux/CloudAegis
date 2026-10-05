import { Link } from "react-router-dom";
import { ScanStatusBadge } from "@/components/ui/badges";
import { SEVERITY_COLOR, dateTime, duration, num } from "@/lib/format";
import type { Scan } from "@/types/api";

const TRIGGER_LABEL: Record<string, string> = { manual: "Manual", onboarding: "Onboarding", seed: "Demo history", scheduled: "Scheduled" };

export function ScoreValue({ score }: { score: number | null }) {
  if (score == null) return <span className="text-faint">—</span>;
  const color = score >= 85 ? "#3DD68C" : score >= 70 ? "#F5A524" : score >= 50 ? SEVERITY_COLOR.HIGH : SEVERITY_COLOR.CRITICAL;
  return (
    <span className="font-medium tabular-nums" style={{ color }}>
      {score}
    </span>
  );
}

function SeverityMini({ counts }: { counts: Scan["severity_counts"] }) {
  const items = (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).filter((s) => counts?.[s]);
  if (!items.length) return <span className="text-faint">—</span>;
  return (
    <span className="inline-flex gap-2.5 tabular-nums">
      {items.map((s) => (
        <span key={s} className="inline-flex items-center gap-1" title={s.toLowerCase()}>
          <span className="h-2.5 w-[3px] rounded-[1px]" style={{ background: SEVERITY_COLOR[s] }} aria-hidden />
          {counts[s]}
        </span>
      ))}
    </span>
  );
}

export function ScanTable({
  scans,
  selectable,
  selected = [],
  onToggle,
  showAccount = true,
}: {
  scans: Scan[];
  selectable?: boolean;
  selected?: number[];
  onToggle?: (id: number) => void;
  showAccount?: boolean;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="data-table">
        <thead>
          <tr>
            {selectable && <th className="w-9"><span className="sr-only">Compare</span></th>}
            <th>Scan ID</th>
            {showAccount && <th>Account</th>}
            <th>Started</th>
            <th>Duration</th>
            <th className="text-right">Assets</th>
            <th className="text-right">Findings</th>
            <th>By severity</th>
            <th className="text-right">Score</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((s) => {
            const comparable = s.status === "COMPLETED" || s.status === "PARTIAL";
            return (
              <tr key={s.id}>
                {selectable && (
                  <td>
                    <input
                      type="checkbox"
                      className="accent-[#F5A524]"
                      aria-label={`Select ${s.display_id} for comparison`}
                      disabled={!comparable || (!selected.includes(s.id) && selected.length >= 2)}
                      checked={selected.includes(s.id)}
                      onChange={() => onToggle?.(s.id)}
                    />
                  </td>
                )}
                <td className="whitespace-nowrap">
                  <Link to={`/scans/${s.id}`} className="mono text-[12.5px] text-ink hover:text-accent-strong">
                    {s.display_id}
                  </Link>
                  <span className="block text-[12px] text-faint">{TRIGGER_LABEL[s.trigger] ?? s.trigger}{s.triggered_by && s.triggered_by !== "system" ? ` · ${s.triggered_by}` : ""}</span>
                </td>
                {showAccount && <td className="whitespace-nowrap text-muted">{s.account_name}</td>}
                <td className="whitespace-nowrap text-muted">{dateTime(s.started_at ?? s.queued_at)}</td>
                <td className="whitespace-nowrap tabular-nums text-muted">{duration(s.duration_seconds)}</td>
                <td className="text-right tabular-nums">{num(s.assets_discovered)}</td>
                <td className="text-right tabular-nums">
                  {num(s.findings_total)}
                  {(s.findings_new > 0 || s.findings_resolved > 0) && (
                    <span className="block text-[11.5px] text-faint">
                      +{s.findings_new} / −{s.findings_resolved}
                    </span>
                  )}
                </td>
                <td className="text-[12.5px]">
                  <SeverityMini counts={s.severity_counts} />
                </td>
                <td className="text-right">
                  <ScoreValue score={s.security_score} />
                </td>
                <td>
                  <ScanStatusBadge status={s.status} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
