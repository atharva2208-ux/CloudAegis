import { CircleDot, MessageSquare, RefreshCcw, ScanSearch, Ticket } from "lucide-react";
import { Link } from "react-router-dom";
import { STATUS_LABEL, dateTime } from "@/lib/format";
import type { FindingEvent } from "@/types/api";

const ICONS: Record<string, typeof CircleDot> = {
  detected: ScanSearch,
  redetected: ScanSearch,
  reopened: RefreshCcw,
  auto_resolved: RefreshCcw,
  comment: MessageSquare,
  ticket_linked: Ticket,
};

function describe(e: FindingEvent): string {
  switch (e.event_type) {
    case "detected":
      return "First detected by scan";
    case "redetected":
      return "Detected again by scan";
    case "reopened":
      return "Reopened — issue is still present";
    case "auto_resolved":
      return "Resolved — a later scan no longer detected the issue";
    case "comment":
      return "Comment";
    case "ticket_linked":
      return "Ticket linked";
    case "status_changed":
      return `Status changed${e.from_status ? ` from ${STATUS_LABEL[e.from_status] ?? e.from_status}` : ""} to ${
        STATUS_LABEL[e.to_status ?? ""] ?? e.to_status
      }`;
    default:
      return e.event_type.replace(/_/g, " ");
  }
}

export function FindingTimeline({ events }: { events: FindingEvent[] }) {
  const ordered = [...events].sort((a, b) => b.created_at.localeCompare(a.created_at));
  return (
    <ol className="relative space-y-4 before:absolute before:bottom-2 before:left-[9px] before:top-2 before:w-px before:bg-line">
      {ordered.map((e) => {
        const Icon = ICONS[e.event_type] ?? CircleDot;
        return (
          <li key={e.id} className="relative flex gap-3">
            <span className="z-[1] mt-0.5 flex h-[19px] w-[19px] shrink-0 items-center justify-center rounded-[1px] border border-line bg-surface">
              <Icon className="h-3 w-3 text-muted" aria-hidden />
            </span>
            <div className="min-w-0 text-[13px]">
              <p className="text-ink">{describe(e)}</p>
              <p className="text-[12px] text-faint">
                {dateTime(e.created_at)}
                {e.user && ` · ${e.user}`}
                {e.scan_id && (
                  <>
                    {" · "}
                    <Link to={`/scans/${e.scan_id}`} className="link">
                      scan #{e.scan_id}
                    </Link>
                  </>
                )}
              </p>
              {e.note && <p className="mt-1 whitespace-pre-wrap rounded-control border border-line bg-canvas px-2.5 py-1.5 text-muted">{e.note}</p>}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
