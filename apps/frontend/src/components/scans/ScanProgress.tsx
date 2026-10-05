import { CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";
import { ProgressBar } from "@/components/ui/misc";
import { num } from "@/lib/format";
import type { Scan, ServiceProgress } from "@/types/api";

const statusText: Record<ServiceProgress["status"], string> = {
  pending: "Waiting",
  discovering: "Discovering",
  discovered: "Discovered",
  analyzing: "Analyzing",
  completed: "Done",
  failed: "Failed",
};

function ServiceRow({ s }: { s: ServiceProgress }) {
  const icon =
    s.status === "completed" ? (
      <CheckCircle2 className="h-4 w-4 text-ok" aria-hidden />
    ) : s.status === "failed" ? (
      <XCircle className="h-4 w-4 text-sev-critical" aria-hidden />
    ) : s.status === "pending" ? (
      <Circle className="h-4 w-4 text-line-strong" aria-hidden />
    ) : (
      <Loader2 className="h-4 w-4 animate-spin text-accent" aria-hidden />
    );
  return (
    <li className="grid grid-cols-[18px_120px_minmax(0,1fr)_96px] items-center gap-3 py-1.5 text-[13px]">
      {icon}
      <span className={s.status === "pending" ? "text-faint" : "text-ink"}>{s.service}</span>
      {s.status === "failed" ? (
        <span className="truncate text-[12.5px] text-sev-critical" title={s.error ?? undefined}>
          {s.error}
        </span>
      ) : (
        <ProgressBar value={s.percent} tone={s.status === "completed" ? "ok" : "accent"} />
      )}
      <span className="text-right text-[12px] tabular-nums text-faint">
        {s.status === "pending" ? statusText[s.status] : `${num(s.resources)} res`}
      </span>
    </li>
  );
}

export function ScanProgress({ scan }: { scan: Scan }) {
  const services = scan.progress.services ?? [];
  const discovered = scan.progress.assets_discovered ?? scan.assets_discovered;
  const analyzed = scan.progress.assets_analyzed ?? scan.assets_analyzed;
  const done = services.filter((s) => s.status === "completed" || s.status === "failed").length;
  const overall = services.length ? services.reduce((a, s) => a + (s.status === "failed" ? 100 : s.percent), 0) / services.length : 0;
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
        <p className="text-[13px] text-muted">
          {scan.status === "QUEUED"
            ? "Queued — waiting for a scan worker"
            : `Scanning ${scan.account_name}: ${done} of ${services.length} services complete`}
        </p>
        <p className="text-[12.5px] tabular-nums text-faint">
          {num(analyzed)} / {num(discovered)} assets analyzed
        </p>
      </div>
      <ProgressBar value={overall} className="mb-3 h-1" />
      <ul>
        {services.map((s) => (
          <ServiceRow key={s.service} s={s} />
        ))}
      </ul>
    </div>
  );
}
