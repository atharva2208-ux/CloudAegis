import { Globe, Lock, LockOpen } from "lucide-react";
import { cn } from "@/lib/cn";
import { SEVERITY_COLOR, SEVERITY_LABEL, STATUS_LABEL } from "@/lib/format";
import type { FindingStatus, Severity } from "@/types/api";

/** Severity is shown as a coloured bar + word, so meaning never depends on colour alone. */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn("inline-flex h-[20px] items-center gap-1.5 border px-1.5 font-mono text-[10.5px] font-medium uppercase tracking-[0.06em]", className)}
      style={{ color: SEVERITY_COLOR[severity], borderColor: `${SEVERITY_COLOR[severity]}55`, background: `${SEVERITY_COLOR[severity]}14` }}
    >
      <span className="h-1.5 w-1.5" style={{ background: SEVERITY_COLOR[severity] }} aria-hidden />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

const statusStyle: Record<FindingStatus, string> = {
  OPEN: "border-ink/30 text-ink",
  ACKNOWLEDGED: "border-accent/35 text-accent-strong",
  IN_PROGRESS: "border-sev-medium/35 text-sev-medium",
  RESOLVED: "border-ok/35 text-ok",
  SUPPRESSED: "border-line-strong text-muted",
};

export function StatusBadge({ status }: { status: FindingStatus }) {
  return (
    <span className={cn("inline-flex h-[20px] items-center border px-1.5 font-mono text-[10.5px] uppercase tracking-[0.06em]", statusStyle[status])}>
      {STATUS_LABEL[status] ?? status}
    </span>
  );
}

const scanStyle: Record<string, string> = {
  QUEUED: "border-line-strong text-muted",
  RUNNING: "border-accent/40 text-accent-strong",
  COMPLETED: "border-ok/35 text-ok",
  PARTIAL: "border-sev-medium/40 text-sev-medium",
  FAILED: "border-sev-critical/40 text-[#FF8589]",
  CANCELLED: "border-line-strong text-faint",
};

export function ScanStatusBadge({ status }: { status: string }) {
  const label = status;
  return (
    <span className={cn("inline-flex h-[20px] items-center gap-1.5 border px-1.5 font-mono text-[10.5px] uppercase tracking-[0.06em]", scanStyle[status])}>
      {status === "RUNNING" && <span className="h-1.5 w-1.5 animate-pulse rounded-[1px] bg-accent" aria-hidden />}
      {label}
    </span>
  );
}

export function Tag({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-[22px] items-center rounded-control border border-line bg-raised px-1.5 text-[12px] text-muted",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function ExposureMark({ exposed }: { exposed: boolean }) {
  return exposed ? (
    <span className="inline-flex items-center gap-1 text-[12.5px] text-sev-high" title="Reachable from the internet">
      <Globe className="h-3.5 w-3.5" aria-hidden /> Public
    </span>
  ) : (
    <span className="text-[12.5px] text-faint">Private</span>
  );
}

export function EncryptionMark({ status }: { status: string }) {
  if (status === "encrypted")
    return (
      <span className="inline-flex items-center gap-1 text-[12.5px] text-muted">
        <Lock className="h-3.5 w-3.5 text-ok" aria-hidden /> Encrypted
      </span>
    );
  if (status === "unencrypted")
    return (
      <span className="inline-flex items-center gap-1 text-[12.5px] text-sev-medium">
        <LockOpen className="h-3.5 w-3.5" aria-hidden /> Unencrypted
      </span>
    );
  return <span className="text-[12.5px] text-faint">n/a</span>;
}

const riskColor: Record<string, string> = {
  CRITICAL: SEVERITY_COLOR.CRITICAL,
  HIGH: SEVERITY_COLOR.HIGH,
  MEDIUM: SEVERITY_COLOR.MEDIUM,
  LOW: SEVERITY_COLOR.LOW,
  NONE: "#38383E",
};

export function RiskMeter({ score, level }: { score: number; level: string }) {
  return (
    <span className="inline-flex items-center gap-2" title={`Risk ${score}/100 (${level.toLowerCase()})`}>
      <span className="relative h-1.5 w-14 overflow-hidden rounded-[1px] bg-line">
        <span
          className="absolute inset-y-0 left-0 rounded-[1px]"
          style={{ width: `${Math.max(score, 3)}%`, background: riskColor[level] }}
        />
      </span>
      <span className="w-6 text-right text-[12.5px] tabular-nums text-muted">{score}</span>
    </span>
  );
}

export function DemoBadge() {
  return (
    <span
      className="inline-flex h-5 items-center border border-accent/50 px-1.5 font-mono text-[10px] uppercase tracking-[0.1em] text-accent"
      title="Simulated environment — no real AWS resources"
    >
      Simulated
    </span>
  );
}
