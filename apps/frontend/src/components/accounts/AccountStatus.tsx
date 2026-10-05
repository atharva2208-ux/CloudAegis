import { cn } from "@/lib/cn";
import type { CloudAccount } from "@/types/api";

const STYLE: Record<CloudAccount["status"], { dot: string; label: string }> = {
  connected: { dot: "bg-ok", label: "Connected" },
  pending: { dot: "bg-sev-medium", label: "Pending validation" },
  error: { dot: "bg-sev-critical", label: "Connection error" },
};

export function AccountStatus({ status, className }: { status: CloudAccount["status"]; className?: string }) {
  const s = STYLE[status] ?? STYLE.pending;
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-[12.5px] text-muted", className)}>
      <span className={cn("h-2 w-2 rounded-[1px]", s.dot)} aria-hidden />
      {s.label}
    </span>
  );
}

export const AUTH_LABEL: Record<string, string> = {
  assume_role: "IAM role (AssumeRole)",
  temporary_credentials: "Temporary STS credentials",
  demo: "Simulated",
};
