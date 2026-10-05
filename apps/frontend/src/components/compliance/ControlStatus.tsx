import { CheckCircle2, CircleSlash, XCircle } from "lucide-react";
import type { ControlResult } from "@/types/api";

export function ControlStatus({ status }: { status: ControlResult["status"] }) {
  if (status === "PASS")
    return (
      <span className="inline-flex items-center gap-1.5 text-[12.5px] text-ok">
        <CheckCircle2 className="h-3.5 w-3.5" aria-hidden /> Passed
      </span>
    );
  if (status === "FAIL")
    return (
      <span className="inline-flex items-center gap-1.5 text-[12.5px] text-[#FF8589]">
        <XCircle className="h-3.5 w-3.5" aria-hidden /> Failed
      </span>
    );
  return (
    <span className="inline-flex items-center gap-1.5 text-[12.5px] text-faint">
      <CircleSlash className="h-3.5 w-3.5" aria-hidden /> Not applicable
    </span>
  );
}

/** Square percentage tile with a bar gauge (kept under its historic name). */
export function ComplianceRing({ value, size = 64 }: { value: number; size?: number }) {
  const color = value >= 85 ? "#3DD68C" : value >= 70 ? "#F5A524" : value >= 50 ? "#F76B15" : "#E5484D";
  return (
    <div
      className="flex shrink-0 flex-col justify-between border border-line bg-canvas p-2"
      style={{ width: size * 1.25, height: size }}
      role="img"
      aria-label={`${value.toFixed(1)}% compliant`}
    >
      <span className="font-mono font-medium leading-none tabular-nums" style={{ color, fontSize: size / 3.2 }}>
        {value.toFixed(0)}
        <span className="text-faint" style={{ fontSize: size / 6 }}>%</span>
      </span>
      <span className="block h-1 w-full bg-line">
        <span className="block h-full" style={{ width: `${value}%`, background: color }} />
      </span>
    </div>
  );
}
