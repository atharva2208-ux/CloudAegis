import { useState } from "react";
import { ChevronRight } from "lucide-react";
import { cn } from "@/lib/cn";

type Json = string | number | boolean | null | Json[] | { [key: string]: Json };

function Scalar({ value }: { value: Json }) {
  if (value === null) return <span className="text-faint">null</span>;
  if (typeof value === "boolean")
    return <span className={value ? "text-ok" : "text-sev-high"}>{String(value)}</span>;
  if (typeof value === "number") return <span className="text-[#FFBE55]">{value}</span>;
  return <span className="break-all text-[#E4E4E7]">"{String(value)}"</span>;
}

function Node({ name, value, depth }: { name?: string; value: Json; depth: number }) {
  const isObject = value !== null && typeof value === "object";
  const [open, setOpen] = useState(depth < 2);
  const label = name !== undefined && <span className="text-muted">{name}: </span>;
  if (!isObject) {
    return (
      <div className="py-[1px]" style={{ paddingLeft: depth * 14 }}>
        {label}
        <Scalar value={value} />
      </div>
    );
  }
  const entries = Array.isArray(value) ? value.map((v, i) => [String(i), v] as const) : Object.entries(value);
  const summary = Array.isArray(value) ? `[${entries.length}]` : `{${entries.length}}`;
  return (
    <div>
      <button
        type="button"
        className="flex items-center py-[1px] text-left hover:text-ink"
        style={{ paddingLeft: depth * 14 }}
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        <ChevronRight className={cn("mr-0.5 h-3 w-3 text-faint transition-transform", open && "rotate-90")} aria-hidden />
        {label}
        {!open && <span className="text-faint">{summary}</span>}
      </button>
      {open && entries.map(([k, v]) => <Node key={k} name={Array.isArray(value) ? undefined : k} value={v} depth={depth + 1} />)}
    </div>
  );
}

/** Collapsible, read-only view of cloud evidence / resource properties. Values are rendered as text, never HTML. */
export function JsonTree({ data, className }: { data: unknown; className?: string }) {
  const value = data as Json;
  const empty = value === null || (typeof value === "object" && Object.keys(value as object).length === 0);
  return (
    <div className={cn("mono overflow-x-auto rounded-control border border-line bg-canvas p-3 leading-relaxed", className)}>
      {empty ? (
        <span className="text-faint">No data captured</span>
      ) : typeof value === "object" && !Array.isArray(value) ? (
        Object.entries(value as Record<string, Json>).map(([k, v]) => <Node key={k} name={k} value={v} depth={0} />)
      ) : (
        <Node value={value} depth={0} />
      )}
    </div>
  );
}
