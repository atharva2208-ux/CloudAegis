import * as RTabs from "@radix-ui/react-tabs";
import { Check, Copy } from "lucide-react";
import { useState, type ReactNode } from "react";
import { cn } from "@/lib/cn";

export function PageHeader({
  title,
  description,
  actions,
  meta,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  meta?: ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-4 border-b border-line pb-4">
      <div className="min-w-0">
        <h1 className="text-[22px] font-semibold leading-tight tracking-tight">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-[13px] text-muted">{description}</p>}
        {meta && <div className="mt-2 flex flex-wrap items-center gap-2">{meta}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Panel({
  title,
  actions,
  children,
  className,
  bodyClassName,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={cn("panel", className)}>
      {(title || actions) && (
        <header className="panel-header">
          {title && <h2 className="panel-title">{title}</h2>}
          {actions}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

export function KeyValue({ label, children, mono }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="font-mono text-[10.5px] uppercase tracking-[0.08em] text-faint">{label}</dt>
      <dd className={cn("mt-0.5 break-words text-[13px] text-ink", mono && "mono")}>{children ?? "—"}</dd>
    </div>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="inline-flex items-center gap-1 rounded-control px-1.5 py-1 text-[12px] text-faint hover:bg-raised hover:text-ink"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
      aria-label={label}
    >
      {copied ? <Check className="h-3.5 w-3.5 text-ok" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? "Copied" : label}
    </button>
  );
}

export function CodeBlock({ code, className, copy = true }: { code: string; className?: string; copy?: boolean }) {
  return (
    <div className={cn("relative rounded-control border border-line bg-canvas", className)}>
      {copy && (
        <div className="absolute right-1.5 top-1.5">
          <CopyButton text={code} />
        </div>
      )}
      <pre className="mono overflow-x-auto whitespace-pre-wrap break-words p-3 pr-20 leading-relaxed text-[#D4D4D8]">{code}</pre>
    </div>
  );
}

export function Tabs({
  value,
  onValueChange,
  tabs,
  children,
}: {
  value: string;
  onValueChange: (v: string) => void;
  tabs: { value: string; label: ReactNode }[];
  children: ReactNode;
}) {
  return (
    <RTabs.Root value={value} onValueChange={onValueChange}>
      <RTabs.List className="mb-4 flex gap-1 border-b border-line">
        {tabs.map((t) => (
          <RTabs.Trigger
            key={t.value}
            value={t.value}
            className="-mb-px border-b-2 border-transparent px-3 py-2 font-mono text-[11.5px] uppercase tracking-[0.08em] text-muted hover:text-ink data-[state=active]:border-accent data-[state=active]:text-ink"
          >
            {t.label}
          </RTabs.Trigger>
        ))}
      </RTabs.List>
      {children}
    </RTabs.Root>
  );
}

export const TabPanel = RTabs.Content;

export function ProgressBar({ value, className, tone = "accent" }: { value: number; className?: string; tone?: "accent" | "ok" | "fail" }) {
  const color = tone === "ok" ? "bg-ok" : tone === "fail" ? "bg-sev-critical" : "bg-accent";
  return (
    <div className={cn("h-1.5 w-full overflow-hidden rounded-[1px] bg-line", className)} role="progressbar" aria-valuenow={value} aria-valuemin={0} aria-valuemax={100}>
      <div className={cn("h-full rounded-[1px] transition-[width] duration-500", color)} style={{ width: `${Math.min(100, Math.max(0, value))}%` }} />
    </div>
  );
}

export function Stat({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: string }) {
  return (
    <div className="min-w-0">
      <p className="eyebrow">{label}</p>
      <p className="mt-2 font-mono text-[22px] font-medium leading-none tabular-nums" style={tone ? { color: tone } : undefined}>
        {value}
      </p>
      {sub && <p className="mt-1.5 text-[12px] text-muted">{sub}</p>}
    </div>
  );
}
