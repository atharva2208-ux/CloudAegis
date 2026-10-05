import * as Popover from "@radix-ui/react-popover";
import { Check, ChevronDown, Search, X } from "lucide-react";
import { useMemo, useState } from "react";
import { cn } from "@/lib/cn";

export interface Option {
  value: string;
  label: string;
  count?: number;
  color?: string;
}

/** Popover multi-select used across list filters. */
export function MultiFilter({
  label,
  options,
  selected,
  onChange,
  searchable = false,
}: {
  label: string;
  options: Option[];
  selected: string[];
  onChange: (values: string[]) => void;
  searchable?: boolean;
}) {
  const [query, setQuery] = useState("");
  const visible = useMemo(
    () => options.filter((o) => o.label.toLowerCase().includes(query.toLowerCase())),
    [options, query],
  );
  const toggle = (value: string) =>
    onChange(selected.includes(value) ? selected.filter((v) => v !== value) : [...selected, value]);
  const summary =
    selected.length === 0
      ? null
      : selected.length === 1
        ? options.find((o) => o.value === selected[0])?.label ?? selected[0]
        : `${selected.length} selected`;

  return (
    <Popover.Root>
      <Popover.Trigger
        className={cn(
          "inline-flex h-8 items-center gap-1.5 rounded-control border px-2.5 text-[12.5px] transition-colors",
          selected.length
            ? "border-accent/50 bg-accent-dim/30 text-ink"
            : "border-line bg-surface text-muted hover:border-line-strong hover:text-ink",
        )}
      >
        {label}
        {summary && <span className="max-w-[140px] truncate text-accent-strong">: {summary}</span>}
        <ChevronDown className="h-3.5 w-3.5 opacity-70" aria-hidden />
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          align="start"
          sideOffset={6}
          className="z-50 w-64 rounded-panel border border-line-strong bg-surface p-1.5 shadow-[0_12px_32px_rgba(0,0,0,0.45)]"
        >
          {searchable && (
            <div className="relative mb-1.5">
              <Search className="pointer-events-none absolute left-2 top-2 h-3.5 w-3.5 text-faint" aria-hidden />
              <input
                className="input h-8 pl-7"
                placeholder={`Filter ${label.toLowerCase()}`}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
          )}
          <div className="max-h-64 overflow-y-auto" role="listbox" aria-multiselectable>
            {visible.length === 0 && <p className="px-2 py-3 text-[12.5px] text-faint">No options</p>}
            {visible.map((o) => {
              const active = selected.includes(o.value);
              return (
                <button
                  key={o.value}
                  role="option"
                  aria-selected={active}
                  onClick={() => toggle(o.value)}
                  className="flex w-full items-center gap-2 rounded-control px-2 py-1.5 text-left text-[13px] hover:bg-raised"
                >
                  <span
                    className={cn(
                      "flex h-4 w-4 items-center justify-center rounded-none border",
                      active ? "border-accent bg-accent text-[#1A1204]" : "border-line-strong",
                    )}
                  >
                    {active && <Check className="h-3 w-3" strokeWidth={3} />}
                  </span>
                  {o.color && <span className="h-3 w-[3px] rounded-[1px]" style={{ background: o.color }} />}
                  <span className="flex-1 truncate">{o.label}</span>
                  {o.count !== undefined && <span className="text-[12px] tabular-nums text-faint">{o.count}</span>}
                </button>
              );
            })}
          </div>
          {selected.length > 0 && (
            <button
              className="mt-1 w-full rounded-control px-2 py-1.5 text-left text-[12.5px] text-muted hover:bg-raised hover:text-ink"
              onClick={() => onChange([])}
            >
              Clear selection
            </button>
          )}
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

export function SearchInput({
  value,
  onChange,
  placeholder,
  className,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  className?: string;
}) {
  return (
    <div className={cn("relative", className)}>
      <Search className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-faint" aria-hidden />
      <input
        className="input h-8 pl-8 pr-7"
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        aria-label={placeholder}
      />
      {value && (
        <button
          className="absolute right-1.5 top-1.5 rounded-control p-1 text-faint hover:text-ink"
          onClick={() => onChange("")}
          aria-label="Clear search"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      )}
    </div>
  );
}

export function SortHeader({
  label,
  field,
  sort,
  order,
  onSort,
  className,
}: {
  label: string;
  field: string;
  sort: string;
  order: "asc" | "desc";
  onSort: (field: string, order: "asc" | "desc") => void;
  className?: string;
}) {
  const active = sort === field;
  return (
    <th className={className} aria-sort={active ? (order === "asc" ? "ascending" : "descending") : "none"}>
      <button
        className={cn("inline-flex items-center gap-1 hover:text-ink", active && "text-ink")}
        onClick={() => onSort(field, active && order === "asc" ? "desc" : "asc")}
      >
        {label}
        <span className="text-[10px]" aria-hidden>
          {active ? (order === "asc" ? "▲" : "▼") : ""}
        </span>
      </button>
    </th>
  );
}
