import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Boxes, Building2, Globe2, Hash, MapPin, Search, ShieldAlert } from "lucide-react";
import { platformApi } from "@/services";
import { useDebounce } from "@/hooks/useDebounce";
import { cn } from "@/lib/cn";
import type { SearchHit } from "@/types/api";

const GROUPS: { key: SearchHit["category"]; label: string; icon: typeof Boxes }[] = [
  { key: "finding", label: "Findings", icon: ShieldAlert },
  { key: "asset", label: "Assets", icon: Boxes },
  { key: "ip", label: "IP addresses", icon: Globe2 },
  { key: "rule", label: "Rules", icon: Hash },
  { key: "account", label: "Accounts", icon: Building2 },
  { key: "region", label: "Regions", icon: MapPin },
];

export function GlobalSearch() {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const debounced = useDebounce(query.trim(), 200);

  const { data, isFetching } = useQuery({
    queryKey: ["search", debounced],
    queryFn: () => platformApi.search(debounced),
    enabled: debounced.length >= 2,
    staleTime: 15_000,
  });

  const flat = useMemo(
    () => GROUPS.flatMap((g) => (data?.groups[g.key] ?? []).map((hit) => ({ ...hit, group: g }))),
    [data],
  );

  useEffect(() => setActive(0), [data]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.key === "k" && (e.metaKey || e.ctrlKey)) || (e.key === "/" && document.activeElement === document.body)) {
        e.preventDefault();
        inputRef.current?.focus();
        setOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const go = (hit: SearchHit) => {
    navigate(hit.link);
    setOpen(false);
    setQuery("");
    inputRef.current?.blur();
  };

  return (
    <div className="relative w-full max-w-md">
      <Search className="pointer-events-none absolute left-2.5 top-2 h-4 w-4 text-faint" aria-hidden />
      <input
        ref={inputRef}
        value={query}
        onChange={(e) => {
          setQuery(e.target.value);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setActive((a) => Math.min(flat.length - 1, a + 1));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setActive((a) => Math.max(0, a - 1));
          } else if (e.key === "Enter" && flat[active]) {
            go(flat[active]);
          } else if (e.key === "Escape") {
            setOpen(false);
            inputRef.current?.blur();
          }
        }}
        placeholder="Search assets, findings, rules, IPs…"
        className="input h-8 border-transparent bg-surface pl-8 pr-3 text-[12.5px] sm:pr-14"
        role="combobox"
        aria-expanded={open && debounced.length >= 2}
        aria-controls="global-search-results"
        aria-label="Global search"
      />
      <kbd className="pointer-events-none absolute right-2 top-1.5 hidden border sm:block border-line px-1.5 font-mono text-[10.5px] text-faint">
        Ctrl K
      </kbd>
      {open && debounced.length >= 2 && (
        <div
          id="global-search-results"
          role="listbox"
          className="absolute left-0 right-0 top-10 z-50 max-h-[60vh] overflow-y-auto rounded-panel border border-line-strong bg-surface py-1.5 shadow-[0_16px_40px_rgba(0,0,0,0.5)]"
        >
          {isFetching && !data && <p className="px-4 py-3 text-[13px] text-muted">Searching…</p>}
          {data && data.total === 0 && (
            <p className="px-4 py-3 text-[13px] text-muted">No matches for “{data.query}”.</p>
          )}
          {GROUPS.map((g) => {
            const hits = data?.groups[g.key];
            if (!hits?.length) return null;
            return (
              <div key={g.key} className="py-1">
                <p className="px-4 pb-1 pt-1.5 text-[11.5px] font-medium text-faint">{g.label}</p>
                {hits.map((hit) => {
                  const index = flat.findIndex((f) => f.category === hit.category && f.id === hit.id);
                  return (
                    <button
                      key={`${hit.category}-${hit.id}`}
                      role="option"
                      aria-selected={index === active}
                      onMouseDown={(e) => e.preventDefault()}
                      onMouseEnter={() => setActive(index)}
                      onClick={() => go(hit)}
                      className={cn(
                        "flex w-full items-start gap-3 px-4 py-2 text-left",
                        index === active ? "bg-raised" : "hover:bg-raised/60",
                      )}
                    >
                      <g.icon className="mt-0.5 h-4 w-4 shrink-0 text-faint" aria-hidden />
                      <span className="min-w-0">
                        <span className="block truncate text-[13px] text-ink">{hit.title}</span>
                        <span className="block truncate text-[12px] text-faint">{hit.subtitle}</span>
                      </span>
                    </button>
                  );
                })}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
