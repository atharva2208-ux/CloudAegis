/** Wordmark: a faceted diamond (an aegis facet) with a cut-out core. */
export function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2">
      <svg viewBox="0 0 24 24" className="h-[22px] w-[22px]" aria-hidden>
        <path d="M12 1.5 22.5 12 12 22.5 1.5 12Z" fill="#F5A524" />
        <path d="M12 7.2 16.8 12 12 16.8 7.2 12Z" fill="#0C0C0E" />
        <path d="M12 1.5V7.2M22.5 12h-5.7" stroke="#0C0C0E" strokeWidth="1.2" />
      </svg>
      {!compact && (
        <span className="font-mono text-[13px] font-semibold uppercase tracking-[0.16em] text-ink">CloudAegis</span>
      )}
    </span>
  );
}
