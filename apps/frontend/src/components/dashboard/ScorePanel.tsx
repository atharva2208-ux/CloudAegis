import { num } from "@/lib/format";
import type { ScoreBreakdown } from "@/types/api";

const BANDS = [
  { from: 0, to: 50, label: "Poor", color: "#E5484D" },
  { from: 50, to: 70, label: "Weak", color: "#F76B15" },
  { from: 70, to: 85, label: "Moderate", color: "#F5A524" },
  { from: 85, to: 100, label: "Strong", color: "#3DD68C" },
];

export function postureLabel(score: number) {
  return BANDS.find((b) => score >= b.from && score < b.to + (b.to === 100 ? 1 : 0)) ?? BANDS[0];
}

/** 25 square cells; filled cells take the colour of the band they fall in. */
export function SegmentMeter({ value, cells = 25 }: { value: number; cells?: number }) {
  const filled = Math.round((value / 100) * cells);
  return (
    <div className="flex gap-[3px]" role="img" aria-label={`${value} out of 100`}>
      {Array.from({ length: cells }).map((_, i) => {
        const at = ((i + 0.5) / cells) * 100;
        return (
          <span
            key={i}
            className="h-3 flex-1"
            style={{ background: i < filled ? postureLabel(at).color : "#26262A" }}
          />
        );
      })}
    </div>
  );
}

function Term({ value, label, tone }: { value: string; label: string; tone?: string }) {
  return (
    <div className="min-w-0">
      <p className="font-mono text-[22px] font-medium leading-none tabular-nums" style={tone ? { color: tone } : undefined}>
        {value}
      </p>
      <p className="mt-1.5 text-[11.5px] leading-snug text-faint">{label}</p>
    </div>
  );
}

/**
 * The score shown as the equation that produces it, so an analyst can verify it:
 * weighted pass rate − critical penalty = score.
 */
export function ScorePanel({ score }: { score: ScoreBreakdown; previous?: number | null }) {
  const band = postureLabel(score.score);
  const base = score.weighted_pass_rate * 100;
  return (
    <section className="panel h-full" aria-labelledby="score-heading">
      <header className="panel-header">
        <h2 id="score-heading" className="panel-title">
          Score derivation
        </h2>
        <span className="font-mono text-[11px] uppercase tracking-[0.08em]" style={{ color: band.color }}>
          {band.label} posture
        </span>
      </header>
      <div className="p-4">
        <div className="grid grid-cols-[1fr_auto_1fr_auto_1fr] items-start gap-3">
          <Term value={base.toFixed(1)} label={`weighted pass rate · ${num(score.total_checks - score.failed_checks)}/${num(score.total_checks)} checks`} />
          <span className="pt-1 font-mono text-[18px] text-faint">−</span>
          <Term value={String(score.critical_penalty)} label={`critical penalty · ${score.critical_findings} open × 3, max 25`} tone="#E5484D" />
          <span className="pt-1 font-mono text-[18px] text-faint">=</span>
          <Term value={String(score.score)} label="security score (0–100)" tone={band.color} />
        </div>
        <div className="mt-5">
          <SegmentMeter value={score.score} />
          <div className="mt-1.5 flex justify-between font-mono text-[10.5px] text-faint">
            <span>0</span>
            <span>50 weak</span>
            <span>70 moderate</span>
            <span>85 strong</span>
            <span>100</span>
          </div>
        </div>
        <p className="mt-4 border-t border-line pt-3 text-[12px] leading-relaxed text-faint">
          Each check is weighted by severity (critical {score.weights.CRITICAL}, high {score.weights.HIGH}, medium{" "}
          {score.weights.MEDIUM}, low {score.weights.LOW}, info {score.weights.INFO}). Suppressed findings count as accepted risk.
        </p>
      </div>
    </section>
  );
}
