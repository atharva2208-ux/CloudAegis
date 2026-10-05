import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL, num, shortDate } from "@/lib/format";
import type { Severity } from "@/types/api";

const AXIS = { stroke: "#6E6E78", fontSize: 11.5, tickLine: false, axisLine: false } as const;
const GRID = { stroke: "#26262A", strokeDasharray: "3 4", vertical: false } as const;

function ChartTooltip({ active, payload, label, labelFormatter }: {
  active?: boolean;
  payload?: { name: string; value: number; color: string }[];
  label?: string;
  labelFormatter?: (l: string) => string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-control border border-line-strong bg-raised px-3 py-2 text-[12.5px] shadow-lg">
      {label !== undefined && <p className="mb-1 text-faint">{labelFormatter ? labelFormatter(label) : label}</p>}
      {payload.map((p) => (
        <p key={p.name} className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-[1px]" style={{ background: p.color }} />
          <span className="text-muted">{p.name}</span>
          <span className="ml-auto pl-4 tabular-nums text-ink">{num(p.value)}</span>
        </p>
      ))}
    </div>
  );
}

export function ScoreTrendChart({ data, height = 200 }: { data: { date: string; score: number }[]; height?: number }) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
        <defs>
          <linearGradient id="scoreFill" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="#F5A524" stopOpacity={0.16} />
            <stop offset="100%" stopColor="#F5A524" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid {...GRID} />
        <XAxis dataKey="date" tickFormatter={shortDate} {...AXIS} minTickGap={24} />
        <YAxis domain={[0, 100]} {...AXIS} ticks={[0, 25, 50, 75, 100]} />
        <Tooltip content={<ChartTooltip labelFormatter={shortDate} />} />
        <Area type="linear" dataKey="score" name="Score" stroke="#F5A524" strokeWidth={2} fill="url(#scoreFill)" dot={{ r: 2.5, fill: "#0C0C0E", stroke: "#F5A524", strokeWidth: 1.5 }} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function SeverityTrendChart({
  data,
  height = 220,
  severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
}: {
  data: Record<string, number | string>[];
  height?: number;
  severities?: Severity[];
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
        <CartesianGrid {...GRID} />
        <XAxis dataKey="date" tickFormatter={shortDate} {...AXIS} minTickGap={24} />
        <YAxis {...AXIS} allowDecimals={false} />
        <Tooltip content={<ChartTooltip labelFormatter={shortDate} />} />
        <Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize: 12, color: "#A1A1AA" }} />
        {severities.map((s) => (
          <Line key={s} type="linear" dataKey={s} name={SEVERITY_LABEL[s]} stroke={SEVERITY_COLOR[s]} strokeWidth={1.8} dot={false} />
        ))}
      </LineChart>
    </ResponsiveContainer>
  );
}

export function SeverityDonut({ counts, size = 168 }: { counts: Record<Severity, number>; size?: number }) {
  const data = SEVERITIES.map((s) => ({ name: SEVERITY_LABEL[s], value: counts[s] ?? 0, color: SEVERITY_COLOR[s] })).filter(
    (d) => d.value > 0,
  );
  const total = data.reduce((a, b) => a + b.value, 0);
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" innerRadius="78%" outerRadius="100%" paddingAngle={2} stroke="none" isAnimationActive={false}>
            {data.map((d) => (
              <Cell key={d.name} fill={d.color} />
            ))}
          </Pie>
          <Tooltip content={<ChartTooltip />} />
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-[22px] font-medium tabular-nums">{num(total)}</span>
        <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-faint">open</span>
      </div>
    </div>
  );
}

export function StackedSeverityBars({
  data,
  categoryKey,
  height,
}: {
  data: Record<string, number | string>[];
  categoryKey: string;
  height?: number;
}) {
  const h = height ?? Math.max(160, data.length * 30 + 30);
  return (
    <ResponsiveContainer width="100%" height={h}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 12, bottom: 0, left: 8 }} barCategoryGap={7}>
        <CartesianGrid stroke="#26262A" strokeDasharray="3 4" horizontal={false} />
        <XAxis type="number" {...AXIS} allowDecimals={false} />
        <YAxis type="category" dataKey={categoryKey} {...AXIS} width={104} tick={{ fill: "#A1A1AA", fontSize: 12 }} />
        <Tooltip cursor={{ fill: "#1C1C1F" }} content={<ChartTooltip />} />
        {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as Severity[]).map((s, i, arr) => (
          <Bar key={s} dataKey={s} name={SEVERITY_LABEL[s]} stackId="sev" fill={SEVERITY_COLOR[s]} radius={i === arr.length - 1 ? [0, 2, 2, 0] : 0} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}

export function SimpleBars({
  data,
  dataKey,
  categoryKey,
  color = "#F5A524",
  height = 200,
  name,
}: {
  data: Record<string, number | string>[];
  dataKey: string;
  categoryKey: string;
  color?: string;
  height?: number;
  name: string;
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -14 }}>
        <CartesianGrid {...GRID} />
        <XAxis dataKey={categoryKey} {...AXIS} />
        <YAxis {...AXIS} allowDecimals={false} />
        <Tooltip cursor={{ fill: "#1C1C1F" }} content={<ChartTooltip />} />
        <Bar dataKey={dataKey} name={name} fill={color} radius={[2, 2, 0, 0]} maxBarSize={42} />
      </BarChart>
    </ResponsiveContainer>
  );
}

export function NewResolvedChart({ data, height = 200 }: { data: Record<string, number | string>[]; height?: number }) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -14 }}>
        <CartesianGrid {...GRID} />
        <XAxis dataKey="date" tickFormatter={shortDate} {...AXIS} />
        <YAxis {...AXIS} allowDecimals={false} />
        <Tooltip cursor={{ fill: "#1C1C1F" }} content={<ChartTooltip labelFormatter={shortDate} />} />
        <Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize: 12 }} />
        <Bar dataKey="new" name="New" fill="#F76B15" radius={[2, 2, 0, 0]} maxBarSize={22} />
        <Bar dataKey="resolved" name="Resolved" fill="#3DD68C" radius={[2, 2, 0, 0]} maxBarSize={22} />
      </BarChart>
    </ResponsiveContainer>
  );
}

export function MultiLineChart({
  data,
  lines,
  height = 220,
  domain,
}: {
  data: Record<string, number | string>[];
  lines: { key: string; name: string; color: string }[];
  height?: number;
  domain?: [number, number];
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -14 }}>
        <CartesianGrid {...GRID} />
        <XAxis dataKey="date" tickFormatter={shortDate} {...AXIS} minTickGap={24} />
        <YAxis {...AXIS} domain={domain ?? ["auto", "auto"]} />
        <Tooltip content={<ChartTooltip labelFormatter={shortDate} />} />
        <Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize: 12 }} />
        {lines.map((l) => (
          <Line key={l.key} type="linear" dataKey={l.key} name={l.name} stroke={l.color} strokeWidth={1.8} dot={{ r: 2 }} />
        ))}
      </LineChart>
    </ResponsiveContainer>
  );
}

export function CoverageBar({ label, value, covered, total, tone }: { label: string; value: number | null; covered: number; total: number; tone?: string }) {
  const color = tone ?? (value == null ? "#38383E" : value >= 90 ? "#3DD68C" : value >= 70 ? "#F5A524" : "#E5484D");
  return (
    <div>
      <div className="flex items-baseline justify-between">
        <span className="text-[12.5px] text-muted">{label}</span>
        <span className="text-[13px] font-medium tabular-nums">{value == null ? "—" : `${value.toFixed(1)}%`}</span>
      </div>
      <div className="mt-1.5 h-1.5 overflow-hidden rounded-[1px] bg-line">
        <div className="h-full rounded-[1px]" style={{ width: `${value ?? 0}%`, background: color }} />
      </div>
      <p className="mt-1 text-[11.5px] text-faint">
        {num(covered)} of {num(total)}
      </p>
    </div>
  );
}
