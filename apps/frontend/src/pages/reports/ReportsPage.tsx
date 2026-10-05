import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Download, FileJson, FileSpreadsheet, FileText, Trash2 } from "lucide-react";
import { reportsApi } from "@/services";
import { useScope } from "@/stores/scope";
import { PERMS, useAuth } from "@/stores/auth";
import { PageHeader, Panel } from "@/components/ui/misc";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, InlineError, LoadingRows } from "@/components/ui/states";
import { useToast } from "@/components/ui/toast";
import { FieldError } from "@/components/accounts/CredentialFields";
import { cn } from "@/lib/cn";
import { downloadFile, errorMessage } from "@/lib/api";
import { bytes, dateTime } from "@/lib/format";
import type { Report } from "@/types/api";

const schema = z.object({
  title: z.string().trim().min(3, "Use at least 3 characters").max(200),
  report_type: z.enum(["executive", "technical"]),
  format: z.enum(["pdf", "json", "csv"]),
  account_id: z.string().optional(),
});
type FormValues = z.infer<typeof schema>;

const FORMAT_ICON = { pdf: FileText, json: FileJson, csv: FileSpreadsheet } as const;

const TYPES: { value: Report["report_type"]; title: string; body: string }[] = [
  {
    value: "executive",
    title: "Executive summary",
    body: "Score and how it is calculated, severity breakdown, compliance results, top risks and prioritised recommendations.",
  },
  {
    value: "technical",
    title: "Technical findings",
    body: "Everything in the summary plus every open finding with evidence, remediation steps and the affected asset inventory.",
  },
];

function GenerateForm() {
  const { accounts, accountId } = useScope();
  const queryClient = useQueryClient();
  const toast = useToast();
  const { register, handleSubmit, watch, setValue, formState } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      title: "Cloud Security Posture Report",
      report_type: "executive",
      format: "pdf",
      account_id: accountId ? String(accountId) : "",
    },
  });
  const create = useMutation({
    mutationFn: (v: FormValues) =>
      reportsApi.create({ title: v.title, report_type: v.report_type, format: v.format, account_id: v.account_id ? Number(v.account_id) : null }),
    onSuccess: async (r) => {
      queryClient.invalidateQueries({ queryKey: ["reports"] });
      toast.success(`${r.title} generated`);
      try {
        await downloadFile(`/reports/${r.id}/download`);
      } catch (e) {
        toast.error(errorMessage(e));
      }
    },
  });
  const type = watch("report_type");
  const format = watch("format");

  return (
    <Panel title="Generate a report" bodyClassName="p-4">
      <form className="space-y-4" onSubmit={handleSubmit((v) => create.mutate(v))} noValidate>
        <div>
          <label htmlFor="report-title" className="field-label">
            Title
          </label>
          <input id="report-title" className="input" {...register("title")} />
          <FieldError message={formState.errors.title?.message} />
        </div>
        <div>
          <p className="field-label">Report type</p>
          <div className="grid gap-2">
            {TYPES.map((t) => (
              <button
                type="button"
                key={t.value}
                onClick={() => setValue("report_type", t.value)}
                aria-pressed={type === t.value}
                className={cn(
                  "rounded-panel border p-3 text-left transition-colors",
                  type === t.value ? "border-accent/70 bg-accent-dim/20" : "border-line hover:border-line-strong",
                )}
              >
                <span className="block text-[13px] font-medium">{t.title}</span>
                <span className="mt-0.5 block text-[12px] text-muted">{t.body}</span>
              </button>
            ))}
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <p className="field-label">Format</p>
            <div className="inline-flex rounded-control border border-line p-0.5">
              {(["pdf", "csv", "json"] as const).map((f) => (
                <button
                  type="button"
                  key={f}
                  onClick={() => setValue("format", f)}
                  aria-pressed={format === f}
                  className={cn("h-7 rounded-[4px] px-3 text-[12.5px] uppercase", format === f ? "bg-raised text-ink" : "text-muted hover:text-ink")}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label htmlFor="report-account" className="field-label">
              Scope
            </label>
            <select id="report-account" className="input" {...register("account_id")}>
              <option value="">All accounts</option>
              {accounts.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </div>
        </div>
        <p className="text-[12px] text-faint">
          {format === "csv"
            ? "CSV exports one row per open finding, ready for spreadsheets or ticket imports."
            : format === "json"
              ? "JSON contains the full structured report for automation and archiving."
              : "PDF is formatted for sharing with security leadership."}
        </p>
        <InlineError error={create.error} />
        <Button type="submit" variant="primary" loading={create.isPending} className="w-full">
          Generate and download
        </Button>
      </form>
    </Panel>
  );
}

export default function ReportsPage() {
  const { can } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [downloading, setDownloading] = useState<number | null>(null);
  const { data, error, isLoading, refetch } = useQuery({ queryKey: ["reports"], queryFn: reportsApi.list });
  const remove = useMutation({
    mutationFn: (id: number) => reportsApi.remove(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["reports"] }),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const download = async (r: Report) => {
    setDownloading(r.id);
    try {
      await downloadFile(`/reports/${r.id}/download`);
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setDownloading(null);
    }
  };
  const canGenerate = can(PERMS.reportsGenerate);

  return (
    <>
      <PageHeader title="Reports" description="Point-in-time security reports built from the latest completed scan of each account. Files are stored with a SHA-256 digest." />
      <div className={cn("grid gap-4", canGenerate && "xl:grid-cols-[minmax(0,1fr)_380px]")}>
        <div className="panel min-w-0 overflow-hidden">
          {isLoading ? (
            <LoadingRows rows={5} />
          ) : error ? (
            <ErrorState error={error} onRetry={refetch} />
          ) : !data?.length ? (
            <EmptyState icon={<FileText className="h-7 w-7" />} title="No reports yet" description="Generate an executive summary or a full technical findings report." />
          ) : (
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Report</th>
                    <th>Type</th>
                    <th>Scope</th>
                    <th>Generated</th>
                    <th className="text-right">Size</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {data.map((r) => {
                    const Icon = FORMAT_ICON[r.format] ?? FileText;
                    return (
                      <tr key={r.id}>
                        <td className="min-w-[220px]">
                          <span className="flex items-center gap-2">
                            <Icon className="h-4 w-4 shrink-0 text-faint" aria-hidden />
                            <span>{r.title}</span>
                            <span className="rounded-control border border-line px-1 text-[11px] uppercase text-faint">{r.format}</span>
                          </span>
                          {r.sha256 && (
                            <span className="mono block text-faint" title={`SHA-256 ${r.sha256}`}>
                              sha256 {r.sha256.slice(0, 16)}…
                            </span>
                          )}
                        </td>
                        <td className="whitespace-nowrap capitalize text-muted">{r.report_type}</td>
                        <td className="whitespace-nowrap text-muted">{r.account_name ?? "All accounts"}</td>
                        <td className="whitespace-nowrap text-muted">
                          {dateTime(r.created_at)}
                          <span className="block text-[12px] text-faint">{r.generated_by}</span>
                        </td>
                        <td className="whitespace-nowrap text-right tabular-nums text-muted">{bytes(r.size_bytes)}</td>
                        <td className="whitespace-nowrap text-right">
                          <Button size="sm" loading={downloading === r.id} onClick={() => download(r)} aria-label={`Download ${r.title}`}>
                            <Download className="h-3.5 w-3.5" aria-hidden /> Download
                          </Button>
                          {canGenerate && (
                            <Button
                              size="sm"
                              variant="ghost"
                              className="ml-1"
                              aria-label={`Delete ${r.title}`}
                              onClick={() => remove.mutate(r.id)}
                              disabled={remove.isPending && remove.variables === r.id}
                            >
                              <Trash2 className="h-3.5 w-3.5" aria-hidden />
                            </Button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
        {canGenerate && (
          <aside>
            <GenerateForm />
          </aside>
        )}
      </div>
    </>
  );
}
