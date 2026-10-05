import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, ExternalLink, ShieldCheck, Ticket, TriangleAlert } from "lucide-react";
import { findingsApi } from "@/services";
import { PERMS, useAuth } from "@/stores/auth";
import { CodeBlock, KeyValue, Panel } from "@/components/ui/misc";
import { ErrorState, LoadingRows } from "@/components/ui/states";
import { ExposureMark, SeverityBadge, StatusBadge, Tag } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { JsonTree } from "@/components/ui/json";
import { useToast } from "@/components/ui/toast";
import { STATUS_TRANSITIONS, StatusDialog, statusVerb } from "@/components/findings/StatusActions";
import { TicketDialog } from "@/components/findings/TicketDialog";
import { FindingTimeline } from "@/components/findings/FindingTimeline";
import { dateTime, relative, resourceTypeLabel } from "@/lib/format";
import { errorMessage } from "@/lib/api";
import type { FindingDetail, FindingStatus } from "@/types/api";

function referenceLabel(url: string): string {
  try {
    const u = new URL(url);
    if (u.hostname.includes("cisecurity")) return "CIS Benchmark";
    if (u.hostname.startsWith("docs.aws")) {
      const part = (u.pathname.split("/").filter(Boolean)[0] ?? "").toLowerCase();
      const guides: Record<string, string> = {
        iam: "IAM", amazons3: "Amazon S3", awsec2: "Amazon EC2", ec2: "Amazon EC2", amazonrds: "Amazon RDS",
        awscloudtrail: "CloudTrail", vpc: "Amazon VPC", lambda: "AWS Lambda", amazonecr: "Amazon ECR", kms: "AWS KMS",
        secretsmanager: "Secrets Manager", ebs: "Amazon EBS", wellarchitected: "Well-Architected", securityhub: "Security Hub",
      };
      return guides[part] ? `AWS documentation · ${guides[part]}` : "AWS documentation";
    }
    return u.hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

function Header({ f, onStatus, onTicket, canUpdate }: { f: FindingDetail; onStatus: (s: FindingStatus) => void; onTicket: () => void; canUpdate: boolean }) {
  const transitions = STATUS_TRANSITIONS[f.status];
  const primary = transitions.find((t) => t === "RESOLVED") ?? transitions[0];
  return (
    <div className="mb-5">
      <Link to="/findings" className="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-muted hover:text-ink">
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Findings
      </Link>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-2.5">
            <SeverityBadge severity={f.severity} className="text-[13px]" />
            <StatusBadge status={f.status} />
            {f.public_exposure && <ExposureMark exposed />}
            {f.ticket_ref && (
              <Tag>
                <Ticket className="mr-1 h-3 w-3" aria-hidden />
                {f.ticket_ref}
              </Tag>
            )}
          </div>
          <h1 className="text-[20px] font-semibold leading-snug">{f.title}</h1>
          <p className="mono mt-1.5 text-faint">
            {f.display_id} · Rule {f.rule_id} · {f.category}
          </p>
        </div>
        {canUpdate && (
          <div className="flex flex-wrap items-center gap-2">
            {transitions
              .filter((t) => t !== primary)
              .map((t) => (
                <Button key={t} size="md" variant={t === "SUPPRESSED" ? "ghost" : "secondary"} onClick={() => onStatus(t)}>
                  {statusVerb(t)}
                </Button>
              ))}
            {!f.ticket_ref && f.status !== "RESOLVED" && f.status !== "SUPPRESSED" && (
              <Button onClick={onTicket}>
                <Ticket className="h-3.5 w-3.5" aria-hidden /> Create ticket
              </Button>
            )}
            <Button variant="primary" onClick={() => onStatus(primary)}>
              {statusVerb(primary)}
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}

function CommentBox({ id }: { id: number }) {
  const [note, setNote] = useState("");
  const queryClient = useQueryClient();
  const toast = useToast();
  const m = useMutation({
    mutationFn: () => findingsApi.comment(id, note.trim()),
    onSuccess: (f) => {
      queryClient.setQueryData(["finding", id], f);
      setNote("");
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  return (
    <form
      className="mb-5 flex flex-col gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        if (note.trim()) m.mutate();
      }}
    >
      <label htmlFor="comment" className="sr-only">
        Add a comment
      </label>
      <textarea
        id="comment"
        className="input h-16 resize-y py-2"
        placeholder="Add investigation notes for your team"
        value={note}
        maxLength={2000}
        onChange={(e) => setNote(e.target.value)}
      />
      <div className="flex justify-end">
        <Button size="sm" type="submit" loading={m.isPending} disabled={!note.trim()}>
          Add comment
        </Button>
      </div>
    </form>
  );
}

export default function FindingDetailPage() {
  const id = Number(useParams().id);
  const { can } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [dialog, setDialog] = useState<FindingStatus | null>(null);
  const [ticketOpen, setTicketOpen] = useState(false);
  const { data: f, error, isLoading, refetch } = useQuery({
    queryKey: ["finding", id],
    queryFn: () => findingsApi.get(id),
    enabled: Number.isFinite(id),
  });
  const setStatus = useMutation({
    mutationFn: ({ status, note }: { status: FindingStatus; note: string }) => findingsApi.setStatus(id, status, note),
    onSuccess: (updated) => {
      queryClient.setQueryData(["finding", id], updated);
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      toast.success(`${updated.display_id} is now ${updated.status.toLowerCase().replace("_", " ")}`);
      setDialog(null);
    },
  });

  if (isLoading) return <LoadingRows rows={10} />;
  if (error || !f) return <div className="panel"><ErrorState error={error} onRetry={refetch} /></div>;
  const canUpdate = can(PERMS.findingsUpdate);

  return (
    <>
      <Header f={f} canUpdate={canUpdate} onStatus={setDialog} onTicket={() => setTicketOpen(true)} />

      {f.status === "SUPPRESSED" && f.suppression_reason && (
        <div className="mb-4 rounded-panel border border-line-strong bg-raised px-4 py-3 text-[13px]">
          <span className="font-medium">Accepted risk.</span> <span className="text-muted">{f.suppression_reason}</span>
        </div>
      )}
      {f.status === "RESOLVED" && (
        <div className="mb-4 flex items-center gap-2 rounded-panel border border-ok/35 bg-ok/10 px-4 py-3 text-[13px]">
          <ShieldCheck className="h-4 w-4 text-ok" aria-hidden /> Resolved {relative(f.resolved_at)}. The next scan verifies the fix and reopens the finding if it is still present.
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="min-w-0 space-y-4">
          <Panel title="Why this matters" bodyClassName="grid gap-4 p-4 md:grid-cols-2">
            <div>
              <p className="mb-1 text-[12px] font-medium text-faint">What was found</p>
              <p className="text-[13.5px] leading-relaxed">{f.description}</p>
              {f.message && f.message !== f.title && <p className="mt-2 text-[13px] text-muted">{f.message}</p>}
            </div>
            <div>
              <p className="mb-1 flex items-center gap-1.5 text-[12px] font-medium text-faint">
                <TriangleAlert className="h-3.5 w-3.5 text-sev-high" aria-hidden /> Impact
              </p>
              <p className="text-[13.5px] leading-relaxed">{f.impact}</p>
            </div>
          </Panel>

          <Panel title="Evidence" actions={<span className="text-[12px] text-faint">Captured {dateTime(f.last_detected_at)}</span>} bodyClassName="p-4">
            <p className="mb-2 text-[12.5px] text-muted">
              Configuration observed on <span className="mono text-ink">{f.resource_uid}</span> that caused this check to fail.
            </p>
            <JsonTree data={f.evidence} />
          </Panel>

          <Panel title="Recommended remediation" bodyClassName="p-4">
            <p className="mb-3 text-[13.5px]">{f.remediation.summary}</p>
            {f.remediation.steps.length > 1 && (
              <ol className="mb-4 list-decimal space-y-1.5 pl-5 text-[13px] text-muted marker:text-faint">
                {f.remediation.steps.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
            )}
            {f.remediation.cli_example && (
              <>
                <p className="mb-1.5 text-[12px] font-medium text-faint">Example AWS CLI (review before running)</p>
                <CodeBlock code={f.remediation.cli_example} />
                <p className="mt-2 text-[12px] text-faint">
                  CloudAegis operates with read-only access and never changes your infrastructure. Run remediation through your normal change process.
                </p>
              </>
            )}
          </Panel>

          <Panel title="Activity" bodyClassName="p-4">
            {canUpdate && <CommentBox id={f.id} />}
            <FindingTimeline events={f.events} />
          </Panel>
        </div>

        <aside className="min-w-0 space-y-4">
          <Panel title="Resource" bodyClassName="p-4">
            <dl className="grid gap-3">
              <KeyValue label="Name">
                <Link to={`/assets/${f.asset_id}`} className="link">
                  {f.asset_name}
                </Link>
              </KeyValue>
              <KeyValue label="Resource ID" mono>
                {f.resource_uid}
              </KeyValue>
              <div className="grid grid-cols-2 gap-3">
                <KeyValue label="Type">{resourceTypeLabel(f.resource_type)}</KeyValue>
                <KeyValue label="Service">{f.service}</KeyValue>
                <KeyValue label="Region">{f.region}</KeyValue>
                <KeyValue label="Exposure">
                  <ExposureMark exposed={f.public_exposure} />
                </KeyValue>
              </div>
              <KeyValue label="Account">
                {f.account_name} <span className="mono text-faint">{f.account_identifier}</span>
              </KeyValue>
              <div className="grid grid-cols-2 gap-3">
                <KeyValue label="First detected">{dateTime(f.first_detected_at)}</KeyValue>
                <KeyValue label="Last detected">{dateTime(f.last_detected_at)}</KeyValue>
              </div>
            </dl>
          </Panel>

          <Panel title="Compliance impact" bodyClassName="divide-y divide-line">
            {f.compliance.length === 0 ? (
              <p className="p-4 text-[13px] text-faint">Not mapped to a compliance control.</p>
            ) : (
              f.compliance.map((c) => (
                <Link
                  key={`${c.framework_key}-${c.control_id}`}
                  to={`/compliance/${c.framework_key}?control=${encodeURIComponent(c.control_id)}`}
                  className="block px-4 py-2.5 hover:bg-raised/60"
                >
                  <span className="flex items-center gap-2 text-[12px] text-faint">
                    {c.framework} <span className="mono text-muted">{c.control_id}</span>
                  </span>
                  <span className="text-[13px]">{c.title}</span>
                </Link>
              ))
            )}
          </Panel>

          <Panel title="References" bodyClassName="p-2">
            {f.references.map((r) => (
              <a key={r} href={r} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 rounded-control px-2 py-1.5 text-[13px] text-muted hover:bg-raised hover:text-ink">
                <ExternalLink className="h-3.5 w-3.5 shrink-0" aria-hidden />
                <span className="truncate" title={r}>
                  {referenceLabel(r)}
                </span>
              </a>
            ))}
          </Panel>
        </aside>
      </div>

      <StatusDialog
        status={dialog}
        onClose={() => {
          setDialog(null);
          setStatus.reset();
        }}
        onConfirm={(note) => dialog && setStatus.mutate({ status: dialog, note })}
        pending={setStatus.isPending}
        error={setStatus.error}
      />
      <TicketDialog findingId={f.id} open={ticketOpen} onOpenChange={setTicketOpen} />
    </>
  );
}
