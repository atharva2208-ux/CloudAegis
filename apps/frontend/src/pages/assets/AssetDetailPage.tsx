import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, ArrowRight, ArrowLeftRight } from "lucide-react";
import { assetsApi } from "@/services";
import { CopyButton, KeyValue, Panel, Tabs, TabPanel } from "@/components/ui/misc";
import { ErrorState, LoadingRows } from "@/components/ui/states";
import { EncryptionMark, ExposureMark, RiskMeter, Tag } from "@/components/ui/badges";
import { JsonTree } from "@/components/ui/json";
import { CompactFindingList } from "@/components/findings/CompactFindingList";
import { SEVERITY_COLOR, dateTime, relative, resourceTypeLabel } from "@/lib/format";
import type { AssetDetail } from "@/types/api";

const KIND_LABEL: Record<string, string> = {
  member_of: "Member of",
  executes_as: "Executes as",
  attached_to: "Attached to",
  in_vpc: "In VPC",
  in_subnet: "In subnet",
  protected_by: "Protected by",
  encrypted_by: "Encrypted by",
  logs_to: "Logs to",
  routes_via: "Routes via",
  associated_with: "Associated with",
};

function Relationships({ asset }: { asset: AssetDetail }) {
  if (!asset.relationships.length)
    return <p className="px-4 py-6 text-center text-[13px] text-faint">No relationships recorded for this resource.</p>;
  return (
    <ul className="divide-y divide-line">
      {asset.relationships.map((r) => (
        <li key={`${r.direction}-${r.kind}-${r.id}`} className="flex items-center gap-3 px-4 py-2.5 text-[13px]">
          {r.direction === "outbound" ? (
            <ArrowRight className="h-3.5 w-3.5 text-faint" aria-label="outbound" />
          ) : (
            <ArrowLeftRight className="h-3.5 w-3.5 text-faint" aria-label="inbound" />
          )}
          <span className="w-36 shrink-0 text-muted">
            {r.direction === "inbound" ? "Referenced by" : KIND_LABEL[r.kind] ?? r.kind.replace(/_/g, " ")}
          </span>
          <Link to={`/assets/${r.id}`} className="min-w-0 flex-1 truncate hover:text-accent-strong">
            {r.name}
          </Link>
          <span className="text-[12px] text-faint">{resourceTypeLabel(r.resource_type)}</span>
        </li>
      ))}
    </ul>
  );
}

export default function AssetDetailPage() {
  const id = Number(useParams().id);
  const [tab, setTab] = useState("findings");
  const { data: a, error, isLoading, refetch } = useQuery({ queryKey: ["asset", id], queryFn: () => assetsApi.get(id) });

  if (isLoading) return <LoadingRows rows={10} />;
  if (error || !a) return <div className="panel"><ErrorState error={error} onRetry={refetch} /></div>;
  const open = a.findings.filter((f) => !["RESOLVED", "SUPPRESSED"].includes(f.status));
  const closed = a.findings.length - open.length;
  const tags = Object.entries(a.tags);

  return (
    <>
      <Link to="/assets" className="mb-3 inline-flex items-center gap-1.5 text-[12.5px] text-muted hover:text-ink">
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Assets
      </Link>
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="mb-1.5 flex items-center gap-2">
            <Tag>{resourceTypeLabel(a.resource_type)}</Tag>
            {!a.is_active && <Tag className="text-sev-medium">No longer present</Tag>}
          </div>
          <h1 className="break-all text-[20px] font-semibold">{a.name}</h1>
          <p className="mono mt-1 flex flex-wrap items-center gap-1 break-all text-faint">
            {a.resource_uid} <CopyButton text={a.resource_uid} label="Copy ARN" />
          </p>
        </div>
      </div>

      <div className="panel mb-4 grid grid-cols-2 divide-line sm:grid-cols-4 sm:divide-x">
        <div className="p-4">
          <p className="text-[12px] text-faint">Risk score</p>
          <div className="mt-2 flex items-center gap-2">
            <span className="text-[22px] font-semibold tabular-nums" style={{ color: a.risk_level === "NONE" ? undefined : SEVERITY_COLOR[a.risk_level] }}>
              {a.risk_score}
            </span>
            <RiskMeter score={a.risk_score} level={a.risk_level} />
          </div>
        </div>
        <div className="p-4">
          <p className="text-[12px] text-faint">Open findings</p>
          <p className="mt-2 text-[22px] font-semibold tabular-nums">{open.length}</p>
        </div>
        <div className="p-4">
          <p className="text-[12px] text-faint">Exposure</p>
          <div className="mt-3">
            <ExposureMark exposed={a.public_exposure} />
          </div>
        </div>
        <div className="p-4">
          <p className="text-[12px] text-faint">Encryption</p>
          <div className="mt-3">
            <EncryptionMark status={a.encryption_status} />
          </div>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="panel min-w-0 p-4 pt-2">
          <Tabs
            value={tab}
            onValueChange={setTab}
            tabs={[
              { value: "findings", label: `Findings (${open.length}${closed ? ` + ${closed} closed` : ""})` },
              { value: "relationships", label: `Relationships (${a.relationships.length})` },
              { value: "config", label: "Configuration" },
            ]}
          >
            <TabPanel value="findings" className="-mx-4">
              <CompactFindingList findings={a.findings} empty="No findings for this resource. All applicable checks passed." />
            </TabPanel>
            <TabPanel value="relationships" className="-mx-4">
              <Relationships asset={a} />
            </TabPanel>
            <TabPanel value="config">
              <p className="mb-2 text-[12.5px] text-muted">Normalised configuration captured during discovery. Secret values are never collected.</p>
              <JsonTree data={a.properties} />
            </TabPanel>
          </Tabs>
        </div>

        <aside className="space-y-4">
          <Panel title="Details" bodyClassName="p-4">
            <dl className="grid gap-3">
              <div className="grid grid-cols-2 gap-3">
                <KeyValue label="Service">{a.service}</KeyValue>
                <KeyValue label="Region">{a.region}</KeyValue>
              </div>
              <KeyValue label="Account">
                {a.account_name} <span className="mono text-faint">{a.account_identifier}</span>
              </KeyValue>
              <KeyValue label="First seen">{dateTime(a.first_seen_at)}</KeyValue>
              <KeyValue label="Last scanned">
                {dateTime(a.last_seen_at)} <span className="text-faint">({relative(a.last_seen_at)})</span>
              </KeyValue>
            </dl>
          </Panel>
          <Panel title="Tags" bodyClassName="p-4">
            {tags.length === 0 ? (
              <p className="text-[13px] text-faint">Untagged. Ownership tags help route remediation.</p>
            ) : (
              <dl className="grid gap-2">
                {tags.map(([k, v]) => (
                  <div key={k} className="flex gap-2 text-[13px]">
                    <dt className="mono w-28 shrink-0 truncate text-faint" title={k}>
                      {k}
                    </dt>
                    <dd className="min-w-0 break-all">{v}</dd>
                  </div>
                ))}
              </dl>
            )}
          </Panel>
        </aside>
      </div>
    </>
  );
}
