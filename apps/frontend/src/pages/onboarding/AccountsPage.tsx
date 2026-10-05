import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Building2, Plus, Radar } from "lucide-react";
import { accountsApi } from "@/services";
import { PERMS, useAuth } from "@/stores/auth";
import { PageHeader } from "@/components/ui/misc";
import { Button } from "@/components/ui/button";
import { DemoBadge } from "@/components/ui/badges";
import { EmptyState, ErrorState, LoadingRows } from "@/components/ui/states";
import { StartScanDialog } from "@/components/scans/StartScanDialog";
import { ScoreValue } from "@/components/scans/ScanTable";
import { AUTH_LABEL, AccountStatus } from "@/components/accounts/AccountStatus";
import { num, relative } from "@/lib/format";

export default function AccountsPage() {
  const { can } = useAuth();
  const [scanFor, setScanFor] = useState<number | undefined>();
  const { data, error, isLoading, refetch } = useQuery({ queryKey: ["accounts"], queryFn: accountsApi.list });
  const canManage = can(PERMS.accountsManage);
  const canScan = can(PERMS.scansRun);

  return (
    <>
      <PageHeader
        title="Cloud accounts"
        description="Connected AWS accounts and the read-only access CloudAegis uses to assess them."
        actions={
          canManage && (
            <Link to="/accounts/new">
              <Button variant="primary">
                <Plus className="h-4 w-4" aria-hidden /> Add account
              </Button>
            </Link>
          )
        }
      />
      <div className="panel overflow-hidden">
        {isLoading ? (
          <LoadingRows rows={4} />
        ) : error ? (
          <ErrorState error={error} onRetry={refetch} />
        ) : !data?.length ? (
          <EmptyState
            icon={<Building2 className="h-7 w-7" />}
            title="No cloud accounts connected"
            description="Connect an AWS account with a read-only audit role, or start with the simulated environment."
            action={
              canManage && (
                <Link to="/accounts/new">
                  <Button variant="primary">Add account</Button>
                </Link>
              )
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Account</th>
                  <th>Connection</th>
                  <th>Authentication</th>
                  <th className="text-right">Regions</th>
                  <th className="text-right">Assets</th>
                  <th className="text-right">Open findings</th>
                  <th className="text-right">Score</th>
                  <th>Last scan</th>
                  {canScan && <th />}
                </tr>
              </thead>
              <tbody>
                {data.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <Link to={`/accounts/${a.id}`} className="flex items-center gap-2 text-ink hover:text-accent-strong">
                        {a.name}
                        {a.is_demo && <DemoBadge />}
                      </Link>
                      <span className="mono text-faint">{a.account_identifier ?? "not yet validated"}</span>
                    </td>
                    <td>
                      <AccountStatus status={a.status} />
                    </td>
                    <td className="whitespace-nowrap text-muted">{AUTH_LABEL[a.auth_method] ?? a.auth_method}</td>
                    <td className="text-right tabular-nums">{a.regions.filter((r) => r.enabled).length}</td>
                    <td className="text-right tabular-nums">{num(a.asset_count)}</td>
                    <td className="text-right tabular-nums">{num(a.open_findings)}</td>
                    <td className="text-right">
                      <ScoreValue score={a.security_score} />
                    </td>
                    <td className="whitespace-nowrap text-muted">{relative(a.last_scan_at)}</td>
                    {canScan && (
                      <td className="text-right">
                        <Button size="sm" onClick={() => setScanFor(a.id)} disabled={a.status === "error"}>
                          <Radar className="h-3.5 w-3.5" aria-hidden /> Scan
                        </Button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <StartScanDialog open={scanFor !== undefined} onOpenChange={(o) => !o && setScanFor(undefined)} defaultAccountId={scanFor} />
    </>
  );
}
