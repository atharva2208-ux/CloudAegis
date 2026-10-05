import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { accountsApi } from "@/services";
import { CodeBlock, Tabs, TabPanel } from "@/components/ui/misc";
import { InlineError, LoadingRows } from "@/components/ui/states";

/**
 * Shows the exact IAM artefacts needed for a least-privilege audit role, with the external ID
 * the user will enter filled in so the trust policy can be pasted as-is.
 */
export function RoleSetupGuide({ externalId }: { externalId?: string }) {
  const [tab, setTab] = useState("cfn");
  const { data, error, isLoading } = useQuery({ queryKey: ["onboarding-guide"], queryFn: accountsApi.guide, staleTime: Infinity });

  const swap = useMemo(() => {
    const suggestion = data?.external_id_suggestion;
    return (text: string) => (suggestion && externalId ? text.split(suggestion).join(externalId) : text);
  }, [data, externalId]);

  if (isLoading) return <LoadingRows rows={3} className="p-0" />;
  if (!data) return <InlineError error={error} />;

  const cli = [
    "aws cloudformation deploy \\",
    "  --stack-name cloudaegis-audit-role \\",
    "  --template-file cloudaegis-audit-role.yaml \\",
    "  --capabilities CAPABILITY_NAMED_IAM",
  ].join("\n");

  return (
    <div>
      <ol className="mb-3 list-decimal space-y-1 pl-5 text-[12.5px] text-muted marker:text-faint">
        <li>Create the role in the AWS account you want to assess (CloudFormation is quickest).</li>
        <li>The role only grants read-only <span className="mono">Describe*</span>, <span className="mono">Get*</span> and <span className="mono">List*</span> actions needed by the checks.</li>
        <li>Copy the role ARN from the stack outputs into the field above.</li>
      </ol>
      {!data.platform_principal && (
        <p className="mb-3 text-[12px] text-faint">
          Replace <span className="mono">&lt;CLOUDAEGIS_ACCOUNT_ID&gt;</span> with the AWS account where CloudAegis runs (set{" "}
          <span className="mono">PLATFORM_AWS_PRINCIPAL_ARN</span> to pre-fill it).
        </p>
      )}
      <Tabs
        value={tab}
        onValueChange={setTab}
        tabs={[
          { value: "cfn", label: "CloudFormation" },
          { value: "trust", label: "Trust policy" },
          { value: "perms", label: "Permissions policy" },
        ]}
      >
        <TabPanel value="cfn" className="space-y-2">
          <CodeBlock code={swap(data.cloudformation_template)} className="max-h-72 overflow-y-auto" />
          <CodeBlock code={cli} />
        </TabPanel>
        <TabPanel value="trust">
          <CodeBlock code={swap(JSON.stringify(data.trust_policy, null, 2))} className="max-h-72 overflow-y-auto" />
        </TabPanel>
        <TabPanel value="perms" className="space-y-2">
          <ul className="text-[12.5px] text-muted">
            {data.permissions_policies.map((p) => (
              <li key={p}>• {p}</li>
            ))}
          </ul>
          <CodeBlock code={JSON.stringify(data.inline_policy, null, 2)} className="max-h-72 overflow-y-auto" />
        </TabPanel>
      </Tabs>
    </div>
  );
}
