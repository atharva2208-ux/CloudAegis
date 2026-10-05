import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { CodeBlock } from "@/components/ui/misc";
import { InlineError, LoadingRows } from "@/components/ui/states";
import { useToast } from "@/components/ui/toast";
import { findingsApi } from "@/services";

/**
 * CloudAegis does not push to an external tracker by default. The dialog prepares a
 * ready-to-paste ticket body and records the resulting ticket reference on the finding.
 */
export function TicketDialog({ findingId, open, onOpenChange }: { findingId: number; open: boolean; onOpenChange: (o: boolean) => void }) {
  const [ref, setRef] = useState("");
  const queryClient = useQueryClient();
  const toast = useToast();
  const draft = useQuery({
    queryKey: ["ticket-draft", findingId],
    queryFn: () => findingsApi.ticketDraft(findingId),
    enabled: open,
  });
  const link = useMutation({
    mutationFn: () => findingsApi.linkTicket(findingId, ref.trim()),
    onSuccess: (finding) => {
      queryClient.setQueryData(["finding", findingId], finding);
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      toast.success(`Linked ticket ${finding.ticket_ref}`);
      setRef("");
      onOpenChange(false);
    },
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      width="max-w-2xl"
      title="Create remediation ticket"
      description="Copy the prepared ticket into your tracker (Jira, Linear, ServiceNow), then record its reference here."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" loading={link.isPending} disabled={ref.trim().length < 2} onClick={() => link.mutate()}>
            Link ticket
          </Button>
        </>
      }
    >
      {draft.isLoading ? (
        <LoadingRows rows={4} className="p-0" />
      ) : draft.data ? (
        <div className="space-y-3">
          <div>
            <p className="field-label">Title</p>
            <CodeBlock code={draft.data.title} />
          </div>
          <div>
            <p className="field-label">Description</p>
            <CodeBlock code={draft.data.body} className="max-h-64 overflow-y-auto" />
          </div>
        </div>
      ) : (
        <InlineError error={draft.error} />
      )}
      <div className="mt-4">
        <label className="field-label" htmlFor="ticket-ref">
          Ticket reference
        </label>
        <input
          id="ticket-ref"
          className="input"
          placeholder="e.g. SEC-1423"
          value={ref}
          maxLength={120}
          onChange={(e) => setRef(e.target.value)}
        />
      </div>
      <div className="mt-3">
        <InlineError error={link.error} />
      </div>
    </Dialog>
  );
}
