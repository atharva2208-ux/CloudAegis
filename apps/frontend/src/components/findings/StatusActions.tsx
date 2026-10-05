import { useState } from "react";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { InlineError } from "@/components/ui/states";
import { STATUS_LABEL } from "@/lib/format";
import type { FindingStatus } from "@/types/api";

const COPY: Record<FindingStatus, { title: string; description: string; noteLabel: string; required: boolean; cta: string }> = {
  OPEN: { title: "Reopen finding", description: "The finding returns to the open queue.", noteLabel: "Reason (optional)", required: false, cta: "Reopen" },
  ACKNOWLEDGED: { title: "Acknowledge finding", description: "Confirms the finding was reviewed and is valid.", noteLabel: "Note (optional)", required: false, cta: "Acknowledge" },
  IN_PROGRESS: { title: "Mark in progress", description: "Signals that remediation work has started.", noteLabel: "Note (optional)", required: false, cta: "Mark in progress" },
  RESOLVED: {
    title: "Mark resolved",
    description: "Use this after remediating. The next scan verifies the fix and reopens the finding if the issue is still present.",
    noteLabel: "What was changed (optional)",
    required: false,
    cta: "Mark resolved",
  },
  SUPPRESSED: {
    title: "Suppress finding",
    description: "Suppressed findings are excluded from the security score as accepted risk. Record why the risk is accepted.",
    noteLabel: "Justification (required)",
    required: true,
    cta: "Suppress",
  },
};

export function StatusDialog({
  status,
  count = 1,
  onClose,
  onConfirm,
  pending,
  error,
}: {
  status: FindingStatus | null;
  count?: number;
  onClose: () => void;
  onConfirm: (note: string) => void;
  pending: boolean;
  error: unknown;
}) {
  const [note, setNote] = useState("");
  if (!status) return null;
  const copy = COPY[status];
  return (
    <Dialog
      open={!!status}
      onOpenChange={(o) => {
        if (!o) {
          setNote("");
          onClose();
        }
      }}
      title={count > 1 ? `${copy.title.replace("finding", `${count} findings`)}` : copy.title}
      description={copy.description}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant={status === "SUPPRESSED" ? "danger" : "primary"}
            loading={pending}
            disabled={copy.required && note.trim().length < 5}
            onClick={() => onConfirm(note.trim())}
          >
            {copy.cta}
          </Button>
        </>
      }
    >
      <label className="field-label" htmlFor="status-note">
        {copy.noteLabel}
      </label>
      <textarea
        id="status-note"
        className="input h-24 resize-y py-2"
        value={note}
        maxLength={2000}
        onChange={(e) => setNote(e.target.value)}
        placeholder={status === "SUPPRESSED" ? "e.g. Public static website bucket; approved by security review SR-114" : ""}
      />
      {copy.required && note.trim().length > 0 && note.trim().length < 5 && (
        <p className="mt-1 text-[12px] text-sev-medium">Add a few more words of justification.</p>
      )}
      <div className="mt-3">
        <InlineError error={error} />
      </div>
    </Dialog>
  );
}

export const STATUS_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  OPEN: ["ACKNOWLEDGED", "IN_PROGRESS", "RESOLVED", "SUPPRESSED"],
  ACKNOWLEDGED: ["IN_PROGRESS", "RESOLVED", "SUPPRESSED", "OPEN"],
  IN_PROGRESS: ["RESOLVED", "SUPPRESSED", "OPEN"],
  RESOLVED: ["OPEN"],
  SUPPRESSED: ["OPEN"],
};

export const statusVerb = (s: FindingStatus) => COPY[s].cta || STATUS_LABEL[s];
