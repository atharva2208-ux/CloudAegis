import * as RDialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export function Dialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  width = "max-w-lg",
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  width?: string;
}) {
  return (
    <RDialog.Root open={open} onOpenChange={onOpenChange}>
      <RDialog.Portal>
        <RDialog.Overlay className="fixed inset-0 z-40 bg-[#000000]/70" />
        <RDialog.Content
          className={cn(
            "fixed left-1/2 top-[12vh] z-50 max-h-[78vh] w-[calc(100%-2rem)] -translate-x-1/2 overflow-y-auto rounded-panel border border-line-strong bg-surface",
            width,
          )}
        >
          <div className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
            <div>
              <RDialog.Title className="text-[15px] font-semibold">{title}</RDialog.Title>
              {description && (
                <RDialog.Description className="mt-1 text-[13px] text-muted">{description}</RDialog.Description>
              )}
            </div>
            <RDialog.Close className="rounded-control p-1 text-faint hover:bg-raised hover:text-ink" aria-label="Close">
              <X className="h-4 w-4" />
            </RDialog.Close>
          </div>
          <div className="px-5 py-4">{children}</div>
          {footer && <div className="flex justify-end gap-2 border-t border-line px-5 py-3">{footer}</div>}
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>
  );
}
