import type { ReactNode } from "react";
import { AlertTriangle, RotateCw } from "lucide-react";
import { ApiError, errorMessage } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Button } from "./button";

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-control bg-raised", className)} aria-hidden />;
}

export function LoadingRows({ rows = 8, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn("space-y-2 p-4", className)} role="status" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-8 w-full" />
      ))}
    </div>
  );
}

export function LoadingPanel({ height = "h-64" }: { height?: string }) {
  return (
    <div className={cn("panel flex items-center justify-center", height)} role="status" aria-label="Loading">
      <Skeleton className="h-3/4 w-[92%]" />
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
}: {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center px-6 py-14 text-center", className)}>
      {icon && <div className="mb-3 text-faint">{icon}</div>}
      <p className="text-[14px] font-medium text-ink">{title}</p>
      {description && <p className="mt-1 max-w-md text-[13px] text-muted">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry, className }: { error: unknown; onRetry?: () => void; className?: string }) {
  const requestId = error instanceof ApiError ? error.requestId : undefined;
  const forbidden = error instanceof ApiError && error.status === 403;
  return (
    <div className={cn("flex flex-col items-center justify-center px-6 py-12 text-center", className)} role="alert">
      <AlertTriangle className="mb-3 h-6 w-6 text-sev-high" aria-hidden />
      <p className="text-[14px] font-medium text-ink">
        {forbidden ? "You don't have access to this view" : "This data couldn't be loaded"}
      </p>
      <p className="mt-1 max-w-md text-[13px] text-muted">{errorMessage(error)}</p>
      {requestId && <p className="mono mt-2 text-faint">Request ID {requestId}</p>}
      {onRetry && !forbidden && (
        <Button className="mt-4" size="sm" onClick={onRetry}>
          <RotateCw className="h-3.5 w-3.5" aria-hidden /> Try again
        </Button>
      )}
    </div>
  );
}

export function InlineError({ error }: { error: unknown }) {
  if (!error) return null;
  const details = error instanceof ApiError ? error.details : undefined;
  return (
    <div className="rounded-control border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-[13px] text-[#FF8589]" role="alert">
      {errorMessage(error)}
      {details && details.length > 0 && (
        <ul className="mt-1 list-disc pl-5">
          {details.map((d, i) => (
            <li key={i}>{d.message}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
