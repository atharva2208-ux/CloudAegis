import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { SeverityBadge, StatusBadge } from "@/components/ui/badges";
import { JsonTree } from "@/components/ui/json";
import { Pagination } from "@/components/ui/pagination";
import { StatusDialog } from "@/components/findings/StatusActions";
import { ScorePanel, postureLabel } from "@/components/dashboard/ScorePanel";
import { ErrorState } from "@/components/ui/states";
import { ApiError } from "@/lib/api";

describe("badges", () => {
  it("shows severity as text, not colour alone", () => {
    render(<SeverityBadge severity="CRITICAL" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });
  it("labels statuses", () => {
    render(<StatusBadge status="IN_PROGRESS" />);
    expect(screen.getByText("In progress")).toBeInTheDocument();
  });
});

describe("JsonTree", () => {
  it("renders untrusted evidence as text, never HTML", () => {
    const { container } = render(<JsonTree data={{ BucketName: '<img src=x onerror="alert(1)">', Public: true }} />);
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText(/onerror/)).toBeInTheDocument();
    expect(screen.getByText("true")).toBeInTheDocument();
  });
  it("shows an empty state", () => {
    render(<JsonTree data={{}} />);
    expect(screen.getByText("No data captured")).toBeInTheDocument();
  });
});

describe("Pagination", () => {
  it("reports the range and pages", () => {
    const onPage = vi.fn();
    render(<Pagination page={2} pages={5} total={120} pageSize={25} onPage={onPage} />);
    expect(screen.getByText("26–50 of 120")).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText("Next page"));
    expect(onPage).toHaveBeenCalledWith(3);
  });
});

describe("StatusDialog", () => {
  it("requires a justification before suppressing", () => {
    const onConfirm = vi.fn();
    render(<StatusDialog status="SUPPRESSED" onClose={() => {}} onConfirm={onConfirm} pending={false} error={null} />);
    const confirm = screen.getByRole("button", { name: "Suppress" });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Justification/), { target: { value: "Accepted risk per SR-114" } });
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);
    expect(onConfirm).toHaveBeenCalledWith("Accepted risk per SR-114");
  });
});

describe("ScorePanel", () => {
  it("shows the equation behind the score", () => {
    render(
      <ScorePanel
        score={{
          score: 69, total_checks: 5946, failed_checks: 598, total_weight: 21671, failed_weight: 1377,
          weighted_pass_rate: 0.9365, critical_findings: 9, critical_penalty: 25,
          weights: { CRITICAL: 10, HIGH: 5, MEDIUM: 2, LOW: 1, INFO: 0 }, formula: "",
        }}
      />,
    );
    expect(screen.getByText("93.7")).toBeInTheDocument();
    expect(screen.getByText("25")).toBeInTheDocument();
    expect(screen.getByText("69")).toBeInTheDocument();
    expect(screen.getByText("Weak posture")).toBeInTheDocument();
  });
  it("bands scores", () => {
    expect(postureLabel(40).label).toBe("Poor");
    expect(postureLabel(90).label).toBe("Strong");
    expect(postureLabel(100).label).toBe("Strong");
  });
});

describe("ErrorState", () => {
  it("shows the request ID for support", () => {
    render(<ErrorState error={new ApiError(500, "internal_error", "Boom", "req-42")} onRetry={() => {}} />);
    expect(screen.getByText(/req-42/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Try again/ })).toBeInTheDocument();
  });
  it("hides retry on permission errors", () => {
    render(<ErrorState error={new ApiError(403, "forbidden", "No")} onRetry={() => {}} />);
    expect(screen.queryByRole("button", { name: /Try again/ })).toBeNull();
  });
});
