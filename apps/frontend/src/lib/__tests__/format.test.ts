import { describe, expect, it, vi } from "vitest";
import { bytes, duration, humanizeAction, num, pct, plural, relative, resourceTypeLabel } from "@/lib/format";

describe("format helpers", () => {
  it("formats numbers and handles missing values", () => {
    expect(num(1677)).toBe("1,677");
    expect(num(null)).toBe("—");
    expect(pct(83.44, 1)).toBe("83.4%");
    expect(pct(undefined)).toBe("—");
  });

  it("pluralises", () => {
    expect(plural(1, "scan")).toBe("1 scan");
    expect(plural(3, "scan")).toBe("3 scans");
  });

  it("formats durations and sizes", () => {
    expect(duration(9.48)).toBe("9.5s");
    expect(duration(125)).toBe("2m 5s");
    expect(duration(null)).toBe("—");
    expect(bytes(512)).toBe("512 B");
    expect(bytes(93288)).toBe("91.1 KB");
  });

  it("describes relative times", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-05T12:00:00Z"));
    expect(relative("2026-10-05T11:59:50Z")).toBe("just now");
    expect(relative("2026-10-05T11:56:00Z")).toBe("4 minutes ago");
    expect(relative("2026-10-03T12:00:00Z")).toBe("2 days ago");
    expect(relative(null)).toBe("never");
    vi.useRealTimers();
  });

  it("labels resource types and audit actions", () => {
    expect(resourceTypeLabel("aws.s3.bucket")).toBe("S3 bucket");
    expect(resourceTypeLabel("custom.thing")).toBe("custom.thing");
    expect(humanizeAction("finding.in_progress")).toBe("Finding in progress");
  });
});
