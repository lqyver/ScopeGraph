import { describe, expect, it } from "vitest";

import { formatLatency, isHealthReport } from "./health";

describe("health response helpers", () => {
  it("accepts a valid health payload", () => {
    expect(
      isHealthReport({
        status: "healthy",
        version: "1.0.0",
        edition: "community",
        environment: "test",
        checked_at: "2026-07-16T00:00:00Z",
        checks: { api: { status: "healthy" } },
      }),
    ).toBe(true);
  });

  it("rejects an incomplete health payload", () => {
    expect(isHealthReport({ status: "healthy", checks: null })).toBe(false);
    expect(
      isHealthReport({
        status: "healthy",
        version: "1.0.0",
        environment: "test",
        checked_at: "2026-07-16T00:00:00Z",
        checks: { api: { status: "healthy" } },
      }),
    ).toBe(false);
  });

  it("formats optional latency", () => {
    expect(formatLatency(12.6)).toBe("13 ms");
    expect(formatLatency(null)).toBe("—");
  });
});
