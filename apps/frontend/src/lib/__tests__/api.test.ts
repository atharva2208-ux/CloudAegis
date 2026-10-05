import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, setCsrfToken, toSearch } from "@/lib/api";
import { mockFetch } from "@/test/utils";

afterEach(() => setCsrfToken(null));

describe("api client", () => {
  it("serialises query params including arrays and skips empties", () => {
    expect(toSearch({ severity: ["HIGH", "LOW"], q: "", page: 2, x: undefined })).toBe("?severity=HIGH&severity=LOW&page=2");
  });

  it("sends the CSRF header on writes only", async () => {
    const calls = mockFetch({ "GET /api/v1/x": () => ({ json: {} }), "POST /api/v1/x": () => ({ json: {} }) });
    setCsrfToken("tok-1");
    await api.get("/x");
    await api.post("/x", { a: 1 });
    expect(calls[0].headers["X-CSRF-Token"]).toBeUndefined();
    expect(calls[1].headers["X-CSRF-Token"]).toBe("tok-1");
  });

  it("normalises errors with code and request ID", async () => {
    mockFetch({ "GET /api/v1/fail": () => ({ status: 422, json: { error: { code: "validation_error", message: "Bad", request_id: "rid", details: [{ field: "q", message: "too long" }] } } }) });
    const err = (await api.get("/fail").catch((e) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(422);
    expect(err.code).toBe("validation_error");
    expect(err.requestId).toBe("rid");
    expect(err.details?.[0].field).toBe("q");
  });

  it("reports network failures clearly", async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new TypeError("Failed to fetch"));
    const err = (await api.get("/x").catch((e) => e)) as ApiError;
    expect(err.code).toBe("network_error");
  });
});
