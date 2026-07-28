import { afterEach, describe, expect, it, vi } from "vitest";

import { apiRequest, errorMessage } from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("project API client", () => {
  it("normalizes the proxy path and returns JSON", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ total: 0 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(apiRequest<{ total: number }>("/projects")).resolves.toEqual({ total: 0 });
    expect(fetchMock).toHaveBeenCalledWith("/api/backend/projects", {
      cache: "no-store",
    });
  });

  it("preserves structured API errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({ error: { code: "SCOPE_VIOLATION", message: "目标不在 Scope 内" } }),
          { status: 409 },
        ),
      ),
    );

    const request = apiRequest("scope/check");
    await expect(request).rejects.toMatchObject({
      code: "SCOPE_VIOLATION",
      message: "目标不在 Scope 内",
    });
  });

  it("turns validation details into a field-specific message", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            error: {
              code: "VALIDATION_ERROR",
              message: "请求参数验证失败",
              details: {
                errors: [
                  {
                    loc: ["body", "value"],
                    msg: "Value error, 请输入根域名，不要填写完整 URL",
                    type: "value_error",
                  },
                ],
              },
            },
          }),
          { status: 422 },
        ),
      ),
    );

    await expect(apiRequest("scope-rules", { method: "POST" })).rejects.toThrow(
      "value：请输入根域名，不要填写完整 URL",
    );
  });

  it("falls back to the HTTP status for a non-JSON failure", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("bad gateway", { status: 502 })));

    await expect(apiRequest("projects")).rejects.toThrow("请求失败（HTTP 502）");
  });

  it("handles an empty 204 response and unknown errors", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 204 })));

    await expect(apiRequest("projects/example", { method: "DELETE" })).resolves.toBeUndefined();
    expect(errorMessage("not-an-error")).toBe("发生未知错误");
  });
});
