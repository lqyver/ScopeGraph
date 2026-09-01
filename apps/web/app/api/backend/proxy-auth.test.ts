import { afterEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

import { GET, POST } from "./[...path]/route";

describe("server-side API proxy authentication", () => {
  afterEach(() => {
    delete process.env.SCOPEGRAPH_API_KEY;
    delete process.env.SCOPEGRAPH_WEB_ALLOWED_HOSTS;
    delete process.env.SCOPEGRAPH_PROXY_MAX_BODY_BYTES;
    vi.unstubAllGlobals();
  });

  it("forwards the API key from server environment without reading it from the browser", async () => {
    process.env.SCOPEGRAPH_API_KEY = "server-only-test-key";
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await GET(new NextRequest("http://localhost/api/backend/system/settings"), {
      params: Promise.resolve({ path: ["system", "settings"] }),
    });

    expect(response.status).toBe(200);
    const options = fetchMock.mock.calls[0][1] as RequestInit;
    expect(new Headers(options.headers).get("x-scopegraph-api-key")).toBe("server-only-test-key");
  });

  it("rejects cross-site mutation requests before contacting the API", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await POST(
      new NextRequest("http://localhost/api/backend/projects", {
        method: "POST",
        headers: { origin: "https://evil.example", "content-type": "application/json" },
        body: "{}",
      }),
      { params: Promise.resolve({ path: ["projects"] }) },
    );

    expect(response.status).toBe(403);
    expect((await response.json()).error.code).toBe("WEB_ORIGIN_BLOCKED");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("enforces a bounded request body before proxying", async () => {
    process.env.SCOPEGRAPH_PROXY_MAX_BODY_BYTES = "4";
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await POST(
      new NextRequest("http://localhost/api/backend/projects", {
        method: "POST",
        headers: { "content-type": "application/json", "content-length": "5" },
        body: "12345",
      }),
      { params: Promise.resolve({ path: ["projects"] }) },
    );

    expect(response.status).toBe(413);
    expect((await response.json()).error.code).toBe("REQUEST_BODY_TOO_LARGE");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
