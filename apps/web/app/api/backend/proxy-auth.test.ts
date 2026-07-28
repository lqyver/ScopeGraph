import { afterEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

import { GET } from "./[...path]/route";

describe("server-side API proxy authentication", () => {
  afterEach(() => {
    delete process.env.SCOPEGRAPH_API_KEY;
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
});
