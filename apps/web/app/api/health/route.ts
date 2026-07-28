import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET() {
  const apiUrl = process.env.API_INTERNAL_URL ?? "http://127.0.0.1:8000";
  const headers = new Headers();
  const apiKey = process.env.SCOPEGRAPH_API_KEY;
  if (apiKey) headers.set("x-scopegraph-api-key", apiKey);
  try {
    const response = await fetch(`${apiUrl.replace(/\/$/, "")}/health`, {
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(5_000),
    });
    const data: unknown = await response.json();
    return NextResponse.json(data, { status: response.status });
  } catch {
    return NextResponse.json(
      {
        status: "unhealthy",
        version: "1.0.0",
        environment: "unknown",
        checked_at: new Date().toISOString(),
        checks: {
          api: { status: "unhealthy", detail: "API_UNREACHABLE" },
        },
      },
      { status: 503 },
    );
  }
}
