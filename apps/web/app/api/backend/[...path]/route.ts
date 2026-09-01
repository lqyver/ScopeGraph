import type { NextRequest } from "next/server";

export const dynamic = "force-dynamic";

const DEFAULT_ALLOWED_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);
const DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024;
const MAX_BODY_BYTES_CEILING = 50 * 1024 * 1024;
const SAFE_METHODS = new Set(["GET", "HEAD"]);

interface RouteContext {
  params: Promise<{ path: string[] }>;
}

function normalizeHost(value: string | null): string | null {
  if (!value) return null;
  const candidate = value.trim().toLowerCase();
  if (!candidate) return null;
  if (candidate.startsWith("[")) {
    const closing = candidate.indexOf("]");
    return closing > 0 ? candidate.slice(1, closing) : null;
  }
  if (candidate.includes(":") && candidate.split(":").length > 2) return candidate;
  return candidate.split(":", 1)[0];
}

function allowedHosts(): Set<string> {
  const configured = (process.env.SCOPEGRAPH_WEB_ALLOWED_HOSTS ?? "")
    .split(",")
    .map((item) => normalizeHost(item))
    .filter((item): item is string => item !== null);
  return configured.length > 0 ? new Set(configured) : DEFAULT_ALLOWED_HOSTS;
}

function isAllowedHost(value: string | null): boolean {
  const host = normalizeHost(value);
  return host !== null && allowedHosts().has(host);
}

function maxBodyBytes(): number {
  const configured = Number.parseInt(process.env.SCOPEGRAPH_PROXY_MAX_BODY_BYTES ?? "", 10);
  if (!Number.isFinite(configured) || configured <= 0) return DEFAULT_MAX_BODY_BYTES;
  return Math.min(configured, MAX_BODY_BYTES_CEILING);
}

function blockedResponse(code: string, message: string, status: number): Response {
  return Response.json(
    { error: { code, message, details: {}, request_id: crypto.randomUUID() } },
    { status },
  );
}

async function proxy(request: NextRequest, context: RouteContext) {
  if (!isAllowedHost(request.headers.get("host") ?? request.nextUrl.hostname)) {
    return blockedResponse("WEB_HOST_BLOCKED", "请求 Host 不在允许列表中", 400);
  }
  if (!SAFE_METHODS.has(request.method)) {
    const origin = request.headers.get("origin");
    if (origin) {
      try {
        if (!isAllowedHost(new URL(origin).hostname)) {
          return blockedResponse("WEB_ORIGIN_BLOCKED", "请求来源不在允许列表中", 403);
        }
      } catch {
        return blockedResponse("WEB_ORIGIN_BLOCKED", "请求来源无效", 403);
      }
    }
    if (request.headers.get("sec-fetch-site") === "cross-site") {
      return blockedResponse("WEB_ORIGIN_BLOCKED", "跨站请求被拒绝", 403);
    }
  }

  const { path } = await context.params;
  const apiUrl = process.env.API_INTERNAL_URL ?? "http://127.0.0.1:8000";
  const target = `${apiUrl.replace(/\/$/, "")}/api/v1/${path.join("/")}${request.nextUrl.search}`;
  const headers = new Headers();
  const contentType = request.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);
  const apiKey = process.env.SCOPEGRAPH_API_KEY;
  if (apiKey) headers.set("x-scopegraph-api-key", apiKey);
  const contentLength = Number.parseInt(request.headers.get("content-length") ?? "", 10);
  if (Number.isFinite(contentLength) && contentLength > maxBodyBytes()) {
    return blockedResponse("REQUEST_BODY_TOO_LARGE", "请求体超过允许大小", 413);
  }

  try {
    const body = SAFE_METHODS.has(request.method) ? undefined : await request.arrayBuffer();
    if (body && body.byteLength > maxBodyBytes()) {
      return blockedResponse("REQUEST_BODY_TOO_LARGE", "请求体超过允许大小", 413);
    }
    const response = await fetch(target, {
      method: request.method,
      headers,
      body,
      cache: "no-store",
      signal: AbortSignal.timeout(20_000),
    });
    const responseHeaders = new Headers();
    const responseContentType = response.headers.get("content-type");
    if (responseContentType) responseHeaders.set("content-type", responseContentType);
    const requestId = response.headers.get("x-request-id");
    if (requestId) responseHeaders.set("x-request-id", requestId);
    return new Response(response.body, {
      status: response.status,
      headers: responseHeaders,
    });
  } catch {
    return Response.json(
      {
        error: {
          code: "API_UNREACHABLE",
          message: "本地 API 暂时不可用",
          details: {},
          request_id: crypto.randomUUID(),
        },
      },
      { status: 503 },
    );
  }
}

export const GET = proxy;
export const POST = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
