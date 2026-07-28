export type CheckStatus = "healthy" | "unhealthy";

export interface HealthCheck {
  status: CheckStatus;
  latency_ms?: number | null;
  detail?: string | null;
}

export interface HealthReport {
  status: CheckStatus;
  version: string;
  environment: string;
  checked_at: string;
  checks: Record<string, HealthCheck>;
}

export function isHealthReport(value: unknown): value is HealthReport {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<HealthReport>;
  return (
    (candidate.status === "healthy" || candidate.status === "unhealthy") &&
    typeof candidate.version === "string" &&
    typeof candidate.checks === "object" &&
    candidate.checks !== null
  );
}

export function formatLatency(value?: number | null): string {
  return typeof value === "number" ? `${value.toFixed(0)} ms` : "—";
}

