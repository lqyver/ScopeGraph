export interface Project {
  id: string;
  name: string;
  company_name: string;
  status: "DRAFT" | "ACTIVE" | "ARCHIVED";
  default_scan_profile: "quick" | "standard" | "deep" | "custom";
  authorization_confirmed_at: string;
  created_at: string;
  updated_at: string;
}

export interface ProjectPage {
  items: Project[];
  page: number;
  page_size: number;
  total: number;
}

export interface ScopeRule {
  id: string;
  project_id: string;
  rule_type: "DOMAIN" | "ROOT_DOMAIN" | "IP" | "CIDR" | "URL";
  value: string;
  action: "INCLUDE" | "EXCLUDE";
  source: "USER" | "AUTO_CONFIRMED";
  created_at: string;
}

export interface Asset {
  id: string;
  asset_type: string;
  display_value: string;
  normalized_value: string;
  scope_status: string;
  ownership_status: string;
  last_seen_at: string;
}

export interface AssetPage {
  items: Asset[];
  total: number;
}

export interface ProjectSummary {
  asset_count: number;
  scope_rule_count: number;
  assets_by_type: Record<string, number>;
  assets_by_scope: Record<string, number>;
}

export interface ScopeCheck {
  status: string;
  normalized_value: string;
  reason: string;
  matched_rule_id: string | null;
  active_allowed: boolean;
}

export interface AssetImportResult {
  input_count: number;
  normalized_count: number;
  created_count: number;
  duplicate_count: number;
  rejected_count: number;
  rejected: Array<{ index: number; value: string; error: string }>;
}

export type ScanStatus =
  | "PENDING"
  | "QUEUED"
  | "RUNNING"
  | "PAUSED"
  | "PARTIAL_SUCCESS"
  | "SUCCESS"
  | "FAILED"
  | "TIMEOUT"
  | "CANCELLED"
  | "SKIPPED";

export interface ScanRun {
  id: string;
  project_id: string;
  profile: "quick" | "standard" | "deep" | "custom";
  config_snapshot: {
    root_domain?: string;
    execution_mode?: "fixture" | "host";
    chain?: string[];
    port_scan_enabled?: boolean;
    full_port_scan?: boolean;
    profile?: Record<string, unknown>;
  };
  status: ScanStatus;
  progress: number;
  started_at: string | null;
  finished_at: string | null;
  coverage_score: number | null;
  coverage_level: string | null;
  summary: Record<string, unknown>;
  cancellation_requested: boolean;
  created_at: string;
}

export interface ScanRunPage {
  items: ScanRun[];
  page: number;
  page_size: number;
  total: number;
}

export interface ScanRunOverviewPage {
  items: Array<{ run: ScanRun; jobs: ScanJob[] }>;
  page: number;
  page_size: number;
  total: number;
}

export interface ScanJob {
  id: string;
  scan_run_id: string;
  sequence: number;
  job_type: string;
  adapter_name: string;
  input_ref: Record<string, unknown>;
  status: ScanStatus;
  attempt: number;
  max_attempts: number;
  timeout_seconds: number;
  started_at: string | null;
  finished_at: string | null;
  stdout_path: string | null;
  stderr_path: string | null;
  error_code: string | null;
  error_message: string | null;
  result_summary: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export type IPClassification =
  | "OWNED"
  | "CLOUD_SERVER"
  | "SHARED_HOSTING"
  | "CDN_WAF"
  | "UNKNOWN"
  | "PRIVATE_RESERVED";

export interface IPInventory {
  asset_id: string;
  ip: string;
  scope_status: string;
  classification: IPClassification;
  classification_source: string;
  asn: number | null;
  organization: string | null;
  provider: string | null;
  reverse_dns: string | null;
  is_private: boolean;
  is_cdn: boolean;
  environment_warning: string | null;
  updated_at: string | null;
}

export interface IPInventoryPage {
  items: IPInventory[];
  page: number;
  page_size: number;
  total: number;
  ignored_environment_mappings: number;
}

export interface PortService {
  id: string;
  name: string | null;
  product: string | null;
  version: string | null;
  tunnel: string | null;
  cpe: string | null;
  tls: boolean;
  observed_at: string;
}

export interface PortInventory {
  id: string;
  scan_run_id: string;
  ip_asset_id: string;
  ip: string;
  port: number;
  protocol: "tcp" | "udp";
  state: "OPEN" | "CLOSED" | "FILTERED" | "UNKNOWN";
  source_tool: string;
  first_seen_at: string;
  last_seen_at: string;
  service: PortService | null;
}

export interface PortInventoryPage {
  items: PortInventory[];
  page: number;
  page_size: number;
  total: number;
}

export type AttackSurfacePriorityTier = "urgent" | "high" | "review" | "observed";

export interface AttackSurfacePort {
  ip: string;
  port: number;
  protocol: "tcp" | "udp";
  state: "OPEN" | "CLOSED" | "FILTERED" | "UNKNOWN";
  source_tool: string;
  last_seen_at: string;
  service: {
    name: string | null;
    product: string | null;
    version: string | null;
    tls: boolean;
  } | null;
}

export interface AttackSurfaceWebsite {
  id: string;
  url: string;
  final_url: string | null;
  title: string | null;
  status_code: number | null;
  port: number | null;
  is_alive: boolean;
  endpoint_count: number;
  last_seen_at: string;
}

export interface AttackSurfaceFinding {
  id: string;
  template_id: string;
  template_name: string;
  severity: Finding["severity"];
  status: Finding["status"];
  target: string;
  is_active: boolean;
  last_seen_at: string;
}

export interface AttackSurfaceItem {
  domain_asset_id: string;
  domain: string;
  scope_status: string;
  ownership_status: string;
  resolved_ips: string[];
  ports: AttackSurfacePort[];
  websites: AttackSurfaceWebsite[];
  technologies: string[];
  endpoint_count: number;
  findings: AttackSurfaceFinding[];
  active_finding_count: number;
  high_finding_count: number;
  priority_score: number;
  priority_tier: AttackSurfacePriorityTier;
  priority_reasons: string[];
  last_seen_at: string;
}

export interface AttackSurfacePage {
  items: AttackSurfaceItem[];
  page: number;
  page_size: number;
  total: number;
  summary: {
    domains: number;
    active_websites: number;
    domains_with_ports: number;
    open_ports: number;
    technologies: number;
    active_findings: number;
    high_findings: number;
    high_priority_targets: number;
  };
  environment_mappings_excluded: number;
}

export type ICPAssociationStatus =
  | "PAGE_DIRECT"
  | "ROOT_DOMAIN_INFERRED"
  | "SUBJECT_MATCH"
  | "RELATED_SUBJECT"
  | "SUBJECT_CONFLICT"
  | "NOT_FOUND"
  | "NOT_APPLICABLE"
  | "PENDING_MANUAL_VERIFY"
  | "HISTORICAL";

export interface WebsiteSummary {
  id: string;
  project_id: string;
  asset_id: string;
  url: string;
  final_url: string | null;
  title: string | null;
  status_code: number | null;
  content_type: string | null;
  ip: string | null;
  port: number | null;
  is_alive: boolean;
  scope_status: string;
  ownership_status: string;
  icp_status: ICPAssociationStatus;
  technologies: string[];
  cdn_waf: string[];
  screenshot_path: string | null;
  endpoint_count: number;
  finding_count: number;
  first_seen_at: string;
  last_seen_at: string;
}

export interface WebsitePage {
  items: WebsiteSummary[];
  page: number;
  page_size: number;
  total: number;
}

export interface WebSnapshot {
  id: string;
  scan_run_id: string;
  input_url: string;
  final_url: string;
  redirect_chain: unknown[];
  response_time_ms: number | null;
  content_length: number | null;
  server_header: string | null;
  response_headers: Record<string, unknown>;
  cdn_waf: string[];
  tls_summary: Record<string, unknown>;
  favicon_hash: string | null;
  body_hash: string | null;
  screenshot_path: string | null;
  error: string | null;
  observed_at: string;
}

export interface TechnologyDetail {
  name: string;
  version: string;
  category: string | null;
  confidence: number;
  source_tool: string;
}

export interface CertificateDetail {
  id: string;
  subject: string | null;
  issuer: string | null;
  serial_number: string | null;
  not_before: string | null;
  not_after: string | null;
  san: string[];
  fingerprint_sha256: string;
  validation_errors: string[];
  observed_at: string;
}

export interface WebsiteFilingLink {
  record_id: string;
  record_kind: "ICP" | "PUBLIC_SECURITY";
  normalized_number: string;
  display_number: string;
  subject_name: string | null;
  association_status: ICPAssociationStatus;
  source_url: string;
  evidence_excerpt: string;
  official_confirmed: boolean;
}

export interface Endpoint {
  id: string;
  scan_run_id: string;
  website_id: string | null;
  normalized_url: string;
  method: string;
  kind:
    | "PAGE"
    | "JAVASCRIPT"
    | "XHR"
    | "WEBSOCKET"
    | "ROBOTS"
    | "SITEMAP"
    | "API"
    | "EXTERNAL_LINK";
  scope_status: string;
  actively_visited: boolean;
  source_tool: string;
  status_code: number | null;
  discovered_at: string;
}

export interface WebsiteDetail extends WebsiteSummary {
  snapshot: WebSnapshot | null;
  technology_details: TechnologyDetail[];
  certificates: CertificateDetail[];
  filing_links: WebsiteFilingLink[];
  endpoints: Endpoint[];
}

export interface ICPRecord {
  id: string;
  record_kind: "ICP" | "PUBLIC_SECURITY";
  normalized_number: string;
  display_number: string;
  subject_name: string | null;
  website_name: string | null;
  source_url: string;
  excerpt: string;
  official_confirmed: boolean;
  observed_at: string;
  websites: Array<{
    website_id: string;
    url: string;
    association_status: ICPAssociationStatus;
  }>;
}

export type ReviewDecision =
  | "CONFIRM"
  | "ADD_TO_SCOPE"
  | "EXCLUDE"
  | "MARK_THIRD_PARTY"
  | "DEFER";

export interface CandidateEvidence {
  evidence_type: string;
  value: string;
  score_delta: number;
  source_tool: string | null;
  source_url: string | null;
  observed_at: string;
  is_manual: boolean;
  metadata_json: Record<string, unknown>;
}

export interface CandidateRoot {
  id: string;
  project_id: string;
  root_domain: string;
  display_domain: string;
  score: number;
  raw_score: number;
  status: string;
  source_count: number;
  evidence_summary: Array<{ signal: string; weight: number; rule_version: number }>;
  source_failures: Array<Record<string, unknown>>;
  confirmed_at: string | null;
  rejected_at: string | null;
  evidence: CandidateEvidence[];
}

export interface EnterpriseDiscoveryRun {
  id: string;
  status: "RUNNING" | "SUCCESS" | "PARTIAL_SUCCESS" | "FAILED";
  summary: {
    candidate_count?: number;
    source_count?: number;
    source_failure_count?: number;
    source_completed_count?: number;
    source_partial_count?: number;
    source_unavailable_count?: number;
    source_skipped_count?: number;
    source_running_count?: number;
    source_pending_count?: number;
    source_attempted_count?: number;
    source_successful_request_count?: number;
    corroborated_candidate_count?: number;
    enrichment_seed_count?: number;
    rejected_value_count?: number;
    failure_reason?: string | null;
    stage?: string;
    progress_percent?: number;
  };
  source_results: Array<{
    source: string;
    category?: string;
    status?: "PENDING" | "RUNNING" | "COMPLETED" | "PARTIAL" | "UNAVAILABLE" | "SKIPPED";
    candidate_count: number;
    attempted_count?: number;
    completed_count?: number;
    skipped_reason?: string | null;
    error: string | null;
  }>;
}

export interface ReviewQueueItem {
  resource_type: "ASSET" | "CANDIDATE_ROOT_DOMAIN";
  resource_id: string;
  value: string;
  status: string;
  score: number;
  reasons: string[];
}

export interface CoverageAssessment {
  task_status: string;
  task_completed: boolean;
  coverage_score: number;
  coverage_level: string;
  factors: Array<{
    key: string;
    label: string;
    weight: number;
    completed: boolean;
    evidence: string;
  }>;
  blind_spots: string[];
  assessed_at: string;
}

export interface Finding {
  id: string;
  template_id: string;
  template_name: string;
  tool_version: string;
  target: string;
  matched_at: string | null;
  severity: "info" | "low" | "medium" | "high" | "critical" | "unknown";
  status:
    | "UNVERIFIED"
    | "POTENTIAL"
    | "REPRODUCIBLE"
    | "MANUALLY_VERIFIED"
    | "FALSE_POSITIVE"
    | "ACCEPTED_RISK";
  evidence: Record<string, unknown>;
  raw_artifact_path: string;
  first_seen_at: string;
  last_seen_at: string;
  is_active: boolean;
}

export interface ScanDiff {
  counts: { added: number; removed: number; changed: number };
  added: Array<{ category: string; identity: string }>;
  removed: Array<{ category: string; identity: string }>;
  changed: Array<{ category: string; identity: string }>;
}

export interface ExportArtifact {
  id: string;
  export_format: "xlsx" | "csv" | "json" | "html" | "markdown";
  export_scope: string;
  status: "PENDING" | "SUCCESS" | "FAILED";
  media_type: string | null;
  size_bytes: number | null;
  sha256: string | null;
  row_counts: Record<string, number>;
  error_message: string | null;
  created_at: string;
}

export interface ToolStatus {
  name: string;
  category: string;
  installed: boolean;
  installation_path: string | null;
  version_output: string | null;
  compatible: boolean;
  minimum_version: string | null;
  automatic_update: boolean;
  error: string | null;
}

export interface SystemSettings {
  proxy_url: string | null;
  proxy_credentials_supported: boolean;
  public_bind: boolean;
  api_key_configured: boolean;
}

export interface StorageStatus {
  total_bytes: number;
  raw_artifact_bytes: number;
  export_bytes: number;
  file_count: number;
}

interface ApiErrorEnvelope {
  error?: {
    code?: string;
    message?: string;
    details?: {
      errors?: Array<{
        loc?: Array<string | number>;
        msg?: string;
        type?: string;
      }>;
    };
  };
}

function validationErrorMessage(envelope: ApiErrorEnvelope): string | null {
  const errors = envelope.error?.details?.errors;
  if (!errors?.length) return null;
  return errors.slice(0, 3).map((item) => {
    const field = item.loc?.filter((part) => part !== "body").join(".") || "输入";
    const raw = item.msg ?? "格式不正确";
    const message = raw === "Field required"
      ? "不能为空"
      : raw.replace(/^Value error,\s*/i, "");
    return `${field}：${message}`;
  }).join("；");
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message);
  }
}

export async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/backend/${path.replace(/^\//, "")}`, {
    ...init,
    cache: "no-store",
  });
  if (!response.ok) {
    let envelope: ApiErrorEnvelope = {};
    try {
      envelope = (await response.json()) as ApiErrorEnvelope;
    } catch {
      // The status code remains useful if a proxy or runtime returns non-JSON.
    }
    throw new ApiError(
      validationErrorMessage(envelope)
        ?? envelope.error?.message
        ?? `请求失败（HTTP ${response.status}）`,
      envelope.error?.code ?? "REQUEST_FAILED",
    );
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "发生未知错误";
}
