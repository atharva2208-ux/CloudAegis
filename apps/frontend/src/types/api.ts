export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type FindingStatus = "OPEN" | "ACKNOWLEDGED" | "IN_PROGRESS" | "RESOLVED" | "SUPPRESSED";
export type RoleName = "ADMIN" | "SECURITY_ANALYST" | "VIEWER";

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface User {
  id: number;
  email: string;
  full_name: string;
  role: RoleName;
  permissions: string[];
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
  locked?: boolean;
  failed_login_attempts?: number;
}

export interface SessionInfo {
  user: User;
  csrf_token: string;
  expires_at: string;
  idle_timeout_minutes: number;
}

export interface Region {
  name: string;
  enabled: boolean;
}

export interface CloudAccount {
  id: number;
  name: string;
  provider: string;
  account_identifier: string | null;
  auth_method: string;
  role_arn: string | null;
  has_stored_secret: boolean;
  credentials_expire_at: string | null;
  principal_arn: string | null;
  status: "pending" | "connected" | "error";
  status_message: string | null;
  is_demo: boolean;
  default_region: string;
  regions: Region[];
  last_validated_at: string | null;
  last_scan_at: string | null;
  created_at: string;
  asset_count: number;
  open_findings: number;
  security_score: number | null;
}

export interface ConnectionResult {
  ok: boolean;
  account_id: string | null;
  principal_arn: string | null;
  regions: string[];
  message: string;
  warnings: string[];
}

export interface OnboardingGuide {
  trust_policy: Record<string, unknown>;
  permissions_policies: string[];
  inline_policy: Record<string, unknown>;
  cloudformation_template: string;
  platform_principal: string | null;
  external_id_suggestion: string;
}

export interface AssetSummary {
  id: number;
  name: string;
  resource_uid: string;
  resource_type: string;
  service: string;
  region: string;
  account_id: number;
  account_name: string;
  account_identifier: string | null;
  public_exposure: boolean;
  encryption_status: "encrypted" | "unencrypted" | "not_applicable";
  risk_score: number;
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
  open_findings: number;
  last_seen_at: string;
  is_active: boolean;
}

export interface RelatedAsset {
  id: number;
  name: string;
  service: string;
  resource_type: string;
  kind: string;
  direction: "outbound" | "inbound";
}

export interface AssetDetail extends AssetSummary {
  tags: Record<string, string>;
  properties: Record<string, unknown>;
  first_seen_at: string;
  relationships: RelatedAsset[];
  findings: FindingSummary[];
}

export interface AssetStats {
  total: number;
  by_service: { service: string; count: number; public: number; with_findings: number }[];
  public: number;
  encrypted: number;
  unencrypted: number;
  regions: { value: string; count: number }[];
  resource_types: { value: string; count: number }[];
}

export interface FindingSummary {
  id: number;
  display_id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  service: string;
  region: string;
  category: string;
  asset_id: number;
  asset_name: string;
  resource_uid: string;
  resource_type: string;
  account_id: number;
  account_name: string;
  first_detected_at: string;
  last_detected_at: string;
  public_exposure: boolean;
  ticket_ref: string | null;
}

export interface FindingEvent {
  id: number;
  event_type: string;
  from_status: string | null;
  to_status: string | null;
  note: string | null;
  user: string | null;
  scan_id: number | null;
  created_at: string;
}

export interface FindingDetail extends FindingSummary {
  description: string;
  impact: string;
  message: string;
  evidence: Record<string, unknown>;
  remediation: { summary: string; steps: string[]; cli_example: string | null; automated: boolean };
  references: string[];
  compliance: { framework_key: string; framework: string; control_id: string; title: string }[];
  suppression_reason: string | null;
  resolved_at: string | null;
  status_changed_at: string;
  account_identifier: string | null;
  events: FindingEvent[];
}

export interface FacetCount {
  value: string;
  count: number;
}

export interface FindingFacets {
  severity: FacetCount[];
  status: FacetCount[];
  service: FacetCount[];
  region: FacetCount[];
  rule: FacetCount[];
}

export interface ServiceProgress {
  service: string;
  status: "pending" | "discovering" | "discovered" | "analyzing" | "completed" | "failed";
  percent: number;
  resources: number;
  findings: number;
  error: string | null;
}

export interface ScoreBreakdown {
  score: number;
  total_checks: number;
  failed_checks: number;
  total_weight: number;
  failed_weight: number;
  weighted_pass_rate: number;
  critical_findings: number;
  critical_penalty: number;
  weights: Record<Severity, number>;
  formula: string;
}

export interface FrameworkSummary {
  key: string;
  name: string;
  short_name: string;
  version: string;
  score: number;
  passed: number;
  failed: number;
  not_applicable: number;
  total: number;
}

export interface Scan {
  id: number;
  display_id: string;
  account_id: number;
  account_name: string;
  is_demo: boolean;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "PARTIAL" | "FAILED" | "CANCELLED";
  trigger: string;
  triggered_by: string | null;
  regions: string[];
  services: string[];
  progress: {
    phase?: string;
    services?: ServiceProgress[];
    assets_discovered?: number;
    assets_analyzed?: number;
  };
  assets_discovered: number;
  assets_analyzed: number;
  checks_evaluated: number;
  findings_total: number;
  findings_new: number;
  findings_resolved: number;
  severity_counts: Record<Severity, number>;
  public_assets: number;
  security_score: number | null;
  score_breakdown: ScoreBreakdown | Record<string, never>;
  compliance_summary: FrameworkSummary[];
  service_errors: Record<string, string>;
  error_message: string | null;
  queued_at: string;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
}

export interface BriefFinding {
  id: number;
  display_id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  asset_name: string;
}

export interface ScanComparison {
  base: Scan;
  target: Scan;
  score_delta: number | null;
  severity_delta: Record<Severity, number>;
  public_assets_delta: number;
  assets_delta: number;
  compliance_delta: { key: string; short_name: string; base: number | null; target: number; delta: number | null }[];
  new_findings: BriefFinding[];
  resolved_findings: BriefFinding[];
}

export interface TrendPoint {
  scan_id: number;
  date: string;
  score: number;
}

export interface FrameworkOverview extends FrameworkSummary {
  description: string;
  trend: { scan_id: number; date: string; score: number }[];
}

export interface DashboardSummary {
  score: ScoreBreakdown | null;
  previous_score: number | null;
  severity_counts: Record<Severity, number>;
  open_findings: number;
  assets: number;
  public_assets: number;
  public_by_service: { service: string; count: number }[];
  encryption: { encrypted: number; unencrypted: number; coverage: number | null };
  mfa: { total: number; covered: number; coverage: number | null };
  findings_by_service: ({ service: string; total: number } & Record<Severity, number>)[];
  score_trend: TrendPoint[];
  findings_trend: ({ scan_id: number; date: string; total: number; new: number; resolved: number } & Record<
    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    number
  >)[];
  compliance: FrameworkOverview[];
  top_risky_assets: AssetSummary[];
  recent_findings: FindingSummary[];
  active_scans: Scan[];
  last_scan_at: string | null;
  accounts_scanned: number;
}

export interface ControlRule {
  rule_id: string;
  title: string;
  severity: Severity;
  evaluated: number;
  failed: number;
  open_findings: number;
  remediation: string;
}

export interface ControlResult {
  control_id: string;
  title: string;
  section: string;
  description: string;
  status: "PASS" | "FAIL" | "NOT_APPLICABLE";
  compliance: number | null;
  evaluated_resources: number;
  failed_resources: number;
  failing_rules: string[];
  rules: ControlRule[];
  framework_key?: string;
  framework?: string;
}

export interface FrameworkDetail extends FrameworkOverview {
  controls: ControlResult[];
  as_of: string | null;
}

export interface Report {
  id: number;
  title: string;
  report_type: "executive" | "technical";
  format: "pdf" | "json" | "csv";
  status: string;
  account_id: number | null;
  account_name: string | null;
  scan_id: number | null;
  generated_by: string | null;
  size_bytes: number;
  sha256: string | null;
  created_at: string;
}

export interface AuditLog {
  id: number;
  timestamp: string;
  user_email: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  result: "success" | "failure" | "denied";
  ip_address: string | null;
  user_agent: string | null;
  request_id: string | null;
  details: Record<string, unknown>;
}

export interface Notification {
  id: number;
  kind: string;
  severity: Severity;
  title: string;
  message: string;
  link: string | null;
  created_at: string;
  read_at: string | null;
}

export interface Rule {
  rule_id: string;
  title: string;
  severity: Severity;
  service: string;
  category: string;
  resource_type: string;
  description: string;
  impact: string;
  remediation: string;
  remediation_steps: string[];
  remediation_cli: string | null;
  references: string[];
  enabled: boolean;
  compliance: { framework: string; control_id: string }[];
  open_findings: number;
}

export interface PlatformSettings {
  thresholds: Record<string, number>;
  scan_services: string[];
  available_services: string[];
  notify_on_critical: boolean;
  session_idle_minutes: number;
  demo_mode: boolean;
}

export interface SearchHit {
  category: "asset" | "finding" | "rule" | "account" | "region" | "ip";
  id: string;
  title: string;
  subtitle: string;
  link: string;
}

export interface SearchResults {
  query: string;
  groups: Partial<Record<SearchHit["category"], SearchHit[]>>;
  total: number;
}

export interface RiskAnalytics {
  by_service: ({ key: string; total: number; weighted: number } & Record<Severity, number>)[];
  by_region: ({ key: string; total: number; weighted: number } & Record<Severity, number>)[];
  by_category: { category: string; count: number }[];
  top_rules: { rule_id: string; title: string; severity: Severity; count: number }[];
  exposure_by_service: { service: string; public: number; total: number }[];
  encryption_by_service: { service: string; encrypted: number; unencrypted: number }[];
  top_risky_assets: AssetSummary[];
  severity_weights: Record<Severity, number>;
}

export interface TrendAnalytics {
  scans: ({
    scan_id: number;
    display_id: string;
    date: string;
    account_id: number;
    score: number;
    total: number;
    new: number;
    resolved: number;
    assets: number;
    public_assets: number;
    compliance: Record<string, number>;
  } & Record<Severity, number>)[];
  mttr: Record<Severity, { hours: number | null; resolved: number }>;
  open_age: { bucket: string; count: number }[];
  days: number;
}
