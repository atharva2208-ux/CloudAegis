import { api } from "@/lib/api";
import type {
  AssetDetail,
  AssetStats,
  AssetSummary,
  AuditLog,
  CloudAccount,
  ConnectionResult,
  DashboardSummary,
  FindingDetail,
  FindingFacets,
  FindingStatus,
  FindingSummary,
  FrameworkDetail,
  FrameworkOverview,
  ControlResult,
  Notification,
  OnboardingGuide,
  Page,
  PlatformSettings,
  Report,
  RiskAnalytics,
  Rule,
  Scan,
  ScanComparison,
  SearchResults,
  SessionInfo,
  TrendAnalytics,
  User,
} from "@/types/api";

type Params = Record<string, string | number | boolean | null | undefined | (string | number)[]>;

export const authApi = {
  login: (email: string, password: string) => api.post<SessionInfo>("/auth/login", { email, password }),
  logout: () => api.post<{ message: string }>("/auth/logout"),
  me: () => api.get<SessionInfo>("/auth/me"),
  changePassword: (current_password: string, new_password: string) =>
    api.post<{ message: string }>("/auth/change-password", { current_password, new_password }),
  demoInfo: () =>
    api.get<{ demo_mode: boolean; password: string | null; accounts: { email: string; role: string }[] }>(
      "/auth/demo-info",
    ),
};

export interface AwsCredentials {
  method: "assume_role" | "temporary_credentials";
  role_arn?: string;
  external_id?: string;
  access_key_id?: string;
  secret_access_key?: string;
  session_token?: string;
}

export const accountsApi = {
  list: () => api.get<CloudAccount[]>("/accounts"),
  get: (id: number) => api.get<CloudAccount>(`/accounts/${id}`),
  guide: () => api.get<OnboardingGuide>("/accounts/onboarding-guide"),
  test: (credentials: AwsCredentials, default_region: string) =>
    api.post<ConnectionResult>("/accounts/test-connection", { credentials, default_region }),
  create: (body: {
    name: string;
    credentials: AwsCredentials;
    default_region: string;
    regions: string[];
    start_scan: boolean;
  }) => api.post<CloudAccount>("/accounts", body),
  createDemo: (name: string, start_scan = true) => api.post<CloudAccount>("/accounts/demo", { name, start_scan }),
  update: (id: number, body: { name?: string; regions?: string[]; credentials?: AwsCredentials }) =>
    api.patch<CloudAccount>(`/accounts/${id}`, body),
  validate: (id: number) => api.post<ConnectionResult>(`/accounts/${id}/validate`),
  remove: (id: number) => api.delete<{ message: string }>(`/accounts/${id}`),
};

export const assetsApi = {
  list: (params: Params) => api.get<Page<AssetSummary>>("/assets", params),
  stats: (account_id?: number) => api.get<AssetStats>("/assets/stats", { account_id }),
  get: (id: number) => api.get<AssetDetail>(`/assets/${id}`),
};

export const findingsApi = {
  list: (params: Params) => api.get<Page<FindingSummary>>("/findings", params),
  facets: (account_id?: number) => api.get<FindingFacets>("/findings/facets", { account_id }),
  get: (id: number) => api.get<FindingDetail>(`/findings/${id}`),
  setStatus: (id: number, status: FindingStatus, note?: string) =>
    api.patch<FindingDetail>(`/findings/${id}/status`, { status, note: note || null }),
  bulkStatus: (finding_ids: number[], status: FindingStatus, note?: string) =>
    api.post<{ message: string }>("/findings/bulk-status", { finding_ids, status, note: note || null }),
  comment: (id: number, note: string) => api.post<FindingDetail>(`/findings/${id}/comments`, { note }),
  ticketDraft: (id: number) => api.get<{ title: string; body: string }>(`/findings/${id}/ticket-draft`),
  linkTicket: (id: number, ticket_ref: string, note?: string) =>
    api.post<FindingDetail>(`/findings/${id}/ticket`, { ticket_ref, note: note || null }),
};

export const scansApi = {
  list: (params: Params) => api.get<Page<Scan>>("/scans", params),
  active: () => api.get<Scan[]>("/scans/active"),
  get: (id: number) => api.get<Scan>(`/scans/${id}`),
  start: (account_id: number, regions?: string[], services?: string[]) =>
    api.post<Scan>("/scans", { account_id, regions: regions?.length ? regions : null, services: services?.length ? services : null }),
  cancel: (id: number) => api.post<Scan>(`/scans/${id}/cancel`),
  compare: (base: number, target: number) => api.get<ScanComparison>("/scans/compare", { base, target }),
};

export const complianceApi = {
  frameworks: (account_id?: number) =>
    api.get<{ frameworks: FrameworkOverview[]; assessed: boolean; as_of: string | null }>("/compliance/frameworks", {
      account_id,
    }),
  framework: (key: string, account_id?: number) =>
    api.get<FrameworkDetail>(`/compliance/frameworks/${key}`, { account_id }),
  controls: (params: Params) => api.get<ControlResult[]>("/compliance/controls", params),
  controlFindings: (key: string, control: string, account_id?: number) =>
    api.get<FindingSummary[]>(`/compliance/frameworks/${key}/controls/${encodeURIComponent(control)}/findings`, {
      account_id,
    }),
};

export const reportsApi = {
  list: () => api.get<Report[]>("/reports"),
  create: (body: {
    title: string;
    format: Report["format"];
    report_type: Report["report_type"];
    account_id?: number | null;
  }) => api.post<Report>("/reports", body),
  remove: (id: number) => api.delete<{ message: string }>(`/reports/${id}`),
};

export const platformApi = {
  dashboard: (account_id?: number) => api.get<DashboardSummary>("/dashboard/summary", { account_id }),
  trends: (account_id?: number, days = 90) => api.get<TrendAnalytics>("/analytics/trends", { account_id, days }),
  risk: (account_id?: number) => api.get<RiskAnalytics>("/analytics/risk", { account_id }),
  search: (q: string) => api.get<SearchResults>("/search", { q }),
  audit: (params: Params) => api.get<Page<AuditLog>>("/audit", params),
  auditFacets: () => api.get<{ actions: string[]; users: string[]; results: string[] }>("/audit/facets"),
  notifications: () => api.get<{ items: Notification[]; unread: number }>("/notifications"),
  markRead: (ids?: number[]) => api.post<{ message: string }>("/notifications/read", { ids: ids ?? null }),
  rules: () => api.get<Rule[]>("/rules"),
  toggleRule: (ruleId: string, enabled: boolean) => api.patch<Rule>(`/rules/${ruleId}`, { enabled }),
  settings: () => api.get<PlatformSettings>("/settings"),
  updateSettings: (body: Partial<{ thresholds: Record<string, number>; scan_services: string[]; notify_on_critical: boolean }>) =>
    api.patch<PlatformSettings>("/settings", body),
};

export const usersApi = {
  list: () => api.get<User[]>("/users"),
  create: (body: { email: string; full_name: string; role: string; password: string }) =>
    api.post<User>("/users", body),
  update: (id: number, body: { full_name?: string; role?: string; is_active?: boolean }) =>
    api.patch<User>(`/users/${id}`, body),
  unlock: (id: number) => api.post<User>(`/users/${id}/unlock`),
  roles: () => api.get<{ name: string; description: string; permissions: string[] }[]>("/users/roles"),
};
