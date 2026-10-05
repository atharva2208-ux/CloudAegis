import { lazy, Suspense, type ReactNode } from "react";
import { createBrowserRouter, Navigate, useLocation } from "react-router-dom";
import { AppLayout } from "@/layouts/AppLayout";
import { useAuth } from "@/stores/auth";
import { LoadingRows } from "@/components/ui/states";
import LoginPage from "@/pages/auth/LoginPage";
import NotFoundPage from "@/pages/NotFoundPage";

const OverviewPage = lazy(() => import("@/pages/dashboard/OverviewPage"));
const AccountsPage = lazy(() => import("@/pages/onboarding/AccountsPage"));
const AddAccountPage = lazy(() => import("@/pages/onboarding/AddAccountPage"));
const AccountDetailPage = lazy(() => import("@/pages/onboarding/AccountDetailPage"));
const AssetsPage = lazy(() => import("@/pages/assets/AssetsPage"));
const AssetDetailPage = lazy(() => import("@/pages/assets/AssetDetailPage"));
const FindingsPage = lazy(() => import("@/pages/findings/FindingsPage"));
const FindingDetailPage = lazy(() => import("@/pages/findings/FindingDetailPage"));
const ScansPage = lazy(() => import("@/pages/scans/ScansPage"));
const ScanDetailPage = lazy(() => import("@/pages/scans/ScanDetailPage"));
const ScanComparePage = lazy(() => import("@/pages/scans/ScanComparePage"));
const FrameworksPage = lazy(() => import("@/pages/compliance/FrameworksPage"));
const FrameworkDetailPage = lazy(() => import("@/pages/compliance/FrameworkDetailPage"));
const ControlsPage = lazy(() => import("@/pages/compliance/ControlsPage"));
const TrendsPage = lazy(() => import("@/pages/analytics/TrendsPage"));
const RiskPage = lazy(() => import("@/pages/analytics/RiskPage"));
const ReportsPage = lazy(() => import("@/pages/reports/ReportsPage"));
const AuditPage = lazy(() => import("@/pages/audit/AuditPage"));
const SettingsPage = lazy(() => import("@/pages/settings/SettingsPage"));

function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <div className="p-10"><LoadingRows rows={4} /></div>;
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  return <>{children}</>;
}

function RequirePerm({ perm, children }: { perm: string; children: ReactNode }) {
  const { can } = useAuth();
  if (!can(perm)) {
    return (
      <div className="panel mx-auto mt-10 max-w-md p-8 text-center">
        <p className="text-[15px] font-semibold">You don't have access to this page</p>
        <p className="mt-2 text-[13px] text-muted">Ask an administrator for a role with the required permission.</p>
      </div>
    );
  }
  return <>{children}</>;
}

const page = (node: ReactNode, perm?: string) => {
  const content = <Suspense fallback={<LoadingRows rows={6} />}>{node}</Suspense>;
  return perm ? <RequirePerm perm={perm}>{content}</RequirePerm> : content;
};

export const router = createBrowserRouter([
  { path: "/login", element: <LoginPage /> },
  {
    path: "/",
    element: (
      <RequireAuth>
        <AppLayout />
      </RequireAuth>
    ),
    children: [
      { index: true, element: page(<OverviewPage />, "findings:read") },
      { path: "accounts", element: page(<AccountsPage />, "accounts:read") },
      { path: "accounts/new", element: page(<AddAccountPage />, "accounts:manage") },
      { path: "accounts/:id", element: page(<AccountDetailPage />, "accounts:read") },
      { path: "assets", element: page(<AssetsPage />, "assets:read") },
      { path: "assets/:id", element: page(<AssetDetailPage />, "assets:read") },
      { path: "findings", element: page(<FindingsPage />, "findings:read") },
      { path: "findings/:id", element: page(<FindingDetailPage />, "findings:read") },
      { path: "scans", element: page(<ScansPage />, "scans:read") },
      { path: "scans/compare", element: page(<ScanComparePage />, "scans:read") },
      { path: "scans/:id", element: page(<ScanDetailPage />, "scans:read") },
      { path: "compliance", element: page(<FrameworksPage />, "compliance:read") },
      { path: "compliance/controls", element: page(<ControlsPage />, "compliance:read") },
      { path: "compliance/:key", element: page(<FrameworkDetailPage />, "compliance:read") },
      { path: "analytics/trends", element: page(<TrendsPage />, "findings:read") },
      { path: "analytics/risk", element: page(<RiskPage />, "findings:read") },
      { path: "reports", element: page(<ReportsPage />, "reports:read") },
      { path: "audit", element: page(<AuditPage />, "audit:read") },
      { path: "settings", element: page(<SettingsPage />) },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
]);
