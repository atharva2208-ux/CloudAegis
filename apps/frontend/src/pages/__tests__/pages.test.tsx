import { describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { AuthProvider } from "@/stores/auth";
import { ScopeProvider } from "@/stores/scope";
import LoginPage from "@/pages/auth/LoginPage";
import FindingsPage from "@/pages/findings/FindingsPage";
import { mockFetch, renderWithProviders } from "@/test/utils";

const USER = {
  id: 1, email: "analyst@cloudaegis.local", full_name: "Sam Rivera", role: "SECURITY_ANALYST",
  permissions: ["findings:read", "findings:update", "rules:read"], is_active: true, last_login_at: null, created_at: "2026-01-01",
};
const session = { user: USER, csrf_token: "csrf-1", expires_at: "2026-12-01T00:00:00Z", idle_timeout_minutes: 30 };
const unauthenticated = { status: 401, json: { error: { code: "unauthenticated", message: "Authentication required" } } };

describe("LoginPage", () => {
  it("fills demo credentials and signs in", async () => {
    const calls = mockFetch({
      "GET /api/v1/auth/me": () => unauthenticated,
      "GET /api/v1/auth/demo-info": () => ({ json: { demo_mode: true, password: "Demo!Pass2026", accounts: [{ email: USER.email, role: "SECURITY_ANALYST" }] } }),
      "POST /api/v1/auth/login": () => ({ json: session }),
    });
    renderWithProviders(
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={<p>Dashboard home</p>} />
        </Routes>
      </AuthProvider>,
      { route: "/login" },
    );
    fireEvent.click(await screen.findByText(USER.email));
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Dashboard home")).toBeInTheDocument();
    const login = calls.find((c) => c.path === "/api/v1/auth/login")!;
    expect(login.body).toEqual({ email: USER.email, password: "Demo!Pass2026" });
  });

  it("validates input and shows server errors", async () => {
    mockFetch({
      "GET /api/v1/auth/me": () => unauthenticated,
      "GET /api/v1/auth/demo-info": () => ({ json: { demo_mode: false, password: null, accounts: [] } }),
      "POST /api/v1/auth/login": () => ({ status: 401, json: { error: { code: "unauthenticated", message: "Invalid email or password" } } }),
    });
    renderWithProviders(
      <AuthProvider>
        <LoginPage />
      </AuthProvider>,
      { route: "/login" },
    );
    fireEvent.click(await screen.findByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Enter your email")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "a@b.co" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "nope" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Invalid email or password")).toBeInTheDocument();
  });
});

describe("FindingsPage", () => {
  const finding = {
    id: 15, display_id: "FND-000015", rule_id: "IAM-013", title: "Administrator user without MFA", severity: "CRITICAL",
    status: "OPEN", service: "IAM", region: "global", category: "Identity & Access", asset_id: 18, asset_name: "hannah.zhang",
    resource_uid: "arn:aws:iam::481516234200:user/hannah.zhang", resource_type: "aws.iam.user", account_id: 1,
    account_name: "Demo", first_detected_at: "2026-08-24T05:22:56Z", last_detected_at: "2026-10-05T07:24:12Z",
    public_exposure: false, ticket_ref: null,
  };

  function setup(items: unknown[]) {
    const calls = mockFetch({
      "GET /api/v1/auth/me": () => ({ json: session }),
      "GET /api/v1/accounts": () => ({ json: [] }),
      "GET /api/v1/findings": () => ({ json: { items, total: items.length, page: 1, page_size: 25, pages: 1 } }),
      "GET /api/v1/findings/facets": () => ({ json: { severity: [], status: [], service: [], region: [], rule: [] } }),
      "GET /api/v1/rules": () => ({ json: [] }),
    });
    renderWithProviders(
      <AuthProvider>
        <ScopeProvider>
          <FindingsPage />
        </ScopeProvider>
      </AuthProvider>,
      { route: "/findings?severity=CRITICAL" },
    );
    return calls;
  }

  it("lists findings and passes URL filters to the API", async () => {
    const calls = setup([finding]);
    expect(await screen.findByText("Administrator user without MFA")).toBeInTheDocument();
    expect(screen.getByText("hannah.zhang")).toBeInTheDocument();
    const list = calls.find((c) => c.path === "/api/v1/findings");
    expect(list).toBeDefined();
    await waitFor(() => expect(screen.getByLabelText("Select FND-000015")).toBeInTheDocument());
  });

  it("shows an empty state", async () => {
    setup([]);
    expect(await screen.findByText("No findings match these filters")).toBeInTheDocument();
  });
});
