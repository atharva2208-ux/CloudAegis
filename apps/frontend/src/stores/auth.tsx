import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { setCsrfToken, setUnauthenticatedHandler } from "@/lib/api";
import { authApi } from "@/services";
import type { User } from "@/types/api";

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  can: (permission: string) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const queryClient = useQueryClient();

  useEffect(() => {
    setUnauthenticatedHandler(() => {
      setUser(null);
      setCsrfToken(null);
      queryClient.clear();
    });
    authApi
      .me()
      .then((session) => {
        setCsrfToken(session.csrf_token);
        setUser(session.user);
      })
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, [queryClient]);

  const login = useCallback(async (email: string, password: string) => {
    const session = await authApi.login(email, password);
    setCsrfToken(session.csrf_token);
    setUser(session.user);
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } finally {
      setCsrfToken(null);
      setUser(null);
      queryClient.clear();
    }
  }, [queryClient]);

  const can = useCallback((permission: string) => !!user?.permissions.includes(permission), [user]);

  const value = useMemo(() => ({ user, loading, login, logout, can }), [user, loading, login, logout, can]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

export const PERMS = {
  accountsRead: "accounts:read",
  accountsManage: "accounts:manage",
  assetsRead: "assets:read",
  findingsRead: "findings:read",
  findingsUpdate: "findings:update",
  scansRead: "scans:read",
  scansRun: "scans:run",
  complianceRead: "compliance:read",
  rulesRead: "rules:read",
  reportsRead: "reports:read",
  reportsGenerate: "reports:generate",
  auditRead: "audit:read",
  usersManage: "users:manage",
  settingsManage: "settings:manage",
} as const;
