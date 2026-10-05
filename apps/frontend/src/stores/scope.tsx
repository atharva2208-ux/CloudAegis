import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { accountsApi } from "@/services";
import type { CloudAccount } from "@/types/api";
import { useAuth } from "@/stores/auth";

/** The cloud account the user is currently looking at ("all accounts" when undefined). */
interface ScopeState {
  accountId: number | undefined;
  setAccountId: (id: number | undefined) => void;
  accounts: CloudAccount[];
  current: CloudAccount | undefined;
}

const ScopeContext = createContext<ScopeState | null>(null);
const STORAGE_KEY = "cloudaegis.scope";

export function ScopeProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const [accountId, setAccountId] = useState<number | undefined>(() => {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? Number(raw) || undefined : undefined;
  });
  const { data: accounts = [] } = useQuery({
    queryKey: ["accounts"],
    queryFn: accountsApi.list,
    enabled: !!user,
    staleTime: 30_000,
  });

  useEffect(() => {
    if (accountId === undefined) localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, String(accountId));
  }, [accountId]);

  useEffect(() => {
    if (accountId !== undefined && accounts.length && !accounts.some((a) => a.id === accountId)) {
      setAccountId(undefined);
    }
  }, [accounts, accountId]);

  const value = useMemo(
    () => ({ accountId, setAccountId, accounts, current: accounts.find((a) => a.id === accountId) }),
    [accountId, accounts],
  );
  return <ScopeContext.Provider value={value}>{children}</ScopeContext.Provider>;
}

export function useScope(): ScopeState {
  const ctx = useContext(ScopeContext);
  if (!ctx) throw new Error("useScope must be used within ScopeProvider");
  return ctx;
}
