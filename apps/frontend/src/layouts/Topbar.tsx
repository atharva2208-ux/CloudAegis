import * as Dropdown from "@radix-ui/react-dropdown-menu";
import * as Popover from "@radix-ui/react-popover";
import { Bell, ChevronDown, LogOut, Menu, UserRound } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { platformApi } from "@/services";
import { useAuth } from "@/stores/auth";
import { useScope } from "@/stores/scope";
import { relative, SEVERITY_COLOR } from "@/lib/format";
import { cn } from "@/lib/cn";
import { GlobalSearch } from "./GlobalSearch";
import { Logo } from "@/components/brand";

const menuItem =
  "flex cursor-pointer items-center gap-2 rounded-control px-2.5 py-1.5 text-[13px] text-ink outline-none data-[highlighted]:bg-raised";

function AccountSwitcher() {
  const { accounts, accountId, setAccountId, current } = useScope();
  return (
    <Dropdown.Root>
      <Dropdown.Trigger className="inline-flex h-8 max-w-[260px] items-center gap-2 border border-line bg-surface px-2.5 text-[12.5px] hover:border-line-strong">
        <span className="font-mono text-[10.5px] uppercase tracking-[0.1em] text-faint">Scope</span>
        <span className="truncate">{current ? current.name : "All accounts"}</span>
        <ChevronDown className="h-3.5 w-3.5 text-faint" aria-hidden />
      </Dropdown.Trigger>
      <Dropdown.Portal>
        <Dropdown.Content
          align="end"
          sideOffset={6}
          className="z-50 w-72 rounded-panel border border-line-strong bg-surface p-1.5 shadow-[0_12px_32px_rgba(0,0,0,0.45)]"
        >
          <Dropdown.Item className={cn(menuItem, accountId === undefined && "text-accent-strong")} onSelect={() => setAccountId(undefined)}>
            All accounts
          </Dropdown.Item>
          <Dropdown.Separator className="my-1 h-px bg-line" />
          {accounts.map((a) => (
            <Dropdown.Item
              key={a.id}
              className={cn(menuItem, "justify-between", a.id === accountId && "text-accent-strong")}
              onSelect={() => setAccountId(a.id)}
            >
              <span className="truncate">{a.name}</span>
              <span className="mono text-faint">{a.account_identifier}</span>
            </Dropdown.Item>
          ))}
          {accounts.length === 0 && <p className="px-2.5 py-2 text-[12.5px] text-faint">No accounts connected</p>}
        </Dropdown.Content>
      </Dropdown.Portal>
    </Dropdown.Root>
  );
}

function Notifications() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { data } = useQuery({ queryKey: ["notifications"], queryFn: platformApi.notifications, refetchInterval: 30_000 });
  const markRead = useMutation({
    mutationFn: (ids?: number[]) => platformApi.markRead(ids),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["notifications"] }),
  });
  const unread = data?.unread ?? 0;
  return (
    <Popover.Root>
      <Popover.Trigger
        className="relative inline-flex h-8 w-8 items-center justify-center text-muted hover:bg-raised hover:text-ink"
        aria-label={`Notifications${unread ? `, ${unread} unread` : ""}`}
      >
        <Bell className="h-4 w-4" />
        {unread > 0 && (
          <span className="absolute right-0.5 top-0.5 min-w-[15px] bg-sev-critical px-1 text-center text-[10px] font-semibold leading-4 text-white">
            {unread > 9 ? "9+" : unread}
          </span>
        )}
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          align="end"
          sideOffset={6}
          className="z-50 w-[380px] rounded-panel border border-line-strong bg-surface shadow-[0_16px_40px_rgba(0,0,0,0.5)]"
        >
          <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
            <p className="text-[13px] font-semibold">Notifications</p>
            {unread > 0 && (
              <button className="text-[12.5px] text-accent hover:text-accent-strong" onClick={() => markRead.mutate(undefined)}>
                Mark all as read
              </button>
            )}
          </div>
          <div className="max-h-[420px] overflow-y-auto">
            {!data?.items.length && <p className="px-4 py-8 text-center text-[13px] text-muted">You're all caught up.</p>}
            {data?.items.map((n) => (
              <Popover.Close asChild key={n.id}>
                <button
                  className={cn("flex w-full gap-3 border-b border-line/60 px-4 py-3 text-left hover:bg-raised", !n.read_at && "bg-accent-dim/10")}
                  onClick={() => {
                    if (!n.read_at) markRead.mutate([n.id]);
                    if (n.link) navigate(n.link);
                  }}
                >
                  <span className="mt-1.5 h-2 w-2 shrink-0 rounded-[1px]" style={{ background: n.read_at ? "transparent" : SEVERITY_COLOR[n.severity] ?? "#F5A524" }} />
                  <span className="min-w-0">
                    <span className="block text-[13px] text-ink">{n.title}</span>
                    <span className="mt-0.5 block text-[12.5px] text-muted">{n.message}</span>
                    <span className="mt-1 block text-[11.5px] text-faint">{relative(n.created_at)}</span>
                  </span>
                </button>
              </Popover.Close>
            ))}
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

function UserMenu() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  if (!user) return null;
  const initials = user.full_name
    .split(" ")
    .map((p) => p[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
  return (
    <Dropdown.Root>
      <Dropdown.Trigger className="flex items-center gap-2 rounded-control py-1 pl-1 pr-2 hover:bg-raised" aria-label="Account menu">
        <span className="flex h-7 w-7 items-center justify-center bg-accent font-mono text-[11px] font-semibold text-accent-ink">
          {initials}
        </span>
        <span className="hidden text-left leading-tight lg:block">
          <span className="block text-[12.5px]">{user.full_name}</span>
          <span className="block text-[11px] text-faint">{user.role.replace("_", " ").toLowerCase()}</span>
        </span>
      </Dropdown.Trigger>
      <Dropdown.Portal>
        <Dropdown.Content
          align="end"
          sideOffset={6}
          className="z-50 w-56 rounded-panel border border-line-strong bg-surface p-1.5 shadow-[0_12px_32px_rgba(0,0,0,0.45)]"
        >
          <div className="px-2.5 py-2">
            <p className="truncate text-[13px]">{user.email}</p>
          </div>
          <Dropdown.Separator className="my-1 h-px bg-line" />
          <Dropdown.Item className={menuItem} onSelect={() => navigate("/settings")}>
            <UserRound className="h-4 w-4 text-faint" /> Profile and security
          </Dropdown.Item>
          <Dropdown.Item
            className={menuItem}
            onSelect={async () => {
              await logout();
              navigate("/login");
            }}
          >
            <LogOut className="h-4 w-4 text-faint" /> Sign out
          </Dropdown.Item>
        </Dropdown.Content>
      </Dropdown.Portal>
    </Dropdown.Root>
  );
}

export function Topbar({ onMenu }: { onMenu: () => void }) {
  const { current } = useScope();
  return (
    <header className="flex h-12 items-center gap-3 border-b border-line bg-canvas px-3 lg:px-5">
      <button className="p-2 text-muted hover:bg-raised lg:hidden" onClick={onMenu} aria-label="Open navigation">
        <Menu className="h-4 w-4" />
      </button>
      <Link to="/" className="mr-2 shrink-0" aria-label="CloudAegis home">
        <Logo />
      </Link>
      <span className="hidden h-5 w-px bg-line md:block" aria-hidden />
      <GlobalSearch />
      <div className="ml-auto flex items-center gap-1.5">
        {current?.is_demo && (
          <span className="hidden border border-accent/40 px-1.5 py-0.5 font-mono text-[10.5px] uppercase tracking-[0.1em] text-accent xl:inline" title="Simulated demo data — no real AWS resources">
            Simulated data
          </span>
        )}
        <div className="hidden md:block">
          <AccountSwitcher />
        </div>
        <Notifications />
        <UserMenu />
      </div>
    </header>
  );
}
