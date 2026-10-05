import * as Dropdown from "@radix-ui/react-dropdown-menu";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { ChevronDown } from "lucide-react";
import { cn } from "@/lib/cn";
import { PERMS, useAuth } from "@/stores/auth";

interface NavItem {
  to: string;
  label: string;
  hint?: string;
  perm?: string;
}

interface NavGroup {
  label: string;
  /** Route prefixes that mark the group as active. */
  match: string[];
  items: NavItem[];
}

type NavEntry = NavItem | NavGroup;

const isGroup = (e: NavEntry): e is NavGroup => "items" in e;

export const NAVIGATION: NavEntry[] = [
  { to: "/", label: "Overview", perm: PERMS.findingsRead },
  {
    label: "Cloud security",
    match: ["/accounts", "/assets", "/findings", "/scans"],
    items: [
      { to: "/findings", label: "Findings", hint: "Misconfigurations to triage", perm: PERMS.findingsRead },
      { to: "/assets", label: "Asset inventory", hint: "Every discovered resource", perm: PERMS.assetsRead },
      { to: "/scans", label: "Scans", hint: "History, progress and comparison", perm: PERMS.scansRead },
      { to: "/accounts", label: "Cloud accounts", hint: "Connections and onboarding", perm: PERMS.accountsRead },
    ],
  },
  {
    label: "Compliance",
    match: ["/compliance"],
    items: [
      { to: "/compliance", label: "Frameworks", hint: "CIS, Well-Architected, NIST CSF", perm: PERMS.complianceRead },
      { to: "/compliance/controls", label: "Controls", hint: "Every control across frameworks", perm: PERMS.complianceRead },
    ],
  },
  {
    label: "Analytics",
    match: ["/analytics"],
    items: [
      { to: "/analytics/trends", label: "Security trends", hint: "Score, findings and MTTR over time", perm: PERMS.findingsRead },
      { to: "/analytics/risk", label: "Risk analytics", hint: "Where open risk concentrates", perm: PERMS.findingsRead },
    ],
  },
  { to: "/reports", label: "Reports", perm: PERMS.reportsRead },
  { to: "/audit", label: "Audit log", perm: PERMS.auditRead },
  { to: "/settings", label: "Settings" },
];

function useVisibleNav(): NavEntry[] {
  const { can } = useAuth();
  return NAVIGATION.flatMap((entry): NavEntry[] => {
    if (isGroup(entry)) {
      const items = entry.items.filter((i) => !i.perm || can(i.perm));
      return items.length ? [{ ...entry, items }] : [];
    }
    return !entry.perm || can(entry.perm) ? [entry] : [];
  });
}

const tab =
  "relative inline-flex h-10 items-center gap-1 px-3 text-[13px] transition-colors outline-none after:absolute after:inset-x-3 after:bottom-0 after:h-[2px]";

/** Horizontal navigation strip under the utility bar (desktop). */
export function NavStrip() {
  const entries = useVisibleNav();
  const { pathname } = useLocation();
  const navigate = useNavigate();
  return (
    <nav aria-label="Main" className="hidden border-b border-line bg-[#101012] lg:block">
      <ul className="mx-auto flex max-w-[1600px] items-center px-3 lg:px-5">
        {entries.map((entry) => {
          if (!isGroup(entry)) {
            return (
              <li key={entry.to}>
                <NavLink
                  to={entry.to}
                  end={entry.to === "/"}
                  className={({ isActive }) =>
                    cn(tab, isActive ? "text-ink after:bg-accent" : "text-muted hover:text-ink after:bg-transparent")
                  }
                >
                  {entry.label}
                </NavLink>
              </li>
            );
          }
          const active = entry.match.some((m) => pathname.startsWith(m));
          return (
            <li key={entry.label}>
              <Dropdown.Root modal={false}>
                <Dropdown.Trigger
                  className={cn(
                    tab,
                    active ? "text-ink after:bg-accent" : "text-muted hover:text-ink after:bg-transparent",
                    "data-[state=open]:text-ink",
                  )}
                >
                  {entry.label}
                  <ChevronDown className="h-3.5 w-3.5 opacity-60" aria-hidden />
                </Dropdown.Trigger>
                <Dropdown.Portal>
                  <Dropdown.Content
                    align="start"
                    sideOffset={0}
                    className="z-50 w-72 border border-line-strong bg-surface p-1 shadow-[0_16px_40px_rgba(0,0,0,0.6)]"
                  >
                    {entry.items.map((item) => (
                      <Dropdown.Item
                        key={item.to}
                        onSelect={() => navigate(item.to)}
                        className={cn(
                          "flex cursor-pointer flex-col border-l-2 px-3 py-2 outline-none data-[highlighted]:bg-raised",
                          pathname === item.to || (item.to !== "/compliance" && pathname.startsWith(item.to))
                            ? "border-accent"
                            : "border-transparent",
                        )}
                      >
                        <span className="text-[13px] text-ink">{item.label}</span>
                        {item.hint && <span className="text-[12px] text-faint">{item.hint}</span>}
                      </Dropdown.Item>
                    ))}
                  </Dropdown.Content>
                </Dropdown.Portal>
              </Dropdown.Root>
            </li>
          );
        })}
        <li className="ml-auto flex items-center gap-2 pr-1 font-mono text-[10.5px] uppercase tracking-[0.1em] text-faint">
          <span className="h-1.5 w-1.5 bg-ok" aria-hidden /> Read-only access
        </li>
      </ul>
    </nav>
  );
}

/** Full navigation list for the mobile drawer. */
export function MobileNav({ onNavigate }: { onNavigate: () => void }) {
  const entries = useVisibleNav();
  const link = ({ isActive }: { isActive: boolean }) =>
    cn("block border-l-2 px-4 py-2 text-[13.5px]", isActive ? "border-accent bg-raised text-ink" : "border-transparent text-muted");
  return (
    <nav aria-label="Main" className="py-2">
      {entries.map((entry) =>
        isGroup(entry) ? (
          <div key={entry.label} className="mt-3">
            <p className="eyebrow px-4 pb-1">{entry.label}</p>
            {entry.items.map((item) => (
              <NavLink key={item.to} to={item.to} end={item.to === "/compliance"} className={link} onClick={onNavigate}>
                {item.label}
              </NavLink>
            ))}
          </div>
        ) : (
          <NavLink key={entry.to} to={entry.to} end={entry.to === "/"} className={link} onClick={onNavigate}>
            {entry.label}
          </NavLink>
        ),
      )}
    </nav>
  );
}
