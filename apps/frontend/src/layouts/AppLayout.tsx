import { useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import * as RDialog from "@radix-ui/react-dialog";
import { Topbar } from "./Topbar";
import { MobileNav, NavStrip } from "./Navigation";
import { Logo } from "@/components/brand";
import { ErrorBoundary } from "@/components/ErrorBoundary";

export function AppLayout() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();
  return (
    <div className="min-h-screen">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-[70] focus:bg-accent focus:px-3 focus:py-2 focus:text-accent-ink">
        Skip to content
      </a>
      <div className="sticky top-0 z-30">
        <Topbar onMenu={() => setMobileOpen(true)} />
        <NavStrip />
      </div>
      <RDialog.Root open={mobileOpen} onOpenChange={setMobileOpen}>
        <RDialog.Portal>
          <RDialog.Overlay className="fixed inset-0 z-40 bg-black/70 lg:hidden" />
          <RDialog.Content className="fixed inset-y-0 left-0 z-50 w-[280px] overflow-y-auto border-r border-line bg-surface lg:hidden">
            <RDialog.Title className="sr-only">Navigation</RDialog.Title>
            <div className="flex h-12 items-center border-b border-line px-4">
              <Logo />
            </div>
            <MobileNav onNavigate={() => setMobileOpen(false)} />
          </RDialog.Content>
        </RDialog.Portal>
      </RDialog.Root>
      <main id="main" className="mx-auto max-w-[1600px] px-4 py-6 lg:px-5">
        <ErrorBoundary key={location.pathname}>
          <Outlet />
        </ErrorBoundary>
      </main>
    </div>
  );
}
