import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "react-router-dom";
import { ApiError } from "@/lib/api";
import { AuthProvider } from "@/stores/auth";
import { ScopeProvider } from "@/stores/scope";
import { ToastProvider } from "@/components/ui/toast";
import { TooltipProvider } from "@radix-ui/react-tooltip";
import { router } from "@/routes";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 20_000,
      refetchOnWindowFocus: false,
      // Retry transient failures, never auth/permission/validation errors.
      retry: (count, error) =>
        count < 2 && !(error instanceof ApiError && error.status >= 400 && error.status < 500),
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ScopeProvider>
          <TooltipProvider delayDuration={300}>
            <ToastProvider>
              <RouterProvider router={router} />
            </ToastProvider>
          </TooltipProvider>
        </ScopeProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}
