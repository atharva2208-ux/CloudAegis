import { Component, type ErrorInfo, type ReactNode } from "react";
import { Button } from "@/components/ui/button";

interface State {
  error: Error | null;
}

/** Catches render errors so one broken view never blanks the whole application. */
export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Hook point for an error-tracking service (Sentry, etc.).
    console.error("ui_render_error", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="panel mx-auto mt-10 max-w-lg p-8 text-center" role="alert">
          <p className="text-[15px] font-semibold">This page failed to render</p>
          <p className="mt-2 text-[13px] text-muted">
            The error has been logged. Reload the page, or go back to the overview.
          </p>
          <div className="mt-5 flex justify-center gap-2">
            <Button onClick={() => window.location.reload()}>Reload</Button>
            <Button variant="ghost" onClick={() => (window.location.href = "/")}>
              Go to overview
            </Button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
