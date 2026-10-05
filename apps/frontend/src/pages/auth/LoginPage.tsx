import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Logo } from "@/components/brand";
import { Button } from "@/components/ui/button";
import { InlineError } from "@/components/ui/states";
import { authApi } from "@/services";
import { useAuth } from "@/stores/auth";

const schema = z.object({
  email: z.string().trim().min(1, "Enter your email").email("Enter a valid email address"),
  password: z.string().min(1, "Enter your password"),
});
type FormValues = z.infer<typeof schema>;

export default function LoginPage() {
  const { user, login, loading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState<unknown>(null);
  const from = (location.state as { from?: string } | null)?.from ?? "/";
  const { data: demo } = useQuery({ queryKey: ["demo-info"], queryFn: authApi.demoInfo, staleTime: Infinity });
  const {
    register,
    handleSubmit,
    setValue,
    formState: { errors, isSubmitting },
  } = useForm<FormValues>({ resolver: zodResolver(schema) });

  useEffect(() => {
    document.title = "Sign in · CloudAegis";
  }, []);

  if (!loading && user) return <Navigate to={from} replace />;

  const onSubmit = async (values: FormValues) => {
    setError(null);
    try {
      await login(values.email, values.password);
      navigate(from, { replace: true });
    } catch (e) {
      setError(e);
    }
  };

  return (
    <div className="grid min-h-screen lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
      <aside
        className="relative hidden flex-col justify-between overflow-hidden border-r border-line bg-[#101012] p-10 lg:flex"
        style={{
          backgroundImage:
            "linear-gradient(#1a1a1d 1px, transparent 1px), linear-gradient(90deg, #1a1a1d 1px, transparent 1px)",
          backgroundSize: "48px 48px",
        }}
      >
        <Logo />
        <div className="max-w-md">
          <p className="eyebrow text-accent">Cloud security posture management</p>
          <p className="mt-4 text-[34px] font-semibold leading-[1.1] tracking-tight">
            Find the misconfiguration before someone else does.
          </p>
          <p className="mt-4 text-[14px] leading-relaxed text-muted">
            Continuous assessment of AWS accounts for exposed resources, excessive permissions, weak encryption and logging gaps, mapped to CIS, AWS Well-Architected and NIST CSF.
          </p>
        </div>
        <dl className="grid grid-cols-3 border border-line bg-canvas/80">
          {[
            ["10", "AWS services"],
            ["3", "frameworks"],
            ["0", "write permissions"],
          ].map(([v, l]) => (
            <div key={l} className="border-r border-line p-4 last:border-r-0">
              <dt className="eyebrow">{l}</dt>
              <dd className="mt-2 font-mono text-[26px] text-ink">{v}</dd>
            </div>
          ))}
        </dl>
      </aside>
      <div className="flex items-center justify-center px-4 py-10">
      <div className="w-full max-w-[400px]">
        <div className="mb-8 lg:hidden">
          <Logo />
        </div>
        <div>
          <p className="eyebrow">Secure access</p>
          <h1 className="mt-2 text-[24px] font-semibold tracking-tight">Sign in</h1>
          <p className="mt-1 text-[13px] text-muted">Use your CloudAegis account to review your cloud security posture.</p>
          <form className="mt-5 space-y-4" onSubmit={handleSubmit(onSubmit)} noValidate>
            <div>
              <label htmlFor="email" className="field-label">
                Email
              </label>
              <input id="email" type="email" autoComplete="username" className="input" {...register("email")} aria-invalid={!!errors.email} />
              {errors.email && <p className="mt-1 text-[12.5px] text-sev-critical">{errors.email.message}</p>}
            </div>
            <div>
              <label htmlFor="password" className="field-label">
                Password
              </label>
              <input
                id="password"
                type="password"
                autoComplete="current-password"
                className="input"
                {...register("password")}
                aria-invalid={!!errors.password}
              />
              {errors.password && <p className="mt-1 text-[12.5px] text-sev-critical">{errors.password.message}</p>}
            </div>
            <InlineError error={error} />
            <Button type="submit" variant="primary" className="w-full" loading={isSubmitting}>
              Sign in
            </Button>
          </form>
        </div>

        {demo?.demo_mode && demo.password && (
          <div className="mt-8 border-t border-line pt-5">
            <p className="eyebrow text-accent">Demo environment</p>
            <p className="mt-1 text-[12.5px] text-muted">
              This instance runs with simulated AWS data. Choose a role to fill in its credentials.
            </p>
            <div className="mt-3 grid gap-1.5">
              {demo.accounts.map((a) => (
                <button
                  key={a.email}
                  type="button"
                  onClick={() => {
                    setValue("email", a.email, { shouldValidate: true });
                    setValue("password", demo.password!, { shouldValidate: true });
                  }}
                  className="flex items-center justify-between rounded-control border border-line px-3 py-2 text-left text-[12.5px] hover:border-line-strong hover:bg-raised"
                >
                  <span className="mono text-ink">{a.email}</span>
                  <span className="text-faint">{a.role.replace("_", " ").toLowerCase()}</span>
                </button>
              ))}
            </div>
          </div>
        )}
        <p className="mt-6 text-[12px] text-faint">
          Sessions expire after inactivity. Repeated failed sign-ins temporarily lock the account.
        </p>
      </div>
      </div>
    </div>
  );
}
