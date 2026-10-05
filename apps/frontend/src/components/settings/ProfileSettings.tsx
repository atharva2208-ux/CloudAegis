import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import { authApi, platformApi } from "@/services";
import { useAuth } from "@/stores/auth";
import { KeyValue, Panel } from "@/components/ui/misc";
import { Button } from "@/components/ui/button";
import { InlineError } from "@/components/ui/states";
import { useToast } from "@/components/ui/toast";
import { FieldError } from "@/components/accounts/CredentialFields";
import { passwordSchema } from "@/lib/validation";
import { dateTime } from "@/lib/format";

const schema = z
  .object({
    current_password: z.string().min(1, "Enter your current password"),
    new_password: passwordSchema,
    confirm: z.string(),
  })
  .refine((v) => v.new_password === v.confirm, { path: ["confirm"], message: "Passwords do not match" })
  .refine((v) => v.new_password !== v.current_password, { path: ["new_password"], message: "Choose a different password" });
type FormValues = z.infer<typeof schema>;

export function ProfileSettings() {
  const { user, logout } = useAuth();
  const toast = useToast();
  const { data: settings } = useQuery({ queryKey: ["settings"], queryFn: platformApi.settings });
  const { register, handleSubmit, reset, formState } = useForm<FormValues>({ resolver: zodResolver(schema) });
  const change = useMutation({
    mutationFn: (v: FormValues) => authApi.changePassword(v.current_password, v.new_password),
    onSuccess: async () => {
      reset();
      toast.success("Password changed. Other sessions were signed out — please sign in again.");
      await logout();
    },
  });
  if (!user) return null;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel title="Your account" bodyClassName="grid gap-3 p-4">
        <KeyValue label="Name">{user.full_name}</KeyValue>
        <KeyValue label="Email">{user.email}</KeyValue>
        <KeyValue label="Role">{user.role.replace("_", " ").toLowerCase()}</KeyValue>
        <KeyValue label="Last sign-in">{dateTime(user.last_login_at)}</KeyValue>
        <KeyValue label="Permissions">
          <span className="flex flex-wrap gap-1">
            {user.permissions.map((p) => (
              <span key={p} className="mono rounded-control border border-line px-1.5 py-0.5 text-[11.5px] text-muted">
                {p}
              </span>
            ))}
          </span>
        </KeyValue>
        {settings && (
          <p className="text-[12px] text-faint">Sessions end after {settings.session_idle_minutes} minutes of inactivity.</p>
        )}
      </Panel>
      <Panel title="Change password" bodyClassName="p-4">
        <form className="space-y-3" onSubmit={handleSubmit((v) => change.mutate(v))} noValidate>
          <div>
            <label className="field-label" htmlFor="current_password">
              Current password
            </label>
            <input id="current_password" type="password" autoComplete="current-password" className="input" {...register("current_password")} />
            <FieldError message={formState.errors.current_password?.message} />
          </div>
          <div>
            <label className="field-label" htmlFor="new_password">
              New password
            </label>
            <input id="new_password" type="password" autoComplete="new-password" className="input" {...register("new_password")} />
            <FieldError message={formState.errors.new_password?.message} />
            <p className="mt-1 text-[12px] text-faint">At least 12 characters using three of: lowercase, uppercase, digits, symbols.</p>
          </div>
          <div>
            <label className="field-label" htmlFor="confirm">
              Confirm new password
            </label>
            <input id="confirm" type="password" autoComplete="new-password" className="input" {...register("confirm")} />
            <FieldError message={formState.errors.confirm?.message} />
          </div>
          <InlineError error={change.error} />
          <Button type="submit" variant="primary" loading={change.isPending}>
            Update password
          </Button>
        </form>
      </Panel>
    </div>
  );
}
