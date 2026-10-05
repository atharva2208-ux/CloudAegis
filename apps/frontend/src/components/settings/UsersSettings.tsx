import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Lock, UserPlus } from "lucide-react";
import { usersApi } from "@/services";
import { useAuth } from "@/stores/auth";
import { Panel } from "@/components/ui/misc";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { ErrorState, InlineError, LoadingRows } from "@/components/ui/states";
import { useToast } from "@/components/ui/toast";
import { FieldError } from "@/components/accounts/CredentialFields";
import { errorMessage } from "@/lib/api";
import { passwordSchema } from "@/lib/validation";
import { relative } from "@/lib/format";
import type { User } from "@/types/api";

const ROLE_LABEL: Record<string, string> = { ADMIN: "Admin", SECURITY_ANALYST: "Security analyst", VIEWER: "Viewer" };

const createSchema = z.object({
  full_name: z.string().trim().min(2, "Enter a name").max(120),
  email: z.string().trim().email("Enter a valid email"),
  role: z.enum(["ADMIN", "SECURITY_ANALYST", "VIEWER"]),
  password: passwordSchema,
});
type CreateValues = z.infer<typeof createSchema>;

function CreateUserDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const { register, handleSubmit, reset, formState } = useForm<CreateValues>({
    resolver: zodResolver(createSchema),
    defaultValues: { role: "VIEWER" },
  });
  const create = useMutation({
    mutationFn: (v: CreateValues) => usersApi.create(v),
    onSuccess: (u) => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
      toast.success(`${u.email} added as ${ROLE_LABEL[u.role]}`);
      reset();
      onOpenChange(false);
    },
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Add user"
      description="Share the initial password through a secure channel and ask the user to change it after signing in."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" loading={create.isPending} onClick={handleSubmit((v) => create.mutate(v))}>
            Add user
          </Button>
        </>
      }
    >
      <form className="space-y-3" onSubmit={(e) => e.preventDefault()} noValidate>
        <div>
          <label className="field-label" htmlFor="u-name">
            Full name
          </label>
          <input id="u-name" className="input" {...register("full_name")} />
          <FieldError message={formState.errors.full_name?.message} />
        </div>
        <div>
          <label className="field-label" htmlFor="u-email">
            Email
          </label>
          <input id="u-email" type="email" className="input" autoComplete="off" {...register("email")} />
          <FieldError message={formState.errors.email?.message} />
        </div>
        <div>
          <label className="field-label" htmlFor="u-role">
            Role
          </label>
          <select id="u-role" className="input" {...register("role")}>
            {Object.entries(ROLE_LABEL).map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="field-label" htmlFor="u-password">
            Initial password
          </label>
          <input id="u-password" type="password" className="input" autoComplete="new-password" {...register("password")} />
          <FieldError message={formState.errors.password?.message} />
        </div>
        <InlineError error={create.error} />
      </form>
    </Dialog>
  );
}

export function UsersSettings() {
  const { user: me } = useAuth();
  const queryClient = useQueryClient();
  const toast = useToast();
  const [createOpen, setCreateOpen] = useState(false);
  const users = useQuery({ queryKey: ["users"], queryFn: usersApi.list });
  const roles = useQuery({ queryKey: ["roles"], queryFn: usersApi.roles, staleTime: Infinity });
  const done = (u: User, msg: string) => {
    queryClient.invalidateQueries({ queryKey: ["users"] });
    toast.success(`${u.email}: ${msg}`);
  };
  const update = useMutation({
    mutationFn: ({ id, body }: { id: number; body: { role?: string; is_active?: boolean } }) => usersApi.update(id, body),
    onSuccess: (u, v) => done(u, v.body.role ? `role changed to ${ROLE_LABEL[u.role]}` : u.is_active ? "reactivated" : "deactivated"),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const unlock = useMutation({
    mutationFn: (id: number) => usersApi.unlock(id),
    onSuccess: (u) => done(u, "unlocked"),
    onError: (e) => toast.error(errorMessage(e)),
  });

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
      <Panel
        title="Users"
        actions={
          <Button size="sm" variant="primary" onClick={() => setCreateOpen(true)}>
            <UserPlus className="h-3.5 w-3.5" aria-hidden /> Add user
          </Button>
        }
      >
        {users.isLoading ? (
          <LoadingRows rows={4} />
        ) : users.error ? (
          <ErrorState error={users.error} onRetry={users.refetch} />
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>User</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Last sign-in</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {users.data?.map((u) => {
                  const self = u.id === me?.id;
                  return (
                    <tr key={u.id}>
                      <td>
                        {u.full_name} {self && <span className="text-[12px] text-faint">(you)</span>}
                        <span className="block text-[12px] text-faint">{u.email}</span>
                      </td>
                      <td>
                        <select
                          className="input h-8 w-auto pr-8"
                          aria-label={`Role for ${u.email}`}
                          value={u.role}
                          disabled={self || update.isPending}
                          onChange={(e) => update.mutate({ id: u.id, body: { role: e.target.value } })}
                        >
                          {Object.entries(ROLE_LABEL).map(([v, l]) => (
                            <option key={v} value={v}>
                              {l}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td className="whitespace-nowrap text-[12.5px]">
                        {!u.is_active ? (
                          <span className="text-faint">Deactivated</span>
                        ) : u.locked ? (
                          <span className="inline-flex items-center gap-1 text-sev-high">
                            <Lock className="h-3.5 w-3.5" aria-hidden /> Locked out
                          </span>
                        ) : (
                          <span className="text-ok">Active</span>
                        )}
                      </td>
                      <td className="whitespace-nowrap text-muted">{relative(u.last_login_at)}</td>
                      <td className="whitespace-nowrap text-right">
                        {u.locked && (
                          <Button size="sm" onClick={() => unlock.mutate(u.id)} loading={unlock.isPending && unlock.variables === u.id}>
                            Unlock
                          </Button>
                        )}
                        {!self && (
                          <Button
                            size="sm"
                            variant={u.is_active ? "ghost" : "secondary"}
                            className="ml-1"
                            onClick={() => update.mutate({ id: u.id, body: { is_active: !u.is_active } })}
                          >
                            {u.is_active ? "Deactivate" : "Reactivate"}
                          </Button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      <Panel title="Roles" bodyClassName="divide-y divide-line">
        {roles.data?.map((r) => (
          <div key={r.name} className="p-4">
            <p className="text-[13px] font-medium">{ROLE_LABEL[r.name] ?? r.name}</p>
            <p className="mt-0.5 text-[12.5px] text-muted">{r.description}</p>
            <p className="mono mt-2 text-[11.5px] leading-relaxed text-faint">{r.permissions.join(" · ")}</p>
          </div>
        ))}
      </Panel>
      <CreateUserDialog open={createOpen} onOpenChange={setCreateOpen} />
    </div>
  );
}
