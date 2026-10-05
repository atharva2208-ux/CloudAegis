import { PERMS, useAuth } from "@/stores/auth";
import { useUrlState } from "@/hooks/useUrlState";
import { PageHeader, TabPanel, Tabs } from "@/components/ui/misc";
import { ProfileSettings } from "@/components/settings/ProfileSettings";
import { UsersSettings } from "@/components/settings/UsersSettings";
import { RulesSettings } from "@/components/settings/RulesSettings";
import { ScanSettings } from "@/components/settings/ScanSettings";

export default function SettingsPage() {
  const { can } = useAuth();
  const url = useUrlState();
  const tabs = [
    { value: "profile", label: "Profile & security", show: true },
    { value: "users", label: "Users & roles", show: can(PERMS.usersManage) },
    { value: "rules", label: "Detection rules", show: can(PERMS.rulesRead) },
    { value: "scanning", label: "Scanning", show: can(PERMS.settingsManage) },
  ].filter((t) => t.show);
  const requested = url.get("tab") ?? "profile";
  const tab = tabs.some((t) => t.value === requested) ? requested : "profile";

  return (
    <>
      <PageHeader title="Settings" description="Your profile, platform users, the detection rule catalogue and scan configuration." />
      <Tabs value={tab} onValueChange={(v) => url.update({ tab: v })} tabs={tabs}>
        <TabPanel value="profile">
          <ProfileSettings />
        </TabPanel>
        {can(PERMS.usersManage) && (
          <TabPanel value="users">
            <UsersSettings />
          </TabPanel>
        )}
        {can(PERMS.rulesRead) && (
          <TabPanel value="rules">
            <RulesSettings />
          </TabPanel>
        )}
        {can(PERMS.settingsManage) && (
          <TabPanel value="scanning">
            <ScanSettings />
          </TabPanel>
        )}
      </Tabs>
    </>
  );
}
