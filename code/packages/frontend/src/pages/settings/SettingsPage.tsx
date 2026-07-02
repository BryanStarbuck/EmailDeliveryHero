import { useParams } from "@tanstack/react-router";
import { AdminSettings } from "./AdminSettings";
import { GeneralSettings } from "./GeneralSettings";
import { SchedulingSettings } from "./SchedulingSettings";

/**
 * Settings (pm/settings.mdx): the right content pane behind the settings left bar
 * (Sidebar variant="settings", data-driven from pm/left_bar.yaml). Three sections:
 *
 *   /settings            → GeneralSettings — the all-users groups: Account & access (§7),
 *                          Appearance (§8), Notifications — my prefs (§4), Monitored domains (§1),
 *                          Checks configuration shown read-only (§2), Storage & data (§5),
 *                          Tools & environment (§6).
 *   /settings/scheduling → SchedulingSettings — the §3 Scheduling tab (default OFF, one-flip
 *                          enable, times of day + weekday chips, status block).
 *   /settings/admin      → AdminSettings — every admin-only control, gated by role:admin in the
 *                          UI and enforced 403 by the backend either way.
 */
export function SettingsPage() {
	const params = useParams({ strict: false }) as { section?: string };
	const section = params.section ?? "account";

	return (
		<div className="mx-auto max-w-3xl">
			<h1 className="mb-6 text-2xl font-bold">
				{section === "scheduling"
					? "Settings › Scheduling"
					: section === "admin"
						? "Settings › Admin"
						: "Settings"}
			</h1>

			{section === "scheduling" ? (
				<SchedulingSettings />
			) : section === "admin" ? (
				<AdminSettings />
			) : (
				<GeneralSettings />
			)}
		</div>
	);
}
