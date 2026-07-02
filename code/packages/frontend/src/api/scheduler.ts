import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./axios";

/**
 * The scheduler contract (pm/scheduled_checks.mdx) the dashboard's Scheduled toggle rides on
 * (pm/dashboard.mdx §7.2): GET /api/scheduler reports whether recurring checks are enabled;
 * PUT /api/scheduler/config flips the `schedule.enabled` flag (merged over the current block so
 * the toggle never clobbers cadence/times set on the configuration page).
 */

const STATUS_KEY = ["scheduler"] as const;
const CONFIG_KEY = ["scheduler", "config"] as const;

export type ScheduleCadence = "interval" | "daily" | "weekly";
export type ScheduleRunner = "in-process" | "os";
export type Weekday = "mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun";

/** Monday-first, matching the backend's schedule.types.ts and the day chips (pm/settings.mdx §3.2). */
export const WEEKDAYS: Weekday[] = [
	"mon",
	"tue",
	"wed",
	"thu",
	"fri",
	"sat",
	"sun",
];
export type OsSchedulerKind = "launchd" | "cron" | "systemd" | "schtasks";

export interface ScheduleOsState {
	kind: OsSchedulerKind;
	installed: boolean;
	label: string;
}

/** The `schedule:` block of config.yaml (pm/scheduled_checks.mdx "Schedule config model"). */
export interface ScheduleConfig {
	enabled: boolean;
	cadence: ScheduleCadence;
	everyHours: number;
	times: string[];
	weekdays: Weekday[];
	timezone: string;
	domains: "all" | string[];
	runner: ScheduleRunner;
	os: ScheduleOsState;
}

/** GET /api/scheduler — one read backs the dashboard toggle AND the Settings §3 status block. */
export interface SchedulerStatus {
	enabled: boolean;
	runner?: ScheduleRunner;
	cadence?: ScheduleCadence;
	times?: string[];
	weekdays?: Weekday[];
	nextRunAt?: string | null;
	lastRunAt?: string | null;
	lastTrigger?: "in-process" | "os" | "manual" | null;
	running?: boolean;
	/** Scheduled-run coverage: global switch ANDed with per-domain scheduleEnabled. */
	domainsCovered?: number;
	domainsTotal?: number;
	os?: ScheduleOsState;
}

/** POST /api/scheduler/run outcome — skipped triggers report why (pm/settings.mdx §3.3). */
export interface SchedulerRunOutcome {
	started: boolean;
	reason?: "disabled" | "already_running" | "recently_ran";
	domains?: number;
}

/** GET /api/scheduler/os/preview — the rendered native artifact, before installing. */
export interface OsArtifactPreview {
	kind: OsSchedulerKind;
	path: string;
	content: string;
	installed: boolean;
}

/** Scheduler status — backs the dashboard's Scheduled on/off toggle. */
export function useSchedulerStatus() {
	return useQuery({
		queryKey: STATUS_KEY,
		queryFn: async () => (await api.get<SchedulerStatus>("/scheduler")).data,
		retry: false,
	});
}

/** Flip recurring checks on/off — merges `enabled` into the persisted schedule config. */
export function useSetScheduleEnabled() {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: async (enabled: boolean) => {
			// The backend merges the patch over the current block (pm/settings.mdx §3.3) — and enabling
			// with no times configured seeds 06:00 every day, so one flip yields a working schedule.
			return (await api.put<ScheduleConfig>("/scheduler/config", { enabled }))
				.data;
		},
		onSettled: () => {
			qc.invalidateQueries({ queryKey: STATUS_KEY });
			qc.invalidateQueries({ queryKey: CONFIG_KEY });
		},
	});
}

/** "Run a scheduled check now" — forced, so it runs even while the master toggle is off. */
export function useRunScheduledNow() {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: async () =>
			(await api.post<SchedulerRunOutcome>("/scheduler/run", { force: true }))
				.data,
		onSettled: () => {
			qc.invalidateQueries({ queryKey: STATUS_KEY });
			// A forced run writes fresh audit results + run records.
			qc.invalidateQueries({ queryKey: ["audit", "results"] });
			qc.invalidateQueries({ queryKey: ["audit", "runs"] });
		},
	});
}

/** The persisted `schedule:` block — backs the Scheduled Checks configuration page. */
export function useScheduleConfig() {
	return useQuery({
		queryKey: CONFIG_KEY,
		queryFn: async () =>
			(await api.get<ScheduleConfig>("/scheduler/config")).data,
		retry: false,
	});
}

/**
 * PUT /api/scheduler/config — persist the whole schedule block. The backend (re)starts or stops
 * the in-process job and, when the OS layer is installed, regenerates the native artifact so the
 * installed schedule matches the saved config (pm/scheduled_checks.mdx "Save").
 */
export function useSaveScheduleConfig() {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: async (config: Partial<ScheduleConfig>) =>
			(await api.put<ScheduleConfig>("/scheduler/config", config)).data,
		onSettled: () => {
			qc.invalidateQueries({ queryKey: STATUS_KEY });
			qc.invalidateQueries({ queryKey: CONFIG_KEY });
		},
	});
}

/** The rendered OS-level artifact (plist / systemd units + crontab / schtasks commands). */
export async function fetchOsPreview(): Promise<OsArtifactPreview> {
	return (await api.get<OsArtifactPreview>("/scheduler/os/preview")).data;
}

/** POST /api/scheduler/os/install — write + load the native OS schedule. */
export function useInstallOsSchedule() {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: async () =>
			(await api.post<ScheduleConfig>("/scheduler/os/install")).data,
		onSettled: () => {
			qc.invalidateQueries({ queryKey: STATUS_KEY });
			qc.invalidateQueries({ queryKey: CONFIG_KEY });
		},
	});
}

/** POST /api/scheduler/os/uninstall — unload + remove the native OS schedule. */
export function useUninstallOsSchedule() {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: async () =>
			(await api.post<ScheduleConfig>("/scheduler/os/uninstall")).data,
		onSettled: () => {
			qc.invalidateQueries({ queryKey: STATUS_KEY });
			qc.invalidateQueries({ queryKey: CONFIG_KEY });
		},
	});
}
