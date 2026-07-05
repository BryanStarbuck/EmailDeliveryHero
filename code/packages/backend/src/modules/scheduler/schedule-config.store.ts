import { join } from "node:path";
import { resolveStateDir } from "@shared/state-dir";
import { readYaml, writeYaml } from "@shared/yaml-store";
import {
	type OsSchedulerKind,
	type ScheduleCadence,
	type ScheduleConfig,
	type ScheduleRunner,
	WEEKDAYS,
	type Weekday,
} from "./schedule.types";

/**
 * The schedule config store (pm/scheduled_checks.mdx "Schedule config model"). The schedule lives
 * as one `schedule:` block inside config.yaml under the state dir. Reads/writes preserve every
 * other top-level key of config.yaml (other subsystems keep their blocks there too), and every
 * read is normalized so a hand-edited file can never crash the scheduler.
 */

const HHMM_RE = /^([01]\d|2[0-3]):[0-5]\d$/;

export const DEFAULT_OS_LABEL = "com.emaildeliveryhero.scheduler";

/**
 * Allowed shape for an OS scheduler label (security audit finding #2). The label is interpolated
 * into a filesystem path (`~/Library/LaunchAgents/<label>.plist`, systemd unit names, schtasks task
 * names), so it must be a single reverse-DNS-style segment with NO path separators, `..`, or
 * whitespace — otherwise a crafted label (e.g. "../../../tmp/evil") escapes the managed directory
 * when joined. Only these characters are permitted; anything else falls back to DEFAULT_OS_LABEL.
 */
const OS_LABEL_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/;

/** True when `label` is a safe, path-separator-free scheduler label. */
export function isSafeOsLabel(label: string): boolean {
	return OS_LABEL_RE.test(label) && !label.includes("..");
}

/** The OS scheduler flavor for the platform we are running on. */
export function detectOsKind(
	platform: NodeJS.Platform = process.platform,
): OsSchedulerKind {
	if (platform === "darwin") return "launchd";
	if (platform === "win32") return "schtasks";
	// Linux and friends: prefer systemd user timers (the cron flavor is shown in the preview too).
	return "systemd";
}

/** The machine's IANA timezone — the default when none is configured. */
export function systemTimezone(): string {
	try {
		return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
	} catch {
		return "UTC";
	}
}

/** True when `tz` is an IANA name this Node can resolve. */
export function isValidTimezone(tz: string): boolean {
	try {
		new Intl.DateTimeFormat("en-US", { timeZone: tz });
		return true;
	} catch {
		return false;
	}
}

export function defaultScheduleConfig(): ScheduleConfig {
	return {
		enabled: false,
		cadence: "daily",
		everyHours: 6,
		times: ["06:00"],
		weekdays: [],
		timezone: systemTimezone(),
		domains: "all",
		runner: "in-process",
		os: { kind: detectOsKind(), installed: false, label: DEFAULT_OS_LABEL },
	};
}

function configFile(): string {
	return join(resolveStateDir(), "config.yaml");
}

/**
 * Coerce whatever is in the `schedule:` block into a fully-populated, valid ScheduleConfig.
 * Unknown/invalid values fall back to the defaults rather than throwing — config.yaml is
 * operator-editable.
 */
export function normalizeSchedule(raw: unknown): ScheduleConfig {
	const def = defaultScheduleConfig();
	if (raw == null || typeof raw !== "object") return def;
	const r = raw as Record<string, unknown>;

	const cadence: ScheduleCadence =
		r.cadence === "interval" || r.cadence === "daily" || r.cadence === "weekly"
			? r.cadence
			: def.cadence;

	const everyHoursNum = Number(r.everyHours);
	const everyHours =
		Number.isFinite(everyHoursNum) &&
		everyHoursNum >= 1 &&
		everyHoursNum <= 24 * 7
			? Math.round(everyHoursNum)
			: def.everyHours;

	const times = Array.isArray(r.times)
		? [
				...new Set(
					r.times.filter(
						(t): t is string => typeof t === "string" && HHMM_RE.test(t),
					),
				),
			]
		: [];
	// Daily/weekly require at least one time (acceptance criterion 4).
	const safeTimes = times.length > 0 ? times.sort() : [...def.times];

	const weekdays = Array.isArray(r.weekdays)
		? [
				...new Set(
					r.weekdays
						.map((d) => String(d).toLowerCase().slice(0, 3))
						.filter((d): d is Weekday => (WEEKDAYS as string[]).includes(d)),
				),
			]
		: [];

	const timezone =
		typeof r.timezone === "string" && isValidTimezone(r.timezone)
			? r.timezone
			: def.timezone;

	// "all" | ["<domainId>", …]; an empty selection is treated as "all" (spec: Domains to include).
	let domains: ScheduleConfig["domains"] = "all";
	if (Array.isArray(r.domains)) {
		const ids = r.domains.filter(
			(d): d is string => typeof d === "string" && d.trim() !== "",
		);
		domains = ids.length > 0 ? [...new Set(ids)] : "all";
	}

	const runner: ScheduleRunner = r.runner === "os" ? "os" : "in-process";

	const rawOs = (r.os ?? {}) as Record<string, unknown>;
	const kind: OsSchedulerKind =
		rawOs.kind === "launchd" ||
		rawOs.kind === "cron" ||
		rawOs.kind === "systemd" ||
		rawOs.kind === "schtasks"
			? rawOs.kind
			: detectOsKind();

	return {
		enabled: r.enabled === true,
		cadence,
		everyHours,
		times: safeTimes,
		weekdays,
		timezone,
		domains,
		runner,
		os: {
			kind,
			installed: rawOs.installed === true,
			label:
				typeof rawOs.label === "string" && isSafeOsLabel(rawOs.label.trim())
					? rawOs.label.trim()
					: DEFAULT_OS_LABEL,
		},
	};
}

/** Read the `schedule:` block of config.yaml (normalized; defaults when absent). */
export function readScheduleConfig(): ScheduleConfig {
	const doc = readYaml<Record<string, unknown>>(configFile(), {});
	return normalizeSchedule(doc.schedule);
}

/** Write the `schedule:` block, preserving every other top-level key of config.yaml. */
export function writeScheduleConfig(schedule: ScheduleConfig): void {
	const doc = readYaml<Record<string, unknown>>(configFile(), {});
	writeYaml(configFile(), { ...doc, schedule });
}
