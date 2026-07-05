import { execFile } from "node:child_process";
import { existsSync, mkdirSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { logInfo } from "@shared/logging";
import type {
	OsArtifactPreview,
	ScheduleConfig,
	Weekday,
} from "./schedule.types";
import { WEEKDAYS } from "./schedule.types";

const execFileAsync = promisify(execFile);

/**
 * OS-level schedule artifacts (pm/scheduled_checks.mdx "OS-level scheduling"). Generates, installs
 * and uninstalls the native scheduler entry for the detected platform — a launchd LaunchAgent on
 * macOS, a systemd user timer (with the equivalent crontab shown in the preview) on Linux, and
 * schtasks tasks on Windows. Every artifact simply triggers `POST /api/scheduler/run` on the
 * localhost backend: the Node trigger script (deploy/launchd/trigger-scheduler.mjs) when the repo
 * layout is found, else plain curl exactly as the spec shows.
 */

const API_PORT = Number(process.env.PORT ?? 9312);
const RUN_URL = `http://localhost:${API_PORT}/api/scheduler/run`;

/** launchd Weekday numbers: 0/7 = Sunday, 1 = Monday … */
const LAUNCHD_WEEKDAY: Record<Weekday, number> = {
	sun: 0,
	mon: 1,
	tue: 2,
	wed: 3,
	thu: 4,
	fri: 5,
	sat: 6,
};
/** systemd OnCalendar / cron style day names. */
const SYSTEMD_DAY: Record<Weekday, string> = {
	mon: "Mon",
	tue: "Tue",
	wed: "Wed",
	thu: "Thu",
	fri: "Fri",
	sat: "Sat",
	sun: "Sun",
};
/** cron DOW numbers (0 = Sunday). */
const CRON_DOW: Record<Weekday, number> = LAUNCHD_WEEKDAY;

/**
 * Locate the in-repo Node trigger script by walking up from the compiled module. Works from both
 * src/ (ts-jest) and dist/ layouts; returns null when the app runs outside the repo.
 */
export function findTriggerScript(startDir: string = __dirname): string | null {
	let dir = startDir;
	for (let i = 0; i < 8; i++) {
		const candidate = join(dir, "deploy", "launchd", "trigger-scheduler.mjs");
		if (existsSync(candidate)) return candidate;
		const parent = dirname(dir);
		if (parent === dir) break;
		dir = parent;
	}
	return null;
}

/**
 * The custom header the scheduler-run endpoint requires so it is never a CORS-"simple" request a
 * hostile page could fire cross-origin (security audit finding #9). All OS trigger commands send it.
 */
const TRIGGER_HEADER = "X-EDH-Trigger: os";

function triggerCommand(): string[] {
	const script = findTriggerScript();
	if (script) return [process.execPath, script];
	return ["/usr/bin/curl", "-fsS", "-H", TRIGGER_HEADER, "-X", "POST", RUN_URL];
}

function xmlEscape(s: string): string {
	return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function parsedTimes(cfg: ScheduleConfig): [number, number][] {
	return cfg.times.map((t) => t.split(":").map(Number) as [number, number]);
}

function activeWeekdays(cfg: ScheduleConfig): Weekday[] {
	return cfg.weekdays.length > 0 ? cfg.weekdays : [...WEEKDAYS];
}

/* ---------------------------------------- launchd ---------------------------------------- */

export function launchdPlistPath(label: string): string {
	const agentsDir = join(homedir(), "Library", "LaunchAgents");
	const path = join(agentsDir, `${label}.plist`);
	// Defense-in-depth (security audit finding #2): even though the label is sanitized in the config
	// store, refuse any resolved path that escapes ~/Library/LaunchAgents before we write/load it.
	const resolved = resolve(path);
	if (resolved !== path || !resolved.startsWith(agentsDir + sep)) {
		throw new Error(
			`Refusing launchd label "${label}": resolves outside ~/Library/LaunchAgents`,
		);
	}
	return path;
}

export function renderLaunchdPlist(cfg: ScheduleConfig): string {
	const args = triggerCommand()
		.map((a) => `        <string>${xmlEscape(a)}</string>`)
		.join("\n");

	let scheduleXml: string;
	if (cfg.cadence === "interval") {
		scheduleXml = `    <key>StartInterval</key>\n    <integer>${cfg.everyHours * 3600}</integer>`;
	} else {
		const entries: string[] = [];
		const days = cfg.cadence === "weekly" ? activeWeekdays(cfg) : null;
		for (const [hh, mm] of parsedTimes(cfg)) {
			if (days) {
				for (const day of days) {
					entries.push(
						`        <dict>\n            <key>Weekday</key><integer>${LAUNCHD_WEEKDAY[day]}</integer>\n            <key>Hour</key><integer>${hh}</integer>\n            <key>Minute</key><integer>${mm}</integer>\n        </dict>`,
					);
				}
			} else {
				entries.push(
					`        <dict>\n            <key>Hour</key><integer>${hh}</integer>\n            <key>Minute</key><integer>${mm}</integer>\n        </dict>`,
				);
			}
		}
		scheduleXml = `    <key>StartCalendarInterval</key>\n    <array>\n${entries.join("\n")}\n    </array>`;
	}

	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!--
  EmailDeliveryHero — generated from the Scheduled Checks configuration page.
  Times fire in the machine's local timezone (configured tz: ${xmlEscape(cfg.timezone)}).
  Regenerate from the app after changing the schedule.
-->
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${xmlEscape(cfg.os.label)}</string>

    <key>ProgramArguments</key>
    <array>
${args}
    </array>

    <key>EnvironmentVariables</key>
    <dict>
        <key>API_PORT</key>
        <string>${API_PORT}</string>
    </dict>

${scheduleXml}

    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/tmp/edh.scheduler.out.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/edh.scheduler.err.log</string>
</dict>
</plist>
`;
}

/* ------------------------------------- systemd / cron ------------------------------------- */

const SYSTEMD_UNIT = "edh-scheduler";

export function systemdUserDir(): string {
	return join(homedir(), ".config", "systemd", "user");
}

export function renderSystemdUnits(cfg: ScheduleConfig): {
	service: string;
	timer: string;
} {
	const exec = triggerCommand()
		.map((a) => (a.includes(" ") ? `"${a}"` : a))
		.join(" ");
	const service = `# ${systemdUserDir()}/${SYSTEMD_UNIT}.service — generated by EmailDeliveryHero
[Unit]
Description=EmailDeliveryHero scheduled audit

[Service]
Type=oneshot
Environment=API_PORT=${API_PORT}
ExecStart=${exec}
`;
	let onCalendar: string[];
	if (cfg.cadence === "interval") {
		onCalendar = [`OnCalendar=*-*-* 00/${cfg.everyHours}:00:00`];
	} else {
		const dayPrefix =
			cfg.cadence === "weekly"
				? `${activeWeekdays(cfg)
						.map((d) => SYSTEMD_DAY[d])
						.join(",")} `
				: "";
		onCalendar = cfg.times.map((t) => `OnCalendar=${dayPrefix}*-*-* ${t}:00`);
	}
	const timer = `# ${systemdUserDir()}/${SYSTEMD_UNIT}.timer — generated by EmailDeliveryHero
[Unit]
Description=Run EmailDeliveryHero audit (${cfg.cadence})

[Timer]
${onCalendar.join("\n")}
Persistent=true

[Install]
WantedBy=timers.target
`;
	return { service, timer };
}

/** The equivalent crontab lines — shown in the Linux preview alongside the systemd units. */
export function renderCrontab(cfg: ScheduleConfig): string {
	const cmd = `curl -fsS -H "${TRIGGER_HEADER}" -X POST ${RUN_URL} >> /tmp/edh.cron.log 2>&1`;
	if (cfg.cadence === "interval")
		return `0 */${cfg.everyHours} * * *  ${cmd}\n`;
	const dow =
		cfg.cadence === "weekly"
			? activeWeekdays(cfg)
					.map((d) => CRON_DOW[d])
					.join(",")
			: "*";
	return `${parsedTimes(cfg)
		.map(([hh, mm]) => `${mm} ${hh} * * ${dow}  ${cmd}`)
		.join("\n")}\n`;
}

/* ---------------------------------------- schtasks ---------------------------------------- */

/** schtasks /D day codes. */
const SCHTASKS_DAY: Record<Weekday, string> = {
	mon: "MON",
	tue: "TUE",
	wed: "WED",
	thu: "THU",
	fri: "FRI",
	sat: "SAT",
	sun: "SUN",
};

function schtasksTaskNames(cfg: ScheduleConfig): string[] {
	if (cfg.cadence === "interval") return ["EmailDeliveryHero Audit"];
	return cfg.times.map((t) => `EmailDeliveryHero Audit ${t.replace(":", "")}`);
}

export function schtasksCommands(cfg: ScheduleConfig): string[][] {
	const tr = `curl.exe -fsS -H "${TRIGGER_HEADER}" -X POST ${RUN_URL}`;
	if (cfg.cadence === "interval") {
		return [
			[
				"schtasks",
				"/Create",
				"/TN",
				"EmailDeliveryHero Audit",
				"/SC",
				"HOURLY",
				"/MO",
				String(cfg.everyHours),
				"/F",
				"/TR",
				tr,
			],
		];
	}
	const weekly = cfg.cadence === "weekly";
	const days = activeWeekdays(cfg)
		.map((d) => SCHTASKS_DAY[d])
		.join(",");
	return cfg.times.map((t) => {
		const base = [
			"schtasks",
			"/Create",
			"/TN",
			`EmailDeliveryHero Audit ${t.replace(":", "")}`,
			"/SC",
			weekly ? "WEEKLY" : "DAILY",
		];
		if (weekly) base.push("/D", days);
		base.push("/ST", t, "/F", "/TR", tr);
		return base;
	});
}

/* ---------------------------------------- facade ---------------------------------------- */

/**
 * Whether the native schedule artifact ACTUALLY exists on THIS machine. The persisted
 * `cfg.os.installed` flag only records installs done through the API — `just build` /
 * `just install-agent` write the same launchd plist directly, and state synced from another
 * computer can say either value. Disk is the source of truth wherever we can check it
 * (launchd/systemd); the flag remains the fallback for schtasks.
 */
export function artifactInstalled(cfg: ScheduleConfig): boolean {
	const kind = cfg.os.kind;
	if (kind === "launchd") return existsSync(launchdPlistPath(cfg.os.label));
	if (kind === "systemd" || kind === "cron")
		return existsSync(join(systemdUserDir(), `${SYSTEMD_UNIT}.timer`));
	return cfg.os.installed;
}

/** Render the artifact for the configured OS kind, without touching the system. */
export function previewArtifact(cfg: ScheduleConfig): OsArtifactPreview {
	const kind = cfg.os.kind;
	if (kind === "launchd") {
		return {
			kind,
			path: launchdPlistPath(cfg.os.label),
			content: renderLaunchdPlist(cfg),
			installed: artifactInstalled(cfg),
		};
	}
	if (kind === "systemd" || kind === "cron") {
		const { service, timer } = renderSystemdUnits(cfg);
		const content = `${service}\n${timer}\n# Equivalent crontab (crontab -e):\n${renderCrontab(cfg)}`;
		return {
			kind,
			path: join(systemdUserDir(), `${SYSTEMD_UNIT}.timer`),
			content,
			installed: artifactInstalled(cfg),
		};
	}
	// schtasks: the "artifact" is the command set.
	const content = `${schtasksCommands(cfg)
		.map((c) => c.map((a) => (a.includes(" ") ? `"${a}"` : a)).join(" "))
		.join("\n")}\n`;
	return {
		kind,
		path: `Task Scheduler: ${schtasksTaskNames(cfg).join(", ")}`,
		content,
		installed: cfg.os.installed,
	};
}

/** Write + load the artifact for the current platform. Throws with a readable message on failure. */
export async function installArtifact(cfg: ScheduleConfig): Promise<void> {
	const kind = cfg.os.kind;
	if (kind === "launchd") {
		const path = launchdPlistPath(cfg.os.label);
		mkdirSync(dirname(path), { recursive: true });
		writeFileSync(path, renderLaunchdPlist(cfg), "utf8");
		// Reload cleanly: unload is best-effort (fails when not yet loaded), load -w must succeed.
		await execFileAsync("launchctl", ["unload", path]).catch(() => {});
		await execFileAsync("launchctl", ["load", "-w", path]);
		logInfo(`Installed launchd agent ${cfg.os.label} (${path})`, "Scheduler");
		return;
	}
	if (kind === "systemd" || kind === "cron") {
		const dir = systemdUserDir();
		mkdirSync(dir, { recursive: true });
		const { service, timer } = renderSystemdUnits(cfg);
		writeFileSync(join(dir, `${SYSTEMD_UNIT}.service`), service, "utf8");
		writeFileSync(join(dir, `${SYSTEMD_UNIT}.timer`), timer, "utf8");
		await execFileAsync("systemctl", ["--user", "daemon-reload"]);
		await execFileAsync("systemctl", [
			"--user",
			"enable",
			"--now",
			`${SYSTEMD_UNIT}.timer`,
		]);
		logInfo(`Installed systemd user timer ${SYSTEMD_UNIT}.timer`, "Scheduler");
		return;
	}
	for (const [bin, ...args] of schtasksCommands(cfg)) {
		await execFileAsync(bin, args);
	}
	logInfo(
		`Installed schtasks task(s): ${schtasksTaskNames(cfg).join(", ")}`,
		"Scheduler",
	);
}

/** Unload + remove the artifact. Best-effort: a partially-removed artifact never throws. */
export async function uninstallArtifact(cfg: ScheduleConfig): Promise<void> {
	const kind = cfg.os.kind;
	if (kind === "launchd") {
		const path = launchdPlistPath(cfg.os.label);
		await execFileAsync("launchctl", ["unload", path]).catch(() => {});
		try {
			if (existsSync(path)) unlinkSync(path);
		} catch {
			/* best-effort */
		}
		logInfo(`Removed launchd agent ${cfg.os.label}`, "Scheduler");
		return;
	}
	if (kind === "systemd" || kind === "cron") {
		await execFileAsync("systemctl", [
			"--user",
			"disable",
			"--now",
			`${SYSTEMD_UNIT}.timer`,
		]).catch(() => {});
		for (const f of [`${SYSTEMD_UNIT}.service`, `${SYSTEMD_UNIT}.timer`]) {
			try {
				const p = join(systemdUserDir(), f);
				if (existsSync(p)) unlinkSync(p);
			} catch {
				/* best-effort */
			}
		}
		await execFileAsync("systemctl", ["--user", "daemon-reload"]).catch(
			() => {},
		);
		logInfo(`Removed systemd user timer ${SYSTEMD_UNIT}.timer`, "Scheduler");
		return;
	}
	for (const name of schtasksTaskNames(cfg)) {
		await execFileAsync("schtasks", ["/Delete", "/TN", name, "/F"]).catch(
			() => {},
		);
	}
	logInfo("Removed schtasks task(s)", "Scheduler");
}
