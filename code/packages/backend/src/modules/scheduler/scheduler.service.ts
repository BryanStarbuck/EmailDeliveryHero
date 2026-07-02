import { join } from "node:path";
import type { AuditService } from "@module/audit/audit.service";
import type { AuditTrigger } from "@module/audit/checks/types";
import type { DomainsService } from "@module/domains/domains.service";
import {
	Injectable,
	type OnModuleDestroy,
	type OnModuleInit,
} from "@nestjs/common";
import { mapLimit } from "@shared/concurrency";
import { readJson, writeJson } from "@shared/json-store";
import { logError, logInfo } from "@shared/logging";
import { resolveStateDir } from "@shared/state-dir";
import { computeNextRun } from "./next-run";
import {
	artifactInstalled,
	installArtifact,
	previewArtifact,
	uninstallArtifact,
} from "./os-artifact";
import type {
	OsArtifactPreview,
	RunTrigger,
	ScheduleConfig,
	SchedulerRunOutcome,
	SchedulerStatus,
} from "./schedule.types";
import {
	normalizeSchedule,
	readScheduleConfig,
	writeScheduleConfig,
} from "./schedule-config.store";

/** How many domains a scheduled run audits concurrently (matches AuditService's manual path). */
const SCHEDULED_RUN_CONCURRENCY = 4;

/**
 * A scheduled trigger landing within this window of the previous run is a duplicate, not a new
 * slot (pm/settings.mdx §3.3): the in-process timer and the OS-level agent can both fire around
 * the same configured time, and launchd replays missed slots after wake.
 */
const DEDUPE_WINDOW_MS = 5 * 60 * 1000;

/** Scheduler telemetry persisted across restarts (lastRunAt survives a backend reboot). */
interface SchedulerState {
	lastRunAt: string | null;
	lastTrigger: RunTrigger | null;
}

/**
 * The scheduled-checks service (pm/scheduled_checks.mdx). Owns the `schedule:` block of
 * config.yaml, runs the IN-PROCESS scheduling layer (a timer armed to the next tz-aware slot;
 * fires only while the backend runs), and manages the OS-LEVEL layer's native artifact
 * (launchd / cron / systemd / schtasks) so audits can fire even when the app is closed. Exactly
 * one layer is active at a time (`runner`); both trigger the very same audit engine a manual
 * "Run checks" uses.
 */
@Injectable()
export class SchedulerService implements OnModuleInit, OnModuleDestroy {
	private readonly stateFile = join(resolveStateDir(), "scheduler-state.json");
	private timer: NodeJS.Timeout | null = null;
	/** Guard so overlapping triggers (timer + POST /run) never run two audits at once. */
	private running = false;

	constructor(
		private readonly audit: AuditService,
		private readonly domains: DomainsService,
	) {}

	onModuleInit(): void {
		const cfg = this.getConfig();
		if (cfg.enabled) {
			logInfo(
				`Scheduled checks enabled (${cfg.cadence}, runner: ${cfg.runner})`,
				"Scheduler",
			);
		} else {
			logInfo(
				"Scheduled checks disabled (turn on from the dashboard toggle)",
				"Scheduler",
			);
		}
		this.rearm(cfg);
	}

	onModuleDestroy(): void {
		this.disarm();
	}

	/* ------------------------------------ config ------------------------------------ */

	getConfig(): ScheduleConfig {
		return readScheduleConfig();
	}

	/**
	 * PUT /api/scheduler/config — merge + persist the schedule block, (re)start or stop the
	 * in-process job, and, when the OS layer is active and installed, regenerate the artifact so
	 * the native schedule matches the saved config.
	 */
	async updateConfig(patch: Record<string, unknown>): Promise<ScheduleConfig> {
		const current = this.getConfig();
		// Merge over the current block so the dashboard toggle can PUT { enabled } alone.
		const merged = normalizeSchedule({
			...(current as unknown as Record<string, unknown>),
			...patch,
			os: {
				...current.os,
				...((patch.os as Record<string, unknown> | undefined) ?? {}),
			},
		});
		writeScheduleConfig(merged);
		logInfo(
			`Schedule config saved (enabled: ${merged.enabled}, cadence: ${merged.cadence}, runner: ${merged.runner})`,
			"Scheduler",
		);
		this.rearm(merged);
		if (merged.runner === "os" && merged.os.installed) {
			// Keep the installed native schedule in sync with what was just saved.
			try {
				await installArtifact(merged);
			} catch (err) {
				logError(
					"Could not regenerate the OS-level schedule after save",
					err,
					"Scheduler",
				);
			}
		}
		return merged;
	}

	/* ------------------------------------ status ------------------------------------ */

	/**
	 * GET /api/scheduler — everything the dashboard toggle and the Settings §3 status block need in
	 * one read: the switch + slots, computed next run, last-run telemetry, coverage, OS install.
	 */
	status(): SchedulerStatus {
		const cfg = this.getConfig();
		const state = this.loadState();
		const all = this.domains.list();
		return {
			enabled: cfg.enabled,
			runner: cfg.runner,
			cadence: cfg.cadence,
			times: cfg.times,
			weekdays: cfg.weekdays,
			nextRunAt: computeNextRun(cfg, new Date(), state.lastRunAt),
			lastRunAt: state.lastRunAt,
			lastTrigger: state.lastTrigger,
			running: this.running,
			domainsCovered: this.scopedDomains(cfg).length,
			domainsTotal: all.length,
			// Report the artifact's ACTUAL on-disk presence on this machine, not the persisted flag —
			// `just build` installs the launchd plist outside the API, and state files synced between
			// computers can carry the other machine's value.
			os: { ...cfg.os, installed: artifactInstalled(cfg) },
		};
	}

	/* ------------------------------------- runs ------------------------------------- */

	/**
	 * POST /api/scheduler/run — trigger a scheduled audit NOW for the configured scope
	 * ("all" monitored domains or the selected subset, ANDed with each domain's own
	 * scheduleEnabled flag per pm/domains.mdx §6). This is what the OS-level artifacts call.
	 *
	 * It honors the master switch (pm/settings.mdx §3.3): scheduling defaults OFF, and the launchd
	 * agent is installed by `just build` regardless — so a trigger while `enabled: false` must be a
	 * clean no-op, not a surprise audit. `force: true` (the Settings tab's "Run a scheduled check
	 * now") bypasses the switch AND the dedupe so the user can preview what a scheduled run does.
	 */
	async runNow(
		trigger: RunTrigger = "manual",
		force = false,
	): Promise<SchedulerRunOutcome> {
		const cfg = this.getConfig();
		if (!cfg.enabled && !force) {
			logInfo(
				`Scheduled run skipped — scheduling is off (${trigger})`,
				"Scheduler",
			);
			return { started: false, reason: "disabled" };
		}
		if (this.running) {
			logInfo(
				`Scheduled run skipped — a run is already in progress (${trigger})`,
				"Scheduler",
			);
			return { started: false, reason: "already_running" };
		}
		// Dedupe: the in-process timer and the OS agent may both fire at the same configured slot.
		if (!force) {
			const last = Date.parse(this.loadState().lastRunAt ?? "");
			if (Number.isFinite(last) && Date.now() - last < DEDUPE_WINDOW_MS) {
				logInfo(
					`Scheduled run skipped — last run was under 5 minutes ago (${trigger})`,
					"Scheduler",
				);
				return { started: false, reason: "recently_ran" };
			}
		}
		this.running = true;
		try {
			const included = this.scopedDomains(cfg);
			logInfo(
				`Scheduled check run started (${trigger}; ${included.length}/${this.domains.list().length} domain(s))`,
				"Scheduler",
			);
			// The audit-record trigger tag (pm/run_checks.mdx §1/§9): who asked — data only, the same
			// runForDomain runs regardless. "manual" here is the Settings tab's "Run a scheduled check
			// now" button hitting POST /api/scheduler/run by hand.
			const auditTrigger: AuditTrigger =
				trigger === "os"
					? "scheduled-os"
					: trigger === "in-process"
						? "scheduled-inprocess"
						: "manual";
			const results = await mapLimit(included, SCHEDULED_RUN_CONCURRENCY, (d) =>
				this.audit.runForDomain(d.id, auditTrigger),
			);
			this.saveState({
				lastRunAt: new Date().toISOString(),
				lastTrigger: trigger,
			});
			logInfo(
				`Scheduled check run finished (${results.length} domain(s))`,
				"Scheduler",
			);
			return { started: true, domains: results.length };
		} finally {
			this.running = false;
			// A completed run moves the next slot forward — re-arm against the fresh lastRunAt.
			this.rearm(this.getConfig());
		}
	}

	/** The domains a scheduled run covers: the configured scope AND each domain's own switch. */
	private scopedDomains(cfg: ScheduleConfig) {
		const all = this.domains.list();
		const scoped =
			cfg.domains === "all"
				? all
				: all.filter((d) => (cfg.domains as string[]).includes(d.id));
		return scoped.filter((d) => d.scheduleEnabled);
	}

	/* --------------------------------- OS-level layer --------------------------------- */

	/** GET /api/scheduler/os/preview — the rendered native artifact for the detected OS. */
	preview(): OsArtifactPreview {
		return previewArtifact(this.getConfig());
	}

	/** POST /api/scheduler/os/install — write + load the native schedule; marks os.installed. */
	async install(): Promise<ScheduleConfig> {
		const cfg = this.getConfig();
		await installArtifact(cfg);
		const next = { ...cfg, os: { ...cfg.os, installed: true } };
		writeScheduleConfig(next);
		return next;
	}

	/** POST /api/scheduler/os/uninstall — unload + remove the native schedule. */
	async uninstall(): Promise<ScheduleConfig> {
		const cfg = this.getConfig();
		await uninstallArtifact(cfg);
		const next = { ...cfg, os: { ...cfg.os, installed: false } };
		writeScheduleConfig(next);
		return next;
	}

	/* --------------------------------- in-process layer --------------------------------- */

	private disarm(): void {
		if (this.timer) clearTimeout(this.timer);
		this.timer = null;
	}

	/**
	 * Arm (or stop) the in-process timer to the next tz-aware slot. Only the "in-process" runner
	 * keeps a live timer — with `runner: os` the OS artifact does the firing (exactly one layer
	 * active at a time, acceptance criterion 10).
	 */
	private rearm(cfg: ScheduleConfig): void {
		this.disarm();
		if (!cfg.enabled || cfg.runner !== "in-process") return;
		const nextIso = computeNextRun(cfg, new Date(), this.loadState().lastRunAt);
		if (!nextIso) return;
		// Chunk long waits below the 32-bit setTimeout ceiling; re-check the slot at each hop so a
		// config change mid-wait (rearm already ran) or clock drift never fires stale.
		const MAX_CHUNK = 2 ** 31 - 1;
		const delay = Math.max(0, Date.parse(nextIso) - Date.now());
		this.timer = setTimeout(
			() => {
				if (delay > MAX_CHUNK) {
					this.rearm(this.getConfig());
					return;
				}
				this.runNow("in-process").catch((err) =>
					logError("Scheduled check run failed", err, "Scheduler"),
				);
			},
			Math.min(delay, MAX_CHUNK),
		);
		// Don't keep the event loop alive solely for the schedule.
		this.timer.unref?.();
		logInfo(`Next scheduled run armed for ${nextIso}`, "Scheduler");
	}

	/* ------------------------------------ telemetry ------------------------------------ */

	private loadState(): SchedulerState {
		return readJson<SchedulerState>(this.stateFile, {
			lastRunAt: null,
			lastTrigger: null,
		});
	}

	private saveState(state: SchedulerState): void {
		writeJson(this.stateFile, state);
	}
}
