/**
 * Scheduled-checks config model (pm/scheduled_checks.mdx "Schedule config model"). The schedule
 * lives as the `schedule:` block of the on-disk config.yaml under the state dir and is edited by
 * the dashboard toggle and the Scheduled Checks configuration page.
 */

export type ScheduleCadence = "interval" | "daily" | "weekly"

export type ScheduleRunner = "in-process" | "os"

export type Weekday = "mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun"

export const WEEKDAYS: Weekday[] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]

/** The OS-native scheduler flavors we can generate artifacts for. */
export type OsSchedulerKind = "launchd" | "cron" | "systemd" | "schtasks"

export interface ScheduleOsState {
  /** Detected for the current platform: launchd (macOS), cron/systemd (Linux), schtasks (Windows). */
  kind: OsSchedulerKind
  /** Whether the OS artifact is currently installed. */
  installed: boolean
  /** launchd label / systemd unit base / schtasks task-name prefix. */
  label: string
}

export interface ScheduleConfig {
  /** The dashboard toggle / single on-off switch for the whole scheduling feature. */
  enabled: boolean
  /** "interval" (every N hours) | "daily" | "weekly". */
  cadence: ScheduleCadence
  /** Used only when cadence: interval. */
  everyHours: number
  /** "HH:MM" wall-clock times — used by daily/weekly; supports multiple per day. */
  times: string[]
  /** Used only when cadence: weekly. Empty = every day. */
  weekdays: Weekday[]
  /** IANA tz the times are interpreted in; defaults to the system timezone. */
  timezone: string
  /** "all" monitored domains, or an explicit subset of domain ids. Empty subset = "all". */
  domains: "all" | string[]
  /** Which scheduling layer is active: the in-process interval job or the OS-level scheduler. */
  runner: ScheduleRunner
  os: ScheduleOsState
}

/** What fired a scheduled run (recorded as scheduler telemetry). */
export type RunTrigger = "in-process" | "os" | "manual"

/** GET /api/scheduler payload (pm/scheduled_checks.mdx criterion 12 + pm/settings.mdx §3.3). */
export interface SchedulerStatus {
  enabled: boolean
  runner: ScheduleRunner
  cadence: ScheduleCadence
  /** The configured "HH:MM" slots — surfaced so the Settings §3 status block needs one GET. */
  times: string[]
  weekdays: Weekday[]
  nextRunAt: string | null
  lastRunAt: string | null
  lastTrigger: RunTrigger | null
  /** True while a scheduled run is in flight. */
  running: boolean
  /** How many monitored domains a scheduled run covers right now (global AND per-domain switch). */
  domainsCovered: number
  domainsTotal: number
  os: ScheduleOsState
}

/**
 * POST /api/scheduler/run outcome (pm/settings.mdx §3.3). The endpoint honors the master switch:
 * when scheduling is off it SKIPS (`started: false`) unless the body forces it, and a scheduled
 * trigger that lands within the dedupe window of the previous run is also skipped — that is what
 * lets the launchd agent stay installed while the toggle is off, and lets both scheduling layers
 * coexist without double-running.
 */
export interface SchedulerRunOutcome {
  started: boolean
  reason?: "disabled" | "already_running" | "recently_ran"
  /** How many domains the run covered (present when started). */
  domains?: number
}

/** GET /api/scheduler/os/preview payload — the generated OS artifact, before installing. */
export interface OsArtifactPreview {
  kind: OsSchedulerKind
  /** Where the artifact is (or would be) installed. */
  path: string
  /** The rendered artifact (plist XML / systemd units / schtasks commands). */
  content: string
  installed: boolean
}
