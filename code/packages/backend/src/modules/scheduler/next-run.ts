import { type ScheduleConfig, WEEKDAYS, type Weekday } from "./schedule.types"
import { isValidTimezone, systemTimezone } from "./schedule-config.store"

/**
 * Next-run computation (pm/scheduled_checks.mdx acceptance criterion 5: scheduled runs fire in the
 * configured IANA timezone). Pure functions over Date + Intl — no timers here; the service arms a
 * setTimeout against the instant this returns.
 */

const DAY_MS = 24 * 60 * 60 * 1000

/** Milliseconds the zone is ahead of UTC at instant `ts` (DST-aware, via Intl). */
function tzOffsetMs(ts: number, timeZone: string): number {
  const dtf = new Intl.DateTimeFormat("en-US", {
    timeZone,
    hour12: false,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })
  const parts: Record<string, number> = {}
  for (const p of dtf.formatToParts(new Date(ts))) {
    if (p.type !== "literal") parts[p.type] = Number(p.value)
  }
  // Intl can render midnight as hour 24 — normalize.
  const hour = parts.hour === 24 ? 0 : parts.hour
  const asUtc = Date.UTC(parts.year, parts.month - 1, parts.day, hour, parts.minute, parts.second)
  return asUtc - Math.floor(ts / 1000) * 1000
}

/** The UTC instant of the wall-clock time y-m-d hh:mm in `timeZone`. */
function zonedTimeToUtc(
  y: number,
  m: number,
  d: number,
  hh: number,
  mm: number,
  timeZone: string,
): Date {
  // Guess the instant as if the wall time were UTC, then correct by the zone offset at the guess.
  // Two passes converge across DST transitions.
  let ts = Date.UTC(y, m - 1, d, hh, mm, 0)
  for (let i = 0; i < 2; i++) {
    ts = Date.UTC(y, m - 1, d, hh, mm, 0) - tzOffsetMs(ts, timeZone)
  }
  return new Date(ts)
}

/** The wall-clock calendar date of instant `at` in `timeZone`. */
function zonedDateParts(at: Date, timeZone: string): { y: number; m: number; d: number } {
  const dtf = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  })
  const [y, m, d] = dtf.format(at).split("-").map(Number)
  return { y, m, d }
}

/** Weekday ("mon"…"sun") of the calendar date y-m-d. */
function weekdayOf(y: number, m: number, d: number): Weekday {
  // getUTCDay: 0 = Sunday … 6 = Saturday; WEEKDAYS starts at "mon".
  const dow = new Date(Date.UTC(y, m - 1, d)).getUTCDay()
  return WEEKDAYS[(dow + 6) % 7]
}

/**
 * The next instant the schedule should fire strictly after `from` (ISO string), or null when the
 * schedule is disabled. `lastRunAt` anchors the interval cadence so restarts don't reset the clock.
 */
export function computeNextRun(
  cfg: ScheduleConfig,
  from: Date = new Date(),
  lastRunAt: string | null = null,
): string | null {
  if (!cfg.enabled) return null

  if (cfg.cadence === "interval") {
    const stepMs = cfg.everyHours * 60 * 60 * 1000
    const last = lastRunAt ? Date.parse(lastRunAt) : Number.NaN
    let next = Number.isFinite(last) ? last + stepMs : from.getTime() + stepMs
    // If the anchor is far in the past (machine was off), fire one step from now, not a backlog.
    if (next <= from.getTime()) next = from.getTime() + stepMs
    return new Date(next).toISOString()
  }

  const tz = isValidTimezone(cfg.timezone) ? cfg.timezone : systemTimezone()
  const times = cfg.times
    .map((t) => t.split(":").map(Number) as [number, number])
    .sort((a, b) => a[0] * 60 + a[1] - (b[0] * 60 + b[1]))
  if (times.length === 0) return null
  // Weekly with no weekdays selected behaves like daily (normalization treats empty as every day).
  const days: Weekday[] =
    cfg.cadence === "weekly" && cfg.weekdays.length > 0 ? cfg.weekdays : WEEKDAYS

  // Scan today + the next 8 calendar days in the target tz — always finds a weekly slot.
  for (let offset = 0; offset <= 8; offset++) {
    const { y, m, d } = zonedDateParts(new Date(from.getTime() + offset * DAY_MS), tz)
    if (!days.includes(weekdayOf(y, m, d))) continue
    for (const [hh, mm] of times) {
      const candidate = zonedTimeToUtc(y, m, d, hh, mm, tz)
      if (candidate.getTime() > from.getTime()) return candidate.toISOString()
    }
  }
  return null
}
