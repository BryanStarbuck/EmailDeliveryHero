import { Link, useNavigate } from "@tanstack/react-router"
import { ArrowLeft, Loader2, Minus, Plus } from "lucide-react"
import { useEffect, useMemo, useState } from "react"
import { toast } from "sonner"
import { useDomains } from "@/api/domains"
import {
  fetchOsPreview,
  type OsArtifactPreview,
  type OsSchedulerKind,
  type ScheduleCadence,
  type ScheduleConfig,
  type ScheduleRunner,
  useInstallOsSchedule,
  useSaveScheduleConfig,
  useScheduleConfig,
  useSchedulerStatus,
  useUninstallOsSchedule,
  type Weekday,
} from "@/api/scheduler"

/**
 * The Scheduled Checks configuration page (pm/scheduled_checks.mdx "The configuration page").
 * Reached from the dashboard chevron next to the scheduled-checks toggle. Edits the `schedule:`
 * block of config.yaml through GET/PUT /api/scheduler/config: the on/off flag (mirrored from the
 * dashboard toggle) with the computed Next run, the cadence (every N hours / daily / weekly with
 * weekday selection), one or more times of day, the IANA timezone, the domain scope (all vs a
 * selected subset), and the scheduling layer — in-process only, or an OS-level schedule
 * (launchd / cron+systemd / schtasks) with Preview, Install / Update, and Uninstall actions.
 */

const WEEKDAY_ORDER: { key: Weekday; label: string }[] = [
  { key: "mon", label: "Mon" },
  { key: "tue", label: "Tue" },
  { key: "wed", label: "Wed" },
  { key: "thu", label: "Thu" },
  { key: "fri", label: "Fri" },
  { key: "sat", label: "Sat" },
  { key: "sun", label: "Sun" },
]

/** Human name for the detected OS scheduler flavor (pm/scheduled_checks.mdx "Detected OS"). */
const OS_KIND_LABEL: Record<OsSchedulerKind, { os: string; artifact: string }> = {
  launchd: { os: "macOS", artifact: "launchd LaunchAgent" },
  systemd: { os: "Linux", artifact: "systemd user timer (crontab shown in the preview)" },
  cron: { os: "Linux", artifact: "cron / systemd timer" },
  schtasks: { os: "Windows", artifact: "Task Scheduler (schtasks)" },
}

/** The machine's IANA timezone — the default when none is configured. */
function systemTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC"
  } catch {
    return "UTC"
  }
}

/** IANA zone names for the timezone datalist (graceful when Intl lacks supportedValuesOf). */
function timezoneOptions(): string[] {
  try {
    return Intl.supportedValuesOf("timeZone")
  } catch {
    return [systemTimezone(), "UTC"]
  }
}

function fmtNextRun(iso: string | null | undefined): string {
  if (!iso) return "—"
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return "—"
  return d.toLocaleString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })
}

/** A time-of-day row with a stable client-side id (so add/remove never reuses React keys). */
interface TimeRow {
  id: string
  value: string
}

let timeRowSeq = 0
function timeRow(value: string): TimeRow {
  timeRowSeq += 1
  return { id: `t${timeRowSeq}`, value }
}

/** The editable draft — ScheduleConfig with the domain scope split for the radio + checkbox UI. */
interface Draft {
  enabled: boolean
  cadence: ScheduleCadence
  everyHours: number
  times: TimeRow[]
  weekdays: Weekday[]
  timezone: string
  scopeAll: boolean
  selectedDomains: string[]
  runner: ScheduleRunner
}

function toDraft(cfg: ScheduleConfig): Draft {
  return {
    enabled: cfg.enabled,
    cadence: cfg.cadence,
    everyHours: cfg.everyHours,
    times: (cfg.times.length > 0 ? cfg.times : ["06:00"]).map(timeRow),
    weekdays: [...cfg.weekdays],
    timezone: cfg.timezone || systemTimezone(),
    scopeAll: cfg.domains === "all",
    selectedDomains: cfg.domains === "all" ? [] : [...cfg.domains],
    runner: cfg.runner,
  }
}

function fromDraft(draft: Draft): Partial<ScheduleConfig> {
  return {
    enabled: draft.enabled,
    cadence: draft.cadence,
    everyHours: draft.everyHours,
    times: draft.times.map((t) => t.value).filter((v) => v !== ""),
    weekdays: draft.weekdays,
    timezone: draft.timezone,
    // Empty selection is treated as "all" (pm/scheduled_checks.mdx "Domains to include").
    domains: draft.scopeAll || draft.selectedDomains.length === 0 ? "all" : draft.selectedDomains,
    runner: draft.runner,
  }
}

export function ScheduledChecksPage() {
  const navigate = useNavigate()
  const config = useScheduleConfig()
  const status = useSchedulerStatus()
  const { data: domains } = useDomains()
  const save = useSaveScheduleConfig()
  const install = useInstallOsSchedule()
  const uninstall = useUninstallOsSchedule()

  const [draft, setDraft] = useState<Draft | null>(null)
  const [preview, setPreview] = useState<OsArtifactPreview | null>(null)
  const [previewLoading, setPreviewLoading] = useState(false)

  // Seed the editable draft from the persisted block once it arrives (later refetches — e.g. after
  // install/uninstall — must not clobber in-progress edits).
  useEffect(() => {
    if (config.data && draft === null) setDraft(toDraft(config.data))
  }, [config.data, draft])

  const tzOptions = useMemo(timezoneOptions, [])

  if (config.isLoading || !draft) {
    return (
      <div className="mx-auto max-w-3xl">
        <div className="h-8 w-72 animate-pulse rounded-md bg-slate-100" />
        <div className="mt-6 space-y-3">
          {["a", "b", "c", "d"].map((k) => (
            <div key={k} className="h-24 animate-pulse rounded-lg bg-slate-100" />
          ))}
        </div>
      </div>
    )
  }

  const os = config.data?.os ?? { kind: "launchd" as OsSchedulerKind, installed: false, label: "" }
  const osLabel = OS_KIND_LABEL[os.kind]
  const needsTimes = draft.cadence !== "interval"
  const timesInvalid = needsTimes && draft.times.every((t) => t.value === "")
  const canSave = !timesInvalid && !save.isPending

  const set = (patch: Partial<Draft>) => setDraft((d) => (d ? { ...d, ...patch } : d))

  const onSave = async () => {
    try {
      await save.mutateAsync(fromDraft(draft))
      toast.success("Schedule saved", {
        description:
          draft.runner === "os" && os.installed
            ? "The installed OS-level schedule was regenerated to match."
            : undefined,
      })
    } catch {
      toast.error("Could not save the schedule")
    }
  }

  const onPreview = async () => {
    setPreviewLoading(true)
    try {
      // Persist the draft first so the rendered artifact reflects what is on screen.
      await save.mutateAsync(fromDraft(draft))
      setPreview(await fetchOsPreview())
    } catch {
      toast.error("Could not render the OS-level schedule preview")
    } finally {
      setPreviewLoading(false)
    }
  }

  const onInstall = async () => {
    try {
      // Save first so the artifact is generated from the on-screen config (spec: "Save also
      // regenerates the artifact so the installed schedule matches the config").
      await save.mutateAsync(fromDraft({ ...draft, runner: "os" }))
      await install.mutateAsync()
      set({ runner: "os" })
      toast.success("OS-level schedule installed", { description: os.label })
    } catch {
      toast.error("Could not install the OS-level schedule")
    }
  }

  const onUninstall = async () => {
    try {
      await uninstall.mutateAsync()
      toast.success("OS-level schedule removed")
    } catch {
      toast.error("Could not remove the OS-level schedule")
    }
  }

  return (
    <div className="mx-auto max-w-3xl">
      <header className="mb-6 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <Link
            to="/"
            aria-label="Back to the dashboard"
            className="inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
          >
            <ArrowLeft className="h-4 w-4" /> Dashboard
          </Link>
          <h1 className="text-2xl font-bold">Scheduled Checks — Configuration</h1>
        </div>
        <button
          type="button"
          onClick={onSave}
          disabled={!canSave}
          className="rounded-md bg-[var(--edh-primary)] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
        >
          {save.isPending ? "Saving…" : "Save"}
        </button>
      </header>

      {/* On/off — the same schedule.enabled flag as the dashboard toggle, plus the next run. */}
      <Section>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="font-semibold">Scheduled checks</span>
            <button
              type="button"
              role="switch"
              aria-checked={draft.enabled}
              aria-label="Toggle scheduled checks"
              onClick={() => set({ enabled: !draft.enabled })}
              className={`relative h-5 w-9 rounded-full transition-colors ${draft.enabled ? "bg-[var(--edh-primary)]" : "bg-slate-300"}`}
            >
              <span
                className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${draft.enabled ? "left-4" : "left-0.5"}`}
              />
            </button>
            <span className="text-sm text-[var(--edh-muted)]">{draft.enabled ? "ON" : "OFF"}</span>
          </div>
          <span className="text-sm text-[var(--edh-muted)]">
            Next run:{" "}
            <span className="font-medium text-slate-700">{fmtNextRun(status.data?.nextRunAt)}</span>
          </span>
        </div>
        <p className="mt-2 text-xs text-[var(--edh-muted)]">
          Turning the schedule off never disables the manual Run checks button on the dashboard.
        </p>
      </Section>

      {/* Frequency — interval / daily / weekly. */}
      <Section title="Frequency">
        <label className="flex items-center gap-2 py-1 text-sm">
          <input
            type="radio"
            name="cadence"
            checked={draft.cadence === "interval"}
            onChange={() => set({ cadence: "interval" })}
          />
          <span className="w-28">Every N hours</span>
          <span className="inline-flex items-center gap-1 text-[var(--edh-muted)]">
            Every
            <input
              type="number"
              min={1}
              max={168}
              value={draft.everyHours}
              disabled={draft.cadence !== "interval"}
              onChange={(e) =>
                set({ everyHours: Math.max(1, Math.min(168, Number(e.target.value) || 1)) })
              }
              aria-label="Run every this many hours"
              className="w-16 rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm disabled:opacity-50"
            />
            hours
          </span>
        </label>
        <label className="flex items-center gap-2 py-1 text-sm">
          <input
            type="radio"
            name="cadence"
            checked={draft.cadence === "daily"}
            onChange={() => set({ cadence: "daily" })}
          />
          <span className="w-28">Daily</span>
          <span className="text-[var(--edh-muted)]">at the time(s) below</span>
        </label>
        <div className="flex items-center gap-2 py-1 text-sm">
          <input
            type="radio"
            name="cadence"
            id="cadence-weekly"
            checked={draft.cadence === "weekly"}
            onChange={() => set({ cadence: "weekly" })}
          />
          <label htmlFor="cadence-weekly" className="w-28">
            Weekly
          </label>
          <span className="flex flex-wrap gap-1">
            {WEEKDAY_ORDER.map((d) => {
              const on = draft.weekdays.includes(d.key)
              return (
                <button
                  key={d.key}
                  type="button"
                  aria-pressed={on}
                  disabled={draft.cadence !== "weekly"}
                  onClick={() =>
                    set({
                      weekdays: on
                        ? draft.weekdays.filter((w) => w !== d.key)
                        : [...draft.weekdays, d.key],
                    })
                  }
                  className={`rounded-md border px-2 py-1 text-xs disabled:opacity-40 ${
                    on
                      ? "border-[var(--edh-primary)] bg-[var(--edh-primary)] text-white"
                      : "border-[var(--edh-border)] bg-white text-slate-700"
                  }`}
                >
                  {d.label}
                </button>
              )
            })}
          </span>
        </div>
        {draft.cadence === "weekly" && draft.weekdays.length === 0 && (
          <p className="mt-1 text-xs text-[var(--edh-muted)]">
            No weekdays selected — the schedule runs every day.
          </p>
        )}
      </Section>

      {/* Times of day — one or more HH:MM rows; used by daily and weekly. */}
      <Section title="Time(s) of day">
        <div className={draft.cadence === "interval" ? "opacity-50" : ""}>
          {draft.times.map((t, i) => (
            <div key={t.id} className="flex items-center gap-2 py-1">
              <input
                type="time"
                value={t.value}
                disabled={draft.cadence === "interval"}
                onChange={(e) =>
                  set({
                    times: draft.times.map((row) =>
                      row.id === t.id ? { ...row, value: e.target.value } : row,
                    ),
                  })
                }
                aria-label={`Scheduled time ${i + 1}`}
                className="rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm"
              />
              <button
                type="button"
                onClick={() => set({ times: draft.times.filter((row) => row.id !== t.id) })}
                disabled={draft.cadence === "interval" || draft.times.length <= 1}
                aria-label={`Remove time ${t.value}`}
                title="Remove this time"
                className="rounded p-1 text-[var(--edh-muted)] hover:bg-slate-100 hover:text-slate-700 disabled:opacity-40"
              >
                <Minus className="h-4 w-4" />
              </button>
            </div>
          ))}
          <button
            type="button"
            onClick={() => set({ times: [...draft.times, timeRow("18:00")] })}
            disabled={draft.cadence === "interval"}
            className="mt-1 inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-40"
          >
            <Plus className="h-4 w-4" /> Add another time
          </button>
          {timesInvalid && (
            <p className="mt-1 text-xs text-red-700">
              Daily and Weekly schedules need at least one time of day.
            </p>
          )}
        </div>
        <div className="mt-3 flex items-center gap-2 text-sm">
          <span className="text-[var(--edh-muted)]">Timezone:</span>
          <input
            list="edh-timezones"
            value={draft.timezone}
            onChange={(e) => set({ timezone: e.target.value })}
            aria-label="Timezone (IANA name)"
            className="w-64 rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm"
          />
          <datalist id="edh-timezones">
            {tzOptions.map((tz) => (
              <option key={tz} value={tz} />
            ))}
          </datalist>
          <span className="text-xs text-[var(--edh-muted)]">(default: system tz)</span>
        </div>
      </Section>

      {/* Domain scope — all monitored domains, or an explicit subset. */}
      <Section title="Domains to include">
        <label className="flex items-center gap-2 py-1 text-sm">
          <input
            type="radio"
            name="scope"
            checked={draft.scopeAll}
            onChange={() => set({ scopeAll: true })}
          />
          All monitored domains
        </label>
        <label className="flex items-center gap-2 py-1 text-sm">
          <input
            type="radio"
            name="scope"
            checked={!draft.scopeAll}
            onChange={() => set({ scopeAll: false })}
          />
          Only selected:
        </label>
        <div className={`ml-6 ${draft.scopeAll ? "opacity-50" : ""}`}>
          {(domains ?? []).length === 0 ? (
            <p className="py-1 text-sm text-[var(--edh-muted)]">
              No monitored domains yet —{" "}
              <Link to="/domains" className="text-[var(--edh-primary)] underline">
                add one
              </Link>{" "}
              first.
            </p>
          ) : (
            (domains ?? []).map((d) => {
              const checked = draft.selectedDomains.includes(d.id)
              return (
                <label key={d.id} className="flex items-center gap-2 py-0.5 text-sm">
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={draft.scopeAll}
                    onChange={() =>
                      set({
                        selectedDomains: checked
                          ? draft.selectedDomains.filter((id) => id !== d.id)
                          : [...draft.selectedDomains, d.id],
                      })
                    }
                  />
                  {d.name}
                </label>
              )
            })
          )}
          {!draft.scopeAll && draft.selectedDomains.length === 0 && (
            <p className="mt-1 text-xs text-[var(--edh-muted)]">
              Empty selection is treated as all monitored domains.
            </p>
          )}
        </div>
      </Section>

      {/* Scheduling layer — in-process vs the OS-level native schedule. */}
      <Section title="Run even when the app is closed">
        <p className="mb-2 text-sm text-[var(--edh-muted)]">
          Detected OS: <span className="font-medium text-slate-700">{osLabel.os}</span> (
          {osLabel.artifact})
        </p>
        <label className="flex items-center gap-2 py-1 text-sm">
          <input
            type="radio"
            name="runner"
            checked={draft.runner === "in-process"}
            onChange={() => set({ runner: "in-process" })}
          />
          In-process only (runs while EmailDeliveryHero is open)
        </label>
        <label className="flex items-center gap-2 py-1 text-sm">
          <input
            type="radio"
            name="runner"
            checked={draft.runner === "os"}
            onChange={() => set({ runner: "os" })}
          />
          Install OS-level schedule ({osLabel.artifact})
        </label>
        <div className="ml-6 mt-2 flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={onPreview}
            disabled={previewLoading}
            className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-50"
          >
            {previewLoading && <Loader2 className="h-4 w-4 animate-spin" />} Preview
          </button>
          <button
            type="button"
            onClick={onInstall}
            disabled={install.isPending}
            className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-50"
          >
            {install.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            {os.installed ? "Update" : "Install"}
          </button>
          <button
            type="button"
            onClick={onUninstall}
            disabled={uninstall.isPending || !os.installed}
            className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm text-red-700 hover:bg-red-50 disabled:opacity-50"
          >
            {uninstall.isPending && <Loader2 className="h-4 w-4 animate-spin" />} Uninstall
          </button>
          <span className="text-sm text-[var(--edh-muted)]">
            Status:{" "}
            {os.installed ? (
              <span className="font-medium text-green-700">installed ✓ ({os.label})</span>
            ) : (
              "not installed"
            )}
          </span>
        </div>
        {preview && (
          <div className="ml-6 mt-3">
            <p className="mb-1 text-xs text-[var(--edh-muted)]">
              {preview.kind} · {preview.path}
            </p>
            <pre className="max-h-80 overflow-auto rounded-md border border-[var(--edh-border)] bg-slate-50 p-3 text-xs leading-relaxed">
              {preview.content}
            </pre>
          </div>
        )}
      </Section>

      <footer className="mt-6 flex justify-end gap-2">
        <button
          type="button"
          onClick={() => navigate({ to: "/" })}
          className="rounded-md border border-[var(--edh-border)] px-4 py-2 text-sm text-slate-700 hover:bg-slate-50"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={onSave}
          disabled={!canSave}
          className="rounded-md bg-[var(--edh-primary)] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
        >
          {save.isPending ? "Saving…" : "Save"}
        </button>
      </footer>
    </div>
  )
}

function Section({ title, children }: { title?: string; children: React.ReactNode }) {
  return (
    <section className="mb-4 rounded-lg border border-[var(--edh-border)] bg-white p-5">
      {title && (
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-900">
          {title}
        </h2>
      )}
      {children}
    </section>
  )
}
