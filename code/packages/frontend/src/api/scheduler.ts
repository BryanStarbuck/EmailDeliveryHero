import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api } from "./axios"

/**
 * The scheduler contract (pm/scheduled_checks.mdx) the dashboard's Scheduled toggle rides on
 * (pm/dashboard.mdx §7.2): GET /api/scheduler reports whether recurring checks are enabled;
 * PUT /api/scheduler/config flips the `schedule.enabled` flag (merged over the current block so
 * the toggle never clobbers cadence/times set on the configuration page).
 */

const STATUS_KEY = ["scheduler"] as const
const CONFIG_KEY = ["scheduler", "config"] as const

export type ScheduleCadence = "interval" | "daily" | "weekly"
export type ScheduleRunner = "in-process" | "os"
export type Weekday = "mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun"
export type OsSchedulerKind = "launchd" | "cron" | "systemd" | "schtasks"

export interface ScheduleOsState {
  kind: OsSchedulerKind
  installed: boolean
  label: string
}

/** The `schedule:` block of config.yaml (pm/scheduled_checks.mdx "Schedule config model"). */
export interface ScheduleConfig {
  enabled: boolean
  cadence: ScheduleCadence
  everyHours: number
  times: string[]
  weekdays: Weekday[]
  timezone: string
  domains: "all" | string[]
  runner: ScheduleRunner
  os: ScheduleOsState
}

export interface SchedulerStatus {
  enabled: boolean
  runner?: string
  nextRunAt?: string | null
  lastRunAt?: string | null
  lastTrigger?: string | null
  os?: ScheduleOsState
}

/** GET /api/scheduler/os/preview — the rendered native artifact, before installing. */
export interface OsArtifactPreview {
  kind: OsSchedulerKind
  path: string
  content: string
  installed: boolean
}

/** Scheduler status — backs the dashboard's Scheduled on/off toggle. */
export function useSchedulerStatus() {
  return useQuery({
    queryKey: STATUS_KEY,
    queryFn: async () => (await api.get<SchedulerStatus>("/scheduler")).data,
    retry: false,
  })
}

/** Flip recurring checks on/off — merges `enabled` into the persisted schedule config. */
export function useSetScheduleEnabled() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (enabled: boolean) => {
      // Read-merge-write so only the on/off flag changes (pm/scheduled_checks.mdx "Enabling").
      const config = await api
        .get<Record<string, unknown>>("/scheduler/config")
        .then((r) => r.data)
        .catch(() => ({}))
      return (await api.put("/scheduler/config", { ...config, enabled })).data
    },
    onSettled: () => qc.invalidateQueries({ queryKey: STATUS_KEY }),
  })
}

/** The persisted `schedule:` block — backs the Scheduled Checks configuration page. */
export function useScheduleConfig() {
  return useQuery({
    queryKey: CONFIG_KEY,
    queryFn: async () => (await api.get<ScheduleConfig>("/scheduler/config")).data,
    retry: false,
  })
}

/**
 * PUT /api/scheduler/config — persist the whole schedule block. The backend (re)starts or stops
 * the in-process job and, when the OS layer is installed, regenerates the native artifact so the
 * installed schedule matches the saved config (pm/scheduled_checks.mdx "Save").
 */
export function useSaveScheduleConfig() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (config: Partial<ScheduleConfig>) =>
      (await api.put<ScheduleConfig>("/scheduler/config", config)).data,
    onSettled: () => {
      qc.invalidateQueries({ queryKey: STATUS_KEY })
      qc.invalidateQueries({ queryKey: CONFIG_KEY })
    },
  })
}

/** The rendered OS-level artifact (plist / systemd units + crontab / schtasks commands). */
export async function fetchOsPreview(): Promise<OsArtifactPreview> {
  return (await api.get<OsArtifactPreview>("/scheduler/os/preview")).data
}

/** POST /api/scheduler/os/install — write + load the native OS schedule. */
export function useInstallOsSchedule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async () => (await api.post<ScheduleConfig>("/scheduler/os/install")).data,
    onSettled: () => {
      qc.invalidateQueries({ queryKey: STATUS_KEY })
      qc.invalidateQueries({ queryKey: CONFIG_KEY })
    },
  })
}

/** POST /api/scheduler/os/uninstall — unload + remove the native OS schedule. */
export function useUninstallOsSchedule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async () => (await api.post<ScheduleConfig>("/scheduler/os/uninstall")).data,
    onSettled: () => {
      qc.invalidateQueries({ queryKey: STATUS_KEY })
      qc.invalidateQueries({ queryKey: CONFIG_KEY })
    },
  })
}
