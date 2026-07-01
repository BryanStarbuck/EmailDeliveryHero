import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api } from "./axios"

/**
 * The scheduler contract (pm/scheduled_checks.mdx) the dashboard's Scheduled toggle rides on
 * (pm/dashboard.mdx §7.2): GET /api/scheduler reports whether recurring checks are enabled;
 * PUT /api/scheduler/config flips the `schedule.enabled` flag (merged over the current block so
 * the toggle never clobbers cadence/times set on the configuration page).
 */

const STATUS_KEY = ["scheduler"] as const

export interface SchedulerStatus {
  enabled: boolean
  runner?: string
  nextRunAt?: string | null
  lastRunAt?: string | null
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
