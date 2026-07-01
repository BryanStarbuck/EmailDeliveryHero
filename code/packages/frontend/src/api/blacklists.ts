import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api } from "./axios"
import type {
  BlacklistHistoryEntry,
  BlacklistRunResults,
  PortalUserState,
  ProviderPortal,
} from "./types"

/** The Blacklists technology API (pm/checks/blacklists.mdx §13) — latest runs, history, portals. */

const RUNS_KEY = ["blacklists", "results"] as const

/** Latest blacklist run for every domain that has one (the summary cards). */
export function useBlacklistRuns() {
  return useQuery({
    queryKey: RUNS_KEY,
    queryFn: async () => (await api.get<BlacklistRunResults[]>("/blacklists/results")).data,
  })
}

/** Latest blacklist run for one domain (the full technology page). */
export function useBlacklistRun(domain: string) {
  return useQuery({
    queryKey: [...RUNS_KEY, domain],
    queryFn: async () =>
      (await api.get<BlacklistRunResults>(`/blacklists/results/${encodeURIComponent(domain)}`))
        .data,
    retry: false,
  })
}

/** Per-run summary history — powers the sparkline strip. */
export function useBlacklistHistory(domain: string) {
  return useQuery({
    queryKey: ["blacklists", "history", domain],
    queryFn: async () =>
      (
        await api.get<BlacklistHistoryEntry[]>(
          `/blacklists/results/${encodeURIComponent(domain)}/history`,
        )
      ).data,
  })
}

/** Set the user's provider-portal checklist state (Unverified / Clean / Problem). */
export function useSetPortalState(domain: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (input: { provider: string; state: PortalUserState }) =>
      (
        await api.patch<ProviderPortal[]>(
          `/blacklists/${encodeURIComponent(domain)}/portals/${encodeURIComponent(input.provider)}`,
          { state: input.state },
        )
      ).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: RUNS_KEY })
    },
  })
}
