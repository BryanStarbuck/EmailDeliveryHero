import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api } from "./axios"
import type {
  AuditResult,
  BlacklistHistoryEntry,
  BlacklistLiveRecheck,
  BlacklistRegistryInfo,
  BlacklistRunResults,
  PortalUserState,
  ProviderPortal,
} from "./types"

/** The Blacklists technology API (pm/checks/blacklists.mdx §13) — latest runs, history, portals. */

const RUNS_KEY = ["blacklists", "results"] as const

/** The effective blocklist registry — feeds the §17 dashboard registry-health panel. */
export function useBlacklistRegistry() {
  return useQuery({
    queryKey: ["blacklists", "zones"] as const,
    queryFn: async () => (await api.get<BlacklistRegistryInfo>("/blacklists/zones")).data,
    staleTime: 5 * 60 * 1000,
  })
}

/** Latest blacklist run for every domain that has one (the summary cards). */
export function useBlacklistRuns() {
  return useQuery({
    queryKey: RUNS_KEY,
    queryFn: async () => (await api.get<BlacklistRunResults[]>("/blacklists/results")).data,
  })
}

/** Latest blacklist run for one domain (the newest-run alias of the full technology page). */
export function useBlacklistRun(domain: string, enabled = true) {
  return useQuery({
    queryKey: [...RUNS_KEY, domain],
    queryFn: async () =>
      (await api.get<BlacklistRunResults>(`/blacklists/results/${encodeURIComponent(domain)}`))
        .data,
    retry: false,
    enabled: enabled && domain.length > 0,
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

/**
 * Update one zone's operator override — enabled toggle / weight (the §4 admin "Blocklist Zones"
 * panel). Writes <stateDir>/blacklist_zones.yaml server-side, never the checked-in registry.
 */
export function useUpdateBlacklistZone() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (input: {
      zone: string
      enabled?: boolean
      weight?: number
      kind?: "ip" | "domain"
    }) => {
      const { zone, ...patch } = input
      return (
        await api.patch<BlacklistRegistryInfo>(
          `/blacklists/zones/${encodeURIComponent(zone)}`,
          patch,
        )
      ).data
    },
    onSuccess: (data) => {
      qc.setQueryData(["blacklists", "zones"], data)
    },
  })
}

/**
 * Category-scoped re-run (pm/checks/blacklists.mdx §21 / AC 26): POST /audit/run/:id/blacklists
 * executes ONLY the Blacklists category and writes a NEW run file with run.scope: blacklists —
 * the viewed run is never mutated. Every Blacklists surface's [Run this check now] uses this and
 * navigates to the returned run on completion.
 */
export function useRunBlacklistsCheck() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (domainId: string) =>
      (await api.post<AuditResult>(`/audit/run/${encodeURIComponent(domainId)}/blacklists`)).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["blacklists"] })
      qc.invalidateQueries({ queryKey: ["audit"] })
    },
  })
}

/**
 * Live recheck (pm/checks/blacklists.mdx §21.3 / AC 27): POST /blacklists/:domainId/recheck with
 * optional { zones, targets } scoping. Ephemeral — the backend never writes a run file, and the
 * UI renders the result as a "live recheck HH:MM" overlay beside the stored run values.
 */
export function useBlacklistRecheck() {
  return useMutation({
    mutationFn: async (input: { domain: string; zones?: string[]; targets?: string[] }) => {
      const { domain, ...body } = input
      return (
        await api.post<BlacklistLiveRecheck>(
          `/blacklists/${encodeURIComponent(domain)}/recheck`,
          body,
        )
      ).data
    },
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
