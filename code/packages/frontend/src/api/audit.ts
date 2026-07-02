import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api } from "./axios"
import type { AuditResult, DnsSpotCheckResult, GeneratedTlsaRecord } from "./types"

const RESULTS_KEY = ["audit", "results"] as const

/** Latest audit result for every monitored domain (dashboard + audits list). */
export function useAuditResults() {
  return useQuery({
    queryKey: RESULTS_KEY,
    queryFn: async () => (await api.get<AuditResult[]>("/audit/results")).data,
  })
}

/** Run history, newest first — the dashboard's Runs table (pm/dashboard.mdx §4.2). */
export function useAuditRuns() {
  return useQuery({
    queryKey: ["audit", "runs"] as const,
    queryFn: async () => (await api.get<AuditResult[]>("/audit/runs")).data,
  })
}

/**
 * One domain's run history, newest startedAt first — powers the category run pages' run context
 * strip (‹ prev / next ›, `newest` badge — pm/checks/dns.mdx §6.2).
 */
export function useDomainRuns(domainId: string | undefined) {
  return useQuery({
    queryKey: ["audit", "runs", "domain", domainId] as const,
    queryFn: async () =>
      (await api.get<AuditResult[]>("/audit/runs", { params: { domainId } })).data,
    enabled: !!domainId,
  })
}

/** One historical run in full — the run report for a Runs-table row. */
export function useAuditRun(runId: string | undefined) {
  return useQuery({
    queryKey: ["audit", "runs", runId] as const,
    queryFn: async () => (await api.get<AuditResult>(`/audit/runs/${runId}`)).data,
    enabled: !!runId,
  })
}

/** Delete one run from the history (Runs-row ⋮ menu). */
export function useDeleteRun() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (runId: string) => (await api.delete(`/audit/runs/${runId}`)).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["audit", "runs"] }),
  })
}

/** Run a fresh audit for one domain. */
export function useRunAudit() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (domainId: string) =>
      (await api.post<AuditResult>(`/audit/run/${domainId}`)).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: RESULTS_KEY }),
  })
}

/**
 * Re-run ONE DNS & Infrastructure family checker live (pm/checks/dns.mdx §6.2 item 6 — the
 * DNS page's ⟳ spot-check button and the check-detail explainer's "run this check now").
 * The result is a fresh observation, never persisted — no query invalidation needed.
 */
export function useDnsSpotCheck() {
  return useMutation({
    mutationFn: async ({ domainId, checkKey }: { domainId: string; checkKey: string }) =>
      (await api.post<DnsSpotCheckResult>(`/audit/spot-check/${domainId}/${checkKey}`)).data,
  })
}

/**
 * The DANE subsection's one-click TLSA generator (pm/checks/dane_tlsa.mdx §4): paste a PEM
 * certificate, get back the exact `3 1 1` record to publish at `_25._tcp.<mx-host>`. Pure
 * computation on the backend — nothing persisted, no queries to invalidate.
 */
export function useGenerateTlsaRecord() {
  return useMutation({
    mutationFn: async (input: { mxHost: string; pem: string; ttl?: number }) =>
      (await api.post<GeneratedTlsaRecord>("/audit/tlsa-record", input)).data,
  })
}

/** One hit from an on-demand DKIM selector discovery probe (pm/checks/dkim.mdx §6.2 item 6). */
export interface DkimDiscoveryHit {
  selector: string
  query_name: string
  key_type: string | null
  key_bits: number | null
  is_revoked: boolean
}

/** The on-demand discovery outcome the selectors editor renders for one-click import. */
export interface DkimDiscoveryOutcome {
  /** True when a wildcard TXT answers every selector — hits are suppressed. */
  wildcard_shadow: boolean
  /** How many candidate names were probed (0 when the wildcard guard fired). */
  probed: number
  hits: DkimDiscoveryHit[]
}

/**
 * "Run discovery now" (pm/checks/dkim.mdx §6.2 item 6): probe the MX-guided common-selector
 * wordlist live for one domain and return the hits for one-click import. A probe, not a run —
 * nothing is persisted, so no queries need invalidating.
 */
export function useDkimDiscovery() {
  return useMutation({
    mutationFn: async (domainId: string) =>
      (await api.post<DkimDiscoveryOutcome>(`/audit/dkim-discovery/${domainId}`)).data,
  })
}

/** Run a fresh audit for every monitored domain. */
export function useRunAllAudits() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async () => (await api.post<AuditResult[]>("/audit/run")).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: RESULTS_KEY }),
  })
}
