import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api } from "./axios"
import type { AuditResult } from "./types"

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

/** Run a fresh audit for every monitored domain. */
export function useRunAllAudits() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async () => (await api.post<AuditResult[]>("/audit/run")).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: RESULTS_KEY }),
  })
}
