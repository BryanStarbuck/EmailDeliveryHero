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
