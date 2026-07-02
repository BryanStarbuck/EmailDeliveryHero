import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api } from "./axios"
import type { AuditResult, ContentSampleView } from "./types"

/**
 * The per-domain sample-message API (pm/checks/content_scoring.mdx §4): upload/paste the raw .eml
 * that content scoring grades, read it back, and the dedicated Re-score action that re-runs just
 * the content checker without a full re-audit (§6).
 */

const sampleKey = (domainId: string) => ["content-sample", domainId] as const

export interface ContentSampleResponse {
  sample: ContentSampleView | null
  history: ContentSampleView[]
}

/** The domain's active sample message + upload history. */
export function useContentSample(domainId: string | undefined) {
  return useQuery({
    queryKey: sampleKey(domainId ?? ""),
    queryFn: async () =>
      (await api.get<ContentSampleResponse>(`/audit/content-sample/${domainId}`)).data,
    enabled: !!domainId,
  })
}

/** Upload/paste a new sample .eml — it becomes the active scored sample (§8 AC 2). */
export function useUploadContentSample(domainId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (raw: string) =>
      (await api.put<{ sample: ContentSampleView }>(`/audit/content-sample/${domainId}`, { raw }))
        .data,
    onSuccess: () => qc.invalidateQueries({ queryKey: sampleKey(domainId) }),
  })
}

/** The active sample's raw RFC 5322 source (the "View raw .eml" action). */
export function useContentSampleRaw(domainId: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: [...sampleKey(domainId ?? ""), "raw"] as const,
    queryFn: async () =>
      (await api.get<{ raw: string }>(`/audit/content-sample/${domainId}/raw`)).data,
    enabled: !!domainId && enabled,
  })
}

/** Re-score just the content check (no full re-audit) and refresh the audit results. */
export function useRescoreContent(domainId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async () =>
      (await api.post<AuditResult>(`/audit/content-sample/${domainId}/rescore`)).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["audit", "results"] })
      qc.invalidateQueries({ queryKey: sampleKey(domainId) })
    },
  })
}
