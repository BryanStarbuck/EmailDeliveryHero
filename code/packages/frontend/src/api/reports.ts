import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api } from "./axios"
import type { DomainReportsView, ReportIngestSummary } from "./types"

/**
 * Report-email ingestion API (pm/emails.mdx §7.1/§10): the per-domain view of the ingested DMARC
 * aggregate (rua) + TLS-RPT reports, and the on-demand "Ingest now" scan.
 */

const KEY = (domainId: string) => ["reports", "ingested", domainId] as const

/** GET /domains/:id/reports — aggregates + report-derived findings for one domain. */
export function useDomainReports(domainId: string | undefined) {
  return useQuery({
    queryKey: KEY(domainId ?? ""),
    queryFn: async () => (await api.get<DomainReportsView>(`/domains/${domainId}/reports`)).data,
    enabled: !!domainId,
  })
}

/** POST /domains/:id/reports/ingest — "Ingest now" (pm/emails.mdx §7.1). */
export function useIngestReports(domainId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async () =>
      (
        await api.post<{ summary: ReportIngestSummary; view: DomainReportsView }>(
          `/domains/${domainId}/reports/ingest`,
        )
      ).data,
    onSuccess: (data) => {
      qc.setQueryData(KEY(domainId), data.view)
      qc.invalidateQueries({ queryKey: ["reports", "ingested"] })
    },
  })
}
