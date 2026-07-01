import { useQueryClient } from "@tanstack/react-query"
import { createContext, type ReactNode, useCallback, useContext, useMemo, useState } from "react"
import { toast } from "sonner"
import { api } from "@/api/axios"
import { mapLimit } from "@/lib/concurrency"

/**
 * The scan-progress engine (pm/progress_ui.mdx §3–4). Holds the set of domains currently being
 * scanned (one card each in <ScanProgressDock/>) and drives the parallel per-domain fan-out so a
 * "Run All" scans every domain at once and each card leaves the instant its domain finishes.
 */

/** One in-flight scan = one card in the dock. */
export interface ActiveScan {
  domainId: string
  domain: string
  startedAt: number
}

/** Domains scan in parallel, bounded so a large fleet doesn't open a socket per domain at once. */
const SCAN_CONCURRENCY = 4

interface ScanContextValue {
  active: ActiveScan[]
  runDomains: (domains: { id: string; name: string }[]) => Promise<void>
}

const ScanContext = createContext<ScanContextValue | null>(null)

export function ScanProgressProvider({ children }: { children: ReactNode }) {
  const [active, setActive] = useState<ActiveScan[]>([])
  const qc = useQueryClient()

  const begin = useCallback((domainId: string, domain: string) => {
    setActive((prev) =>
      prev.some((s) => s.domainId === domainId)
        ? prev
        : [{ domainId, domain, startedAt: Date.now() }, ...prev],
    )
  }, [])

  const end = useCallback((domainId: string) => {
    setActive((prev) => prev.filter((s) => s.domainId !== domainId))
  }, [])

  const runDomains = useCallback(
    async (domains: { id: string; name: string }[]) => {
      if (domains.length === 0) return
      let failures = 0

      await mapLimit(domains, SCAN_CONCURRENCY, async (d) => {
        begin(d.id, d.name)
        try {
          await api.post(`/audit/run/${d.id}`)
          // Recolor this domain's cells as soon as it finishes — not after the whole batch.
          qc.invalidateQueries({ queryKey: ["audit"] })
        } catch {
          failures++
          toast.error(`Audit failed for ${d.name}`)
        } finally {
          end(d.id)
        }
      })

      if (failures === 0) {
        toast.success(domains.length === 1 ? `Audited ${domains[0].name}` : "Checks complete")
      }
    },
    [begin, end, qc],
  )

  const value = useMemo(() => ({ active, runDomains }), [active, runDomains])
  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>
}

function useScanContext(): ScanContextValue {
  const ctx = useContext(ScanContext)
  if (!ctx) throw new Error("useScan* must be used within <ScanProgressProvider>")
  return ctx
}

/** The list of in-flight scans, for the dock. */
export function useScanProgress(): ActiveScan[] {
  return useScanContext().active
}

/** The single entry point pages call to run scans with live per-domain progress. */
export function useScanRunner(): (domains: { id: string; name: string }[]) => Promise<void> {
  return useScanContext().runDomains
}
