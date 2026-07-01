import { ChevronDown, ChevronRight, RefreshCw } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"
import { useAuditResults, useRunAudit } from "@/api/audit"
import { useDomains } from "@/api/domains"
import { ScoreBadge, SeverityBadge } from "@/components/Badges"
import { FindingsList } from "@/components/FindingsList"

/**
 * The audits view: one card per domain with its latest result, a per-domain "Run audit" button, and
 * an expandable list of findings (each with its concrete fix).
 */
export function AuditsPage() {
  const { data: domains } = useDomains()
  const { data: results } = useAuditResults()
  const run = useRunAudit()
  const [openId, setOpenId] = useState<string | null>(null)

  const byId = new Map((results ?? []).map((r) => [r.domainId, r]))
  const list = domains ?? []

  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="mb-1 text-2xl font-bold">Audits</h1>
      <p className="mb-6 text-sm text-[var(--edh-muted)]">
        SPF, DKIM, DMARC, MX, and blacklist findings — with the exact fix for each problem.
      </p>

      {list.length === 0 && (
        <p className="rounded-lg border border-dashed border-[var(--edh-border)] p-8 text-center text-[var(--edh-muted)]">
          Add a domain first, then run an audit.
        </p>
      )}

      <div className="space-y-3">
        {list.map((d) => {
          const r = byId.get(d.id)
          const open = openId === d.id
          const running = run.isPending && run.variables === d.id
          return (
            <div key={d.id} className="rounded-lg border border-[var(--edh-border)] bg-white">
              <div className="flex items-center justify-between gap-3 p-4">
                <button
                  type="button"
                  onClick={() => setOpenId(open ? null : d.id)}
                  className="flex min-w-0 items-center gap-2 text-left"
                >
                  {open ? (
                    <ChevronDown className="h-4 w-4 shrink-0" />
                  ) : (
                    <ChevronRight className="h-4 w-4 shrink-0" />
                  )}
                  <span className="truncate font-medium">{d.name}</span>
                  {r && <SeverityBadge severity={r.status} />}
                </button>
                <div className="flex items-center gap-3">
                  {r && <ScoreBadge score={r.score} />}
                  <button
                    type="button"
                    onClick={() =>
                      run.mutate(d.id, {
                        onSuccess: () => {
                          setOpenId(d.id)
                          toast.success(`Audited ${d.name}`)
                        },
                        onError: () => toast.error(`Audit failed for ${d.name}`),
                      })
                    }
                    disabled={running}
                    className="inline-flex items-center gap-2 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm font-medium hover:bg-slate-50 disabled:opacity-50"
                  >
                    <RefreshCw className={running ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
                    Run audit
                  </button>
                </div>
              </div>
              {open && (
                <div className="border-t border-[var(--edh-border)] bg-slate-50 p-4">
                  {r ? (
                    <>
                      <p className="mb-3 text-xs text-[var(--edh-muted)]">
                        Last run {new Date(r.ranAt).toLocaleString()} · {r.counts.critical} critical
                        · {r.counts.warning} warning · {r.counts.ok} ok
                      </p>
                      <FindingsList findings={r.findings} />
                    </>
                  ) : (
                    <p className="text-sm text-[var(--edh-muted)]">
                      No audit yet — click “Run audit”.
                    </p>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
