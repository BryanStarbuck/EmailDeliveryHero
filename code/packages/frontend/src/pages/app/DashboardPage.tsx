import { Link } from "@tanstack/react-router"
import { RefreshCw } from "lucide-react"
import { useAuditResults, useRunAllAudits } from "@/api/audit"
import { useDomains } from "@/api/domains"
import { ScoreBadge, SeverityBadge } from "@/components/Badges"

/**
 * The dashboard: every monitored domain with its latest audit score, status, and open-problem
 * count. This is the "are my domains healthy?" at-a-glance view.
 */
export function DashboardPage() {
  const { data: domains } = useDomains()
  const { data: results } = useAuditResults()
  const runAll = useRunAllAudits()

  const byId = new Map((results ?? []).map((r) => [r.domainId, r]))
  const list = domains ?? []

  return (
    <div className="mx-auto max-w-5xl">
      <header className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-sm text-[var(--edh-muted)]">
            Deliverability health across your monitored domains.
          </p>
        </div>
        <button
          type="button"
          onClick={() => runAll.mutate()}
          disabled={runAll.isPending || list.length === 0}
          className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
        >
          <RefreshCw className={runAll.isPending ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
          Audit all
        </button>
      </header>

      {list.length === 0 ? (
        <div className="rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center">
          <p className="text-slate-600">No domains yet.</p>
          <Link to="/domains" className="mt-2 inline-block text-[var(--edh-primary)] underline">
            Add your first domain
          </Link>
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs uppercase text-[var(--edh-muted)]">
              <tr>
                <th className="px-4 py-2">Domain</th>
                <th className="px-4 py-2">Score</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Problems</th>
                <th className="px-4 py-2">Last audit</th>
              </tr>
            </thead>
            <tbody>
              {list.map((d) => {
                const r = byId.get(d.id)
                const problems = r ? r.counts.warning + r.counts.critical : 0
                return (
                  <tr key={d.id} className="border-t border-[var(--edh-border)]">
                    <td className="px-4 py-3 font-medium">
                      <Link to="/audits" className="hover:underline">
                        {d.name}
                      </Link>
                    </td>
                    <td className="px-4 py-3">{r ? <ScoreBadge score={r.score} /> : "—"}</td>
                    <td className="px-4 py-3">{r ? <SeverityBadge severity={r.status} /> : "—"}</td>
                    <td className="px-4 py-3">{r ? problems : "—"}</td>
                    <td className="px-4 py-3 text-[var(--edh-muted)]">
                      {r ? new Date(r.ranAt).toLocaleString() : "never"}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
