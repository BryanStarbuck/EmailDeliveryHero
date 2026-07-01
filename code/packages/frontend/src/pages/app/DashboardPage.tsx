import { Link, useNavigate } from "@tanstack/react-router"
import { ChevronRight, RefreshCw } from "lucide-react"
import { useEffect, useState } from "react"
import { toast } from "sonner"
import { useAuditResults, useRunAllAudits } from "@/api/audit"
import { useDomains } from "@/api/domains"
import { BrandHeader } from "@/components/BrandHeader"
import { StatusCell } from "@/components/StatusCell"
import { CATEGORIES, NEVER_CELL, rollupCategories } from "@/lib/categories"

/**
 * The Dashboard (pm/ui.mdx §4) — the fleet health grid. A big brand header over one row per
 * monitored domain, each row six color-coded category cells (SPF, DKIM, DMARC, Blacklists, DNS &
 * Infrastructure, Spam & Content). Top-right: a Run-checks button and a scheduled-checks toggle with
 * a chevron to the scheduling settings. Clicking a row opens that domain's run detail.
 */
export function DashboardPage() {
  const { data: domains, isLoading } = useDomains()
  const { data: results } = useAuditResults()
  const runAll = useRunAllAudits()
  const navigate = useNavigate()

  const byId = new Map((results ?? []).map((r) => [r.domainId, r]))
  const list = domains ?? []

  const onRunChecks = () =>
    runAll.mutate(undefined, {
      onSuccess: () => toast.success("Checks complete"),
      onError: () => toast.error("Run failed"),
    })

  return (
    <div className="mx-auto max-w-6xl">
      <header className="mb-8 flex items-start justify-between gap-4">
        <BrandHeader />
        <div className="flex shrink-0 flex-col items-end gap-2">
          <button
            type="button"
            onClick={onRunChecks}
            disabled={runAll.isPending || list.length === 0}
            className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
          >
            <RefreshCw className={runAll.isPending ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
            {runAll.isPending ? "Running…" : "Run checks"}
          </button>
          <ScheduledToggle />
        </div>
      </header>

      {isLoading ? (
        <SkeletonGrid />
      ) : list.length === 0 ? (
        <div className="rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center">
          <p className="text-slate-600">No domains yet.</p>
          <Link to="/domains" className="mt-2 inline-block text-[var(--edh-primary)] underline">
            Add your first domain →
          </Link>
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs uppercase text-[var(--edh-muted)]">
              <tr>
                <th className="px-4 py-2">Domain</th>
                {CATEGORIES.map((c) => (
                  <th key={c.key} className="px-2 py-2 text-center">
                    {c.header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {list.map((d) => {
                const cells = rollupCategories(byId.get(d.id)?.findings)
                return (
                  <tr
                    key={d.id}
                    onClick={() => navigate({ to: "/domains/$id", params: { id: d.id } })}
                    className="cursor-pointer border-t border-[var(--edh-border)] hover:bg-slate-50"
                  >
                    <td className="px-4 py-3 font-medium">{d.name}</td>
                    {CATEGORIES.map((c) => (
                      <td key={c.key} className="px-2 py-2">
                        <StatusCell status={cells[c.key] ?? NEVER_CELL} />
                      </td>
                    ))}
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

/**
 * The recurring-checks on/off switch with a chevron to the scheduling page (pm/ui.mdx §4). The
 * on/off preference is stored client-side for now (the first-round backend enables periodic audits
 * via EDH_PERIODIC_AUDIT_MINUTES); the chevron always routes to the scheduling settings.
 */
function ScheduledToggle() {
  const [on, setOn] = useState(false)
  useEffect(() => {
    setOn(localStorage.getItem("edh.scheduled") === "on")
  }, [])
  const toggle = () => {
    const next = !on
    setOn(next)
    localStorage.setItem("edh.scheduled", next ? "on" : "off")
  }
  return (
    <div className="inline-flex items-center gap-2 rounded-md border border-[var(--edh-border)] bg-white px-3 py-1.5 text-sm">
      <span className="text-[var(--edh-muted)]">Scheduled</span>
      <button
        type="button"
        role="switch"
        aria-checked={on}
        aria-label="Toggle scheduled checks"
        onClick={toggle}
        className={`relative h-5 w-9 rounded-full transition-colors ${on ? "bg-[var(--edh-primary)]" : "bg-slate-300"}`}
      >
        <span
          className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${on ? "left-4" : "left-0.5"}`}
        />
      </button>
      <Link
        to="/settings/$section"
        params={{ section: "scheduling" }}
        aria-label="Configure scheduled checks"
        className="text-[var(--edh-muted)] hover:text-slate-700"
      >
        <ChevronRight className="h-4 w-4" />
      </Link>
    </div>
  )
}

function SkeletonGrid() {
  return (
    <div className="space-y-2">
      {["a", "b", "c"].map((k) => (
        <div key={k} className="h-11 animate-pulse rounded-md bg-slate-100" />
      ))}
    </div>
  )
}
