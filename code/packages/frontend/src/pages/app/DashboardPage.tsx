import { Link, useNavigate } from "@tanstack/react-router"
import { ChevronRight, Loader2, MoreVertical, Play, RefreshCw } from "lucide-react"
import { useEffect, useState } from "react"
import { useAuditResults, useAuditRuns, useDeleteRun } from "@/api/audit"
import { useDeleteDomain, useDomains, useUpdateDomain } from "@/api/domains"
import type { AuditResult, MonitoredDomain } from "@/api/types"
import { BrandHeader } from "@/components/BrandHeader"
import { StatusCell } from "@/components/StatusCell"
import { CATEGORIES, NEVER_CELL, rollupCategories, techPageRoute } from "@/lib/categories"
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext"

/**
 * The Dashboard (pm/dashboard.mdx) — two tables under the brand header:
 *   Table 1 "Domain health": one row per monitored domain, six TEST cells from its newest run,
 *   a ▶ play button that runs checks for just that domain, and a ⋮ menu. Row click → newest report.
 *   Table 2 "Runs": one row per RUN (per-domain, startedAt/finishedAt), Date + Domain + the six
 *   test cells, a › chevron and a ⋮ menu. Row click → that run's report.
 * Top-right: Run checks (all domains) and the scheduled-checks toggle with its chevron.
 */
export function DashboardPage() {
  const { data: domains, isLoading } = useDomains()
  const { data: results } = useAuditResults()
  const { data: runs } = useAuditRuns()
  const runDomains = useScanRunner()
  const scanning = useScanProgress().length > 0
  const list = domains ?? []

  // Fan out one scan per domain so they run in parallel and each shows its own progress card
  // (pm/progress_ui.mdx §4.1); the dock drains card-by-card as domains finish.
  const onRunChecks = () => runDomains(list.map((d) => ({ id: d.id, name: d.name })))

  return (
    <div className="mx-auto max-w-6xl">
      <header className="mb-8 flex items-start justify-between gap-4">
        <BrandHeader />
        <div className="flex shrink-0 flex-col items-end gap-2">
          <button
            type="button"
            onClick={onRunChecks}
            disabled={scanning || list.length === 0}
            className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
          >
            <RefreshCw className={scanning ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
            {scanning ? "Running…" : "Run checks"}
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
        <>
          <DomainHealthTable domains={list} results={results ?? []} />
          <RunsTable runs={runs ?? []} />
        </>
      )}
    </div>
  )
}

/* ------------------------------------------------------------------------------------------------
 * Table 1 — Domain health (pm/dashboard.mdx §4.1): one row per domain, cells from the newest run.
 * Row click → newest report; ▶ runs just that domain; ⋮ menu carries the domain actions.
 * ---------------------------------------------------------------------------------------------- */
function DomainHealthTable({
  domains,
  results,
}: {
  domains: MonitoredDomain[]
  results: AuditResult[]
}) {
  const navigate = useNavigate()
  const runDomains = useScanRunner()
  const progress = useScanProgress()
  const updateDomain = useUpdateDomain()
  const deleteDomain = useDeleteDomain()
  const byId = new Map(results.map((r) => [r.domainId, r]))

  const onDelete = (d: MonitoredDomain) => {
    if (window.confirm(`Delete ${d.name}? Its run history stays until each run is deleted.`)) {
      deleteDomain.mutate(d.id)
    }
  }

  return (
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
            <th className="px-2 py-2" aria-label="Row actions" />
          </tr>
        </thead>
        <tbody>
          {domains.map((d) => {
            const cells = rollupCategories(byId.get(d.id)?.findings)
            const domainScanning = progress.some((s) => s.domainId === d.id)
            return (
              <tr
                key={d.id}
                onClick={() => navigate({ to: "/domains/$id", params: { id: d.id } })}
                className="cursor-pointer border-t border-[var(--edh-border)] hover:bg-slate-50"
              >
                <td className="px-4 py-3 font-medium">{d.name}</td>
                {CATEGORIES.map((c) => {
                  // The one exception to whole-row navigation (pm/dashboard.mdx §6): tests with a
                  // full page get a chevron that goes INSIDE that test.
                  const techRoute = techPageRoute(c.key)
                  return (
                    <td key={c.key} className="px-2 py-2">
                      {techRoute ? (
                        <span className="group flex items-center gap-1">
                          <StatusCell status={cells[c.key] ?? NEVER_CELL} />
                          <Link
                            to={techRoute}
                            params={{ id: d.id }}
                            onClick={(e) => e.stopPropagation()}
                            aria-label={`Open the ${c.header} page for ${d.name}`}
                            className="text-[var(--edh-muted)] opacity-0 transition-opacity hover:text-slate-700 group-hover:opacity-100"
                          >
                            <ChevronRight className="h-4 w-4" />
                          </Link>
                        </span>
                      ) : (
                        <StatusCell status={cells[c.key] ?? NEVER_CELL} />
                      )}
                    </td>
                  )
                })}
                <td className="px-2 py-2">
                  <span
                    className="flex items-center justify-end gap-1"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <button
                      type="button"
                      onClick={() => runDomains([{ id: d.id, name: d.name }])}
                      disabled={domainScanning}
                      aria-label={`Run checks for ${d.name}`}
                      title={`Run checks for ${d.name}`}
                      className="rounded p-1 text-[var(--edh-primary)] hover:bg-slate-100 disabled:opacity-50"
                    >
                      {domainScanning ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Play className="h-4 w-4" />
                      )}
                    </button>
                    <RowMenu
                      label={`Actions for ${d.name}`}
                      items={[
                        {
                          label: "Run checks now",
                          onClick: () => runDomains([{ id: d.id, name: d.name }]),
                        },
                        {
                          label: "Open newest report",
                          onClick: () => navigate({ to: "/domains/$id", params: { id: d.id } }),
                        },
                        { label: "Edit domain", onClick: () => navigate({ to: "/domains" }) },
                        {
                          label: d.scheduleEnabled
                            ? "Scheduled checks: turn off"
                            : "Scheduled checks: turn on",
                          onClick: () =>
                            updateDomain.mutate({
                              id: d.id,
                              input: { scheduleEnabled: !d.scheduleEnabled },
                            }),
                        },
                        { label: "Delete domain", danger: true, onClick: () => onDelete(d) },
                      ]}
                    />
                  </span>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

/* ------------------------------------------------------------------------------------------------
 * Table 2 — Runs (pm/dashboard.mdx §4.2): one row per run, newest startedAt first. Date + Domain +
 * six test cells; the › chevron and the row click both open that run's report; ⋮ menu per run.
 * ---------------------------------------------------------------------------------------------- */
function RunsTable({ runs }: { runs: AuditResult[] }) {
  const navigate = useNavigate()
  const runDomains = useScanRunner()
  const deleteRun = useDeleteRun()
  const shown = runs.slice(0, 100)

  const openRun = (r: AuditResult) => {
    if (r.runId) {
      navigate({ to: "/domains/$id/runs/$runId", params: { id: r.domainId, runId: r.runId } })
    } else {
      navigate({ to: "/domains/$id", params: { id: r.domainId } })
    }
  }

  return (
    <section className="mt-8">
      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-900">Runs</h2>
      {shown.length === 0 ? (
        <div className="rounded-lg border border-dashed border-[var(--edh-border)] p-6 text-center text-slate-600">
          No runs yet. Press <span className="font-medium">Run checks</span> to create the first
          one.
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs uppercase text-[var(--edh-muted)]">
              <tr>
                <th className="px-4 py-2">Date</th>
                <th className="px-4 py-2">Domain</th>
                {CATEGORIES.map((c) => (
                  <th key={c.key} className="px-2 py-2 text-center">
                    {c.header}
                  </th>
                ))}
                <th className="px-2 py-2" aria-label="Row actions" />
              </tr>
            </thead>
            <tbody>
              {shown.map((r) => {
                const cells = rollupCategories(r.findings)
                return (
                  <tr
                    key={r.runId ?? `${r.domainId}-${r.ranAt}`}
                    onClick={() => openRun(r)}
                    className="cursor-pointer border-t border-[var(--edh-border)] hover:bg-slate-50"
                  >
                    <td className="whitespace-nowrap px-4 py-3 font-medium tabular-nums">
                      {fmtRunDate(r.startedAt ?? r.ranAt)}
                    </td>
                    <td className="px-4 py-3">{r.domain}</td>
                    {CATEGORIES.map((c) => (
                      <td key={c.key} className="px-2 py-2">
                        <StatusCell status={cells[c.key] ?? NEVER_CELL} />
                      </td>
                    ))}
                    <td className="px-2 py-2">
                      <span
                        className="flex items-center justify-end gap-1"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <button
                          type="button"
                          onClick={() => openRun(r)}
                          aria-label={`Open the ${r.domain} run report`}
                          title="Open this run's report"
                          className="rounded p-1 text-[var(--edh-muted)] hover:bg-slate-100 hover:text-slate-700"
                        >
                          <ChevronRight className="h-4 w-4" />
                        </button>
                        <RowMenu
                          label={`Actions for the ${r.domain} run`}
                          items={[
                            { label: "Open report", onClick: () => openRun(r) },
                            {
                              label: "Run checks again",
                              onClick: () => runDomains([{ id: r.domainId, name: r.domain }]),
                            },
                            {
                              label: "Delete run",
                              danger: true,
                              onClick: () => {
                                if (r.runId && window.confirm("Delete this run from the history?")) {
                                  deleteRun.mutate(r.runId)
                                }
                              },
                            },
                          ]}
                        />
                      </span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

/** `YYYY-MM-DD HH:mm` in local time (pm/dashboard.mdx §4.2). */
function fmtRunDate(iso: string): string {
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/**
 * The ⋮ triple-dot pull-down on every row of both tables (pm/dashboard.mdx §4.3/§4.4). A plain
 * button + absolutely-positioned menu; the invisible fixed backdrop closes it on any outside click.
 */
function RowMenu({
  label,
  items,
}: {
  label: string
  items: { label: string; danger?: boolean; onClick: () => void }[]
}) {
  const [open, setOpen] = useState(false)
  return (
    <span className="relative inline-block">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        className="rounded p-1 text-[var(--edh-muted)] hover:bg-slate-100 hover:text-slate-700"
      >
        <MoreVertical className="h-4 w-4" />
      </button>
      {open && (
        <>
          <span
            className="fixed inset-0 z-10"
            aria-hidden="true"
            onClick={() => setOpen(false)}
          />
          <div
            role="menu"
            className="absolute right-0 z-20 mt-1 w-56 rounded-md border border-[var(--edh-border)] bg-white py-1 shadow-lg"
          >
            {items.map((item) => (
              <button
                key={item.label}
                type="button"
                role="menuitem"
                onClick={() => {
                  setOpen(false)
                  item.onClick()
                }}
                className={`block w-full px-3 py-2 text-left text-sm hover:bg-slate-100 ${
                  item.danger ? "text-red-700" : "text-slate-900"
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>
        </>
      )}
    </span>
  )
}

/**
 * The recurring-checks on/off switch with a chevron to the scheduling page (pm/dashboard.mdx §7.2).
 * The on/off preference is stored client-side for now (the first-round backend enables periodic
 * audits via EDH_PERIODIC_AUDIT_MINUTES); the chevron always routes to the scheduling settings.
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
