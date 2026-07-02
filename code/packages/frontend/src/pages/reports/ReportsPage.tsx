import { Link, useNavigate } from "@tanstack/react-router"
import { ChevronRight, Mailbox } from "lucide-react"
import { useEffect } from "react"
import { toast } from "sonner"
import { useAuditRuns, useDeleteRun } from "@/api/audit"
import { useDomains } from "@/api/domains"
import type { AuditResult } from "@/api/types"
import { ScoreBadge } from "@/components/Badges"
import { RowMenu } from "@/components/RowMenu"
import { StatusCell } from "@/components/StatusCell"
import { CATEGORIES, NEVER_CELL, rollupCategories } from "@/lib/categories"
import { useScanRunner } from "@/scan/ScanProgressContext"

/** The library shows the newest N reports across all domains (pm/reports.mdx §3.2). */
const NEWEST = 10

/**
 * The Reports page (pm/reports.mdx) — the report library. A report is the rendered view of one RUN;
 * this page is one stacked table of the newest 10 runs read from the on-disk run history
 * (GET /api/audit/runs → runs.json in the state dir). Clicking anywhere in a row opens that report
 * in the existing view-one-report design (/domains/$id/runs/$runId, RunDetailPage).
 */
export function ReportsPage() {
  const { data: runs, isLoading, isError, error } = useAuditRuns()
  const navigate = useNavigate()

  // Error state (pm/reports.mdx §5): the standard query-error toast; the page keeps its last
  // rendered rows if it has any (react-query retains the cached data on a failed refetch).
  useEffect(() => {
    if (isError) toast.error(errMsg(error, "Could not load the report history"))
  }, [isError, error])

  const all = runs ?? []
  const newest = all.slice(0, NEWEST)

  const openReport = (r: AuditResult) => {
    // Pre-history rows lack a runId (pm/reports.mdx §3.3) — fall back to the newest report.
    if (r.runId) {
      navigate({ to: "/domains/$id/runs/$runId", params: { id: r.domainId, runId: r.runId } })
    } else {
      navigate({ to: "/domains/$id", params: { id: r.domainId } })
    }
  }

  return (
    <div className="mx-auto max-w-6xl">
      <header className="mb-6">
        <h1 className="text-2xl font-bold">Reports</h1>
        <p className="mt-1 text-sm text-[var(--edh-muted)]">
          Every health-check run, newest first — click a report to open it.
        </p>
      </header>

      {isLoading ? (
        <SkeletonTable />
      ) : isError && runs === undefined ? (
        // A failed initial load has no rows to keep (§5) — say so rather than claiming "No reports".
        <div className="rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center">
          <p className="text-slate-600">Could not load the report history — see the error toast.</p>
        </div>
      ) : newest.length === 0 ? (
        <div className="rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center">
          <p className="text-slate-600">
            No reports yet. Run checks from the Dashboard and every run will file its report here.
          </p>
          <Link to="/" className="mt-2 inline-block text-[var(--edh-primary)] underline">
            Go to Dashboard →
          </Link>
        </div>
      ) : (
        <>
          <div className="overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 text-left text-xs uppercase text-[var(--edh-muted)]">
                <tr>
                  <th className="px-4 py-2">Date</th>
                  <th className="px-4 py-2">Domain</th>
                  <th className="px-2 py-2 text-center">Score</th>
                  {CATEGORIES.map((c) => (
                    <th key={c.key} className="px-2 py-2 text-center">
                      {c.header}
                    </th>
                  ))}
                  <th className="px-2 py-2" aria-label="Row actions" />
                </tr>
              </thead>
              <tbody>
                {newest.map((r) => (
                  <ReportRow
                    key={r.runId ?? `${r.domainId}-${r.ranAt}`}
                    run={r}
                    onOpen={openReport}
                  />
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-2 text-xs text-[var(--edh-muted)]">
            {all.length > NEWEST
              ? `Showing the newest ${NEWEST} of ${all.length} reports`
              : `${all.length} report${all.length === 1 ? "" : "s"}`}
          </p>
        </>
      )}

      <IngestedReportsSection />
    </div>
  )
}

/**
 * Second section (pm/emails.mdx §7.1 / left_bar.yaml): the INGESTED report emails — DMARC
 * aggregate (rua) and TLS-RPT reports receivers mailed back. One row per monitored domain,
 * opening that domain's Reports view (problems, per-source tables, Ingest now).
 */
function IngestedReportsSection() {
  const { data: domains } = useDomains()
  const list = domains ?? []
  return (
    <section className="mt-10">
      <header className="mb-3 flex items-center gap-2">
        <Mailbox className="h-5 w-5 text-[var(--edh-primary)]" />
        <h2 className="text-lg font-semibold">Report emails (DMARC rua &amp; TLS-RPT)</h2>
      </header>
      <p className="mb-3 text-sm text-[var(--edh-muted)]">
        The machine reports receivers send back to your domains — who sent mail as you and whether
        it authenticated, and whether inbound TLS worked. Open a domain to see the ingested reports,
        the problems they reveal, and the fixes.
      </p>
      {list.length === 0 ? (
        <div className="rounded-lg border border-dashed border-[var(--edh-border)] p-6 text-center text-sm text-slate-600">
          Add a domain first — then publish rua= on its DMARC / TLS-RPT records to receive reports.
        </div>
      ) : (
        <ul className="overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
          {list.map((d) => (
            <li key={d.id} className="border-t border-[var(--edh-border)] first:border-t-0">
              <Link
                to="/domains/$id/reports"
                params={{ id: d.id }}
                className="flex items-center justify-between px-4 py-3 text-sm hover:bg-slate-50"
              >
                <span className="font-medium">{d.name}</span>
                <span className="inline-flex items-center gap-1 text-[var(--edh-muted)]">
                  Ingested reports <ChevronRight className="h-4 w-4" />
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

function ReportRow({ run, onOpen }: { run: AuditResult; onOpen: (r: AuditResult) => void }) {
  // Pass the run's structured results too so the DKIM/DMARC metric text matches the Dashboard's
  // Runs table exactly (pm/reports.mdx §3.2 — "same four colors and metric text rules").
  const cells = rollupCategories(run.findings, run.results)
  return (
    <tr
      onClick={() => onOpen(run)}
      className="cursor-pointer border-t border-[var(--edh-border)] hover:bg-slate-50"
    >
      <td className="whitespace-nowrap px-4 py-3 tabular-nums">
        {formatDate(run.startedAt ?? run.ranAt)}
      </td>
      <td className="px-4 py-3 font-medium">{run.domain}</td>
      <td className="px-2 py-2 text-center">
        <ScoreBadge score={run.score} />
      </td>
      {CATEGORIES.map((c) => (
        <td key={c.key} className="px-2 py-2">
          <StatusCell status={cells[c.key] ?? NEVER_CELL} />
        </td>
      ))}
      <td className="px-2 py-2">
        {/* Row controls (pm/reports.mdx §3.4) — every control stops propagation so a click never
            double-fires the whole-row navigation. */}
        <div className="flex items-center justify-end gap-1">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation()
              onOpen(run)
            }}
            aria-label={`Open the report for ${run.domain}`}
            className="text-[var(--edh-muted)] hover:text-slate-700"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
          <ReportMenu run={run} onOpen={onOpen} />
        </div>
      </td>
    </tr>
  )
}

/** The ⋮ menu — Open report / Run checks again / Delete report (pm/reports.mdx §3.4). */
function ReportMenu({ run, onOpen }: { run: AuditResult; onOpen: (r: AuditResult) => void }) {
  const runDomains = useScanRunner()
  const del = useDeleteRun()

  const onRunAgain = () => {
    runDomains([{ id: run.domainId, name: run.domain }])
  }

  const onDelete = () => {
    if (!window.confirm(`Delete this report for ${run.domain}? The domain itself is unaffected.`)) {
      return
    }
    if (!run.runId) {
      toast.error("This legacy report has no run id and cannot be deleted individually.")
      return
    }
    del.mutate(run.runId, {
      onSuccess: () => toast.success(`Deleted the report for ${run.domain}`),
      onError: (err) => toast.error(errMsg(err, "Could not delete the report")),
    })
  }

  return (
    <RowMenu
      label={`Actions for the ${run.domain} report`}
      items={[
        { label: "Open report", onClick: () => onOpen(run) },
        { label: "Run checks again", onClick: onRunAgain },
        { label: "Delete report", danger: true, onClick: onDelete },
      ]}
    />
  )
}

/** `YYYY-MM-DD HH:mm` in local time (pm/reports.mdx §3.2). */
function formatDate(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function SkeletonTable() {
  return (
    <div className="space-y-2">
      {Array.from({ length: NEWEST }, (_, i) => `row-${i}`).map((k) => (
        <div key={k} className="h-11 animate-pulse rounded-md bg-slate-100" />
      ))}
    </div>
  )
}

function errMsg(err: unknown, fallback: string): string {
  const e = err as { response?: { data?: { message?: string | string[] } } }
  const m = e?.response?.data?.message
  if (Array.isArray(m)) return m.join(", ")
  return m ?? fallback
}
