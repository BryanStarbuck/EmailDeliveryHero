import { Link, useNavigate, useParams } from "@tanstack/react-router"
import { ArrowLeft, ChevronRight, RefreshCw, Wrench } from "lucide-react"
import { useAuditResults, useAuditRun } from "@/api/audit"
import { useDomains } from "@/api/domains"
import type { Finding } from "@/api/types"
import { ScoreBadge, SeverityBadge } from "@/components/Badges"
import { CopyFixButton } from "@/components/CopyFixButton"
import { StatusCell } from "@/components/StatusCell"
import {
  CATEGORIES,
  categoryOf,
  NEVER_CELL,
  rollupCategories,
  techPageRoute,
} from "@/lib/categories"
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext"

const ORDER = { critical: 0, warning: 1, info: 2, ok: 3 } as const

/**
 * The run report (pm/ui.mdx §5, pm/dashboard.mdx §6) — one RUN in full: a summary header (score,
 * status, open-problem count, start/stop times), the six colored TEST chips, and every SUB-TEST
 * finding grouped by test with a Copy-fix control on each non-ok problem. Serves both routes:
 * /domains/$id (the domain's newest run) and /domains/$id/runs/$runId (a historical run from the
 * dashboard's Runs table).
 */
export function RunDetailPage() {
  const { id = "", runId } = useParams({ strict: false }) as { id?: string; runId?: string }
  const { data: domains } = useDomains()
  const { data: results } = useAuditResults()
  const { data: historicalRun } = useAuditRun(runId)
  const runDomains = useScanRunner()
  const scanning = useScanProgress().some((s) => s.domainId === id)
  const navigate = useNavigate()

  const domain = (domains ?? []).find((d) => d.id === id)
  const result = runId ? historicalRun : (results ?? []).find((r) => r.domainId === id)
  const cells = rollupCategories(result?.findings)

  // Runs through the shared scan runner so a "Running <domain>" card shows in the dock.
  const onRunAgain = () => runDomains([{ id, name: domain?.name ?? id }])

  const openProblems = result ? result.counts.warning + result.counts.critical : 0

  return (
    <div className="mx-auto max-w-4xl">
      <div className="mb-4 flex items-center justify-between">
        <button
          type="button"
          onClick={() => navigate({ to: "/" })}
          className="inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
        >
          <ArrowLeft className="h-4 w-4" /> Back to dashboard
        </button>
        <button
          type="button"
          onClick={onRunAgain}
          disabled={scanning}
          className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
        >
          <RefreshCw className={scanning ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
          Run checks again
        </button>
      </div>

      <h1 className="text-2xl font-bold">{domain?.name ?? id}</h1>

      {!result ? (
        <div className="mt-6 rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center">
          <p className="text-slate-600">Not yet audited.</p>
          <button
            type="button"
            onClick={onRunAgain}
            className="mt-2 inline-flex items-center gap-2 text-[var(--edh-primary)] underline"
          >
            Run checks
          </button>
        </div>
      ) : (
        <>
          <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-[var(--edh-muted)]">
            <ScoreBadge score={result.score} />
            <SeverityBadge severity={result.status} />
            <span>
              {openProblems} open problem{openProblems === 1 ? "" : "s"}
            </span>
            <span>
              · started {new Date(result.startedAt ?? result.ranAt).toLocaleString()}
              {result.finishedAt && <> · finished {new Date(result.finishedAt).toLocaleString()}</>}
            </span>
          </div>

          {/* Six category chips, colored to match the Dashboard cells. */}
          <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
            {CATEGORIES.map((c) => {
              // Chevron to the category's full-page technology view (pm/checks/*.mdx §6.1).
              const techRoute = techPageRoute(c.key)
              return (
                <a key={c.key} href={`#cat-${c.key}`} className="block">
                  <div className="mb-1 flex items-center justify-center gap-1 text-center text-[11px] font-medium text-[var(--edh-muted)]">
                    {c.header}
                    {techRoute && (
                      <Link
                        to={techRoute}
                        params={{ id }}
                        aria-label={`Open the ${c.header} page`}
                        className="hover:text-slate-700"
                      >
                        <ChevronRight className="h-3.5 w-3.5" />
                      </Link>
                    )}
                  </div>
                  <StatusCell status={cells[c.key] ?? NEVER_CELL} />
                </a>
              )
            })}
          </div>

          {/* Findings grouped by the six categories. */}
          <div className="mt-6 space-y-5">
            {CATEGORIES.map((c) => {
              const findings = result.findings
                .filter((f) => categoryOf(f.checkId) === c.key)
                .sort((a, b) => ORDER[a.severity] - ORDER[b.severity])
              if (findings.length === 0) return null
              const problems = findings.filter(
                (f) => f.severity === "warning" || f.severity === "critical",
              ).length
              return (
                <section key={c.key} id={`cat-${c.key}`}>
                  <div className="mb-2 flex items-center justify-between">
                    <h2 className="font-semibold">{c.header}</h2>
                    <span className="text-xs text-[var(--edh-muted)]">
                      {problems === 0
                        ? "all healthy"
                        : `${problems} problem${problems === 1 ? "" : "s"}`}
                    </span>
                  </div>
                  <ul className="space-y-2">
                    {findings.map((f) => (
                      <FindingRow key={f.id} finding={f} />
                    ))}
                  </ul>
                </section>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}

function FindingRow({ finding: f }: { finding: Finding }) {
  const showFix = f.severity !== "ok" && Boolean(f.remediation)
  return (
    <li className="rounded-lg border border-[var(--edh-border)] bg-white p-3">
      <div className="flex items-center gap-2">
        <SeverityBadge severity={f.severity} />
        <span className="font-medium">{f.title}</span>
        <span className="text-xs uppercase text-[var(--edh-muted)]">{f.checkId}</span>
      </div>
      <p className="mt-1 text-sm text-slate-600">{f.detail}</p>
      {f.evidence && (
        <p className="mt-1 break-all font-mono text-xs text-slate-500">{f.evidence}</p>
      )}
      {showFix && f.remediation && (
        <div className="mt-2 flex items-start justify-between gap-2 rounded-md bg-slate-50 p-2 text-sm text-slate-700">
          <span className="flex items-start gap-2">
            <Wrench className="mt-0.5 h-4 w-4 shrink-0 text-[var(--edh-primary)]" />
            <span>
              <span className="font-medium">Fix: </span>
              {f.remediation}
            </span>
          </span>
          <CopyFixButton text={f.evidence ?? f.remediation} />
        </div>
      )}
    </li>
  )
}
