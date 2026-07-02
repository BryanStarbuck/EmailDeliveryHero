import { Link, useNavigate, useParams } from "@tanstack/react-router"
import { ArrowLeft, ChevronDown, ChevronLeft, ChevronRight, RefreshCw, Wrench } from "lucide-react"
import { createContext, useContext, useState } from "react"
import { toast } from "sonner"
import { useAuditResults, useAuditRun, useDomainRuns, useRunDnsChecks } from "@/api/audit"
import { useRescoreContent } from "@/api/content-sample"
import { useDomains } from "@/api/domains"
import { useSettings } from "@/api/settings"
import type { AuditResult, ContentScoreResults, Finding, Severity } from "@/api/types"
import { ScoreBadge, SeverityBadge } from "@/components/Badges"
import { CopyFixButton } from "@/components/CopyFixButton"
import { RemediationText } from "@/components/FindingsList"
import { StatusCell } from "@/components/StatusCell"
import {
  CATEGORIES,
  type CategoryKey,
  categoryOf,
  NEVER_CELL,
  rollupCategories,
} from "@/lib/categories"
import { isContentScoringFinding } from "@/lib/content-scoring"
import {
  DMARC_CHECK_UNITS,
  dmarcBandOrder,
  dmarcUnitForFindingId,
  dmarcUnitResult,
  type UnitResult,
} from "@/lib/dmarc-checks"
import { rollupFamilies } from "@/lib/dns-families"
import {
  computeRunDiff,
  isProblem,
  type RegressionMode,
  type RunAnnotation,
  type RunDiff,
} from "@/lib/run-diff"
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext"
import { FiredRulesPanel } from "./ContentScoringPage"

const ORDER = { critical: 0, warning: 1, info: 2, ok: 3 } as const

/**
 * The run report's regression context (pm/use_cases/view_health_check_run.mdx §7): the current
 * run's vs-previous-run diff plus the active All | New | Resolved filter, threaded to every
 * FindingRow so each problem row carries a NEW / STILL PRESENT badge and the filter can hide rows
 * without every sub-group re-plumbing the diff. `null` when there is no prior run to diff against.
 */
const RunDiffContext = createContext<{ diff: RunDiff; mode: RegressionMode } | null>(null)

/** How many sub-tests pass in a category (ok/info) vs total — the §5 "X of Y pass" line. */
function passOf(findings: Finding[]): { pass: number; total: number } {
  const total = findings.length
  const pass = findings.filter((f) => !isProblem(f)).length
  return { pass, total }
}

/**
 * Discriminated-union link props to a category section's run page (the §5 "Open ›" chevron and the
 * header chip chevrons). Run-scoped (`/domains/:id/runs/:runId/<slug>`, slugs spf/dkim/dmarc/
 * blacklists/dns) when a runId is known; the Spam & Content category has no run-scoped page yet so
 * it always opens the Content-scoring full page. Each branch returns a single concrete literal `to`
 * so the union spreads cleanly into TanStack Router's typed <Link>.
 */
function categoryPageLinkProps(catKey: CategoryKey, id: string, runId?: string) {
  if (runId) {
    switch (catKey) {
      case "spf":
        return { to: "/domains/$id/runs/$runId/spf" as const, params: { id, runId } }
      case "dkim":
        return { to: "/domains/$id/runs/$runId/dkim" as const, params: { id, runId } }
      case "dmarc":
        return { to: "/domains/$id/runs/$runId/dmarc" as const, params: { id, runId } }
      case "blacklists":
        return { to: "/domains/$id/runs/$runId/blacklists" as const, params: { id, runId } }
      case "dnsInfra":
        return { to: "/domains/$id/runs/$runId/dns" as const, params: { id, runId } }
      case "spamContent":
        return { to: "/domains/$id/content" as const, params: { id } }
    }
  }
  switch (catKey) {
    case "spf":
      return { to: "/domains/$id/spf" as const, params: { id } }
    case "dkim":
      return { to: "/domains/$id/dkim" as const, params: { id } }
    case "dmarc":
      return { to: "/domains/$id/dmarc" as const, params: { id } }
    case "blacklists":
      return { to: "/domains/$id/blacklists" as const, params: { id } }
    case "dnsInfra":
      return { to: "/domains/$id/dns" as const, params: { id } }
    case "spamContent":
      return { to: "/domains/$id/content" as const, params: { id } }
  }
}

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
  const { data: historicalRun, isLoading: runLoading, isError: runError } = useAuditRun(runId)
  const { data: domainRuns } = useDomainRuns(id)
  const runDomains = useScanRunner()
  const scanning = useScanProgress().some((s) => s.domainId === id)
  const navigate = useNavigate()

  const [mode, setMode] = useState<RegressionMode>("all")

  const domain = (domains ?? []).find((d) => d.id === id)
  const result = runId ? historicalRun : (results ?? []).find((r) => r.domainId === id)
  const cells = rollupCategories(result?.findings, result?.results)

  // Runs through the shared scan runner so a "Running <domain>" card shows in the dock.
  const onRunAgain = () => runDomains([{ id, name: domain?.name ?? id }])

  const openProblems = result ? result.counts.warning + result.counts.critical : 0
  // The vs-previous-run diff (§7) — NEW / STILL PRESENT / RESOLVED, computed from the domain's run
  // history so it works for any historical run, not just the newest.
  const diff = computeRunDiff(result ?? undefined, domainRuns)

  // A requested runId that resolved to nothing is a 404 "run not found" state (§2 / AC1) — distinct
  // from a domain that has simply never been audited.
  if (runId && !runLoading && (runError || !historicalRun)) {
    return (
      <div className="mx-auto max-w-4xl">
        <div className="mb-4">
          <button
            type="button"
            onClick={() => navigate({ to: "/" })}
            className="inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
          >
            <ArrowLeft className="h-4 w-4" /> Back to dashboard
          </button>
        </div>
        <div className="mt-6 rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center">
          <p className="font-medium text-slate-700">Run not found.</p>
          <p className="mt-1 text-sm text-slate-500">
            This health-check run no longer exists — it may have been pruned or deleted.
          </p>
          <button
            type="button"
            onClick={() => navigate({ to: "/" })}
            className="mt-3 inline-flex items-center gap-1 text-[var(--edh-primary)] underline"
          >
            <ArrowLeft className="h-4 w-4" /> Back to dashboard
          </button>
        </div>
      </div>
    )
  }

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

      <h1 className="text-2xl font-bold">{domain?.name ?? id} — run report</h1>

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
              {result.finishedAt && (
                <>
                  {" "}
                  · finished {new Date(result.finishedAt).toLocaleString()}
                  {formatDuration(result.startedAt, result.finishedAt) && (
                    <> · completed in {formatDuration(result.startedAt, result.finishedAt)}</>
                  )}
                </>
              )}
            </span>
          </div>

          {/* Six category chips, colored to match the Dashboard cells. */}
          <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
            {CATEGORIES.map((c) => {
              // Chevron to the category's full-page technology view (pm/checks/*.mdx §6.1).
              const chipLink = categoryPageLinkProps(c.key, id, runId ?? result.runId)
              return (
                <a key={c.key} href={`#cat-${c.key}`} className="block">
                  <div className="mb-1 flex items-center justify-center gap-1 text-center text-[11px] font-medium text-[var(--edh-muted)]">
                    {c.header}
                    {chipLink && (
                      <Link
                        {...chipLink}
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

          {/* The run switcher (§4.1): ‹ prev / next ›, a newest-first runs dropdown, and a NEWEST
              badge on the domain's most recent run. */}
          <RunSwitcher
            domainId={id}
            current={result}
            runs={domainRuns ?? []}
            viaAlias={!runId}
            onNavigate={(nextRunId) =>
              navigate({
                to: "/domains/$id/runs/$runId",
                params: { id, runId: nextRunId },
              })
            }
          />

          {/* The regression toggle (§7): filter to All | New | Resolved vs the previous run. Only
              shown when there is a prior run to diff against. */}
          {diff.hasPrev && (
            <div className="mt-4 flex flex-wrap items-center gap-2 rounded-md border border-[var(--edh-border)] bg-slate-50 px-3 py-2 text-sm">
              <span className="text-[var(--edh-muted)]">
                vs previous run
                {diff.prevRun?.startedAt && (
                  <> ({new Date(diff.prevRun.startedAt).toLocaleString()})</>
                )}
                :
              </span>
              <div className="inline-flex overflow-hidden rounded-md border border-[var(--edh-border)]">
                {(["all", "new", "resolved"] as const).map((m) => (
                  <button
                    key={m}
                    type="button"
                    onClick={() => setMode(m)}
                    className={`px-2.5 py-1 text-xs font-medium capitalize ${
                      mode === m
                        ? "bg-[var(--edh-primary)] text-white"
                        : "bg-white text-slate-600 hover:bg-slate-100"
                    }`}
                  >
                    {m}
                    {m === "new" && diff.annotationById.size > 0 && (
                      <> ({[...diff.annotationById.values()].filter((a) => a === "new").length})</>
                    )}
                    {m === "resolved" && diff.resolved.length > 0 && <> ({diff.resolved.length})</>}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Findings grouped by the six categories — each a collapsible section (pm/ui.mdx §5):
              categories with problems open expanded; healthy categories collapse to a quiet
              "all healthy" line. Keyed by run so a fresh run resets the open/closed state. */}
          <RunDiffContext.Provider value={{ diff, mode }}>
            <div className="mt-6 space-y-5">
              {mode !== "resolved" &&
                CATEGORIES.map((c) => {
                  const findings = result.findings
                    .filter((f) => categoryOf(f.checkId) === c.key)
                    .sort((a, b) => ORDER[a.severity] - ORDER[b.severity])
                  if (findings.length === 0) return null
                  // In "new" mode, skip categories with no newly-appeared problems this run.
                  if (
                    mode === "new" &&
                    !findings.some((f) => diff.annotationById.get(f.id) === "new")
                  ) {
                    return null
                  }
                  return (
                    <CategorySection
                      key={`${c.key}-${result.runId ?? result.ranAt}`}
                      catKey={c.key}
                      header={c.header}
                      findings={findings}
                      domainId={id}
                      runId={runId ?? result.runId}
                      contentScore={
                        c.key === "spamContent"
                          ? (result.results?.["content.scoring"] as ContentScoreResults | undefined)
                          : undefined
                      }
                    />
                  )
                })}

              {/* RESOLVED sub-tests (§7): problems from the prior run that now pass, shown struck. */}
              {mode !== "new" && diff.resolved.length > 0 && (
                <ResolvedSection findings={diff.resolved} />
              )}
            </div>
          </RunDiffContext.Provider>
        </>
      )}
    </div>
  )
}

/** Human duration between two ISO instants, e.g. "3.1s" / "1m 04s"; null when either is absent. */
function formatDuration(startedAt?: string, finishedAt?: string): string | null {
  if (!startedAt || !finishedAt) return null
  const ms = new Date(finishedAt).getTime() - new Date(startedAt).getTime()
  if (!Number.isFinite(ms) || ms < 0) return null
  if (ms < 10_000) return `${(ms / 1000).toFixed(1)}s`
  const secs = Math.round(ms / 1000)
  if (secs < 60) return `${secs}s`
  const m = Math.floor(secs / 60)
  const s = secs % 60
  return `${m}m ${String(s).padStart(2, "0")}s`
}

/** A small severity dot used by the run switcher dropdown entries. */
function StatusDot({ severity }: { severity: Severity }) {
  const color =
    severity === "critical"
      ? "bg-red-500"
      : severity === "warning"
        ? "bg-amber-500"
        : severity === "info"
          ? "bg-slate-400"
          : "bg-emerald-500"
  return <span className={`h-2 w-2 shrink-0 rounded-full ${color}`} aria-hidden />
}

/**
 * The header run switcher (§4.1): ‹ prev / next › step chronologically through THIS domain's runs,
 * the current run's timestamp renders as a dropdown listing every run newest-first with a status
 * dot, and a NEWEST badge marks the most recent run (always the case when arriving via the
 * /domains/:id newest-run alias).
 */
function RunSwitcher({
  domainId: _domainId,
  current,
  runs,
  viaAlias,
  onNavigate,
}: {
  domainId: string
  current: AuditResult
  runs: AuditResult[]
  viaAlias: boolean
  onNavigate: (runId: string) => void
}) {
  const [open, setOpen] = useState(false)
  const idx = current.runId ? runs.findIndex((r) => r.runId === current.runId) : 0
  const newer = idx > 0 ? runs[idx - 1] : undefined // next › (chronologically later)
  const older = idx >= 0 ? runs[idx + 1] : undefined // ‹ prev (chronologically earlier)
  const isNewest = viaAlias || idx === 0
  const currentStamp = current.startedAt
    ? new Date(current.startedAt).toLocaleString()
    : new Date(current.ranAt).toLocaleString()

  return (
    <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
      <button
        type="button"
        disabled={!older?.runId}
        onClick={() => older?.runId && onNavigate(older.runId)}
        className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-medium hover:bg-slate-50 disabled:opacity-40"
      >
        <ChevronLeft className="h-3.5 w-3.5" /> prev run
      </button>

      <div className="relative">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="inline-flex items-center gap-1.5 rounded-md border border-[var(--edh-border)] px-2.5 py-1 text-xs font-medium hover:bg-slate-50"
        >
          <StatusDot severity={current.status} />
          {currentStamp}
          <ChevronDown className="h-3.5 w-3.5 text-[var(--edh-muted)]" />
        </button>
        {open && runs.length > 0 && (
          <ul className="absolute left-0 z-10 mt-1 max-h-72 w-64 overflow-auto rounded-md border border-[var(--edh-border)] bg-white py-1 shadow-lg">
            {runs.map((r) => (
              <li key={r.runId ?? r.startedAt ?? r.ranAt}>
                <button
                  type="button"
                  disabled={!r.runId}
                  onClick={() => {
                    setOpen(false)
                    if (r.runId) onNavigate(r.runId)
                  }}
                  className={`flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-slate-50 disabled:opacity-40 ${
                    r.runId === current.runId ? "font-semibold text-[var(--edh-primary)]" : ""
                  }`}
                >
                  <StatusDot severity={r.status} />
                  {r.startedAt
                    ? new Date(r.startedAt).toLocaleString()
                    : new Date(r.ranAt).toLocaleString()}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <button
        type="button"
        disabled={!newer?.runId}
        onClick={() => newer?.runId && onNavigate(newer.runId)}
        className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-medium hover:bg-slate-50 disabled:opacity-40"
      >
        next run <ChevronRight className="h-3.5 w-3.5" />
      </button>

      {isNewest && (
        <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-emerald-800">
          Newest
        </span>
      )}
    </div>
  )
}

/**
 * The RESOLVED group (§7): sub-tests that were a problem in the prior run and now pass, shown as
 * cleared/struck items so the user sees progress. Sourced from the previous run's findings.
 */
function ResolvedSection({ findings }: { findings: Finding[] }) {
  return (
    <section>
      <h2 className="mb-2 font-semibold text-green-800">
        Resolved since last run ({findings.length})
      </h2>
      <ul className="space-y-2">
        {findings.map((f) => (
          <li
            key={f.id}
            className="flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50 p-3"
          >
            <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-emerald-800">
              Resolved
            </span>
            <span className="font-medium text-slate-500 line-through">{f.title}</span>
            <span className="text-xs uppercase text-[var(--edh-muted)]">{f.checkId}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}

/**
 * One collapsible category section (pm/ui.mdx §5). Sections with open problems start expanded;
 * all-healthy sections start collapsed to their quiet "all healthy" header line.
 */
function CategorySection({
  catKey,
  header,
  findings,
  domainId,
  runId,
  contentScore,
}: {
  catKey: CategoryKey
  header: string
  findings: Finding[]
  domainId: string
  runId?: string
  contentScore?: ContentScoreResults
}) {
  const problems = findings.filter(
    (f) => f.severity === "warning" || f.severity === "critical",
  ).length
  const [open, setOpen] = useState(problems > 0)
  // §5 header metrics: the "X of Y pass" sub-test count, the single worst open problem, and the
  // per-section "Open ›" chevron to this category's run page.
  const { pass, total } = passOf(findings)
  const topProblem = findings.find(isProblem)
  const openLink = categoryPageLinkProps(catKey, domainId, runId)

  // ARC rolls into the DMARC cell but renders as its own labelled advisory sub-group inside the
  // expanded DMARC section (pm/checks/arc.mdx §4 — "DMARC ▸ ARC (Authenticated Received Chain)").
  const arcFindings = catKey === "dmarc" ? findings.filter((f) => f.checkId === "arc") : []
  // BIMI rolls into the Spam & Content cell but renders grouped under its own "BIMI" subhead
  // inside that section (pm/checks/bimi.mdx §4 — "Spam & Content › BIMI").
  const bimiFindings =
    catKey === "spamContent" ? findings.filter((f) => f.checkId === "content.bimi") : []
  // Content scoring renders grouped under its own "Content scoring" subhead with the score gauge,
  // sample line, fired-rule rows, and actions (pm/checks/content_scoring.mdx §4 — "Spam &
  // Content ▸ Content scoring", §8 AC 8).
  const contentScoringFindings =
    catKey === "spamContent" ? findings.filter(isContentScoringFinding) : []
  const mainFindings = findings.filter(
    (f) =>
      !(arcFindings.length > 0 && f.checkId === "arc") &&
      !(bimiFindings.length > 0 && f.checkId === "content.bimi") &&
      !(contentScoringFindings.length > 0 && isContentScoringFinding(f)),
  )
  // A bogus DNSSEC chain is a domain-wide outage: when infra.dnssec_validates is critical the
  // DNS & Infrastructure group carries a "Domain may be unresolvable" banner and the (already
  // severity-sorted) finding sits at the top of the group (pm/checks/dnssec.mdx §4).
  const dnssecBogus =
    catKey === "dnsInfra" &&
    findings.some((f) => f.checkId === "infra.dnssec_validates" && f.severity === "critical")

  return (
    <section id={`cat-${catKey}`}>
      <div className="mb-2 flex items-center gap-2">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          className="flex flex-1 items-center justify-between text-left"
        >
          <h2 className="flex items-center gap-1 font-semibold">
            {open ? (
              <ChevronDown className="h-4 w-4 shrink-0 text-[var(--edh-muted)]" />
            ) : (
              <ChevronRight className="h-4 w-4 shrink-0 text-[var(--edh-muted)]" />
            )}
            {header}
          </h2>
          <span
            className={`text-xs ${problems === 0 ? "text-green-800" : "text-[var(--edh-muted)]"}`}
          >
            {pass} of {total} pass
          </span>
        </button>
        {openLink && (
          <Link
            {...openLink}
            className="inline-flex shrink-0 items-center gap-0.5 rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-medium text-[var(--edh-primary)] hover:bg-slate-50"
            aria-label={`Open the ${header} page for this run`}
          >
            Open <ChevronRight className="h-3.5 w-3.5" />
          </Link>
        )}
      </div>
      {/* The single worst open sub-test — a triage line so a scan down the page reads like a
          triage list (§5). Omitted when all pass. */}
      {topProblem && (
        <p className="mb-2 text-xs text-[var(--edh-muted)]">
          top problem: <span className="font-medium text-slate-700">{topProblem.title}</span>
        </p>
      )}
      {open && (
        <>
          {dnssecBogus && (
            <div
              role="alert"
              className="mb-2 rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm font-medium text-red-800"
            >
              Domain may be unresolvable — the DNSSEC chain is bogus, so validating resolvers
              (including most large mailbox providers) SERVFAIL every lookup for this domain.
            </div>
          )}
          {catKey === "dnsInfra" ? (
            <DnsInfraSubGroup findings={mainFindings} domainId={domainId} runId={runId} />
          ) : catKey === "dmarc" ? (
            <>
              {/* §6.6 item 2: the condensed per-unit mini-list above the finding rows. */}
              <DmarcSubGroup findings={findings} domainId={domainId} runId={runId} />
              <ul className="mt-3 space-y-2">
                {mainFindings.map((f) => (
                  <FindingRow
                    key={f.id}
                    finding={f}
                    explainerKey={dmarcUnitForFindingId(f.id)?.key}
                    domainId={domainId}
                    runId={runId}
                  />
                ))}
              </ul>
            </>
          ) : (
            <ul className="space-y-2">
              {mainFindings.map((f) => (
                <FindingRow key={f.id} finding={f} domainId={domainId} runId={runId} />
              ))}
            </ul>
          )}
          {arcFindings.length > 0 && (
            <ArcSubGroup findings={arcFindings} domainId={domainId} runId={runId} />
          )}
          {bimiFindings.length > 0 && <BimiSubGroup findings={bimiFindings} />}
          {contentScoringFindings.length > 0 && (
            <ContentScoringSubGroup
              domainId={domainId}
              score={contentScore}
              findings={contentScoringFindings}
            />
          )}
        </>
      )}
    </section>
  )
}

/**
 * The grown DNS & Infrastructure section of the run report (pm/checks/dns.mdx §17 / AC 23). Beyond
 * the flat findings list it surfaces (1) the ten-family clickable status list — the primary
 * click-through layer, each row → that family's run-scoped check-detail explainer (§14.1); (3) the
 * fail-first finding rows capped at 5 with "+N more →" to the run-scoped category page; and (4) the
 * footer's category-scoped re-run (§15.1) plus "Open the full DNS report →". Every row navigates —
 * the "no dead ends" rule (§6.2 item 8 / AC 24). (The mail-path one-liner and per-family trend
 * glyphs — §17 item 2 and §16 — live on the full category page; this section stays the triage
 * digest.)
 */
function DnsInfraSubGroup({
  findings,
  domainId,
  runId,
}: {
  findings: Finding[]
  domainId: string
  runId?: string
}) {
  const runDns = useRunDnsChecks()
  const families = rollupFamilies(findings).filter((f) => f.findings.length > 0)
  const failFirst = [...findings].sort((a, b) => ORDER[a.severity] - ORDER[b.severity])
  const CAP = 5
  const capped = failFirst.slice(0, CAP)
  const overflow = failFirst.length - capped.length

  // Newest-run alias vs run-scoped, resolved as a discriminated union so the router types narrow.
  const checkLinkProps = (slug: string) =>
    runId
      ? {
          to: "/domains/$id/runs/$runId/dns/check/$checkKey" as const,
          params: { id: domainId, runId, checkKey: slug },
        }
      : {
          to: "/domains/$id/dns/check/$checkKey" as const,
          params: { id: domainId, checkKey: slug },
        }
  const categoryPageProps = runId
    ? { to: "/domains/$id/runs/$runId/dns" as const, params: { id: domainId, runId } }
    : { to: "/domains/$id/dns" as const, params: { id: domainId } }

  return (
    <div className="space-y-3">
      {/* The ten-family status list — the primary click-through layer (§17 item 1). */}
      <ul className="divide-y divide-[var(--edh-border)] rounded-md border border-[var(--edh-border)]">
        {families.map((fam) => (
          <li key={fam.def.key} className="flex items-center gap-2 px-3 py-2 text-sm">
            <SeverityDot severity={fam.worst ?? "ok"} />
            <span className="font-medium text-slate-700">{fam.def.label}</span>
            <span className="hidden truncate text-xs text-[var(--edh-muted)] md:inline">
              {fam.def.meaning}
            </span>
            <span className="ml-auto shrink-0 text-xs text-[var(--edh-muted)]">
              {fam.failCount === 0 ? "healthy" : `${fam.failCount} of ${fam.findings.length} fail`}
            </span>
            <Link
              {...checkLinkProps(fam.def.slug)}
              className="shrink-0 text-xs font-medium text-[var(--edh-primary)] hover:underline"
            >
              details ›
            </Link>
          </li>
        ))}
      </ul>

      {/* Fail-first finding rows, capped at 5 (§17 item 3). */}
      <ul className="space-y-2">
        {capped.map((f) => (
          <FindingRow key={f.id} finding={f} />
        ))}
      </ul>
      {overflow > 0 && (
        <Link
          {...categoryPageProps}
          className="inline-block text-xs font-medium text-[var(--edh-primary)] hover:underline"
        >
          +{overflow} more →
        </Link>
      )}

      {/* Footer: category-scoped re-run + the full run-scoped category page (§17 item 4). */}
      <div className="flex flex-wrap items-center gap-3 pt-1">
        <button
          type="button"
          onClick={() =>
            runDns.mutate(domainId, {
              onSuccess: () => toast.success("DNS & Infrastructure re-run complete"),
              onError: (err) =>
                toast.error(`Re-run failed: ${err instanceof Error ? err.message : err}`),
            })
          }
          disabled={runDns.isPending}
          className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-medium hover:bg-slate-50 disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${runDns.isPending ? "animate-spin" : ""}`} />
          {runDns.isPending ? "Running…" : "Re-run DNS checks only"}
        </button>
        <Link
          {...categoryPageProps}
          className="text-xs font-medium text-[var(--edh-primary)] hover:underline"
        >
          Open the full DNS &amp; Infrastructure report →
        </Link>
      </div>
    </div>
  )
}

/** A small severity dot for the DNS family status list (pm/checks/dns.mdx §17 item 1). */
function SeverityDot({ severity }: { severity: Severity }) {
  const color =
    severity === "critical"
      ? "bg-red-500"
      : severity === "warning"
        ? "bg-amber-500"
        : severity === "info"
          ? "bg-slate-400"
          : "bg-emerald-500"
  return <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${color}`} aria-hidden />
}

/**
 * The Content-scoring sub-group inside the Spam & Content section (pm/checks/content_scoring.mdx
 * §4 — "Spam & Content ▸ Content scoring"). The header shows the headline SpamAssassin score as a
 * colored gauge chip (< 2 green, 2–5 amber, ≥ 5 red); beneath it the scored sample's
 * subject/from, one row per fired rule sorted by points descending with a copy-to-clipboard fix,
 * the grouped finding rows, and the Re-score / Upload-new-sample / View-raw actions (§8 AC 8).
 * Never-run / no-sample states show "Not scored yet."
 */
function ContentScoringSubGroup({
  domainId,
  score,
  findings,
}: {
  domainId: string
  score?: ContentScoreResults
  findings: Finding[]
}) {
  const rescore = useRescoreContent(domainId)
  const { data: settings } = useSettings()
  const problems = findings.filter(
    (f) => f.severity === "warning" || f.severity === "critical",
  ).length
  // Gauge banding mirrors the check's §3.5 severity bands; the inbox-safe target is the
  // admin-overridable setting (default 2.0), same value the backend bands with.
  const safeTarget = settings?.config.checks.content?.safeTarget ?? 2.0
  const gaugeStyle = score
    ? score.total_score >= score.threshold
      ? "bg-red-100 text-red-800"
      : score.total_score >= safeTarget
        ? "bg-amber-100 text-amber-800"
        : "bg-emerald-100 text-emerald-800"
    : null
  return (
    <div className="mt-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-700">
          Content scoring
          {score && gaugeStyle && (
            <span className={`rounded-md px-2 py-0.5 text-xs font-bold ${gaugeStyle}`}>
              {score.total_score.toFixed(1)} / {score.threshold.toFixed(1)}
            </span>
          )}
        </h3>
        <span className="text-xs text-[var(--edh-muted)]">
          {problems === 0 ? "all healthy" : `${problems} problem${problems === 1 ? "" : "s"}`}
        </span>
      </div>
      {score ? (
        <p className="mb-2 text-xs text-[var(--edh-muted)]">
          sample:{" "}
          <span className="font-medium text-slate-700">"{score.subject ?? "(no subject)"}"</span>{" "}
          from {score.from_header ?? "(unknown sender)"} · scored{" "}
          {new Date(score.checked_at).toLocaleString()}
        </p>
      ) : (
        <p className="mb-2 text-xs text-[var(--edh-muted)]">Not scored yet.</p>
      )}
      {score && score.rules_fired.length > 0 && (
        <div className="mb-2">
          <FiredRulesPanel score={score} findings={findings} />
        </div>
      )}
      <ul className="space-y-2">
        {findings.map((f) => (
          <FindingRow key={f.id} finding={f} />
        ))}
      </ul>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() =>
            rescore.mutate(undefined, {
              onSuccess: () => toast.success("Content re-scored"),
              onError: (err) =>
                toast.error(`Re-score failed: ${err instanceof Error ? err.message : err}`),
            })
          }
          disabled={rescore.isPending}
          className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-medium hover:bg-slate-50 disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${rescore.isPending ? "animate-spin" : ""}`} />
          {rescore.isPending ? "Scoring…" : "Re-score"}
        </button>
        <Link
          to="/domains/$id/content"
          params={{ id: domainId }}
          className="rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-medium hover:bg-slate-50"
        >
          Upload new sample
        </Link>
        <Link
          to="/domains/$id/content"
          params={{ id: domainId }}
          className="rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-medium hover:bg-slate-50"
        >
          View raw .eml
        </Link>
      </div>
    </div>
  )
}

/**
 * The BIMI sub-group inside the Spam & Content section (pm/checks/bimi.mdx §4 — "Spam & Content ›
 * BIMI"). BIMI has no dashboard cell of its own; its content.bimi findings roll into the Spam &
 * Content cell but render under their own subhead here, with the logo/certificate preview panel
 * placeholder until the HTTPS/SVG/VMC validation round ships.
 */
function BimiSubGroup({ findings }: { findings: Finding[] }) {
  const problems = findings.filter(
    (f) => f.severity === "warning" || f.severity === "critical",
  ).length
  return (
    <div className="mt-3">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-700">BIMI (brand logo)</h3>
        <span className="text-xs text-[var(--edh-muted)]">
          {problems === 0 ? "all healthy" : `${problems} problem${problems === 1 ? "" : "s"}`}
        </span>
      </div>
      <ul className="space-y-2">
        {findings.map((f) => (
          <FindingRow key={f.id} finding={f} />
        ))}
      </ul>
      <p className="mt-2 text-xs text-[var(--edh-muted)]">
        Logo &amp; certificate validation (SVG Tiny-PS preview, VMC issuer/expiry) is a future
        round.
      </p>
    </div>
  )
}

/**
 * The ARC advisory sub-group inside the DMARC section (pm/checks/arc.mdx §4). ARC has no dashboard
 * cell of its own; its arc.* findings roll into the DMARC cell but are labelled separately here as
 * "forwarding preservation (advisory)". The "Capture sample…" action (the admin-gated
 * swaks-through-forwarder probe that unlocks the chain-validation sub-checks) ships in a later
 * round, so the affordance is present but disabled.
 */
function ArcSubGroup({
  findings,
  domainId,
  runId,
}: {
  findings: Finding[]
  domainId: string
  runId?: string
}) {
  return (
    <div className="mt-3">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-700">
          ARC (Authenticated Received Chain) — forwarding preservation
          <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium uppercase text-[var(--edh-muted)]">
            advisory
          </span>
        </h3>
        <button
          type="button"
          disabled
          title="Sends a real swaks probe through a declared forwarder to capture and validate the ARC chain. Admin-only; ships in a later round."
          className="rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs text-[var(--edh-muted)] opacity-60"
        >
          Capture sample…
        </button>
      </div>
      <ul className="space-y-2">
        {findings.map((f) => (
          // §6.6 item 3: ARC rows link to …/dmarc/check/arc.
          <FindingRow key={f.id} finding={f} explainerKey="arc" domainId={domainId} runId={runId} />
        ))}
      </ul>
    </div>
  )
}

/**
 * The run report's condensed per-unit DMARC mini-list (pm/checks/dmarc.mdx §6.6 items 1–2): the
 * count sub-line (N passed · M ⚠ · K ✗) plus one line per §6.3 registry unit (chip + name) linking
 * to the run-scoped explainer. Units that are all-pass collapse behind a trailing "✓ N more
 * passing" chip so the section stays triage-sized.
 */
function DmarcSubGroup({
  findings,
  domainId,
  runId,
}: {
  findings: Finding[]
  domainId: string
  runId?: string
}) {
  const [showPassing, setShowPassing] = useState(false)
  const rows = DMARC_CHECK_UNITS.map((unit) => ({
    unit,
    // No persisted tests[] here — derive the chip from this run's findings (the fallback path).
    result: dmarcUnitResult(unit, [], findings),
  }))
    .filter((r) => r.result !== null)
    .sort((a, b) => dmarcBandOrder(a.result) - dmarcBandOrder(b.result))
  const visible = rows.filter((r) => r.result !== "pass")
  const passing = rows.filter((r) => r.result === "pass")
  const counts = {
    pass: findings.filter((f) => f.severity === "ok").length,
    warn: findings.filter((f) => f.severity === "warning").length,
    fail: findings.filter((f) => f.severity === "critical").length,
  }
  const checkProps = (key: string) =>
    runId
      ? {
          to: "/domains/$id/runs/$runId/dmarc/check/$checkKey" as const,
          params: { id: domainId, runId, checkKey: key },
        }
      : {
          to: "/domains/$id/dmarc/check/$checkKey" as const,
          params: { id: domainId, checkKey: key },
        }
  const shown = showPassing ? [...visible, ...passing] : visible
  return (
    <div className="rounded-md border border-[var(--edh-border)] bg-slate-50 p-2">
      <div className="mb-1 px-1 text-xs text-[var(--edh-muted)]">
        {counts.pass} passed · {counts.warn} ⚠ · {counts.fail} ✗
      </div>
      <ul className="divide-y divide-[var(--edh-border)]">
        {shown.map(({ unit, result }) => (
          <li key={unit.key}>
            <Link
              {...checkProps(unit.key)}
              className="flex items-center gap-2 px-1 py-1.5 text-sm hover:bg-white"
            >
              <UnitDot result={result} />
              <span className="font-medium text-slate-700">{unit.title}</span>
              <ChevronRight className="ml-auto h-3.5 w-3.5 shrink-0 text-[var(--edh-muted)]" />
            </Link>
          </li>
        ))}
      </ul>
      {passing.length > 0 && !showPassing && (
        <button
          type="button"
          onClick={() => setShowPassing(true)}
          className="mt-1 inline-flex items-center gap-1 px-1 text-xs font-medium text-emerald-700 hover:underline"
        >
          ✓ {passing.length} more passing
        </button>
      )}
    </div>
  )
}

/** Small result dot for the DMARC mini-list rows (§6.6). */
function UnitDot({ result }: { result: UnitResult | null }) {
  const cls: Record<string, string> = {
    pass: "bg-emerald-600",
    info: "bg-slate-400",
    warn: "bg-amber-500",
    fail: "bg-red-600",
  }
  return (
    <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${cls[result ?? ""] ?? "bg-slate-300"}`} />
  )
}

function FindingRow({
  finding: f,
  explainerKey,
  domainId,
  runId,
}: {
  finding: Finding
  /** When set, a right-edge chevron links to the owning sub-test explainer (§6.6 item 3). */
  explainerKey?: string
  domainId?: string
  runId?: string
}) {
  // §7 regression annotation + the All | New | Resolved filter, read from the run-report context.
  const ctx = useContext(RunDiffContext)
  const annotation: RunAnnotation | undefined = ctx?.diff.annotationById.get(f.id)
  const mode = ctx?.mode ?? "all"
  // In "new" mode show only newly-appeared problems; "resolved" rows render in their own section.
  if (mode === "new" && annotation !== "new") return null
  if (mode === "resolved") return null

  const showFix = f.severity !== "ok" && Boolean(f.remediation)
  const explainerProps =
    explainerKey && domainId
      ? runId
        ? {
            to: "/domains/$id/runs/$runId/dmarc/check/$checkKey" as const,
            params: { id: domainId, runId, checkKey: explainerKey },
          }
        : {
            to: "/domains/$id/dmarc/check/$checkKey" as const,
            params: { id: domainId, checkKey: explainerKey },
          }
      : null
  // Failing Blacklist sub-tests link to the delisting flow (§6 / AC6) — the run-scoped Blacklists
  // category page owns the blocklist-specific removal steps (pm/use_cases/domain_on_blacklist.mdx).
  const isBlacklist = categoryOf(f.checkId) === "blacklists"
  const delistProps =
    isBlacklist && isProblem(f) && domainId
      ? runId
        ? { to: "/domains/$id/runs/$runId/blacklists" as const, params: { id: domainId, runId } }
        : { to: "/domains/$id/blacklists" as const, params: { id: domainId } }
      : null
  return (
    <li className="rounded-lg border border-[var(--edh-border)] bg-white p-3">
      <div className="flex items-center gap-2">
        <SeverityBadge severity={f.severity} />
        <span className="font-medium">{f.title}</span>
        <span className="text-xs uppercase text-[var(--edh-muted)]">{f.checkId}</span>
        {/* Report-derived evidence chip (pm/emails.mdx §7.2): the finding came from an ingested
            DMARC-aggregate/TLS-RPT report email, not a live DNS lookup. */}
        {f.source === "report" && (
          <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[10px] uppercase tracking-wide text-slate-500">
            from reports
          </span>
        )}
        {/* §7 regression badge: NEW (regression) vs STILL PRESENT (carried over). */}
        {annotation === "new" && (
          <span className="rounded-full bg-fuchsia-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-fuchsia-800">
            New
          </span>
        )}
        {annotation === "still" && (
          <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-slate-500">
            Still present
          </span>
        )}
        {explainerProps && (
          <Link
            {...explainerProps}
            aria-label={`Explain ${f.title}`}
            className="ml-auto shrink-0 text-[var(--edh-muted)] hover:text-[var(--edh-primary)]"
          >
            <ChevronRight className="h-4 w-4" />
          </Link>
        )}
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
              <RemediationText text={f.remediation} />
            </span>
          </span>
          <CopyFixButton text={f.evidence ?? f.remediation} />
        </div>
      )}
      {delistProps && (
        <Link
          {...delistProps}
          className="mt-2 inline-flex items-center gap-0.5 text-xs font-medium text-[var(--edh-primary)] hover:underline"
        >
          Delisting steps <ChevronRight className="h-3.5 w-3.5" />
        </Link>
      )}
    </li>
  )
}
