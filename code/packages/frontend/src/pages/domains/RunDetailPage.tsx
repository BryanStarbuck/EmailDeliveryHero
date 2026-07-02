import { Link, useNavigate, useParams } from "@tanstack/react-router"
import { ArrowLeft, ChevronDown, ChevronRight, RefreshCw, Wrench } from "lucide-react"
import { useState } from "react"
import { useAuditResults, useAuditRun } from "@/api/audit"
import { useDomains } from "@/api/domains"
import type { Finding } from "@/api/types"
import { ScoreBadge, SeverityBadge } from "@/components/Badges"
import { CopyFixButton } from "@/components/CopyFixButton"
import { RemediationText } from "@/components/FindingsList"
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
  const cells = rollupCategories(result?.findings, result?.results)

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
                    {/* DKIM's chevron stays run-scoped on a historical run (pm/checks/dkim.mdx
                        §6.2 item 2 — the run report's DKIM chevron opens THAT run's DKIM page). */}
                    {c.key === "dkim" && runId ? (
                      <Link
                        to="/domains/$id/runs/$runId/dkim"
                        params={{ id, runId }}
                        aria-label={`Open the ${c.header} page for this run`}
                        className="hover:text-slate-700"
                      >
                        <ChevronRight className="h-3.5 w-3.5" />
                      </Link>
                    ) : c.key === "dnsInfra" && runId ? (
                      // The DNS & Infrastructure chevron routes to the SAME run's DNS page
                      // (pm/checks/dns.mdx §6.1 — the run report's section chevron is run-scoped).
                      <Link
                        to="/domains/$id/runs/$runId/dns"
                        params={{ id, runId }}
                        aria-label={`Open the ${c.header} page for this run`}
                        className="hover:text-slate-700"
                      >
                        <ChevronRight className="h-3.5 w-3.5" />
                      </Link>
                    ) : (
                      techRoute && (
                        <Link
                          to={techRoute}
                          params={{ id }}
                          aria-label={`Open the ${c.header} page`}
                          className="hover:text-slate-700"
                        >
                          <ChevronRight className="h-3.5 w-3.5" />
                        </Link>
                      )
                    )}
                  </div>
                  <StatusCell status={cells[c.key] ?? NEVER_CELL} />
                </a>
              )
            })}
          </div>

          {/* Findings grouped by the six categories — each a collapsible section (pm/ui.mdx §5):
              categories with problems open expanded; healthy categories collapse to a quiet
              "all healthy" line. Keyed by run so a fresh run resets the open/closed state. */}
          <div className="mt-6 space-y-5">
            {CATEGORIES.map((c) => {
              const findings = result.findings
                .filter((f) => categoryOf(f.checkId) === c.key)
                .sort((a, b) => ORDER[a.severity] - ORDER[b.severity])
              if (findings.length === 0) return null
              return (
                <CategorySection
                  key={`${c.key}-${result.runId ?? result.ranAt}`}
                  catKey={c.key}
                  header={c.header}
                  findings={findings}
                />
              )
            })}
          </div>
        </>
      )}
    </div>
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
}: {
  catKey: string
  header: string
  findings: Finding[]
}) {
  const problems = findings.filter(
    (f) => f.severity === "warning" || f.severity === "critical",
  ).length
  const [open, setOpen] = useState(problems > 0)

  // ARC rolls into the DMARC cell but renders as its own labelled advisory sub-group inside the
  // expanded DMARC section (pm/checks/arc.mdx §4 — "DMARC ▸ ARC (Authenticated Received Chain)").
  const arcFindings = catKey === "dmarc" ? findings.filter((f) => f.checkId === "arc") : []
  // BIMI rolls into the Spam & Content cell but renders grouped under its own "BIMI" subhead
  // inside that section (pm/checks/bimi.mdx §4 — "Spam & Content › BIMI").
  const bimiFindings =
    catKey === "spamContent" ? findings.filter((f) => f.checkId === "content.bimi") : []
  const mainFindings = findings.filter(
    (f) =>
      !(arcFindings.length > 0 && f.checkId === "arc") &&
      !(bimiFindings.length > 0 && f.checkId === "content.bimi"),
  )

  return (
    <section id={`cat-${catKey}`}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="mb-2 flex w-full items-center justify-between text-left"
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
          {problems === 0 ? "all healthy" : `${problems} problem${problems === 1 ? "" : "s"}`}
        </span>
      </button>
      {open && (
        <>
          <ul className="space-y-2">
            {mainFindings.map((f) => (
              <FindingRow key={f.id} finding={f} />
            ))}
          </ul>
          {arcFindings.length > 0 && <ArcSubGroup findings={arcFindings} />}
          {bimiFindings.length > 0 && <BimiSubGroup findings={bimiFindings} />}
        </>
      )}
    </section>
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
function ArcSubGroup({ findings }: { findings: Finding[] }) {
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
          <FindingRow key={f.id} finding={f} />
        ))}
      </ul>
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
        {/* Report-derived evidence chip (pm/emails.mdx §7.2): the finding came from an ingested
            DMARC-aggregate/TLS-RPT report email, not a live DNS lookup. */}
        {f.source === "report" && (
          <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[10px] uppercase tracking-wide text-slate-500">
            from reports
          </span>
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
    </li>
  )
}
