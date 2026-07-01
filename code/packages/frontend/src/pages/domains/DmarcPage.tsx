import { Link, useNavigate, useParams } from "@tanstack/react-router"
import { ArrowLeft, ChevronRight, RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react"
import { useAuditResults } from "@/api/audit"
import { useDomains } from "@/api/domains"
import type { DmarcResults, Finding } from "@/api/types"
import { CopyFixButton } from "@/components/CopyFixButton"
import { StatusCell } from "@/components/StatusCell"
import { TestResultsTable } from "@/components/TestResultsTable"
import { NEVER_CELL, rollupCategories } from "@/lib/categories"
import { matchProblemStates } from "@/lib/dmarc-problems"
import { cn } from "@/lib/utils"
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext"

/** Tag meanings for the parsed-record table (pm/checks/dmarc.mdx §6.2). Order = display order. */
const TAG_META: {
  tag: string
  meaning: string
  fallback?: (r: DmarcResults) => string
  obsolete?: boolean
}[] = [
  { tag: "v", meaning: "Version — must be DMARC1" },
  { tag: "p", meaning: "Policy for the domain: none / quarantine / reject" },
  {
    tag: "sp",
    meaning: "Policy for subdomains",
    fallback: (r) => `${r.policy ?? "—"} (inherits p)`,
  },
  {
    tag: "np",
    meaning: "Policy for non-existent subdomains (RFC 9989)",
    fallback: (r) => `${r.subdomain_policy ?? "—"} (inherits sp)`,
  },
  { tag: "adkim", meaning: "DKIM alignment: r relaxed / s strict", fallback: () => "r (relaxed)" },
  { tag: "aspf", meaning: "SPF alignment: r relaxed / s strict", fallback: () => "r (relaxed)" },
  { tag: "rua", meaning: "Where aggregate reports are sent" },
  { tag: "ruf", meaning: "Where failure reports are sent (optional)" },
  {
    tag: "fo",
    meaning: "Failure-report options (1 = either mechanism fails)",
    fallback: () => "0",
  },
  { tag: "t", meaning: "Testing flag (RFC 9989) — t=y disables enforcement" },
  { tag: "pct", meaning: "Percent of mail policy applies to", obsolete: true },
  { tag: "ri", meaning: "Aggregate report interval (seconds)", obsolete: true },
  { tag: "rf", meaning: "Report format", obsolete: true },
]

/**
 * The full-page DMARC view (pm/checks/dmarc.mdx §6.2/§7) — everything about one domain's DMARC:
 * the policy ladder, the raw + parsed record, the fail-first test-results table with observed DNS
 * values and copyable fixes, report-destination authorization, and problem-state cards linking to
 * the per-problem drill-down pages.
 */
export function DmarcPage() {
  const { id = "" } = useParams({ strict: false }) as { id?: string }
  const { data: domains } = useDomains()
  const { data: results } = useAuditResults()
  const runDomains = useScanRunner()
  const scanning = useScanProgress().some((s) => s.domainId === id)
  const navigate = useNavigate()

  const domain = (domains ?? []).find((d) => d.id === id)
  const result = (results ?? []).find((r) => r.domainId === id)
  const findings = (result?.findings ?? []).filter((f) => f.checkId === "dmarc")
  const dmarc = result?.results?.dmarc
  const cell = rollupCategories(result?.findings).dmarc ?? NEVER_CELL
  const problems = matchProblemStates(findings)

  const onRunAgain = () => runDomains([{ id, name: domain?.name ?? id }])

  return (
    <div className="mx-auto max-w-5xl">
      <div className="mb-4 flex items-center justify-between">
        <button
          type="button"
          onClick={() => navigate({ to: "/domains/$id", params: { id } })}
          className="inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
        >
          <ArrowLeft className="h-4 w-4" /> Back to {domain?.name ?? id}
        </button>
        <button
          type="button"
          onClick={onRunAgain}
          disabled={scanning}
          className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
        >
          <RefreshCw className={scanning ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
          Re-run
        </button>
      </div>

      <h1 className="text-2xl font-bold">DMARC</h1>
      <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-[var(--edh-muted)]">
        <span className="font-medium text-slate-900">{domain?.name ?? id}</span>
        <span className="w-32">
          <StatusCell status={cell} />
        </span>
        {result && <span>· ran {new Date(result.ranAt).toLocaleString()}</span>}
      </div>

      {!result ? (
        <div className="mt-6 rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center">
          <p className="text-slate-600">No audit yet.</p>
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
          <PolicyLadder dmarc={dmarc} findings={findings} />

          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <RecordPanel dmarc={dmarc} />
            <ReportDestinations dmarc={dmarc} domainName={domain?.name ?? id} />
          </div>

          <TestResultsTable findings={findings} emptyText="No DMARC tests in the latest run." />

          {problems.length > 0 && (
            <section className="mt-6">
              <h2 className="mb-2 font-semibold">Problem states</h2>
              <div className="grid gap-3 sm:grid-cols-2">
                {problems.map((ps) => (
                  <Link
                    key={ps.id}
                    to="/domains/$id/dmarc/$problemId"
                    params={{ id, problemId: ps.id }}
                    className="group rounded-lg border border-[var(--edh-border)] bg-white p-4 hover:border-[var(--edh-primary)]"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold uppercase text-[var(--edh-muted)]">
                        {ps.id}
                      </span>
                      <ChevronRight className="h-4 w-4 text-[var(--edh-muted)] group-hover:text-[var(--edh-primary)]" />
                    </div>
                    <div className="mt-1 font-medium">{ps.title}</div>
                    <p className="mt-1 text-sm text-slate-600">{ps.hook}</p>
                  </Link>
                ))}
              </div>
            </section>
          )}
        </>
      )}
    </div>
  )
}

/**
 * The none → quarantine → reject progress visual with the recommended next step
 * (pm/checks/dmarc.mdx §8 state machine).
 */
function PolicyLadder({ dmarc, findings }: { dmarc?: DmarcResults; findings: Finding[] }) {
  const steps = ["none", "quarantine", "reject"] as const
  const policy = dmarc?.policy ?? null
  const stepIndex = policy ? steps.indexOf(policy) : -1
  const testing = dmarc?.parsed?.t?.toLowerCase() === "y"
  const failing = findings.filter((f) => f.severity === "critical" || f.severity === "warning")

  let verdict: string
  let next: string
  if (!dmarc?.record_found) {
    verdict = "No DMARC record — the domain is unprotected."
    next = "Publish the starter record below to begin monitoring."
  } else if (stepIndex === -1) {
    verdict = "The record is broken — receivers treat it as no policy."
    next = "Fix the failing tests below first; a malformed record protects nothing."
  } else if (testing) {
    verdict = `t=y testing mode — p=${policy} is advisory only.`
    next = "Remove t=y once you are ready to enforce."
  } else if (policy === "none") {
    verdict = "Monitoring only — spoofed mail is still delivered."
    next =
      failing.length > 0
        ? `Fix the ${failing.length} failing test${failing.length === 1 ? "" : "s"} below, then raise to p=quarantine.`
        : "Reports look clean? Raise to p=quarantine."
  } else if (policy === "quarantine") {
    verdict = "Enforcing — failing mail is sent to spam folders."
    next = "After ≥30 clean days, raise to p=reject."
  } else {
    verdict = "Fully enforced — spoofed mail is rejected."
    next = "Keep rua monitoring forever; tighten sp=/np= if not already set."
  }

  return (
    <div className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
      <div className="flex items-center gap-2">
        {steps.map((s, i) => (
          <div key={s} className="flex items-center gap-2">
            {i > 0 && (
              <div
                className={cn(
                  "h-0.5 w-10",
                  i <= stepIndex ? "bg-[var(--edh-primary)]" : "bg-slate-200",
                )}
              />
            )}
            <span
              className={cn(
                "rounded-full px-3 py-1 text-xs font-medium",
                i === stepIndex && !testing
                  ? "bg-[var(--edh-primary)] text-white"
                  : i < stepIndex
                    ? "bg-slate-200 text-slate-700"
                    : "border border-slate-300 text-slate-500",
              )}
            >
              {s}
            </span>
          </div>
        ))}
      </div>
      <p className="mt-3 text-sm text-slate-700">{verdict}</p>
      <p className="mt-1 text-sm font-medium text-[var(--edh-primary)]">Next step: {next}</p>
    </div>
  )
}

/** Raw TXT record (copyable) over the parsed-tag table with grayed inherited defaults. */
function RecordPanel({ dmarc }: { dmarc?: DmarcResults }) {
  return (
    <section className="rounded-lg border border-[var(--edh-border)] bg-white p-4">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="font-semibold">Published record</h2>
        {dmarc?.raw_record && <CopyFixButton text={dmarc.raw_record} label="Copy" />}
      </div>
      {!dmarc?.raw_record ? (
        <p className="text-sm text-slate-600">
          No record published{dmarc?.query_name ? ` at ${dmarc.query_name}` : ""}.
        </p>
      ) : (
        <>
          <p className="break-all rounded-md bg-slate-50 p-2 font-mono text-xs text-slate-700">
            {dmarc.raw_record}
          </p>
          {dmarc.found_at && dmarc.found_at !== dmarc.query_name && (
            <p className="mt-1 text-xs text-[var(--edh-muted)]">
              Found at <span className="font-mono">{dmarc.found_at}</span> (tree-walk coverage from
              a parent domain).
            </p>
          )}
          <table className="mt-3 w-full text-sm">
            <tbody>
              {TAG_META.map((meta) => {
                const published = dmarc.parsed?.[meta.tag]
                const value = published ?? (meta.fallback ? meta.fallback(dmarc) : null)
                if (value === null || value === undefined) return null
                return (
                  <tr key={meta.tag} className="border-t border-[var(--edh-border)]">
                    <td className="py-1.5 pr-3 align-top font-mono text-xs font-semibold">
                      <span className={cn(meta.obsolete && "line-through opacity-60")}>
                        {meta.tag}
                      </span>
                      {meta.obsolete && (
                        <span className="ml-1 rounded bg-slate-100 px-1 text-[10px] uppercase text-slate-500">
                          obsolete
                        </span>
                      )}
                    </td>
                    <td
                      className={cn(
                        "py-1.5 pr-3 align-top font-mono text-xs",
                        !published && "text-slate-400",
                      )}
                    >
                      {value}
                    </td>
                    <td className="py-1.5 align-top text-xs text-slate-500">{meta.meaning}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </>
      )}
    </section>
  )
}

/** One card per rua/ruf destination with its _report._dmarc authorization state. */
function ReportDestinations({ dmarc, domainName }: { dmarc?: DmarcResults; domainName: string }) {
  const uris = [
    ...(dmarc?.rua_uris ?? []).map((u) => ({ kind: "rua" as const, uri: u })),
    ...(dmarc?.ruf_uris ?? []).map((u) => ({ kind: "ruf" as const, uri: u })),
  ]
  const authByUri = new Map((dmarc?.external_report_auth ?? []).map((a) => [a.report_uri, a]))
  return (
    <section className="rounded-lg border border-[var(--edh-border)] bg-white p-4">
      <h2 className="mb-2 font-semibold">Report destinations</h2>
      {uris.length === 0 ? (
        <p className="text-sm text-slate-600">
          No report destinations. Add{" "}
          <span className="font-mono text-xs">rua=mailto:dmarc@{domainName}</span> so you can see
          who sends as this domain.
        </p>
      ) : (
        <ul className="space-y-2">
          {uris.map(({ kind, uri }) => {
            const auth = authByUri.get(uri)
            const external = Boolean(auth)
            const ok = !external || auth?.authorized
            return (
              <li
                key={`${kind}:${uri}`}
                className="rounded-md border border-[var(--edh-border)] p-2 text-sm"
              >
                <div className="flex items-center gap-2">
                  {ok ? (
                    <ShieldCheck className="h-4 w-4 shrink-0 text-emerald-600" />
                  ) : (
                    <ShieldAlert className="h-4 w-4 shrink-0 text-red-600" />
                  )}
                  <span className="break-all font-mono text-xs">{uri}</span>
                  <span className="ml-auto shrink-0 text-[10px] uppercase text-[var(--edh-muted)]">
                    {kind}
                  </span>
                </div>
                {external && auth && (
                  <div className="mt-1 pl-6 text-xs text-slate-500">
                    <span className="font-mono">{auth.auth_name}</span> →{" "}
                    {auth.authorized
                      ? "v=DMARC1 (authorized)"
                      : "no record — reports are silently dropped"}
                    {!auth.authorized && (
                      <div className="mt-1">
                        <CopyFixButton
                          text={`${auth.auth_name} TXT "v=DMARC1"`}
                          label="Copy expected record"
                        />
                      </div>
                    )}
                  </div>
                )}
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}
