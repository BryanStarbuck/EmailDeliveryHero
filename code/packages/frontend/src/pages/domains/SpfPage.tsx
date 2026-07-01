import { Link, useNavigate, useParams } from "@tanstack/react-router"
import { ArrowLeft, ChevronRight, RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react"
import { useAuditResults } from "@/api/audit"
import { useDomains } from "@/api/domains"
import type { Finding, SpfResults, SpfTreeNode } from "@/api/types"
import { CopyFixButton } from "@/components/CopyFixButton"
import { StatusCell } from "@/components/StatusCell"
import { TestResultsTable } from "@/components/TestResultsTable"
import { NEVER_CELL, rollupCategories } from "@/lib/categories"
import { matchSpfProblemStates } from "@/lib/spf-problems"
import { cn } from "@/lib/utils"
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext"

/** One-line meanings for the mechanism table (pm/checks/spf.mdx §6.2). */
const TYPE_MEANING: Record<string, string> = {
  ip4: "Authorize this IPv4 range",
  ip6: "Authorize this IPv6 range",
  a: "Authorize the domain's A/AAAA addresses",
  mx: "Authorize the domain's MX hosts",
  include: "Delegate to another domain's SPF",
  exists: "Macro existence test",
  ptr: "Reverse-DNS check — deprecated (RFC 7208 §5.5)",
  all: "Default verdict for unlisted senders",
  redirect: "Hand evaluation to another domain's record",
  exp: "Explanation TXT shown to senders on fail",
  unknown: "Unknown term — receivers reject the record",
}

/**
 * The full-page SPF view (pm/checks/spf.mdx §6.2/§7) — everything about one domain's SPF: the
 * lookup-budget hero, the raw record + mechanism table, the expandable include tree with per-node
 * lookup costs and void badges, the fail-first test-results table, the sending-IP coverage panel,
 * and problem-state cards linking to the per-problem drill-down pages.
 */
export function SpfPage() {
  const { id = "" } = useParams({ strict: false }) as { id?: string }
  const { data: domains } = useDomains()
  const { data: results } = useAuditResults()
  const runDomains = useScanRunner()
  const scanning = useScanProgress().some((s) => s.domainId === id)
  const navigate = useNavigate()

  const domain = (domains ?? []).find((d) => d.id === id)
  const result = (results ?? []).find((r) => r.domainId === id)
  const findings = (result?.findings ?? []).filter((f) => f.checkId === "spf")
  const spf = result?.results?.spf
  const cell = rollupCategories(result?.findings).spf ?? NEVER_CELL
  const problems = matchSpfProblemStates(findings)

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

      <h1 className="text-2xl font-bold">SPF</h1>
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
          <BudgetHero spf={spf} findings={findings} domainName={domain?.name ?? id} />

          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <RecordPanel spf={spf} />
            <IncludeTreePanel spf={spf} />
          </div>

          <TestResultsTable findings={findings} emptyText="No SPF tests in the latest run." />

          <IpCoveragePanel spf={spf} />

          {problems.length > 0 && (
            <section className="mt-6">
              <h2 className="mb-2 font-semibold">Problem states</h2>
              <div className="grid gap-3 sm:grid-cols-2">
                {problems.map((ps) => (
                  <Link
                    key={ps.id}
                    to="/domains/$id/spf/$problemId"
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
 * The verdict banner (pm/checks/spf.mdx §6.2 "budget hero"): the eval result, the 10-lookup gauge,
 * the void count, the all-qualifier chip, and the single next step from the §8 precedence ladder.
 */
function BudgetHero({
  spf,
  findings,
  domainName,
}: {
  spf?: SpfResults
  findings: Finding[]
  domainName: string
}) {
  const lookups = spf?.lookup_count ?? 0
  const failing = (id: string) =>
    findings.some((f) => f.id === id && (f.severity === "critical" || f.severity === "warning"))

  let verdict: string
  let next: string
  if (!spf?.record_found) {
    verdict = "No SPF record — receivers cannot verify any sender for this domain."
    next = `Publish "v=spf1 include:<your-ESP> ~all" at ${domainName} to start.`
  } else if (spf.record_count > 1) {
    verdict = `${spf.record_count} SPF records published — permerror; receivers ignore SPF entirely.`
    next = "Merge everything into ONE v=spf1 record and delete the extras."
  } else if (spf.eval_result === "permerror") {
    verdict = "permerror — receivers ignore this record; ALL mail fails SPF."
    next =
      lookups > 10
        ? "Cut DNS lookups: delete dead includes first, then replace a/mx with explicit ip4/ip6 ranges."
        : "Fix the failing tests below — a permerror record protects nothing."
  } else if (spf.all_qualifier === "+all" || failing("spf.cidr_scope")) {
    verdict = "The record authorizes the entire internet."
    next = "Remove +all (and any /0 range) immediately; end in ~all or -all."
  } else if (failing("spf.ip_coverage")) {
    verdict = "The record is valid, but a configured sending IP is not covered."
    next = "Add the exact ip4:/ip6: line from the coverage panel below, before the all term."
  } else if (spf.all_qualifier === "?all" || spf.all_qualifier === null) {
    verdict = "Valid record, but no meaningful default for unlisted senders."
    next = 'Append "~all" as the last term.'
  } else if (failing("spf.lookups")) {
    verdict = `Valid — but ${lookups}/10 lookups is one vendor away from permerror.`
    next = "Trim now: drop unused includes or replace a/mx with explicit ranges."
  } else {
    verdict = `Valid — ${spf.all_qualifier}, ${lookups}/10 lookups, ${spf.void_count} void.`
    next =
      "Keep it healthy: re-audit after onboarding anything that sends mail — every new vendor nudges the lookup count."
  }

  return (
    <div className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
      <div className="flex flex-wrap items-center gap-4">
        <LookupGauge lookups={lookups} />
        <span className="text-sm text-slate-700">
          voids{" "}
          <span
            className={cn(
              "font-mono font-semibold",
              (spf?.void_count ?? 0) > 2
                ? "text-red-600"
                : (spf?.void_count ?? 0) > 0
                  ? "text-amber-600"
                  : "text-emerald-700",
            )}
          >
            {spf?.void_count ?? 0}/2
          </span>
        </span>
        {spf?.all_qualifier && (
          <span
            className={cn(
              "rounded-full px-3 py-1 font-mono text-xs font-medium",
              spf.all_qualifier === "+all"
                ? "bg-red-100 text-red-700"
                : spf.all_qualifier === "?all"
                  ? "bg-amber-100 text-amber-700"
                  : "bg-emerald-100 text-emerald-700",
            )}
          >
            {spf.all_qualifier}
          </span>
        )}
        <span className="ml-auto font-mono text-xs uppercase text-[var(--edh-muted)]">
          {spf?.eval_result ?? "none"}
        </span>
      </div>
      <p className="mt-3 text-sm text-slate-700">{verdict}</p>
      <p className="mt-1 text-sm font-medium text-[var(--edh-primary)]">Next step: {next}</p>
    </div>
  )
}

/** The 10 gauge segments, keyed by their budget slot (1–10). */
const GAUGE_SEGMENTS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] as const

/** The n/10 lookup-budget segments: green under 8, amber 8–10, red past 10. */
function LookupGauge({ lookups }: { lookups: number }) {
  const color =
    lookups > 10 ? "bg-red-500" : lookups >= 8 ? "bg-amber-400" : "bg-[var(--edh-primary)]"
  return (
    <span className="flex items-center gap-2">
      <span className="text-sm text-slate-700">lookups</span>
      <span className="flex gap-0.5">
        {GAUGE_SEGMENTS.map((slot) => (
          <span
            key={slot}
            className={cn("h-3 w-2 rounded-sm", slot <= lookups ? color : "bg-slate-200")}
          />
        ))}
      </span>
      <span
        className={cn(
          "font-mono text-sm font-semibold",
          lookups > 10 ? "text-red-600" : lookups >= 8 ? "text-amber-600" : "text-emerald-700",
        )}
      >
        {lookups}/10
      </span>
    </span>
  )
}

/** Raw TXT record (copyable) over the mechanism table with lookup costs and dead-term badges. */
function RecordPanel({ spf }: { spf?: SpfResults }) {
  const mechs = spf?.mechanisms ?? []
  // Terms after `all` never evaluate (redirect/exp modifiers excluded from position math).
  const allIdx = mechs.findIndex((m) => m.type === "all")
  // Duplicate terms are legal in SPF, so key rows by raw + occurrence number, not array index.
  const rows = withOccurrenceKeys(mechs, (m) => m.raw)
  return (
    <section className="rounded-lg border border-[var(--edh-border)] bg-white p-4">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="font-semibold">Published record</h2>
        {spf?.raw_record && <CopyFixButton text={spf.raw_record} label="Copy" />}
      </div>
      {!spf?.raw_record ? (
        <p className="text-sm text-slate-600">
          No record published{spf?.query_name ? ` at ${spf.query_name}` : ""}.
        </p>
      ) : (
        <>
          <p className="break-all rounded-md bg-slate-50 p-2 font-mono text-xs text-slate-700">
            {spf.raw_record}
          </p>
          <table className="mt-3 w-full text-sm">
            <thead>
              <tr className="text-left text-[10px] uppercase text-[var(--edh-muted)]">
                <th className="py-1 pr-3 font-medium">Term</th>
                <th className="py-1 pr-3 font-medium">Lookup</th>
                <th className="py-1 font-medium">Meaning</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ item: m, key }, i) => {
                const dead =
                  allIdx !== -1 && i > allIdx && m.type !== "redirect" && m.type !== "exp"
                const flagged = m.type === "ptr" || m.type === "unknown"
                return (
                  <tr key={key} className="border-t border-[var(--edh-border)]">
                    <td className="py-1.5 pr-3 align-top font-mono text-xs font-semibold">
                      <span className={cn(dead && "line-through opacity-60")}>{m.raw}</span>
                      {dead && (
                        <span className="ml-1 rounded bg-slate-100 px-1 text-[10px] uppercase text-slate-500">
                          dead
                        </span>
                      )}
                      {flagged && (
                        <span className="ml-1 rounded bg-amber-100 px-1 text-[10px] uppercase text-amber-700">
                          {m.type === "ptr" ? "deprecated" : "invalid"}
                        </span>
                      )}
                    </td>
                    <td className="py-1.5 pr-3 align-top font-mono text-xs text-slate-500">
                      {m.lookup ? "1" : "0"}
                    </td>
                    <td className="py-1.5 align-top text-xs text-slate-500">
                      {TYPE_MEANING[m.type] ?? m.type}
                    </td>
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

/** The recursively expanded include tree with per-node lookup costs and void badges (§6.2 #4). */
function IncludeTreePanel({ spf }: { spf?: SpfResults }) {
  return (
    <section className="rounded-lg border border-[var(--edh-border)] bg-white p-4">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="font-semibold">Include tree</h2>
        {spf && <span className="text-xs text-[var(--edh-muted)]">{spf.lookup_count} lookups</span>}
      </div>
      {!spf?.include_tree ? (
        <p className="text-sm text-slate-600">No record to expand.</p>
      ) : (
        <ul className="space-y-1">
          <TreeNode node={spf.include_tree} />
        </ul>
      )}
    </section>
  )
}

function TreeNode({ node }: { node: SpfTreeNode }) {
  return (
    <li>
      <div
        className="flex items-baseline gap-2 text-xs"
        style={{ paddingLeft: `${node.depth * 16}px` }}
      >
        <span className="font-mono font-semibold text-slate-700">
          {node.depth === 0 ? "●" : "├─"} {node.term}
        </span>
        {node.is_void && (
          <span className="rounded bg-red-100 px-1 text-[10px] font-semibold uppercase text-red-700">
            void
          </span>
        )}
        {node.cost_lookups > 0 && (
          <span className="font-mono text-[10px] text-[var(--edh-muted)]">
            ({node.cost_lookups})
          </span>
        )}
      </div>
      {node.resolved_to.length > 0 && node.depth > 0 && (
        <div
          className="break-all font-mono text-[10px] text-slate-400"
          style={{ paddingLeft: `${node.depth * 16 + 20}px` }}
        >
          {node.resolved_to.join(" · ").slice(0, 160)}
        </div>
      )}
      {node.children.length > 0 && (
        <ul className="space-y-1">
          {withOccurrenceKeys(node.children, (c) => c.term).map(({ item, key }) => (
            <TreeNode key={key} node={item} />
          ))}
        </ul>
      )}
    </li>
  )
}

/** Stable keys for lists that may repeat the same term: "<term>#<nth occurrence>". */
function withOccurrenceKeys<T>(items: T[], keyOf: (item: T) => string): { item: T; key: string }[] {
  const seen = new Map<string, number>()
  return items.map((item) => {
    const base = keyOf(item)
    const n = (seen.get(base) ?? 0) + 1
    seen.set(base, n)
    return { item, key: `${base}#${n}` }
  })
}

/** One row per configured sending IP: covered ✓/✗ and the matching pass-set entry (§6.2 #6). */
function IpCoveragePanel({ spf }: { spf?: SpfResults }) {
  const rows = spf?.ip_coverage ?? []
  return (
    <section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
      <h2 className="mb-2 font-semibold">Sending-IP coverage</h2>
      {rows.length === 0 ? (
        <p className="text-sm text-slate-600">
          No sending IPs configured — add them on the{" "}
          <Link to="/domains" className="text-[var(--edh-primary)] underline">
            Domains page
          </Link>{" "}
          to verify the record actually covers your hosts.
        </p>
      ) : (
        <ul className="space-y-2">
          {rows.map((c) => (
            <li
              key={c.ip}
              className="flex flex-wrap items-center gap-2 rounded-md border border-[var(--edh-border)] p-2 text-sm"
            >
              {c.covered ? (
                <ShieldCheck className="h-4 w-4 shrink-0 text-emerald-600" />
              ) : (
                <ShieldAlert className="h-4 w-4 shrink-0 text-red-600" />
              )}
              <span className="font-mono text-xs">{c.ip}</span>
              {c.covered ? (
                <span className="text-xs text-slate-500">
                  matched by <span className="font-mono">{c.matched_by}</span>
                </span>
              ) : (
                <span className="ml-auto">
                  <CopyFixButton
                    text={c.ip.includes(":") ? `ip6:${c.ip}` : `ip4:${c.ip}`}
                    label={`Copy ${c.ip.includes(":") ? "ip6" : "ip4"} line`}
                  />
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
