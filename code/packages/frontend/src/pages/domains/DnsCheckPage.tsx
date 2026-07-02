import { Link, useNavigate, useParams } from "@tanstack/react-router"
import { ArrowLeft, Loader2, RefreshCw, Wrench } from "lucide-react"
import { useEffect } from "react"
import { useAuditResults, useDnsSpotCheck, useDomainRuns } from "@/api/audit"
import { useDomains } from "@/api/domains"
import type { AuditResult, Finding, InfraToolRun, Severity } from "@/api/types"
import { SeverityBadge } from "@/components/Badges"
import { CopyFixButton } from "@/components/CopyFixButton"
import { dnsCheckExplainer } from "@/lib/dns-check-explainers"
import { DNS_FAMILIES, familyOf, infraFindings } from "@/lib/dns-families"
import { cn } from "@/lib/utils"

const ORDER: Record<Severity, number> = { critical: 0, warning: 1, info: 2, ok: 3 }
const WORST: Record<Severity, number> = { ok: 0, info: 1, warning: 2, critical: 3 }

/**
 * The run-scoped check-detail explainer page for ONE DNS & Infrastructure test family
 * (pm/checks/dns.mdx frontmatter + §6.2 item 6/8): /domains/:id/runs/:runId/dns/check/:checkKey.
 * Top to bottom: what this check is, the family's current state in the run being viewed (every
 * sub-test row with evidence + fix), what the state means, how to fix it, the raw + parsed
 * record breakdown (the family's §5 snapshot and the tool invocations behind it), the per-family
 * severity trend across the domain's kept runs, a "run this check now" spot-check (live, never
 * persisted), and the `#concept-<term>` glossary sections the DNS page's terms anchor into.
 */
export function DnsCheckPage() {
  const {
    id = "",
    runId,
    checkKey = "",
  } = useParams({ strict: false }) as { id?: string; runId?: string; checkKey?: string }
  const { data: domains } = useDomains()
  const { data: runs } = useDomainRuns(id)
  const { data: results } = useAuditResults()
  const navigate = useNavigate()
  const spot = useDnsSpotCheck()

  const domain = (domains ?? []).find((d) => d.id === id)
  const name = domain?.name ?? id
  const explainer = dnsCheckExplainer(checkKey)
  const familyDef = DNS_FAMILIES.find((f) => f.key === checkKey)

  const history = runs ?? []
  const run: AuditResult | undefined = runId
    ? history.find((r) => r.runId === runId)
    : (history[0] ?? (results ?? []).find((r) => r.domainId === id))

  // This family's sub-test rows in the run being viewed, fail-first (pm/checks/dns.mdx §6.2).
  const familyFindings = infraFindings(run?.findings)
    .filter((f) => familyOf(f.id) === checkKey)
    .sort((a, b) => ORDER[a.severity] - ORDER[b.severity])

  // The family's §5 structured snapshot (results["infra.<key>"]) when the checker persists one.
  const snapshot = run?.results?.[`infra.${checkKey}`]
  const toolRuns = (run?.results?.["infra.tool_runs"] as InfraToolRun[] | undefined) ?? []

  // Deep links from the DNS page land on #concept-<term> — scroll there once content exists.
  useEffect(() => {
    const hash = window.location.hash.slice(1)
    if (hash && explainer) {
      document.getElementById(hash)?.scrollIntoView({ behavior: "smooth", block: "start" })
    }
  }, [explainer])

  const backToDns = () =>
    run?.runId
      ? navigate({ to: "/domains/$id/runs/$runId/dns", params: { id, runId: run.runId } })
      : navigate({ to: "/domains/$id/dns", params: { id } })

  return (
    <div className="mx-auto max-w-3xl">
      <button
        type="button"
        onClick={backToDns}
        className="mb-4 inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
      >
        <ArrowLeft className="h-4 w-4" /> Back to DNS & Infrastructure for {name}
      </button>

      {!explainer || !familyDef ? (
        <p className="text-slate-600">Unknown check "{checkKey}".</p>
      ) : (
        <>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs font-semibold uppercase text-[var(--edh-muted)]">
                infra.{explainer.key}
              </div>
              <h1 className="mt-1 text-2xl font-bold">{explainer.title}</h1>
              <div className="mt-1 text-sm text-[var(--edh-muted)]">{name}</div>
            </div>
            {/* Run this check now (pm/checks/dns.mdx §6.2 item 6): a live single-family re-run —
                a fresh observation, never persisted into the immutable run history. */}
            <button
              type="button"
              onClick={() => spot.mutate({ domainId: id, checkKey })}
              disabled={spot.isPending}
              className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
            >
              {spot.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="h-4 w-4" />
              )}
              Run this check now
            </button>
          </div>

          <Section title="What it is">
            {explainer.whatItIs.map((p) => (
              <p key={p.slice(0, 24)} className="text-sm leading-relaxed text-slate-700">
                {p}
              </p>
            ))}
          </Section>

          <Section
            title={
              run ? `Current state — run ${fmtStamp(run.startedAt ?? run.ranAt)}` : "Current state"
            }
          >
            {!run ? (
              <p className="text-sm text-slate-600">No audit yet — run one.</p>
            ) : familyFindings.length === 0 ? (
              <p className="text-sm text-slate-600">
                This family produced no sub-test rows in this run.
              </p>
            ) : (
              <FindingList findings={familyFindings} />
            )}
          </Section>

          {/* The live spot-check result, when one has been run from this page. */}
          {spot.data && (
            <Section title={`Spot check — ${fmtStamp(spot.data.finishedAt)} (live, not saved)`}>
              <p className="mb-2 text-xs text-[var(--edh-muted)]">
                A fresh observation of just this family. It is never written into the run history —
                re-run the full audit to record a new run.
              </p>
              <FindingList findings={spot.data.findings} />
            </Section>
          )}
          {spot.isError && (
            <p className="mt-4 text-sm text-red-600">
              The spot check failed — try again in a moment.
            </p>
          )}

          <Section title="What it means">
            <ul className="list-disc space-y-1 pl-5 text-sm text-slate-700">
              {explainer.whatItMeans.map((p) => (
                <li key={p.slice(0, 24)}>{p}</li>
              ))}
            </ul>
          </Section>

          <Section title="How to fix it">
            <ol className="list-decimal space-y-2 pl-5 text-sm text-slate-700">
              {explainer.howToFix.map((step) => (
                <li key={step.slice(0, 24)}>{step.replaceAll("<domain>", name)}</li>
              ))}
            </ol>
          </Section>

          {/* Raw + parsed record breakdown: the family's §5 snapshot exactly as persisted in the
              run file, plus the category's external-tool audit trail (pm/checks/dns.mdx §3.1). */}
          {snapshot !== undefined && snapshot !== null && (
            <Section title="Raw + parsed data (this run)">
              <pre className="max-h-96 overflow-auto rounded-md bg-slate-900 p-3 font-mono text-xs leading-relaxed text-slate-100">
                {JSON.stringify(snapshot, null, 2)}
              </pre>
            </Section>
          )}
          {toolRuns.length > 0 && (
            <Section title="Tool invocations (this run, whole category)">
              <ul className="space-y-1">
                {toolRuns.map((tr) => (
                  <li
                    key={`${tr.command}-${tr.started_at}`}
                    className="break-all rounded bg-slate-50 p-2 font-mono text-xs text-slate-600"
                  >
                    {tr.command} · {tr.duration_ms} ms
                    {tr.error ? <span className="text-red-600"> · {tr.error}</span> : null}
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {/* Per-family history trend across the domain's kept runs (newest first). */}
          {history.length > 1 && (
            <Section title="History across runs">
              <ul className="space-y-1">
                {history.map((r) => {
                  // Pre-history persisted runs lack a runId and cannot be linked to.
                  if (!r.runId) return null
                  const worst = worstFor(r, checkKey)
                  const isViewed = r.runId === run?.runId
                  return (
                    <li key={r.runId}>
                      <Link
                        to="/domains/$id/runs/$runId/dns/check/$checkKey"
                        params={{ id, runId: r.runId, checkKey }}
                        className={cn(
                          "flex items-center gap-2 rounded px-2 py-1 text-sm hover:bg-slate-50",
                          isViewed && "bg-slate-100 font-medium",
                        )}
                      >
                        <span
                          className={cn("h-2.5 w-2.5 shrink-0 rounded-full", DOT[worst ?? "none"])}
                        />
                        <span className="tabular-nums">{fmtStamp(r.startedAt ?? r.ranAt)}</span>
                        <span className="text-xs text-[var(--edh-muted)]">
                          {worst ? worst : "no data"}
                          {isViewed ? " · viewing" : ""}
                        </span>
                      </Link>
                    </li>
                  )
                })}
              </ul>
            </Section>
          )}

          <Section title="Concepts">
            <div className="space-y-4">
              {explainer.concepts.map((c) => (
                <div key={c.anchor} id={`concept-${c.anchor}`} className="scroll-mt-4">
                  <h3 className="text-sm font-semibold">{c.term}</h3>
                  <p className="mt-1 text-sm leading-relaxed text-slate-700">{c.text}</p>
                </div>
              ))}
            </div>
          </Section>
        </>
      )}
    </div>
  )
}

/** `YYYY-MM-DD HH:mm` in local time, matching the DNS page's run context strip. */
function fmtStamp(iso: string): string {
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/** The worst severity this family reached in one run (null = the family produced no findings). */
function worstFor(run: AuditResult, checkKey: string): Severity | null {
  let worst: Severity | null = null
  for (const f of infraFindings(run.findings)) {
    if (familyOf(f.id) !== checkKey) continue
    if (worst === null || WORST[f.severity] > WORST[worst]) worst = f.severity
  }
  return worst
}

const DOT: Record<string, string> = {
  critical: "bg-red-600",
  warning: "bg-amber-500",
  info: "bg-slate-300",
  ok: "bg-emerald-600",
  none: "border border-slate-300 bg-white",
}

function FindingList({ findings }: { findings: Finding[] }) {
  return (
    <ul className="space-y-2">
      {findings.map((f) => (
        <li
          key={f.id + f.title}
          className="rounded-md border border-[var(--edh-border)] bg-white p-2"
        >
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <span className="font-mono text-xs text-[var(--edh-muted)]">{f.id}</span>
            <span className="text-sm font-medium">{f.title}</span>
          </div>
          {f.evidence && (
            <p className="mt-1 break-all rounded bg-slate-50 p-1.5 font-mono text-xs text-slate-600">
              observed: {f.evidence}
            </p>
          )}
          {f.remediation && f.severity !== "ok" && (
            <div className="mt-1 flex items-start justify-between gap-2 rounded-md bg-slate-50 p-2 text-sm text-slate-700">
              <span className="flex items-start gap-2">
                <Wrench className="mt-0.5 h-4 w-4 shrink-0 text-[var(--edh-primary)]" />
                <span>
                  <span className="font-medium">Fix: </span>
                  {f.remediation}
                </span>
              </span>
              <CopyFixButton text={f.remediation} />
            </div>
          )}
        </li>
      ))}
    </ul>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-6">
      <h2 className="mb-2 font-semibold">{title}</h2>
      {children}
    </section>
  )
}
