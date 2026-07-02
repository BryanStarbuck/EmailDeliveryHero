import { useNavigate, useParams, useSearch } from "@tanstack/react-router"
import { ArrowLeft, Terminal } from "lucide-react"
import { useAuditResults, useDomainRuns } from "@/api/audit"
import { useDomains } from "@/api/domains"
import { SeverityBadge } from "@/components/Badges"
import { CopyFixButton } from "@/components/CopyFixButton"
import { infraFindings } from "@/lib/dns-families"
import { dnsProblemStateById } from "@/lib/dns-problems"

/**
 * The per-problem drill-down page for DNS & Infrastructure (pm/checks/dns.mdx §7): concept, your
 * data (the §9 data fields rendered LIVE from the run being viewed — `?run=<runId>`, else the
 * newest run), diagnose-it-yourself commands (with the domain substituted in, copyable), tools,
 * extra health metrics, and the numbered path forward. Route: /domains/:id/dns/:problemId.
 */
export function DnsProblemPage() {
  const { id = "", problemId = "" } = useParams({ strict: false }) as {
    id?: string
    problemId?: string
  }
  const { run: runId } = useSearch({ strict: false }) as { run?: string }
  const { data: domains } = useDomains()
  const { data: runs } = useDomainRuns(id)
  const { data: results } = useAuditResults()
  const navigate = useNavigate()

  const domain = (domains ?? []).find((d) => d.id === id)
  const name = domain?.name ?? id
  const ps = dnsProblemStateById(problemId.toUpperCase())

  // The run being viewed (pm/checks/dns.mdx §7): ?run=<runId>, else the domain's newest run.
  const history = runs ?? []
  const run = runId
    ? history.find((r) => r.runId === runId)
    : (history[0] ?? (results ?? []).find((r) => r.domainId === id))
  // This state's live findings from that run — matched by id prefix, worst first.
  const order = { critical: 0, warning: 1, info: 2, ok: 3 } as const
  const liveFindings = ps
    ? infraFindings(run?.findings)
        .filter((f) => {
          const bare = f.id.startsWith("infra.") ? f.id.slice("infra.".length) : f.id
          return ps.findingPrefixes.some((p) => bare.startsWith(p))
        })
        .sort((a, b) => order[a.severity] - order[b.severity])
    : []

  return (
    <div className="mx-auto max-w-3xl">
      <button
        type="button"
        onClick={() =>
          // Back to the DNS page of the run being viewed (run-scoped when we know the run).
          run?.runId
            ? navigate({
                to: "/domains/$id/runs/$runId/dns",
                params: { id, runId: run.runId },
              })
            : navigate({ to: "/domains/$id/dns", params: { id } })
        }
        className="mb-4 inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
      >
        <ArrowLeft className="h-4 w-4" /> Back to DNS & Infrastructure for {name}
      </button>

      {!ps ? (
        <p className="text-slate-600">Unknown problem state "{problemId}".</p>
      ) : (
        <>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase text-[var(--edh-muted)]">
            <span>{ps.id}</span>
            <SeverityBadge severity={ps.severity} />
          </div>
          <h1 className="mt-1 text-2xl font-bold">{ps.title}</h1>

          <section className="mt-4 space-y-2">
            {ps.concept.map((p) => (
              <p key={p.slice(0, 24)} className="text-sm leading-relaxed text-slate-700">
                {p}
              </p>
            ))}
          </section>

          <Section title="Your data">
            {/* The state's live findings from the run being viewed (pm/checks/dns.mdx §7). */}
            {liveFindings.length > 0 && (
              <ul className="mb-3 space-y-2">
                {liveFindings.map((f) => (
                  <li
                    key={f.id + f.title}
                    className="rounded-md border border-[var(--edh-border)] bg-white p-2"
                  >
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={f.severity} />
                      <span className="font-mono text-xs text-[var(--edh-muted)]">{f.id}</span>
                      <span className="text-sm font-medium">{f.title}</span>
                    </div>
                    {f.evidence && (
                      <p className="mt-1 break-all rounded bg-slate-50 p-1.5 font-mono text-xs text-slate-600">
                        {f.evidence}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            )}
            {run && (
              <p className="mb-2 text-xs text-[var(--edh-muted)]">
                From the run of {new Date(run.startedAt ?? run.ranAt).toLocaleString()}. Fields to
                look at in the run file:
              </p>
            )}
            <ul className="list-disc space-y-1 pl-5 text-sm text-slate-700">
              {ps.dataFields.map((d) => (
                <li key={d} className="font-mono text-xs">
                  {d}
                </li>
              ))}
            </ul>
          </Section>

          <Section title="Diagnose it yourself">
            <ul className="space-y-2">
              {ps.commands.map((raw) => {
                const cmd = raw.replaceAll("<domain>", name)
                return (
                  <li
                    key={raw}
                    className="flex items-center justify-between gap-2 rounded-md bg-slate-900 p-2 text-slate-100"
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      <Terminal className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                      <code className="break-all font-mono text-xs">{cmd}</code>
                    </span>
                    <CopyFixButton text={cmd} label="Copy" />
                  </li>
                )
              })}
            </ul>
          </Section>

          <Section title="Tools">
            <ul className="list-disc space-y-1 pl-5 text-sm text-slate-700">
              {ps.tools.map((t) => (
                <li key={t}>{t}</li>
              ))}
            </ul>
          </Section>

          <Section title="More health metrics">
            <ul className="list-disc space-y-1 pl-5 text-sm text-slate-700">
              {ps.metrics.map((m) => (
                <li key={m}>{m}</li>
              ))}
            </ul>
          </Section>

          <Section title="Path forward">
            <ol className="list-decimal space-y-2 pl-5 text-sm text-slate-700">
              {ps.pathForward.map((step) => (
                <li key={step}>{step.replaceAll("<domain>", name)}</li>
              ))}
            </ol>
          </Section>
        </>
      )}
    </div>
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
