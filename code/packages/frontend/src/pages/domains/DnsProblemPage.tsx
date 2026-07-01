import { useNavigate, useParams } from "@tanstack/react-router"
import { ArrowLeft, Terminal } from "lucide-react"
import { useDomains } from "@/api/domains"
import { SeverityBadge } from "@/components/Badges"
import { CopyFixButton } from "@/components/CopyFixButton"
import { dnsProblemStateById } from "@/lib/dns-problems"

/**
 * The per-problem drill-down page for DNS & Infrastructure (pm/checks/dns.mdx §7): concept, your
 * data, diagnose-it-yourself commands (with the domain substituted in, copyable), tools, extra
 * health metrics, and the numbered path forward. Route: /domains/:id/dns/:problemId.
 */
export function DnsProblemPage() {
  const { id = "", problemId = "" } = useParams({ strict: false }) as {
    id?: string
    problemId?: string
  }
  const { data: domains } = useDomains()
  const navigate = useNavigate()

  const domain = (domains ?? []).find((d) => d.id === id)
  const name = domain?.name ?? id
  const ps = dnsProblemStateById(problemId.toUpperCase())

  return (
    <div className="mx-auto max-w-3xl">
      <button
        type="button"
        onClick={() => navigate({ to: "/domains/$id/dns", params: { id } })}
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

          <Section title="Your data — fields to look at">
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
