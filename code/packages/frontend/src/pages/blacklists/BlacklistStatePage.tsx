import { Link, useParams } from "@tanstack/react-router"
import { ExternalLink, Terminal } from "lucide-react"
import { useBlacklistRun } from "@/api/blacklists"
import { SeverityBadge } from "@/components/Badges"
import { problemState } from "@/lib/problemStates"

/**
 * The problem-state deep-dive page (pm/checks/blacklists.mdx §16): /blacklists/$domain/state/$psId.
 * A page purely about ONE state — the concept explained, this domain's live evidence, the
 * diagnose-it-yourself commands, the tools, and the ordered "progress forward" checklist.
 */
export function BlacklistStatePage() {
  const { domain, psId } = useParams({ from: "/blacklists/$domain/state/$psId" as never }) as {
    domain: string
    psId: string
  }
  const { data: run } = useBlacklistRun(domain)
  const ps = problemState(psId)

  if (!ps) {
    return (
      <div className="mx-auto max-w-3xl">
        <p className="text-sm text-[var(--edh-muted)]">Unknown problem state: {psId}</p>
      </div>
    )
  }

  const evidence = run?.results.filter((r) => r.listed && r.problem_state === ps.id) ?? []
  const detected = run?.summary.problem_states.includes(ps.id) ?? false
  const firstIp = run?.targets.ips[0]?.ip
  const substitute = (cmd: string) =>
    cmd
      .replaceAll("<domain>", domain)
      .replaceAll("<ip>", firstIp ?? "<ip>")
      .replaceAll("<reversed-ip>", firstIp ? firstIp.split(".").reverse().join(".") : "<reversed-ip>")

  return (
    <div className="mx-auto max-w-3xl">
      <Link to="/blacklists/$domain" params={{ domain }} className="text-sm text-[var(--edh-primary)]">
        ← Blacklists for {domain}
      </Link>

      <div className="mt-2 flex items-center gap-3">
        <SeverityBadge severity={ps.severity} />
        <h1 className="text-2xl font-bold">
          {ps.id}: {ps.name}
        </h1>
      </div>
      <p className="mt-1 text-sm text-[var(--edh-muted)]">
        Trigger: {ps.trigger}
        {run && (
          <span className={detected ? " font-semibold text-red-700" : " text-emerald-700"}>
            {detected ? " — detected on this domain's latest run." : " — not currently detected on this domain."}
          </span>
        )}
      </p>

      <section className="mt-5 rounded-lg border border-[var(--edh-border)] bg-white p-4">
        <h2 className="mb-1 font-semibold">The concept</h2>
        <p className="text-sm text-slate-700">{ps.concept}</p>
      </section>

      {evidence.length > 0 && (
        <section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
          <h2 className="mb-2 font-semibold">This domain's evidence</h2>
          <ul className="space-y-1 text-sm">
            {evidence.map((r) => (
              <li key={`${r.zone}|${r.target}`} className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={r.severity ?? "warning"} />
                <span className="font-medium">{r.name}</span>
                <span className="font-mono text-xs">{r.target}</span>
                <span className="font-mono text-xs text-slate-500">
                  {r.return_code}
                  {r.sub_list ? ` = ${r.sub_list}` : ""}
                </span>
                <a
                  href={r.delist_url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-[var(--edh-primary)]"
                >
                  Delist <ExternalLink className="h-3 w-3" />
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
        <h2 className="mb-2 flex items-center gap-2 font-semibold">
          <Terminal className="h-4 w-4" /> Diagnose it yourself
        </h2>
        <pre className="overflow-x-auto rounded-md bg-slate-900 p-3 text-xs text-slate-100">
          {ps.diagnose.map((c) => substitute(c)).join("\n")}
        </pre>
        <p className="mt-2 text-xs text-[var(--edh-muted)]">Tools: {ps.tools.join(" · ")}</p>
      </section>

      <section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
        <h2 className="mb-2 font-semibold">How to progress forward</h2>
        <ol className="list-decimal space-y-1 pl-5 text-sm text-slate-700">
          {ps.progress.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
      </section>

      <section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
        <h2 className="mb-2 font-semibold">More health metrics to test</h2>
        <ul className="list-disc space-y-1 pl-5 text-sm text-slate-700">
          {ps.furtherHealth.map((m) => (
            <li key={m}>{m}</li>
          ))}
        </ul>
      </section>
    </div>
  )
}
