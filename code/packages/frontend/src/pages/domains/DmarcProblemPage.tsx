import { useNavigate, useParams } from "@tanstack/react-router"
import { ArrowLeft, ChevronLeft, ChevronRight, Star } from "lucide-react"
import { useMemo } from "react"
import { useAuditResults, useAuditRuns } from "@/api/audit"
import { useDomains } from "@/api/domains"
import type { AuditResult, DmarcResults } from "@/api/types"
import { ProblemDrilldown } from "@/components/ProblemDrilldown"
import { normalizeDmarcSection } from "@/lib/dmarc"
import { problemStateById } from "@/lib/dmarc-problems"

/**
 * The DMARC per-problem drill-down page (pm/checks/dmarc.mdx §7): the same header + run context
 * as the DMARC page (the data shown is THIS run's, not the latest), the concept, this run's
 * actual dmarc data, diagnose-it-yourself commands, and the path forward. Routes:
 * /domains/:id/runs/:runId/dmarc/:problemId and the newest-run alias /domains/:id/dmarc/:problemId.
 */
export function DmarcProblemPage() {
  const {
    id = "",
    runId,
    problemId = "",
  } = useParams({ strict: false }) as {
    id?: string
    runId?: string
    problemId?: string
  }
  const { data: domains } = useDomains()
  const { data: results } = useAuditResults()
  const { data: runs } = useAuditRuns()
  const navigate = useNavigate()

  const domain = (domains ?? []).find((d) => d.id === id)
  const name = domain?.name ?? id
  const ps = problemStateById(problemId.toUpperCase())

  // Run-scoped (§7 drill-down rules): render this RUN's data; the alias renders the newest run.
  const result = runId
    ? (runs ?? []).find((r) => r.runId === runId)
    : (results ?? []).find((r) => r.domainId === id)
  const { record } = normalizeDmarcSection(result?.results?.dmarc)

  // The same run context strip as the DMARC page (§7): this domain's runs in startedAt order
  // give the ‹ prev / next › pager rail and the ★ newest badge.
  const domainRuns = useMemo(
    () =>
      (runs ?? [])
        .filter((r) => r.domainId === id)
        .sort((a, b) => (a.startedAt ?? a.ranAt).localeCompare(b.startedAt ?? b.ranAt)),
    [runs, id],
  )
  const indexInRail = domainRuns.findIndex((r) => r.runId && r.runId === result?.runId)
  const effectiveIndex = indexInRail >= 0 ? indexInRail : !runId ? domainRuns.length - 1 : -1
  const prevRun = effectiveIndex > 0 ? domainRuns[effectiveIndex - 1] : undefined
  const nextRun =
    effectiveIndex >= 0 && effectiveIndex < domainRuns.length - 1
      ? domainRuns[effectiveIndex + 1]
      : undefined
  const isNewest = !runId || (effectiveIndex >= 0 && effectiveIndex === domainRuns.length - 1)

  // Paging swaps :runId while keeping the same problem drill-down in view.
  const goToRun = (r: AuditResult | undefined): void => {
    if (r?.runId) {
      navigate({
        to: "/domains/$id/runs/$runId/dmarc/$problemId",
        params: { id, runId: r.runId, problemId },
      })
    }
  }

  const back = (): void => {
    if (runId) {
      navigate({ to: "/domains/$id/runs/$runId/dmarc", params: { id, runId } })
    } else {
      navigate({ to: "/domains/$id/dmarc", params: { id } })
    }
  }

  return (
    <div className="mx-auto max-w-3xl">
      <button
        type="button"
        onClick={back}
        className="mb-1 inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
      >
        <ArrowLeft className="h-4 w-4" /> Back to DMARC for {name}
      </button>

      {/* Run context strip (§7 — same strip as the DMARC page): the drill-down keeps the run's
          vintage unmistakable, with the ‹ prev / next › pager stepping this domain's runs. */}
      {result && (
        <div className="mb-4 flex flex-wrap items-center gap-2 text-xs text-[var(--edh-muted)]">
          <span className="tabular-nums">
            Run {new Date(result.startedAt ?? result.ranAt).toLocaleString()}
          </span>
          <span>·</span>
          <button
            type="button"
            onClick={() => goToRun(prevRun)}
            disabled={!prevRun}
            aria-label="Previous run"
            className="inline-flex items-center gap-0.5 rounded border border-[var(--edh-border)] px-2 py-0.5 hover:bg-slate-50 disabled:opacity-40"
          >
            <ChevronLeft className="h-3.5 w-3.5" /> prev
          </button>
          <button
            type="button"
            onClick={() => goToRun(nextRun)}
            disabled={!nextRun}
            aria-label="Next run"
            className="inline-flex items-center gap-0.5 rounded border border-[var(--edh-border)] px-2 py-0.5 hover:bg-slate-50 disabled:opacity-40"
          >
            next <ChevronRight className="h-3.5 w-3.5" />
          </button>
          {isNewest && (
            <span className="inline-flex items-center gap-1 rounded bg-amber-50 px-1.5 py-0.5 font-medium text-amber-700">
              <Star className="h-3 w-3" /> newest
            </span>
          )}
        </div>
      )}

      {!ps ? (
        <p className="text-slate-600">Unknown problem state "{problemId}".</p>
      ) : (
        <>
          <ProblemDrilldown ps={ps} domainName={name} />
          <YourRunData record={record} />
        </>
      )}
    </div>
  )
}

/** This run's actual `dmarc.record` values (§7 "Your data" — rendered, not just field names). */
function YourRunData({ record }: { record: DmarcResults | undefined }) {
  if (!record) return null
  const rows: [string, string][] = [
    ["query_name", record.query_name],
    ["record_found", String(record.record_found)],
    ["found_at", record.found_at ?? "—"],
    ["raw_record", record.raw_record ?? "—"],
    ["policy (p)", record.policy ?? "—"],
    ["subdomain_policy (sp)", record.subdomain_policy ?? "—"],
    ["np_policy (np)", record.np_policy ?? "—"],
    ["adkim / aspf", `${record.adkim} / ${record.aspf}`],
    ["rua_uris", record.rua_uris.length > 0 ? record.rua_uris.join(", ") : "—"],
    ["ruf_uris", record.ruf_uris.length > 0 ? record.ruf_uris.join(", ") : "—"],
    ["is_enforcing", String(record.is_enforcing)],
    [
      "external_reports_authorized",
      record.external_reports_authorized === null
        ? "— (no external destinations)"
        : String(record.external_reports_authorized),
    ],
  ]
  return (
    <section className="mt-6">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--edh-muted)]">
        Your data — this run
      </h2>
      <div className="mt-2 overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
        <table className="w-full text-sm">
          <tbody>
            {rows.map(([field, value]) => (
              <tr key={field} className="border-t border-[var(--edh-border)] first:border-t-0">
                <td className="w-56 px-3 py-1.5 align-top font-mono text-xs font-semibold">
                  {field}
                </td>
                <td className="break-all px-3 py-1.5 align-top font-mono text-xs text-slate-700">
                  {value}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {record.external_report_auth.length > 0 && (
        <div className="mt-2 overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-[var(--edh-muted)]">
                <th className="px-3 py-1.5 font-medium">kind</th>
                <th className="px-3 py-1.5 font-medium">auth_name</th>
                <th className="px-3 py-1.5 font-medium">authorized</th>
              </tr>
            </thead>
            <tbody>
              {record.external_report_auth.map((a) => (
                <tr
                  key={a.auth_name + a.report_kind}
                  className="border-t border-[var(--edh-border)]"
                >
                  <td className="px-3 py-1.5 font-mono text-xs uppercase">{a.report_kind}</td>
                  <td className="break-all px-3 py-1.5 font-mono text-xs">{a.auth_name}</td>
                  <td className="px-3 py-1.5 font-mono text-xs">
                    {a.authorized ? "✓ yes" : "✗ no"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
