import { useNavigate, useParams } from "@tanstack/react-router"
import { ArrowLeft } from "lucide-react"
import { useDomains } from "@/api/domains"
import { ProblemDrilldown } from "@/components/ProblemDrilldown"
import { problemStateById } from "@/lib/dmarc-problems"

/**
 * The DMARC per-problem drill-down page (pm/checks/dmarc.mdx §7).
 * Route: /domains/:id/dmarc/:problemId.
 */
export function DmarcProblemPage() {
  const { id = "", problemId = "" } = useParams({ strict: false }) as {
    id?: string
    problemId?: string
  }
  const { data: domains } = useDomains()
  const navigate = useNavigate()

  const domain = (domains ?? []).find((d) => d.id === id)
  const name = domain?.name ?? id
  const ps = problemStateById(problemId.toUpperCase())

  return (
    <div className="mx-auto max-w-3xl">
      <button
        type="button"
        onClick={() => navigate({ to: "/domains/$id/dmarc", params: { id } })}
        className="mb-4 inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
      >
        <ArrowLeft className="h-4 w-4" /> Back to DMARC for {name}
      </button>

      {!ps ? (
        <p className="text-slate-600">Unknown problem state "{problemId}".</p>
      ) : (
        <ProblemDrilldown ps={ps} domainName={name} />
      )}
    </div>
  )
}
