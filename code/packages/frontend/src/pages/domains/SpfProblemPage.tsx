import { useNavigate, useParams } from "@tanstack/react-router"
import { ArrowLeft } from "lucide-react"
import { useDomains } from "@/api/domains"
import { ProblemDrilldown } from "@/components/ProblemDrilldown"
import { spfProblemStateById } from "@/lib/spf-problems"

/** The SPF per-problem drill-down page (pm/checks/spf.mdx §7). Route: /domains/:id/spf/:problemId. */
export function SpfProblemPage() {
  const { id = "", problemId = "" } = useParams({ strict: false }) as {
    id?: string
    problemId?: string
  }
  const { data: domains } = useDomains()
  const navigate = useNavigate()

  const domain = (domains ?? []).find((d) => d.id === id)
  const name = domain?.name ?? id
  const ps = spfProblemStateById(problemId.toUpperCase())

  return (
    <div className="mx-auto max-w-3xl">
      <button
        type="button"
        onClick={() => navigate({ to: "/domains/$id/spf", params: { id } })}
        className="mb-4 inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
      >
        <ArrowLeft className="h-4 w-4" /> Back to SPF for {name}
      </button>

      {!ps ? (
        <p className="text-slate-600">Unknown problem state "{problemId}".</p>
      ) : (
        <ProblemDrilldown ps={ps} domainName={name} />
      )}
    </div>
  )
}
