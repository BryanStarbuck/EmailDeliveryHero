import type { Severity } from "@/api/types"
import { cn } from "@/lib/utils"

const SEVERITY_STYLE: Record<Severity, string> = {
  ok: "bg-emerald-100 text-emerald-800",
  info: "bg-sky-100 text-sky-800",
  warning: "bg-amber-100 text-amber-800",
  critical: "bg-red-100 text-red-800",
}

const SEVERITY_LABEL: Record<Severity, string> = {
  ok: "OK",
  info: "Info",
  warning: "Warning",
  critical: "Critical",
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium",
        SEVERITY_STYLE[severity],
      )}
    >
      {SEVERITY_LABEL[severity]}
    </span>
  )
}

/** A 0–100 deliverability score, colored by band. */
export function ScoreBadge({ score }: { score: number }) {
  const style =
    score >= 90
      ? "bg-emerald-100 text-emerald-800"
      : score >= 70
        ? "bg-amber-100 text-amber-800"
        : "bg-red-100 text-red-800"
  return (
    <span
      className={cn("inline-flex items-center rounded-md px-2 py-1 text-sm font-semibold", style)}
    >
      {score}
      <span className="ml-0.5 text-xs font-normal opacity-70">/100</span>
    </span>
  )
}
