import type { ReactNode } from "react"
import type { AuditResult } from "@/api/types"
import type { UnitResult } from "@/lib/dmarc-checks"
import { cn } from "@/lib/utils"

/** Chip color per result (§6.7: green/slate/amber/red; gray = not measured in that run). */
const CHIP: Record<string, string> = {
  pass: "bg-emerald-600",
  info: "bg-slate-400",
  warn: "bg-amber-500",
  fail: "bg-red-600",
  none: "border border-slate-300 bg-white",
}

/**
 * The run-history strip (pm/checks/dmarc.mdx §6.7) — one reusable element, two scopes: on a
 * category page it shows the category's worst result per run; on a sub-test explainer it shows
 * that unit's result per run. The domain's last 10 runs render as small square chips, oldest →
 * newest left-to-right, colored by result, the currently viewed run outlined. Hover shows the
 * run's timestamp plus a one-line delta versus the previous run; click swaps the viewed run —
 * the same navigation as the ‹ prev / next › pager. Overflow beyond 10 runs renders a leading
 * "…" chip (the caller links it to the domain's runs table).
 */
export function RunHistoryStrip({
  runs,
  currentRunId,
  resultFor,
  deltaFor,
  onSelect,
  overflow,
  ariaLabel = "Run history",
}: {
  /** The domain's runs, oldest → newest (the strip renders the last 10). */
  runs: AuditResult[]
  /** The run currently being viewed (outlined chip). */
  currentRunId?: string
  /** The chip result for one run; null = not measured in that run (gray chip). */
  resultFor: (run: AuditResult) => UnitResult | null
  /** Optional one-line delta versus the previous run, shown in the hover tooltip. */
  deltaFor?: (run: AuditResult, prev: AuditResult | undefined) => string | null
  onSelect: (run: AuditResult) => void
  /** Rendered before the chips when more than 10 runs exist (the "…" overflow link). */
  overflow?: ReactNode
  ariaLabel?: string
}) {
  if (runs.length === 0) return null
  const shown = runs.slice(-10)
  const firstShownIdx = runs.length - shown.length
  return (
    <span className="inline-flex items-center gap-1" aria-label={ariaLabel}>
      {runs.length > 10 && overflow}
      {shown.map((run, i) => {
        const prev = firstShownIdx + i > 0 ? runs[firstShownIdx + i - 1] : undefined
        const result = resultFor(run)
        const stamp = fmtStamp(run.startedAt ?? run.ranAt)
        const delta = deltaFor?.(run, prev)
        const isViewed = Boolean(run.runId && run.runId === currentRunId)
        return (
          <button
            key={run.runId ?? run.ranAt}
            type="button"
            onClick={() => onSelect(run)}
            title={delta ? `${stamp} — ${delta}` : stamp}
            aria-label={`Run ${stamp}${result ? ` (${result})` : " (not measured)"}`}
            aria-current={isViewed ? "true" : undefined}
            className={cn(
              "h-3 w-3 shrink-0 rounded-[3px]",
              CHIP[result ?? "none"],
              isViewed && "ring-2 ring-[var(--edh-primary)] ring-offset-1",
            )}
          />
        )
      })}
    </span>
  )
}

function fmtStamp(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const p = (n: number): string => String(n).padStart(2, "0")
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}
