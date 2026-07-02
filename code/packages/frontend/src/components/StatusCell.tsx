import { ChevronRight } from "lucide-react"
import type { CellStatus } from "@/lib/categories"
import { cn } from "@/lib/utils"

/**
 * A single color-coded category cell (pm/ui.mdx §1.2–1.3). Color is the worst finding severity in
 * the category; the label is the short metric. The four colors are LOCKED and meet WCAG AA. Used
 * identically on the Dashboard and the Domains table so a user reads color the same way everywhere.
 */
const CELL_CLASSES: Record<CellStatus["color"], string> = {
  green: "bg-green-800 text-white",
  amber: "bg-amber-500 text-black",
  red: "bg-red-800 text-white",
  gray: "bg-gray-100 text-gray-500",
}

export function StatusCell({
  status,
  hoverChevron = false,
}: {
  status: CellStatus
  /**
   * Show a small › at the cell's right edge while a `group/cell` ancestor is hovered — the
   * "this cell opens up" affordance for the Dashboard's clickable test cells (pm/dashboard.mdx §6.2).
   */
  hoverChevron?: boolean
}) {
  return (
    <span
      title={status.title}
      className={cn(
        "relative inline-flex w-full items-center justify-center rounded px-2 py-1 text-xs font-medium",
        CELL_CLASSES[status.color],
      )}
    >
      {status.label}
      {hoverChevron && (
        <ChevronRight
          aria-hidden="true"
          className="absolute right-0.5 h-3 w-3 opacity-0 transition-opacity group-hover/cell:opacity-100"
        />
      )}
    </span>
  )
}
