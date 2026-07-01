/**
 * The six LOCKED dashboard categories (pm/ui.mdx §1.1) and the roll-up from a flat finding list to
 * one color-coded StatusCell per category. Every checker's finding lands in exactly one category,
 * chosen by the prefix of its `checkId` (`checkId.split(".")[0]`): spf, dkim, dmarc/arc, blacklist,
 * infra, content. ARC has no cell of its own — it feeds DMARC.
 */
import type { Finding, Severity } from "@/api/types"

/** The six locked column keys, in display order. */
export type CategoryKey = "spf" | "dkim" | "dmarc" | "blacklists" | "dnsInfra" | "spamContent"

/** Cell color drives the Tailwind background (pm/ui.mdx §1.2). */
export type CellColor = "green" | "amber" | "red" | "gray"

export interface CellStatus {
  color: CellColor
  /** Short metric string, ≤10 chars ideal. */
  label: string
  /** Longer text for the cell tooltip (the top open problem, or a healthy summary). */
  title: string
}

interface CategoryDef {
  key: CategoryKey
  header: string
  /** `checkId` prefixes that roll into this category. */
  prefixes: string[]
}

/** The six categories in their locked order. */
export const CATEGORIES: CategoryDef[] = [
  { key: "spf", header: "SPF", prefixes: ["spf"] },
  { key: "dkim", header: "DKIM", prefixes: ["dkim"] },
  { key: "dmarc", header: "DMARC", prefixes: ["dmarc", "arc"] },
  { key: "blacklists", header: "Blacklists", prefixes: ["blacklist"] },
  { key: "dnsInfra", header: "DNS & Infrastructure", prefixes: ["infra"] },
  { key: "spamContent", header: "Spam & Content", prefixes: ["content"] },
]

const PREFIX_TO_KEY: Record<string, CategoryKey> = Object.fromEntries(
  CATEGORIES.flatMap((c) => c.prefixes.map((p) => [p, c.key])),
) as Record<string, CategoryKey>

/** Which of the six categories a finding belongs to (by its checkId prefix). */
export function categoryOf(checkId: string): CategoryKey | null {
  return PREFIX_TO_KEY[checkId.split(".")[0]] ?? null
}

/** The never-run cell — no audit has produced this category yet. */
export const NEVER_CELL: CellStatus = { color: "gray", label: "Never", title: "Never run" }

const WORST: Record<Severity, number> = { ok: 0, info: 1, warning: 2, critical: 3 }

function colorFor(worst: Severity): CellColor {
  if (worst === "critical") return "red"
  if (worst === "warning") return "amber"
  return "green" // ok / info → healthy (info never turns a cell amber)
}

/** Roll one category's findings into a StatusCell. */
function cellFor(key: CategoryKey, findings: Finding[]): CellStatus {
  if (findings.length === 0) return NEVER_CELL

  let worst: Severity = "ok"
  for (const f of findings) if (WORST[f.severity] > WORST[worst]) worst = f.severity
  const color = colorFor(worst)

  const failing = findings.filter((f) => f.severity === "warning" || f.severity === "critical")
  const top = [...failing].sort((a, b) => WORST[b.severity] - WORST[a.severity])[0]

  // Blacklists is count-oriented ("N problems"); every other category is "K of M fail".
  let label: string
  if (failing.length === 0) {
    label = "Healthy"
  } else if (key === "blacklists") {
    label = failing.length === 1 ? "1 problem" : `${failing.length} problems`
  } else {
    label = `${failing.length} of ${findings.length} fail`
  }

  const title = top ? `${top.title}` : `${findings.length} checks passed`
  return { color, label, title }
}

/** Roll a whole audit's findings into the six category cells (in locked order). */
export function rollupCategories(findings: Finding[] | undefined): Record<CategoryKey, CellStatus> {
  const out = {} as Record<CategoryKey, CellStatus>
  for (const cat of CATEGORIES) {
    if (!findings) {
      out[cat.key] = NEVER_CELL
      continue
    }
    out[cat.key] = cellFor(
      cat.key,
      findings.filter((f) => categoryOf(f.checkId) === cat.key),
    )
  }
  return out
}
