import { BREW_CATALOG } from "./brew"
import { NPM_CATALOG } from "./npm"
import type { ToolCatalogEntry, ToolCategory, ToolManager } from "./types"

export * from "./types"

/** The merged catalog spanning both managers (pm/install_npm.mdx §6.1). */
export const CATALOG: ToolCatalogEntry[] = [...BREW_CATALOG, ...NPM_CATALOG]

const BY_ID = new Map(CATALOG.map((e) => [e.id, e]))

export function catalogFor(manager?: ToolManager | "all"): ToolCatalogEntry[] {
  if (!manager || manager === "all") return CATALOG
  // The npm side spans manager "npm"; the brew side spans "brew" + "special" (cpanm/pipx/os).
  if (manager === "npm") return NPM_CATALOG
  return BREW_CATALOG
}

export function catalogEntry(id: string): ToolCatalogEntry | undefined {
  return BY_ID.get(id)
}

/**
 * The categories a run scope touches (pm/install_brew.mdx §5.3). DNS is foundational to every
 * scope. A `run-check:<checkId>` narrows to DNS + that check's category; run-all / run-domain span
 * every category.
 */
export function scopeCategories(scope: string | undefined): ToolCategory[] {
  const all: ToolCategory[] = ["dns", "spf", "dkim", "dmarc", "blacklist", "spam", "tls", "general"]
  if (!scope || scope === "run-all" || scope.startsWith("run-domain")) return all
  if (scope.startsWith("run-check")) {
    const checkId = scope.split(":")[1] ?? ""
    return ["dns", checkCategory(checkId)]
  }
  return all
}

/** Map a checker id (e.g. "spf", "infra.mx_routing", "content.spam") to its catalog category. */
export function checkCategory(checkId: string): ToolCategory {
  const id = checkId.toLowerCase()
  if (id.startsWith("spf")) return "spf"
  if (id.startsWith("dkim")) return "dkim"
  if (id.startsWith("dmarc") || id.startsWith("arc") || id.includes("bimi")) return "dmarc"
  if (id.startsWith("blacklist") || id.includes("dnsbl")) return "blacklist"
  if (id.startsWith("content") || id.includes("spam")) return "spam"
  if (id.includes("tls") || id.includes("smtp") || id.includes("mta_sts") || id.includes("dane"))
    return "tls"
  if (id.startsWith("infra") || id.includes("dns") || id.includes("mx") || id.includes("reverse"))
    return "dns"
  return "general"
}
