/**
 * Helpers for the DMARC run-YAML section (pm/checks/dmarc.mdx §5). `results.dmarc` is the whole
 * section — { status, record, tool_runs, tests, problem_states } — but runs persisted before that
 * shape landed hold the bare `record` object; normalize both so the pages render either vintage.
 */
import type { DmarcResults, DmarcSection, DmarcToolRun } from "@/api/types"

export interface NormalizedDmarc {
  record: DmarcResults | undefined
  toolRuns: DmarcToolRun[]
  /** Backend-derived §9 problem-state ids; null when the run predates backend derivation. */
  problemStates: string[] | null
}

export function normalizeDmarcSection(
  raw: DmarcSection | DmarcResults | undefined,
): NormalizedDmarc {
  if (!raw || typeof raw !== "object") return { record: undefined, toolRuns: [], problemStates: null }
  if ("record" in raw) {
    const section = raw as DmarcSection
    return {
      record: section.record,
      toolRuns: Array.isArray(section.tool_runs) ? section.tool_runs : [],
      problemStates: Array.isArray(section.problem_states) ? section.problem_states : null,
    }
  }
  // Legacy flat shape: the object IS the record; no provenance or derived states available.
  return { record: raw as DmarcResults, toolRuns: [], problemStates: null }
}
