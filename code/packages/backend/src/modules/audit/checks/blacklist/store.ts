import { existsSync, readdirSync, rmSync } from "node:fs"
import { join } from "node:path"
import { stateSubdir } from "@shared/state-dir"
import { readYaml, writeYaml } from "@shared/yaml-store"
import type {
  BlacklistHistoryEntry,
  BlacklistRunResults,
  PortalUserState,
  ProviderPortal,
} from "./blacklist-types"

/**
 * Per-run persistence for the Blacklists checker (pm/checks/blacklists.mdx §12). Layout under the
 * app state dir (EDH_STATE_DIR):
 *
 *   blacklists/<domainId>/latest.yaml            — the most recent full BlacklistRunResults
 *   blacklists/<domainId>/runs/<auditId>.yaml    — append-only history (pruned to MAX_RUNS)
 *   blacklists/<domainId>/portals.yaml           — the user's provider-portal checklist state
 *
 * The audit engine's audits.json stays latest-only; this store is what powers the diff (§6) and the
 * history sparkline (§13.2). Plain functions (no DI) so both the checker and the Nest controller
 * can use them.
 */

const MAX_RUNS = 50

function domainDir(domainId: string): string {
  return stateSubdir("blacklists", sanitize(domainId))
}

function sanitize(part: string): string {
  return part.replace(/[^a-zA-Z0-9._-]/g, "_")
}

export function saveBlacklistRun(domainId: string, run: BlacklistRunResults): void {
  const dir = domainDir(domainId)
  const runsDir = join(dir, "runs")
  writeYaml(join(runsDir, `${sanitize(run.audit_id)}.yaml`), run)
  writeYaml(join(dir, "latest.yaml"), run)
  pruneRuns(runsDir)
}

function pruneRuns(runsDir: string): void {
  if (!existsSync(runsDir)) return
  const files = readdirSync(runsDir)
    .filter((f) => f.endsWith(".yaml"))
    .sort() // audit ids are timestamp-prefixed, so lexical order = chronological
  for (const stale of files.slice(0, Math.max(0, files.length - MAX_RUNS))) {
    try {
      rmSync(join(runsDir, stale))
    } catch {
      // Pruning is best-effort; a leftover run file is harmless.
    }
  }
}

export function readLatestBlacklistRun(domainId: string): BlacklistRunResults | null {
  return readYaml<BlacklistRunResults | null>(join(domainDir(domainId), "latest.yaml"), null)
}

export function readBlacklistHistory(domainId: string): BlacklistHistoryEntry[] {
  const runsDir = join(domainDir(domainId), "runs")
  if (!existsSync(runsDir)) return []
  const entries: BlacklistHistoryEntry[] = []
  for (const file of readdirSync(runsDir)
    .filter((f) => f.endsWith(".yaml"))
    .sort()) {
    const run = readYaml<BlacklistRunResults | null>(join(runsDir, file), null)
    if (!run) continue
    entries.push({
      audit_id: run.audit_id,
      ran_at: run.ran_at,
      listed: run.summary.listed,
      clean: run.summary.clean,
      inconclusive: run.summary.inconclusive,
      worst_severity: run.summary.worst_severity,
    })
  }
  return entries
}

/** All domain ids that have at least one persisted blacklist run. */
export function listBlacklistDomainIds(): string[] {
  const root = stateSubdir("blacklists")
  if (!existsSync(root)) return []
  return readdirSync(root, { withFileTypes: true })
    .filter((e) => e.isDirectory() && existsSync(join(root, e.name, "latest.yaml")))
    .map((e) => e.name)
}

type PortalStateFile = Record<string, PortalUserState>

export function readPortalStates(domainId: string): PortalStateFile {
  return readYaml<PortalStateFile>(join(domainDir(domainId), "portals.yaml"), {})
}

export function writePortalState(
  domainId: string,
  provider: string,
  state: PortalUserState,
): PortalStateFile {
  const states = readPortalStates(domainId)
  states[provider] = state
  writeYaml(join(domainDir(domainId), "portals.yaml"), states)
  return states
}

export function applyPortalStates(
  portals: Array<Omit<ProviderPortal, "user_state">>,
  states: PortalStateFile,
): ProviderPortal[] {
  return portals.map((p) => ({ ...p, user_state: states[p.provider] ?? "unverified" }))
}
