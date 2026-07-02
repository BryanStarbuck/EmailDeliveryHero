import type { ToolManager, ToolStatus } from "./catalog"

/** GET /api/install/catalog + /preflight response. */
export interface PreflightResult {
  manager: ToolManager | "all"
  /** Is Homebrew present? (drives the U4 banner). Null when the query is npm-only. */
  brewPresent: boolean | null
  /** How pnpm can be enabled if absent: 'corepack' | 'npm' | 'none'. */
  pnpmEnable: "corepack" | "npm" | "none"
  /** Tools this scope NEEDS that are absent (default tier) — the page pre-checks these. */
  missing: ToolStatus[]
  /** Optional tools for this scope that are absent (extended tier) — shown unchecked. */
  optional: ToolStatus[]
  /** Already-installed tools for this scope (for the Settings coverage view). */
  installed: ToolStatus[]
}

/** One row's settled outcome after an install batch. */
export interface InstallItemResult {
  id: string
  ok: boolean
  code: number | null
  /** Tail of stderr on failure (pm/install_brew.mdx §6.2). */
  tail: string
}

/** POST /api/install/run response — the client streams by jobId or polls GET /run/:jobId. */
export interface InstallJobAccepted {
  jobId: string
  ids: string[]
}

/** GET /api/install/run/:jobId — coarse status + settled summary (poll fallback). */
export interface InstallJobStatus {
  jobId: string
  done: boolean
  /** Per-id phase for the live rows when polling. */
  phases: Record<string, "queued" | "installing" | "done" | "failed">
  results: InstallItemResult[]
}

/** SSE event shape on GET /api/install/run/:jobId/stream. */
export interface InstallStreamEvent {
  id: string
  phase: "installing" | "done" | "failed"
  line?: string
}
