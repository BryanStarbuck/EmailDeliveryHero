/**
 * The tool-catalog model shared by the brew and npm sides of the Install flow
 * (pm/install_brew.mdx §3, pm/install_npm.mdx §3).
 *
 * One entry describes a tool the audit engine may shell out to (brew CLI) or a JS package the
 * checkers import (npm). The catalog is the SINGLE SOURCE OF TRUTH for "which formula/package
 * provides which capability", superseding the scattered "Testing toolbox" mentions in checks/*.mdx.
 */

/** The audit category a tool serves — drives grouping on the page and scoped preflight. */
export type ToolCategory =
  | "dns"
  | "spf"
  | "dkim"
  | "dmarc"
  | "blacklist"
  | "spam"
  | "tls"
  | "general"

/** Which package manager installs the tool. `special` = cpanm/pipx/docker/os (pm/install_brew.mdx §3.3). */
export type ToolManager = "brew" | "npm" | "special"

/** `default` rows are pre-checked (the baseline audit path); `extended` are opt-in. */
export type ToolTier = "default" | "extended"

/** How detection decides "installed" (pm/install_brew.mdx §5, pm/install_npm.mdx §5). */
export type DetectKind =
  | "binary" // at least one of `binaries` resolves on PATH (brew/special CLI tools)
  | "node-module" // the npm `pkg` resolves from the backend node_modules (npm L1/L2)
  | "pnpm" // the `pnpm` binary itself (npm L0)
  | "workspace" // the monorepo node_modules is present (npm L1 restore)
  | "builtin" // a Node built-in — always satisfied, never missing

/** How installation runs (pm/install_brew.mdx §6, pm/install_npm.mdx §4). */
export type InstallKind =
  | "brew" // brew install <formula>
  | "cpanm" // brew install perl cpanminus && cpanm --notest <module>
  | "pipx" // pipx install <pkg> (when pipx present, else copy-only)
  | "pnpm-add" // pnpm --filter backend add <pkg>
  | "pnpm-install" // pnpm install (restore workspace)
  | "corepack" // corepack enable pnpm (preferred) / npm i -g pnpm
  | "copy" // needs root/Docker — copy the command, never auto-run

/** A concrete spawn: `execFile(file, args)` — NO shell, args are fixed catalog strings. */
export interface InstallSpawn {
  file: string
  args: string[]
  /** When true, run in the `code/` monorepo root (pnpm add/install), else the process cwd. */
  cwd?: "code"
}

export interface ToolCatalogEntry {
  /** Stable id, e.g. "doggo", "spamassassin", "mailauth". */
  id: string
  manager: ToolManager
  category: ToolCategory
  tier: ToolTier
  /** Display name for the row's line 1 (binaries joined, or the package name). */
  label: string
  /** One line shown on the row. */
  summary: string
  /** The executables this entry provides / the ones detection looks for on PATH. */
  binaries: string[]
  /** Brew formula name (may differ from the binary! e.g. drill→ldns). */
  formula?: string
  /** npm package name (for node-module detect + pnpm-add). */
  pkg?: string
  detect: DetectKind
  install: InstallKind
  /** The exact command shown on the row (line 3). */
  installCmd: string
  /** The real spawn when `autoInstallable`; absent for copy-only rows. */
  spawns?: InstallSpawn[]
  /** false → copy-only row (needs root/Docker/pip absent) — never batch-installed. */
  autoInstallable: boolean
  /** checkIds / families that shell out to (or import) this tool — drives scoped preflight. */
  usedBy: ToolCategory[]
  /** The gotcha shown as amber subtext (keg-only, "needs Docker", EUPL license…). */
  notes?: string
}

/** Live status merged onto a catalog entry for the API responses. */
export interface ToolStatus extends ToolCatalogEntry {
  installed: boolean
  /** Resolved absolute path (binary) or version (npm), when known. */
  resolved?: string
}
