import { execFile } from "node:child_process"
import { accessSync, constants } from "node:fs"
import { delimiter, join } from "node:path"
import { readAppConfig } from "./config-store"
import { type ResourceClass, withResource } from "./concurrency"

/**
 * The shared child-process contract for Brew/OS-installed tools (pm/run_checks.mdx §5).
 *
 * ToolRunner (§5.1): every spawn goes through `runTool` — `execFile` with an args array (no shell,
 * ever), stdin as the data plane for content input, a hard timeout (SIGTERM then a grace SIGKILL),
 * a `maxBuffer` cap, and a STRUCTURED result — a non-zero exit is data (e.g. `dig` NXDOMAIN), not
 * an exception.
 *
 * ToolLocator (§5.2): scheduled runs (launchd/cron/schtasks) execute with a minimal PATH that does
 * not include Homebrew's directories, so `locateTool` resolves each tool to an absolute path via
 * (1) an explicit override, (2) an in-process PATH search (`which` semantics — never the macOS
 * `find`), then (3) the platform's conventional locations (§6–§8 fallback dirs). A missing tool is
 * a capability downgrade, never a failure (§5.3) — callers degrade to pure Node or one `info`
 * finding.
 */

export interface ToolResult {
  /** The child's exit code; null when it never ran (spawn failure) or was killed. */
  code: number | null
  stdout: string
  stderr: string
  /** True when the hard timeout expired and the child was killed. */
  timedOut: boolean
}

export interface ToolRunOptions {
  /** Hard kill budget (default 30s; probe tools should pass 10s). */
  timeoutMs?: number
  /** stdout/stderr cap so a misbehaving tool cannot balloon the Node heap (default 10 MB). */
  maxBuffer?: number
  /** Content input (e.g. a raw .eml for SpamAssassin) written as raw bytes to the child's stdin. */
  stdin?: string | Buffer
  /** Cooperative cancellation from the run deadline (pm/run_checks.mdx §10). */
  signal?: AbortSignal
  /** Hold a process-global resource slot while the child runs (e.g. "cpu" for SpamAssassin). */
  resource?: ResourceClass
}

const DEFAULT_TIMEOUT_MS = 30_000
const DEFAULT_MAX_BUFFER = 10 * 1024 * 1024
/** After the SIGTERM timeout, how long a child gets to exit before the SIGKILL escalation. */
const SIGKILL_GRACE_MS = 5_000

/**
 * Spawn `file` with `args` under the ToolRunner contract. Never rejects for tool-level failures:
 * a missing binary, non-zero exit, or timeout all come back as a structured `ToolResult` the
 * checker interprets (graceful degradation, §5.3).
 */
export function runTool(
  file: string,
  args: readonly string[],
  opts: ToolRunOptions = {},
): Promise<ToolResult> {
  const spawn = () => execute(file, args, opts)
  return opts.resource ? withResource(opts.resource, spawn) : spawn()
}

function execute(file: string, args: readonly string[], opts: ToolRunOptions): Promise<ToolResult> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS
  return new Promise((resolve) => {
    const child = execFile(
      file,
      args as string[],
      {
        timeout: timeoutMs,
        killSignal: "SIGTERM",
        maxBuffer: opts.maxBuffer ?? DEFAULT_MAX_BUFFER,
        signal: opts.signal,
        windowsHide: true,
        encoding: "utf8",
      },
      (err, stdout, stderr) => {
        clearTimeout(killTimer)
        if (!err) {
          resolve({ code: 0, stdout, stderr, timedOut: false })
          return
        }
        const e = err as NodeJS.ErrnoException & {
          killed?: boolean
          code?: number | string
          signal?: NodeJS.Signals | null
        }
        const timedOut = e.killed === true || e.signal === "SIGTERM" || e.signal === "SIGKILL"
        // Non-zero exit → numeric code (data, not an exception). Spawn failure (ENOENT…) → null
        // code with the reason appended to stderr for diagnostics.
        const code = typeof e.code === "number" ? e.code : null
        const spawnFailure = typeof e.code === "string" ? `${e.code}: ${e.message}` : ""
        resolve({
          code,
          stdout: stdout ?? "",
          stderr: [stderr ?? "", spawnFailure].filter(Boolean).join("\n"),
          timedOut,
        })
      },
    )
    // Grace escalation: if the SIGTERM from `timeout` didn't end the child, SIGKILL it.
    const killTimer = setTimeout(() => {
      try {
        child.kill("SIGKILL")
      } catch {
        // Already gone.
      }
    }, timeoutMs + SIGKILL_GRACE_MS)
    killTimer.unref?.()
    // stdin is the data plane; always end it so tools reading stdin don't hang.
    if (child.stdin) {
      if (opts.stdin !== undefined) child.stdin.write(opts.stdin)
      child.stdin.end()
    }
  })
}

/** The tools a run may shell out to; the RunContext carries their resolved paths (§5.2). */
export const RUN_TOOLS = ["dig", "openssl", "whois", "swaks", "spamassassin", "spamc"] as const

/** The config.yaml → tools.paths.<name> override (best-effort: a broken config never breaks discovery). */
function configuredToolPath(name: string): string | null {
  try {
    const paths = readAppConfig().tools.paths
    const value = paths?.[name]
    return typeof value === "string" && value.trim().length > 0 ? value.trim() : null
  } catch {
    return null
  }
}

/** Conventional per-platform locations appended after PATH (pm/run_checks.mdx §6–§8). */
function fallbackDirs(): string[] {
  if (process.platform === "darwin") return ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"]
  if (process.platform === "win32") {
    const pf = process.env.ProgramFiles ?? "C:\\Program Files"
    return [join(pf, "ISC BIND 9", "bin"), join(pf, "OpenSSL-Win64", "bin")]
  }
  // Linux and everything else: Homebrew-on-Linux joins before the system dirs.
  return ["/home/linuxbrew/.linuxbrew/bin", "/usr/local/bin", "/usr/bin"]
}

function isExecutable(path: string): boolean {
  try {
    accessSync(path, process.platform === "win32" ? constants.F_OK : constants.X_OK)
    return true
  } catch {
    return false
  }
}

/**
 * Resolve one tool to an absolute path, or null when it is not installed. Resolution order
 * (§5.2): explicit override (`EDH_TOOL_<NAME>`, the Settings → Tools & environment hook), an
 * in-process PATH search, then the platform's conventional fallback dirs — the piece that makes a
 * launchd/cron-scheduled run (minimal PATH) find the same tools a manual run does.
 */
export function locateTool(name: string): string | null {
  // Resolution step 1 (§5.2): the explicit override — config.yaml → tools.paths.<name>
  // (Settings → Tools & environment), or the EDH_TOOL_<NAME> environment variable.
  const configured = configuredToolPath(name)
  if (configured) return configured
  const override = process.env[`EDH_TOOL_${name.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`]?.trim()
  if (override) return override
  const pathDirs = (process.env.PATH ?? "").split(delimiter).filter(Boolean)
  const exts = process.platform === "win32" ? [".exe", ".cmd", ".bat"] : [""]
  for (const dir of [...pathDirs, ...fallbackDirs()]) {
    for (const ext of exts) {
      const candidate = join(dir, name + ext)
      if (isExecutable(candidate)) return candidate
    }
  }
  return null
}

/**
 * Stage-0 tool discovery, once per run (§5.2): the resolved map is cached in the RunContext and
 * surfaced by health-style diagnostics ("dig ✓ /opt/homebrew/bin/dig · spamassassin ✗").
 */
export function locateTools(
  names: readonly string[] = RUN_TOOLS,
): Record<string, string | null> {
  return Object.fromEntries(names.map((n) => [n, locateTool(n)]))
}
