import { locateTool, runTool } from "@shared/tool-runner"
import type { ToolStatus, ToolsDetection } from "./settings.types"

/**
 * §6 Tools & environment — probe the Brew/OS-installed CLI tools the app may shell out to.
 * Resolution goes through the shared ToolLocator (explicit EDH_TOOL_* override → PATH → the
 * platform's conventional dirs), then one short version invocation per tool. A missing tool is a
 * capability downgrade, never an error (pm/run_checks.mdx §5.3).
 */

const PROBE_TIMEOUT_MS = 10_000

/** How each tool reports its version: the args to pass and where the version line lands. */
const VERSION_PROBES: Record<string, string[]> = {
  dig: ["-v"], // "DiG 9.10.6" (bind's dig prints to stderr)
  swaks: ["--version"], // "swaks version 20240103.0"
}

async function probeTool(name: string): Promise<ToolStatus> {
  const path = locateTool(name)
  if (!path) return { found: false, version: null, path: null }
  const result = await runTool(path, VERSION_PROBES[name] ?? ["--version"], {
    timeoutMs: PROBE_TIMEOUT_MS,
  })
  const firstLine = `${result.stdout}\n${result.stderr}`
    .split("\n")
    .map((l) => l.trim())
    .find((l) => l.length > 0)
  return { found: true, version: firstLine ?? null, path }
}

/** Probe dig + swaks (§6) — what POST /api/settings/tools/detect returns and GET caches. */
export async function detectTools(): Promise<ToolsDetection> {
  const [dig, swaks] = await Promise.all([probeTool("dig"), probeTool("swaks")])
  return { dig, swaks, detectedAt: new Date().toISOString() }
}
