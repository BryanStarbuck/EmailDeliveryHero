import { spawn } from "node:child_process"
import { existsSync } from "node:fs"
import { randomUUID } from "node:crypto"
import { dirname, join } from "node:path"
import { Injectable, Logger } from "@nestjs/common"
import { locateTool } from "@shared/tool-runner"
import { Subject } from "rxjs"
import {
  catalogEntry,
  catalogFor,
  type InstallSpawn,
  scopeCategories,
  type ToolCategory,
  type ToolManager,
  type ToolStatus,
} from "./catalog"
import { brewPresent, detectAll, pnpmEnablePath } from "./install.detect"
import type {
  InstallItemResult,
  InstallJobStatus,
  InstallStreamEvent,
  PreflightResult,
} from "./install.types"

/** Generous per-install budget — a cold `brew install nmap` / `cpanm SpamAssassin` is slow. */
const INSTALL_TIMEOUT_MS = 10 * 60_000

interface Job {
  ids: string[]
  phases: Record<string, InstallJobStatus["phases"][string]>
  results: InstallItemResult[]
  done: boolean
  stream: Subject<InstallStreamEvent>
}

@Injectable()
export class InstallService {
  private readonly logger = new Logger(InstallService.name)
  private readonly jobs = new Map<string, Job>()
  /** Resolved once: the `code/` monorepo root (holds pnpm-workspace.yaml) for pnpm cwd. */
  private readonly codeRoot = findCodeRoot()

  /** GET /api/install/catalog — the full catalog for a manager with live status merged in. */
  catalog(manager: ToolManager | "all"): ToolStatus[] {
    return detectAll(catalogFor(manager))
  }

  /** GET /api/install/preflight — the scope-aware missing / optional / installed split (§5.3). */
  preflight(manager: ToolManager | "all", scope: string | undefined): PreflightResult {
    const cats = new Set<ToolCategory>(scopeCategories(scope))
    const statuses = detectAll(catalogFor(manager)).filter((s) =>
      s.usedBy.some((c) => cats.has(c)),
    )
    return {
      manager,
      brewPresent: manager === "npm" ? null : brewPresent(),
      pnpmEnable: pnpmEnablePath(),
      missing: statuses.filter((s) => !s.installed && s.tier === "default" && s.detect !== "builtin"),
      optional: statuses.filter((s) => !s.installed && s.tier === "extended"),
      installed: statuses.filter((s) => s.installed),
    }
  }

  /** POST /api/install/detect — force a fresh detection (Re-detect, §4.5). */
  detect(manager: ToolManager | "all"): ToolStatus[] {
    return this.catalog(manager)
  }

  /**
   * POST /api/install/run — install the selected ids SERIALLY (pm/install_brew.mdx §6). Returns a
   * jobId immediately; the client streams via GET …/stream or polls GET …/:jobId. One failure never
   * sinks the batch (§6.3).
   */
  start(ids: string[]): { jobId: string; ids: string[] } {
    // Validate every id against the in-repo catalog (§12) — unknown id would 400 in the controller.
    const entries = ids.map((id) => catalogEntry(id)).filter((e) => e && e.autoInstallable)
    const validIds = entries.map((e) => e?.id ?? "").filter(Boolean)
    const jobId = randomUUID()
    const job: Job = {
      ids: validIds,
      phases: Object.fromEntries(validIds.map((id) => [id, "queued" as const])),
      results: [],
      done: false,
      stream: new Subject<InstallStreamEvent>(),
    }
    this.jobs.set(jobId, job)
    // Fire-and-forget; the job object is the shared state the stream/poll endpoints read.
    void this.runJob(job)
    return { jobId, ids: validIds }
  }

  status(jobId: string): InstallJobStatus | null {
    const job = this.jobs.get(jobId)
    if (!job) return null
    return { jobId, done: job.done, phases: job.phases, results: job.results }
  }

  stream(jobId: string): Subject<InstallStreamEvent> | null {
    return this.jobs.get(jobId)?.stream ?? null
  }

  private async runJob(job: Job): Promise<void> {
    for (const id of job.ids) {
      const entry = catalogEntry(id)
      if (!entry) continue
      job.phases[id] = "installing"
      const spawns = this.resolveSpawns(entry)
      let ok = true
      let code: number | null = 0
      let tail = ""
      if (spawns.length === 0) {
        ok = false
        tail = `${entry.label} is not auto-installable on this machine (copy the command).`
      }
      for (const s of spawns) {
        const r = await this.runOne(job, id, s)
        code = r.code
        tail = r.tail || tail
        if (!r.ok) {
          ok = false
          break // a failed step aborts this tool's remaining steps, not the batch.
        }
      }
      job.phases[id] = ok ? "done" : "failed"
      job.results.push({ id, ok, code, tail })
      job.stream.next({ id, phase: ok ? "done" : "failed" })
    }
    job.done = true
    job.stream.complete()
  }

  /** Pick the concrete spawns, applying the pnpm-enable fallback and pipx presence guard. */
  private resolveSpawns(entry: ReturnType<typeof catalogEntry>): InstallSpawn[] {
    if (!entry?.spawns) return []
    // pnpm (L0): prefer corepack, fall back to `npm i -g pnpm` (§4.1).
    if (entry.id === "pnpm") {
      const path = pnpmEnablePath()
      if (path === "corepack") return [{ file: "corepack", args: ["enable", "pnpm"] }]
      if (path === "npm") return [{ file: "npm", args: ["install", "-g", "pnpm"] }]
      return [] // no corepack, no npm → copy-only
    }
    // pipx tools: only auto-run when pipx is present, else downgrade to copy-only.
    if (entry.install === "pipx" && !locateTool("pipx")) return []
    return entry.spawns
  }

  private runOne(
    job: Job,
    id: string,
    s: InstallSpawn,
  ): Promise<{ ok: boolean; code: number | null; tail: string }> {
    // Resolve the launcher to an absolute path — scheduled/minimal-PATH safe (ToolLocator, §7.2).
    const file = locateTool(s.file) ?? s.file
    const cwd = s.cwd === "code" ? this.codeRoot : undefined
    const lines: string[] = []
    return new Promise((resolve) => {
      let child: ReturnType<typeof spawn>
      try {
        // NO shell, ever — args is a fixed catalog array (pm/install_brew.mdx §11).
        child = spawn(file, s.args, { cwd, windowsHide: true })
      } catch (err) {
        resolve({ ok: false, code: null, tail: `spawn failed: ${(err as Error).message}` })
        return
      }
      const killTimer = setTimeout(() => {
        try {
          child.kill("SIGKILL")
        } catch {}
      }, INSTALL_TIMEOUT_MS)
      killTimer.unref?.()

      const onData = (buf: Buffer) => {
        for (const raw of buf.toString("utf8").split(/\r?\n/)) {
          const line = raw.trimEnd()
          if (!line) continue
          lines.push(line)
          if (lines.length > 200) lines.shift()
          job.stream.next({ id, phase: "installing", line })
        }
      }
      child.stdout?.on("data", onData)
      child.stderr?.on("data", onData)
      child.on("error", (err) => {
        clearTimeout(killTimer)
        resolve({ ok: false, code: null, tail: `${err.message}\n${tailOf(lines)}` })
      })
      child.on("close", (code) => {
        clearTimeout(killTimer)
        const ok = code === 0
        if (!ok) this.logger.warn(`install ${id} (${s.file} ${s.args.join(" ")}) exited ${code}`)
        resolve({ ok, code, tail: ok ? "" : tailOf(lines) })
      })
    })
  }
}

function tailOf(lines: string[], n = 12): string {
  return lines.slice(-n).join("\n")
}

/** Walk up from this file to the monorepo root that holds pnpm-workspace.yaml. */
function findCodeRoot(): string {
  let dir = __dirname
  for (let i = 0; i < 8; i++) {
    if (existsSync(join(dir, "pnpm-workspace.yaml"))) return dir
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return process.cwd()
}
