import { randomUUID } from "node:crypto"
import { join } from "node:path"
import type { MonitoredDomain } from "@module/domains/domain.types"
import { DomainsService } from "@module/domains/domains.service"
import { Injectable } from "@nestjs/common"
import { mapLimit } from "@shared/concurrency"
import { readAppConfig } from "@shared/config-store"
import { readJson, writeJson } from "@shared/json-store"
import { logError, logInfo } from "@shared/logging"
import { resolveStateDir } from "@shared/state-dir"
import { CHECKERS } from "./checks"
import { type AuditResult, type Finding, summarize } from "./checks/types"

/** How many domains to audit concurrently (pm/progress_ui.mdx §4.2). I/O-bound, so this is plenty. */
const AUDIT_CONCURRENCY = 4

/** Run-history cap: the newest N runs kept per domain (pm/dashboard.mdx §1). */
const RUNS_KEPT_PER_DOMAIN = 50

/**
 * The audit engine. Runs every registered checker against a domain, rolls the findings into a
 * score/status, and persists the latest result per domain as JSON under the state dir. The runner
 * is deliberately dumb — all deliverability logic lives in the individual checkers (checks/*).
 */
@Injectable()
export class AuditService {
  private readonly file = join(resolveStateDir(), "audits.json")
  private readonly runsFile = join(resolveStateDir(), "runs.json")

  /**
   * Serializes every persist so parallel per-domain scans (pm/progress_ui.mdx §4.2) can't clobber
   * each other. Concurrent scans each do a read-modify-write of the single audits.json map and the
   * JSON store writes through one shared temp file; without this chain the last writer would drop
   * the others' results. Each `persistResult` re-reads the latest map, sets its own key, writes.
   */
  private writeChain: Promise<void> = Promise.resolve()

  constructor(private readonly domains: DomainsService) {}

  /** Latest audit result keyed by domain id (persisted map). */
  private loadAll(): Record<string, AuditResult> {
    return readJson<Record<string, AuditResult>>(this.file, {})
  }

  private saveAll(map: Record<string, AuditResult>): void {
    writeJson(this.file, map)
  }

  /** Run history, newest startedAt first, capped per domain (pm/dashboard.mdx §1). */
  private loadRuns(): AuditResult[] {
    return readJson<AuditResult[]>(this.runsFile, [])
  }

  private saveRuns(runs: AuditResult[]): void {
    writeJson(this.runsFile, runs)
  }

  /**
   * Merge one result into the latest-per-domain store AND prepend it to the run history, both
   * under the write-lock (see writeChain).
   */
  private persistResult(result: AuditResult): Promise<void> {
    const run = this.writeChain.then(() => {
      const map = this.loadAll()
      map[result.domainId] = result
      this.saveAll(map)

      const runs = [result, ...this.loadRuns()]
      // Prune history older than the admin retention window (config.yaml → storage.retentionDays,
      // pm/storage.mdx §6) AND cap at the newest RUNS_KEPT_PER_DOMAIN runs per domain.
      const retentionDays = readAppConfig().storage.retentionDays
      const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString()
      const perDomain: Record<string, number> = {}
      this.saveRuns(
        runs.filter((r) => {
          if ((r.startedAt ?? r.finishedAt ?? "") < cutoff) return false
          perDomain[r.domainId] = (perDomain[r.domainId] ?? 0) + 1
          return perDomain[r.domainId] <= RUNS_KEPT_PER_DOMAIN
        }),
      )
    })
    // Keep the chain alive even if a write throws (it's logged + rethrown to the caller below).
    this.writeChain = run.catch(() => {})
    return run
  }

  latest(domainId: string): AuditResult | null {
    return this.loadAll()[domainId] ?? null
  }

  /** Latest results for every domain (used by the dashboard). */
  latestAll(): AuditResult[] {
    return Object.values(this.loadAll())
  }

  /** All kept runs, newest startedAt first (the dashboard's Runs table). */
  listRuns(domainId?: string): AuditResult[] {
    const runs = this.loadRuns()
    const filtered = domainId ? runs.filter((r) => r.domainId === domainId) : runs
    return filtered.sort((a, b) => (b.startedAt ?? "").localeCompare(a.startedAt ?? ""))
  }

  getRun(runId: string): AuditResult | null {
    return this.loadRuns().find((r) => r.runId === runId) ?? null
  }

  /** Remove one run from the history (dashboard Runs-row ⋮ menu → Delete run). */
  deleteRun(runId: string): Promise<void> {
    const run = this.writeChain.then(() => {
      this.saveRuns(this.loadRuns().filter((r) => r.runId !== runId))
    })
    this.writeChain = run.catch(() => {})
    return run
  }

  /** Run all checkers for one domain, persist and return the result. */
  async runForDomain(domainId: string): Promise<AuditResult> {
    const domain = this.domains.get(domainId)
    logInfo(`Manual check started for ${domain.name}`, "AuditService")
    const result = await this.auditDomain(domain)
    await this.persistResult(result)
    logInfo(`Audited ${domain.name}: score ${result.score} (${result.status})`, "AuditService")
    return result
  }

  /**
   * Run audits for every monitored domain (used by the scheduler and programmatic callers). Domains
   * are audited in parallel with a small concurrency cap (pm/progress_ui.mdx §4.2); each result is
   * persisted through the write-lock so concurrent scans never clobber one another.
   */
  async runForAll(trigger: "manual" | "scheduled" = "manual"): Promise<AuditResult[]> {
    // A domain rides the recurring schedule only when its own per-domain scheduleEnabled flag
    // (domains.yaml — pm/storage.mdx §5, pm/domains.mdx §6) is on; a manual run-all covers everything.
    const domains =
      trigger === "scheduled"
        ? this.domains.list().filter((d) => d.scheduleEnabled)
        : this.domains.list()
    // The required timestamped start lines (pm/errors.mdx §4): a manual run-all reads
    // "Manual check started (all domains)"; a scheduled run includes the domain count.
    if (trigger === "scheduled") {
      logInfo(`Scheduled check run started (${domains.length} domain(s))`, "AuditScheduler")
    } else {
      logInfo("Manual check started (all domains)", "AuditService")
    }
    const results = await mapLimit(domains, AUDIT_CONCURRENCY, async (domain) => {
      const result = await this.auditDomain(domain)
      await this.persistResult(result)
      return result
    })
    logInfo(`Audited all ${domains.length} domain(s)`, "AuditService")
    return results
  }

  private async auditDomain(domain: MonitoredDomain): Promise<AuditResult> {
    // One RUN (pm/dashboard.mdx §1): per domain, stamped with when it started and stopped.
    const startedAt = new Date().toISOString()
    // Cross-run context: the other domains' latest DKIM key hashes (dkim.duplicate_key) and this
    // domain's previous structured results (dkim.rotation first-seen carry-forward). Both are
    // best-effort reads of the same store the results land in.
    const all = this.loadAll()
    const peerDkimKeys = Object.values(all)
      .filter((r) => r.domainId !== domain.id)
      .flatMap((r) => {
        const dkim = r.results?.dkim as
          | { selectors?: { selector: string; key_sha256: string | null }[] }
          | undefined
        return (dkim?.selectors ?? [])
          .filter((s) => s.key_sha256)
          .map((s) => ({
            domain: r.domain,
            selector: s.selector,
            keySha256: s.key_sha256 as string,
          }))
      })
    const ctx = {
      domain: domain.name,
      dkimSelectors: domain.dkimSelectors,
      sendingIps: domain.sendingIps,
      peerDkimKeys,
      previousResults: all[domain.id]?.results,
    }
    const findings: Finding[] = []
    const results: Record<string, unknown> = {}
    for (const checker of CHECKERS) {
      try {
        const outcome = await checker.run(ctx)
        if (Array.isArray(outcome)) {
          findings.push(...outcome)
        } else {
          findings.push(...outcome.findings)
          if (outcome.results !== undefined) results[checker.id] = outcome.results
        }
      } catch (err) {
        logError(`Checker ${checker.id} failed for ${domain.name}`, err, "AuditService")
        findings.push({
          id: `${checker.id}.error`,
          checkId: checker.id,
          title: `${checker.label} check errored`,
          severity: "warning",
          detail: `The ${checker.label} check could not complete: ${err instanceof Error ? err.message : String(err)}`,
          remediation: "Re-run the audit. If it keeps failing, this may be a transient DNS issue.",
        })
      }
    }
    const { score, status, counts } = summarize(findings)
    const finishedAt = new Date().toISOString()
    return {
      runId: randomUUID(),
      domainId: domain.id,
      domain: domain.name,
      startedAt,
      finishedAt,
      ranAt: finishedAt,
      score,
      status,
      findings,
      counts,
      results,
    }
  }
}
