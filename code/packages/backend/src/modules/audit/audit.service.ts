import { join } from "node:path"
import type { MonitoredDomain } from "@module/domains/domain.types"
import { DomainsService } from "@module/domains/domains.service"
import { Injectable } from "@nestjs/common"
import { mapLimit } from "@shared/concurrency"
import { readJson, writeJson } from "@shared/json-store"
import { logError, logInfo } from "@shared/logging"
import { resolveStateDir } from "@shared/state-dir"
import { CHECKERS } from "./checks"
import { type AuditResult, type Finding, summarize } from "./checks/types"

/** How many domains to audit concurrently (pm/progress_ui.mdx §4.2). I/O-bound, so this is plenty. */
const AUDIT_CONCURRENCY = 4

/**
 * The audit engine. Runs every registered checker against a domain, rolls the findings into a
 * score/status, and persists the latest result per domain as JSON under the state dir. The runner
 * is deliberately dumb — all deliverability logic lives in the individual checkers (checks/*).
 */
@Injectable()
export class AuditService {
  private readonly file = join(resolveStateDir(), "audits.json")

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

  /** Merge one result into the store under the write-lock (see writeChain). */
  private persistResult(result: AuditResult): Promise<void> {
    const run = this.writeChain.then(() => {
      const map = this.loadAll()
      map[result.domainId] = result
      this.saveAll(map)
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
  async runForAll(): Promise<AuditResult[]> {
    const domains = this.domains.list()
    logInfo(`Check run started (${domains.length} domain(s))`, "AuditService")
    const results = await mapLimit(domains, AUDIT_CONCURRENCY, async (domain) => {
      const result = await this.auditDomain(domain)
      await this.persistResult(result)
      return result
    })
    logInfo(`Audited all ${domains.length} domain(s)`, "AuditService")
    return results
  }

  private async auditDomain(domain: MonitoredDomain): Promise<AuditResult> {
    const ctx = {
      domain: domain.name,
      dkimSelectors: domain.dkimSelectors,
      sendingIps: domain.sendingIps,
    }
    const findings: Finding[] = []
    for (const checker of CHECKERS) {
      try {
        findings.push(...(await checker.run(ctx)))
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
    return {
      domainId: domain.id,
      domain: domain.name,
      ranAt: new Date().toISOString(),
      score,
      status,
      findings,
      counts,
    }
  }
}
