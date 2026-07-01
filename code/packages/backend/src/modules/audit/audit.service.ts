import { join } from "node:path"
import { Injectable } from "@nestjs/common"
import { readJson, writeJson } from "@shared/json-store"
import { logError, logInfo } from "@shared/logging"
import { resolveStateDir } from "@shared/state-dir"
import { DomainsService } from "@module/domains/domains.service"
import type { MonitoredDomain } from "@module/domains/domain.types"
import { CHECKERS } from "./checks"
import { type AuditResult, type Finding, summarize } from "./checks/types"

/**
 * The audit engine. Runs every registered checker against a domain, rolls the findings into a
 * score/status, and persists the latest result per domain as JSON under the state dir. The runner
 * is deliberately dumb — all deliverability logic lives in the individual checkers (checks/*).
 */
@Injectable()
export class AuditService {
  private readonly file = join(resolveStateDir(), "audits.json")

  constructor(private readonly domains: DomainsService) {}

  /** Latest audit result keyed by domain id (persisted map). */
  private loadAll(): Record<string, AuditResult> {
    return readJson<Record<string, AuditResult>>(this.file, {})
  }

  private saveAll(map: Record<string, AuditResult>): void {
    writeJson(this.file, map)
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
    const result = await this.auditDomain(domain)
    const map = this.loadAll()
    map[domainId] = result
    this.saveAll(map)
    logInfo(`Audited ${domain.name}: score ${result.score} (${result.status})`, "AuditService")
    return result
  }

  /** Run audits for every monitored domain (used by the scheduler and the "audit all" button). */
  async runForAll(): Promise<AuditResult[]> {
    const domains = this.domains.list()
    const map = this.loadAll()
    const results: AuditResult[] = []
    for (const domain of domains) {
      const result = await this.auditDomain(domain)
      map[domain.id] = result
      results.push(result)
    }
    this.saveAll(map)
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
