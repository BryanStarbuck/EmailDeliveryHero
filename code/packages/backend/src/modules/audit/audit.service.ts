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
import { locateTools } from "@shared/tool-runner"
import { CHECKERS } from "./checks"
import { isContentScoringFinding } from "./checks/content-scoring/content-scoring.check"
import {
  type TaggedToolRun,
  type ToolRunRecord,
  withCheckTag,
  withDnsMemo,
  withToolRunLog,
} from "./checks/dns-util"
import {
  type AuditResult,
  type AuditTrigger,
  type Checker,
  type Finding,
  flagNewProblems,
  summarize,
} from "./checks/types"
import { runCheckerGraph } from "./run-graph"
import {
  deleteDomainRuns,
  deleteDomainRunsById,
  deleteRun as deleteRunFile,
  getRun as getRunFromStore,
  listRuns as listRunsFromStore,
  migrateLegacyRunsJson,
  pruneRuns,
  saveRun,
} from "./runs-store"

/** How many domains to audit concurrently (pm/progress_ui.mdx §4.2). I/O-bound, so this is plenty. */
const AUDIT_CONCURRENCY = 4

/** Run-history cap: the newest N runs kept per domain (pm/dashboard.mdx §1). */
const RUNS_KEPT_PER_DOMAIN = 50

/**
 * One domain's wall-clock deadline (pm/run_checks.mdx §10): checks still unfinished at the
 * deadline are cancelled via the RunContext AbortSignal and reported as `info` "did not
 * complete"; Stage 4 still finalizes with what it has.
 */
const DOMAIN_DEADLINE_MS = 5 * 60 * 1000

/** Race marker resolved when the per-domain deadline expires (never a value a checker returns). */
const DEADLINE = Symbol("domain-deadline")

function onAbort(signal: AbortSignal): Promise<typeof DEADLINE> {
  return new Promise((resolve) => {
    if (signal.aborted) resolve(DEADLINE)
    else signal.addEventListener("abort", () => resolve(DEADLINE), { once: true })
  })
}

/** Log-line wording per trigger (pm/errors.mdx); the raw tag is recorded alongside it. */
const TRIGGER_LABEL: Record<AuditTrigger, string> = {
  manual: "Manual",
  api: "API",
  "scheduled-inprocess": "Scheduled",
  "scheduled-os": "Scheduled",
}

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

  constructor(private readonly domains: DomainsService) {
    // Removing a monitored domain also removes its audit history under the state dir
    // (pm/domains.mdx §4.2 — "DELETE /api/domains/:id removes the record and its audit history";
    // pm/storage.mdx §7.4 — deleting a domain removes its runs/<domain>/ directory).
    this.domains.onRemoved((domainId) => this.purgeDomain(domainId))
    // One-time migration: a legacy single-file runs.json from an earlier install is split into
    // the per-run YAML tree at runs/<domain>/<timestamp>.yaml (pm/storage.mdx §7).
    try {
      migrateLegacyRunsJson(readAppConfig().schedule.timezone)
    } catch (err) {
      logError("Legacy runs.json migration failed", err, "AuditService")
    }
  }

  /** Latest audit result keyed by domain id (persisted map). */
  private loadAll(): Record<string, AuditResult> {
    return readJson<Record<string, AuditResult>>(this.file, {})
  }

  private saveAll(map: Record<string, AuditResult>): void {
    writeJson(this.file, map)
  }

  /**
   * Merge one result into the latest-per-domain cache (audits.json) AND write the run as its own
   * immutable YAML file at runs/<domain>/<YYYY_MM_DD_hh_mm{AM|PM}>.yaml (pm/storage.mdx §6/§7),
   * both under the write-lock (see writeChain).
   */
  private persistResult(result: AuditResult): Promise<void> {
    const run = this.writeChain.then(() => {
      const map = this.loadAll()
      map[result.domainId] = result
      this.saveAll(map)

      const config = readAppConfig()
      // One YAML file per run; the filename is the start time in the configured local timezone
      // (pm/storage.mdx §7.2). Written once, atomically, never edited afterward.
      saveRun(result, config.schedule.timezone)
      // Prune history older than the admin retention window (config.yaml → storage.retentionDays)
      // AND cap at the newest RUNS_KEPT_PER_DOMAIN runs per domain — whole-file deletes only
      // (pm/storage.mdx §7.4).
      pruneRuns(config.storage.retentionDays, RUNS_KEPT_PER_DOMAIN)
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
    return listRunsFromStore(domainId)
  }

  getRun(runId: string): AuditResult | null {
    return getRunFromStore(runId)
  }

  /**
   * Drop everything held for a removed domain: its latest-result entry in audits.json and its
   * whole runs/<domain>/ directory (pm/domains.mdx §4.2, pm/storage.mdx §7.4). Serialized through
   * the write chain like every other persist.
   */
  purgeDomain(domainId: string): Promise<void> {
    const run = this.writeChain.then(() => {
      const map = this.loadAll()
      // Resolve the domain NAME (the runs/ directory key) before the entry disappears.
      const domainName = map[domainId]?.domain
      if (domainId in map) {
        delete map[domainId]
        this.saveAll(map)
      }
      if (domainName) deleteDomainRuns(domainName)
      // Fallback for a domain that had runs but no latest-cache entry (e.g. hand-pruned cache).
      deleteDomainRunsById(domainId)
    })
    this.writeChain = run.catch(() => {})
    return run
  }

  /** Remove one run from the history by deleting its file (dashboard Runs-row ⋮ → Delete run). */
  deleteRun(runId: string): Promise<void> {
    const run = this.writeChain.then(() => {
      deleteRunFile(runId)
    })
    this.writeChain = run.catch(() => {})
    return run
  }

  /**
   * Per-domain in-flight guard (pm/run_checks.mdx §9): concurrent runs of the SAME domain —
   * e.g. a manual click while a scheduled run has the domain in flight — collapse into one.
   */
  private readonly inFlight = new Map<string, Promise<AuditResult>>()

  /**
   * Run all checkers for one domain, persist and return the result. This is the ONLY place a
   * domain gets audited (pm/run_checks.mdx §1) — all five triggers funnel here, and `trigger` is
   * pure data (§9): it lands on the audit record and in the log lines, never in a branch that
   * changes what runs.
   */
  runForDomain(domainId: string, trigger: AuditTrigger = "manual"): Promise<AuditResult> {
    const existing = this.inFlight.get(domainId)
    if (existing) {
      logInfo(
        `Audit already in flight for domain ${domainId} — joining it (trigger: ${trigger})`,
        "AuditService",
      )
      return existing
    }
    const run = (async () => {
      const domain = this.domains.get(domainId)
      logInfo(
        `${TRIGGER_LABEL[trigger]} check started for ${domain.name} (trigger: ${trigger})`,
        "AuditService",
      )
      const result = await this.auditDomain(domain, trigger)
      await this.persistResult(result)
      logInfo(`Audited ${domain.name}: score ${result.score} (${result.status})`, "AuditService")
      return result
    })().finally(() => this.inFlight.delete(domainId))
    this.inFlight.set(domainId, run)
    return run
  }

  /**
   * Run audits for every monitored domain (used by the scheduler and programmatic callers).
   * Nothing but a bounded parallel loop over `runForDomain` (pm/run_checks.mdx §1) with SETTLED
   * semantics (§10): a failed domain fails alone and never rejects the batch. Each result is
   * persisted through the write-lock so concurrent scans never clobber one another.
   */
  async runForAll(trigger: AuditTrigger = "manual"): Promise<AuditResult[]> {
    const scheduled = trigger === "scheduled-inprocess" || trigger === "scheduled-os"
    // A domain rides the recurring schedule only when its own per-domain scheduleEnabled flag
    // (domains.yaml — pm/storage.mdx §5, pm/domains.mdx §6) is on; a manual run-all covers everything.
    const domains = scheduled
      ? this.domains.list().filter((d) => d.scheduleEnabled)
      : this.domains.list()
    // The required timestamped start lines (pm/errors.mdx §4): a manual run-all reads
    // "Manual check started (all domains)"; a scheduled run includes the domain count.
    if (scheduled) {
      logInfo(`Scheduled check run started (${domains.length} domain(s))`, "AuditScheduler")
    } else {
      logInfo("Manual check started (all domains)", "AuditService")
    }
    const settled = await mapLimit(domains, AUDIT_CONCURRENCY, async (domain) => {
      try {
        return await this.runForDomain(domain.id, trigger)
      } catch (err) {
        // Settled semantics (pm/run_checks.mdx §10): log and drop — the batch never rejects.
        logError(`Audit failed for ${domain.name}`, err, "AuditService")
        return null
      }
    })
    const results = settled.filter((r): r is AuditResult => r !== null)
    logInfo(`Audited ${results.length}/${domains.length} domain(s)`, "AuditService")
    return results
  }

  /**
   * Re-run JUST the content-scoring checker for one domain and merge its findings/payload into
   * the domain's latest result (pm/checks/content_scoring.mdx §6 — the dedicated "Re-score"
   * action after a sample is uploaded/edited, without a full re-audit). With no prior run, a
   * full audit runs instead (there is nothing to merge into).
   */
  async rescoreContent(domainId: string): Promise<AuditResult> {
    const latest = this.latest(domainId)
    if (!latest) return this.runForDomain(domainId, "manual")
    const domain = this.domains.get(domainId)
    logInfo(`Content re-score started for ${domain.name}`, "AuditService")

    const checker = CHECKERS.find((c) => c.id === "content.scoring")
    if (!checker) return latest
    const findings: Finding[] = []
    let payload: unknown
    try {
      const outcome = await checker.run({
        domain: domain.name,
        domainId: domain.id,
        dkimSelectors: domain.dkimSelectors,
        sendingIps: domain.sendingIps,
        previousResults: latest.results,
        tools: locateTools(),
      })
      if (Array.isArray(outcome)) {
        findings.push(...outcome)
      } else {
        findings.push(...outcome.findings)
        payload = outcome.results
      }
    } catch (err) {
      logError(`Content re-score failed for ${domain.name}`, err, "AuditService")
      findings.push({
        id: "content.scoring.error",
        checkId: "content.scoring",
        title: "Message Content Spam Scoring check errored",
        severity: "warning",
        detail: `The content re-score could not complete: ${err instanceof Error ? err.message : String(err)}`,
        remediation: "Re-score again. If it keeps failing, check the SpamAssassin installation.",
      })
    }

    // Surgical merge: swap only this checker's findings/payload, keep every other check's output.
    const merged = [...latest.findings.filter((f) => !isContentScoringFinding(f)), ...findings]
    const results = { ...latest.results }
    if (payload !== undefined) results["content.scoring"] = payload
    const { score, status, counts } = summarize(merged, readAppConfig().checks.weights)
    const updated: AuditResult = { ...latest, findings: merged, score, status, counts, results }

    // Latest-cache-only persist: a re-score refreshes the dashboard/current view but never
    // rewrites the immutable per-run YAML history (pm/storage.mdx §7.2).
    const write = this.writeChain.then(() => {
      const map = this.loadAll()
      map[updated.domainId] = updated
      this.saveAll(map)
    })
    this.writeChain = write.catch(() => {})
    await write
    logInfo(`Content re-score finished for ${domain.name}: score ${updated.score}`, "AuditService")
    return updated
  }

  private async auditDomain(domain: MonitoredDomain, trigger: AuditTrigger): Promise<AuditResult> {
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
    // Stage 4 collectors. `results` doubles as the shared upstream-output map (pm/run_checks.mdx
    // §2 Stage 1): each finished checker's structured payload is published into it, so Stage-2/3
    // consumers (dmarc reading spf/dkim, mta_sts/dane reading mx_routing's MX list) never
    // re-derive an upstream result.
    const findings: Finding[] = []
    const results: Record<string, unknown> = {}
    // Stage 0 — preflight & context (pm/run_checks.mdx §2): tool discovery once per run, and the
    // per-domain deadline's AbortSignal every checker can pass to DNS calls / child processes.
    const deadline = new AbortController()
    const deadlineTimer = setTimeout(() => deadline.abort(), DOMAIN_DEADLINE_MS)
    deadlineTimer.unref?.()
    const ctx = {
      domain: domain.name,
      // The store id keys per-domain stores (e.g. content-scoring's samples/<domainId>/).
      domainId: domain.id,
      dkimSelectors: domain.dkimSelectors,
      sendingIps: domain.sendingIps,
      peerDkimKeys,
      previousResults: all[domain.id]?.results,
      // Per-domain ARC / forwarding config (pm/checks/arc.mdx §4) — powers arc.applicable /
      // arc.forwarding_risk / arc.selector_dns.
      arc: domain.arc,
      // Per-domain BIMI config (pm/checks/bimi.mdx §4) — extra selectors + BIMI-Selector header
      // compare for content.bimi_selector.
      bimi: domain.bimi,
      // Per-domain DNS-health expectations (pm/checks/dns_health.mdx §4) — extra dangling-scan
      // labels, expected-NS drift detection, and the skip-AXFR toggle.
      dnsHealth: domain.dnsHealth,
      // Per-domain registration-reputation config (pm/checks/domain_reputation.mdx §4) — brands,
      // expiry/age thresholds, registrant-public + cousin-scan toggles.
      domainReputation: domain.domainReputation,
      // Pure data (pm/run_checks.mdx §9): the registration checker reads it only to bypass its
      // long-TTL RDAP cache on a manual run-now (pm/checks/domain_reputation.mdx §6).
      trigger,
      signal: deadline.signal,
      tools: locateTools(),
      upstream: results,
    }
    // One checker's execution, fully contained (pm/run_checks.mdx §10): a throw becomes a
    // `warning` finding + an error.err entry; a deadline breach becomes an `info` "did not
    // complete" finding. Never rejects, so a failure can't take down its dependents or the graph.
    const runOne = async (checker: Checker): Promise<void> => {
      const didNotComplete = (): void => {
        findings.push({
          id: `${checker.id}.did_not_complete`,
          checkId: checker.id,
          title: `${checker.label} check did not complete`,
          severity: "info",
          detail: `The ${checker.label} check was still running when the domain's ${Math.round(DOMAIN_DEADLINE_MS / 60000)}-minute run deadline expired, and was cancelled.`,
          remediation: "Re-run the audit. If it keeps timing out, check network connectivity.",
        })
      }
      if (deadline.signal.aborted) {
        didNotComplete()
        return
      }
      try {
        // Race the checker against the deadline so Stage 4 finalizes with what it has; the
        // loser's eventual settlement is swallowed below (the AbortSignal reclaims its sockets).
        // withCheckTag tags every external-tool invocation the checker makes with its id, so the
        // per-category tool_runs audit trail (pm/checks/dns.mdx §3.1) knows which category ran it.
        const running = Promise.resolve().then(() =>
          withCheckTag(checker.id, () => Promise.resolve(checker.run(ctx))),
        )
        running.catch(() => {})
        const outcome = await Promise.race([running, onAbort(deadline.signal)])
        if (outcome === DEADLINE) {
          didNotComplete()
          return
        }
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
    // Stages 1–3 (pm/run_checks.mdx §2–§3): the dependency-ordered promise-graph — every
    // foundation check launches simultaneously, each dependent check starts the moment its own
    // prerequisites finish — all inside the per-run DNS memo so ten checkers asking for the same
    // TXT/MX record cost one query. The tool-run log collects every external-tool invocation the
    // run makes (verbatim argv, timing, exit code — pm/checks/dns.mdx §3.1), in execution order.
    const toolRunLog: TaggedToolRun[] = []
    await withToolRunLog(toolRunLog, () => withDnsMemo(() => runCheckerGraph(CHECKERS, runOne)))
    clearTimeout(deadlineTimer)
    // The DNS & Infrastructure category persists its own tool invocations as
    // `dns_infra.tool_runs[]` in the run file (pm/checks/dns.mdx §5 — the runs-store maps
    // results["infra.tool_runs"] to that key). Entries are append-only within a run and are the
    // evidence trail, never the verdict — the regression differ ignores them.
    const infraToolRuns: ToolRunRecord[] = toolRunLog
      .filter((r) => r.check_id.startsWith("infra."))
      .map(({ check_id: _checkId, ...rest }) => rest)
    if (infraToolRuns.length > 0) results["infra.tool_runs"] = infraToolRuns
    // Findings complete in graph order, not registry order — restore the registry order so runs
    // are deterministic and diffs/UI grouping are stable.
    const registryIndex = new Map(CHECKERS.map((c, i) => [c.id, i]))
    findings.sort(
      (a, b) => (registryIndex.get(a.checkId) ?? 99) - (registryIndex.get(b.checkId) ?? 99),
    )
    // Regression detection (pm/engineering.mdx §8): diff against the domain's previous run so any
    // finding that newly appears — or worsens in severity — is flagged as a NEW problem and the
    // dashboard can surface it. First run for a domain has no baseline, so nothing is flagged.
    const newProblemCount = flagNewProblems(all[domain.id]?.findings, findings)
    // Score with the operator-configured severity weights (config.yaml → checks.weights,
    // pm/settings.mdx §2) so the roll-up reflects real-world impact (pm/spam_checks.mdx).
    const { score, status, counts } = summarize(findings, readAppConfig().checks.weights)
    const finishedAt = new Date().toISOString()
    return {
      runId: randomUUID(),
      domainId: domain.id,
      domain: domain.name,
      startedAt,
      finishedAt,
      ranAt: finishedAt,
      trigger,
      score,
      status,
      findings,
      counts,
      newProblemCount,
      results,
    }
  }
}
