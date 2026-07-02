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
import { type DkimDiscoveryOutcome, discoverDkimSelectors } from "./checks/dkim/dkim.check"
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

/**
 * The ten DNS & Infrastructure family keys (pm/checks/dns.mdx §2), each mapping 1:1 to the
 * checker id `infra.<key>` — the vocabulary of the single-check spot-check endpoint (the
 * check-detail explainer page's "run this check now", pm/checks/dns.mdx §6.2 item 6).
 */
const DNS_INFRA_FAMILY_KEYS = new Set([
  "mx_routing",
  "reverse_dns",
  "tls_transport",
  "mta_sts",
  "tls_rpt",
  "dane_tlsa",
  "dnssec",
  "dns_health",
  "domain_reputation",
  "smtp_security",
])

/** One spot-check's wall-clock deadline — a single family, so far tighter than a full run. */
const SPOT_CHECK_DEADLINE_MS = 60 * 1000

/**
 * Thrown when a scoped re-run is requested while a run for the same domain is already in flight
 * (pm/checks/dns.mdx §15.1 — the controller maps it to 409 Conflict).
 */
export class RunInFlightError extends Error {}

/**
 * Resolve a `:checkKey` route slug (pm/checks/dns.mdx §14.1 — kebab-case, equal to the backend
 * check directory names, e.g. "reverse-dns") to its §5 family key ("reverse_dns"). The snake_case
 * family key itself is tolerated as input; the mapping is 1:1 so this is just kebab → snake.
 * Returns null for anything outside the ten fixed keys.
 */
function dnsFamilyKeyForCheckKey(checkKey: string): string | null {
  const familyKey = checkKey.replaceAll("-", "_")
  return DNS_INFRA_FAMILY_KEYS.has(familyKey) ? familyKey : null
}

/**
 * The result of re-running ONE DNS & Infrastructure family checker live (pm/checks/dns.mdx §6.2
 * item 6 — the ⟳ spot-check / "run this check now" action). A spot check is a LIVE VIEW: it is
 * never persisted — run files are immutable history and stay untouched.
 */
export interface SpotCheckResult {
  checkId: string
  domainId: string
  domain: string
  startedAt: string
  finishedAt: string
  findings: Finding[]
  /** The checker's structured payload (the §5 snapshot shape), when it produces one. */
  results?: unknown
  /** Every external-tool invocation the spot check made (pm/checks/dns.mdx §3.1 shape). */
  toolRuns: ToolRunRecord[]
}

/**
 * The seven Spam & Content family checker registry ids (pm/checks/spam_content.mdx §8 map). The
 * single-check re-run endpoint (§9) accepts exactly these; anything else is a 404.
 */
const CONTENT_CHECKER_IDS = new Set<string>([
  "content.bimi",
  "content.report_emails",
  "content.scoring",
  "content.list_unsubscribe",
  "content.url",
  "content.reputation",
  "content.inbox_placement",
])

/** Sender-reputation finding-id stems (pm/checks/spam_content.mdx §1 prefix table). */
const REPUTATION_FINDING_STEMS = [
  "complaint_rate",
  "bounce_rate",
  "gpt_",
  "fbl_",
  "engagement",
  "warmup",
  "volume_consistency",
  "blocklist_history",
  "reputation_data_available",
  "reputation",
  "postmaster_verified",
  "delivery_errors",
]

/**
 * Whether a finding belongs to one Spam & Content family checker, matched by the §1 id-prefix
 * table (pm/checks/spam_content.mdx §9 — "matched by the §1 id-prefix table, exactly as
 * isContentScoringFinding does today"). Three families (bimi, report_emails, list_unsubscribe)
 * stamp their own checker id as the finding `checkId`, so that is the primary match; the other
 * four share the bare `content` checkId, so ownership is by finding-id prefix. The synthetic
 * runner error/timeout findings carry `<checkerId>.error`, caught by the checkId equality too.
 */
function ownsContentFinding(f: Finding, checkerId: string): boolean {
  if (f.checkId === checkerId) return true
  switch (checkerId) {
    case "content.scoring":
      return isContentScoringFinding(f)
    case "content.bimi":
      return f.id.startsWith("content.bimi")
    case "content.report_emails":
      return f.id.startsWith("content.report_")
    case "content.url":
      return f.id.startsWith("content.url")
    case "content.inbox_placement":
      return (
        f.id.startsWith("content.inbox_placement") ||
        f.id.startsWith("content.placement_") ||
        f.id.startsWith("content.seed")
      )
    case "content.reputation":
      return REPUTATION_FINDING_STEMS.some((stem) => f.id.startsWith(`content.${stem}`))
    case "content.list_unsubscribe":
      return (
        f.id.startsWith("content.list_") ||
        f.id === "content.from_alignment" ||
        f.id === "content.precedence" ||
        f.id === "content.no_priority_abuse"
      )
    default:
      return false
  }
}

/**
 * Timestamp-prefixed run id (pm/storage.mdx §7.5/§16 D8): the run's start instant (UTC, second
 * precision, `:` → `-` so it is filename-safe) plus a short random suffix — e.g.
 * `2026-07-01T16-14-02-a1b2`. Lexical order ≈ chronological order, and the id joins the run file,
 * the REST `/runs/:runId` route, and the blacklists deep store's `audit_id` (D12).
 */
function makeRunId(startedAtIso: string): string {
  const stamp = startedAtIso.slice(0, 19).replace(/:/g, "-")
  return `${stamp}-${randomUUID().slice(0, 4)}`
}

function onAbort(signal: AbortSignal): Promise<typeof DEADLINE> {
  return new Promise((resolve) => {
    if (signal.aborted) resolve(DEADLINE)
    else signal.addEventListener("abort", () => resolve(DEADLINE), { once: true })
  })
}

/**
 * Fold the SPF category's own external-tool invocations into `results.spf.tool_runs[]` (pm/checks/
 * spf.mdx §5). Like the DNS & Infrastructure trail, these are file-only run forensics — never a
 * verdict input — so the regression differ ignores them. No-op when SPF ran no tools or produced
 * no structured payload (e.g. a resolver error before the record was parsed).
 */
function attachSpfToolRuns(results: Record<string, unknown>, log: TaggedToolRun[]): void {
  const spfToolRuns: ToolRunRecord[] = log
    .filter((r) => r.check_id === "spf")
    .map(({ check_id: _checkId, ...rest }) => rest)
  if (spfToolRuns.length === 0) return
  const spf = results.spf
  if (spf && typeof spf === "object") {
    ;(spf as Record<string, unknown>).tool_runs = spfToolRuns
  }
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
   * Category-scoped re-run (pm/checks/blacklists.mdx §21 / AC 26): execute ONLY the Blacklists
   * category for one domain and write a NEW run file with `run.scope: blacklists`. The viewed run
   * is never mutated — a scoped run is its own immutable YAML file, so prev/next stepping and the
   * history strip include it (the UI chip-tags it `blacklists-only` via `scope`). The domain's
   * latest-result cache is merged surgically (only blacklist findings/payload swap) so the
   * dashboard cell refreshes without degrading the other five categories.
   */
  async runBlacklistsForDomain(
    domainId: string,
    trigger: AuditTrigger = "manual",
  ): Promise<AuditResult> {
    // AC 28: a run already in flight for the same domain wins — join it rather than double-query
    // the same DNSBL mirrors (mirrors rate-limit; pm/checks/blacklists.mdx §10.4 etiquette).
    const existing = this.inFlight.get(domainId)
    if (existing) {
      logInfo(
        `Audit already in flight for domain ${domainId} — joining it (blacklists-scoped request)`,
        "AuditService",
      )
      return existing
    }
    const run = (async () => {
      const domain = this.domains.get(domainId)
      logInfo(
        `${TRIGGER_LABEL[trigger]} Blacklists-scoped check started for ${domain.name} (trigger: ${trigger})`,
        "AuditService",
      )
      const checker = CHECKERS.find((c) => c.id === "blacklist")
      if (!checker) throw new Error("blacklist checker not registered")
      const startedAt = new Date().toISOString()
      const runId = makeRunId(startedAt)
      const latest = this.latest(domainId)
      const findings: Finding[] = []
      let payload: unknown
      try {
        const outcome = await checker.run({
          domain: domain.name,
          domainId: domain.id,
          // Deep-store writes of this scoped run carry the same id as its run file (D12).
          runId,
          dkimSelectors: domain.dkimSelectors,
          sendingIps: domain.sendingIps,
          previousResults: latest?.results,
          trigger,
          tools: locateTools(),
        })
        if (Array.isArray(outcome)) {
          findings.push(...outcome)
        } else {
          findings.push(...outcome.findings)
          payload = outcome.results
        }
      } catch (err) {
        logError(`Blacklists-scoped check failed for ${domain.name}`, err, "AuditService")
        findings.push({
          id: "blacklist.error",
          checkId: "blacklist",
          title: "DNS blacklists check errored",
          severity: "warning",
          detail: `The blacklist check could not complete: ${err instanceof Error ? err.message : String(err)}`,
          remediation: "Re-run the check. If it keeps failing, this may be a transient DNS issue.",
        })
      }
      // Regression detection against the previous run's blacklist findings only — a scoped run
      // must never flag the untouched categories as new/resolved.
      flagNewProblems(
        (latest?.findings ?? []).filter((f) => f.checkId === "blacklist"),
        findings,
      )
      const weights = readAppConfig().checks.weights
      const { score, status, counts } = summarize(findings, weights)
      const finishedAt = new Date().toISOString()
      const result: AuditResult = {
        runId,
        domainId: domain.id,
        domain: domain.name,
        startedAt,
        finishedAt,
        ranAt: finishedAt,
        trigger,
        scope: "blacklists",
        score,
        status,
        findings,
        counts,
        newProblemCount: findings.filter((f) => f.isNew).length,
        results: payload !== undefined ? { blacklist: payload } : {},
      }
      // Persist: the scoped run gets its own immutable run file (run.scope: blacklists); the
      // latest cache is merged surgically so other categories' state survives untouched.
      const write = this.writeChain.then(() => {
        const config = readAppConfig()
        saveRun(result, config.schedule.timezone)
        pruneRuns(config.storage.retentionDays, RUNS_KEPT_PER_DOMAIN)
        const map = this.loadAll()
        const prior = map[domainId]
        if (prior) {
          const mergedFindings = [
            ...prior.findings.filter((f) => f.checkId !== "blacklist"),
            ...findings,
          ]
          const rollup = summarize(mergedFindings, weights)
          map[domainId] = {
            ...prior,
            findings: mergedFindings,
            score: rollup.score,
            status: rollup.status,
            counts: rollup.counts,
            newProblemCount: mergedFindings.filter((f) => f.isNew).length,
            results: {
              ...prior.results,
              ...(payload !== undefined ? { blacklist: payload } : {}),
            },
          }
        } else {
          map[domainId] = result
        }
        this.saveAll(map)
      })
      this.writeChain = write.catch(() => {})
      await write
      logInfo(
        `Blacklists-scoped check finished for ${domain.name}: ${result.status}`,
        "AuditService",
      )
      return result
    })().finally(() => this.inFlight.delete(domainId))
    this.inFlight.set(domainId, run)
    return run
  }

  /**
   * DKIM category-scoped re-run (pm/checks/dkim.mdx §7.7 — "Run DKIM now"): execute ONLY the DKIM
   * checker for one domain and persist a NEW run in which the `dkim` key (findings + structured
   * results) is fresh while the other five categories are carried forward unchanged from the
   * domain's previous newest result. The run carries `scope: "dkim"` / `checks: ["dkim"]`, so the
   * Runs table can chip-tag it "DKIM only". Because a scoped re-run is just a new run,
   * immutability, ‹ prev / next › stepping, and the newest-run aliases all keep working with zero
   * special cases. With no prior run there is nothing to carry forward, so a full audit runs
   * instead (§7.7 — "first run checks everything").
   */
  async runDkimForDomain(domainId: string, trigger: AuditTrigger = "manual"): Promise<AuditResult> {
    // A run already in flight for the same domain wins — join it rather than double-query DNS
    // (the same in-flight guard every trigger funnels through, pm/run_checks.mdx §9).
    const existing = this.inFlight.get(domainId)
    if (existing) {
      logInfo(
        `Audit already in flight for domain ${domainId} — joining it (DKIM-scoped request)`,
        "AuditService",
      )
      return existing
    }
    const latest = this.latest(domainId)
    // No prior run → nothing to carry forward: fall back to a full audit (pm/checks/dkim.mdx §7.7).
    if (!latest) return this.runForDomain(domainId, trigger)
    const run = (async () => {
      const domain = this.domains.get(domainId)
      logInfo(
        `${TRIGGER_LABEL[trigger]} DKIM-scoped check started for ${domain.name} (trigger: ${trigger})`,
        "AuditService",
      )
      const checker = CHECKERS.find((c) => c.id === "dkim")
      if (!checker) throw new Error("dkim checker not registered")
      const startedAt = new Date().toISOString()
      const runId = makeRunId(startedAt)
      // Cross-run context — the same derivation a full run makes: the OTHER domains' latest key
      // hashes power dkim.duplicate_key; previousResults powers the rotation first-seen carry.
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
      const findings: Finding[] = []
      let payload: unknown
      try {
        const outcome = await checker.run({
          domain: domain.name,
          domainId: domain.id,
          runId,
          dkimSelectors: domain.dkimSelectors,
          sendingIps: domain.sendingIps,
          peerDkimKeys,
          previousResults: latest.results,
          trigger,
          tools: locateTools(),
        })
        if (Array.isArray(outcome)) {
          findings.push(...outcome)
        } else {
          findings.push(...outcome.findings)
          payload = outcome.results
        }
      } catch (err) {
        logError(`DKIM-scoped check failed for ${domain.name}`, err, "AuditService")
        findings.push({
          id: "dkim.error",
          checkId: "dkim",
          title: "DKIM check errored",
          severity: "warning",
          detail: `The DKIM check could not complete: ${err instanceof Error ? err.message : String(err)}`,
          remediation: "Re-run the check. If it keeps failing, this may be a transient DNS issue.",
        })
      }
      // Regression detection against the previous run's DKIM findings only — the scoped differ
      // must diff only the re-executed category (pm/checks/dkim.mdx §7.7).
      flagNewProblems(
        latest.findings.filter((f) => f.checkId === "dkim"),
        findings,
      )
      // Carry the other five categories forward unchanged — minus stale isNew flags, which
      // described the PREVIOUS run's regressions, not this one's.
      const carried = latest.findings
        .filter((f) => f.checkId !== "dkim")
        .map(({ isNew: _stale, ...rest }) => rest as Finding)
      const merged = [...carried, ...findings]
      // Registry order keeps scoped runs byte-comparable with full runs (stable diffs/grouping).
      const registryIndex = new Map(CHECKERS.map((c, i) => [c.id, i]))
      merged.sort(
        (a, b) => (registryIndex.get(a.checkId) ?? 99) - (registryIndex.get(b.checkId) ?? 99),
      )
      const { score, status, counts } = summarize(merged, readAppConfig().checks.weights)
      const finishedAt = new Date().toISOString()
      const result: AuditResult = {
        runId,
        domainId: domain.id,
        domain: domain.name,
        startedAt,
        finishedAt,
        ranAt: finishedAt,
        trigger,
        scope: "dkim",
        checks: ["dkim"],
        score,
        status,
        findings: merged,
        counts,
        newProblemCount: findings.filter((f) => f.isNew).length,
        results: {
          ...latest.results,
          ...(payload !== undefined ? { dkim: payload } : {}),
        },
      }
      // The scoped run is a complete six-category picture (dkim fresh, five carried forward), so
      // the standard persist covers both the immutable run file and the latest-per-domain cache.
      await this.persistResult(result)
      logInfo(`DKIM-scoped check finished for ${domain.name}: ${result.status}`, "AuditService")
      return result
    })().finally(() => this.inFlight.delete(domainId))
    this.inFlight.set(domainId, run)
    return run
  }

  /**
   * SPF category-scoped re-run (pm/checks/spf.mdx §6.5 — "Run this check now" / "Re-run SPF only",
   * `POST /api/audit/run/:domainId?checks=spf`): execute ONLY the SPF checker for one domain and
   * persist a NEW run in which the `spf` key (findings + structured results + tool_runs) is fresh
   * while the other five categories are carried forward verbatim from the domain's previous newest
   * result. The run carries `scope`-free `checks: ["spf"]`, so the Runs table can chip-tag it
   * "SPF only". A scoped re-run is just a new run, so immutability, ‹ prev / next › stepping, and
   * the newest-run aliases keep working. With no prior run there is nothing to carry forward, so a
   * full audit runs instead.
   */
  async runSpfForDomain(domainId: string, trigger: AuditTrigger = "manual"): Promise<AuditResult> {
    const existing = this.inFlight.get(domainId)
    if (existing) {
      logInfo(
        `Audit already in flight for domain ${domainId} — joining it (SPF-scoped request)`,
        "AuditService",
      )
      return existing
    }
    const latest = this.latest(domainId)
    // No prior run → nothing to carry forward: fall back to a full audit.
    if (!latest) return this.runForDomain(domainId, trigger)
    const run = (async () => {
      const domain = this.domains.get(domainId)
      logInfo(
        `${TRIGGER_LABEL[trigger]} SPF-scoped check started for ${domain.name} (trigger: ${trigger})`,
        "AuditService",
      )
      const checker = CHECKERS.find((c) => c.id === "spf")
      if (!checker) throw new Error("spf checker not registered")
      const startedAt = new Date().toISOString()
      const runId = makeRunId(startedAt)
      const findings: Finding[] = []
      let payload: unknown
      const toolRunLog: TaggedToolRun[] = []
      try {
        const outcome = await withToolRunLog(toolRunLog, () =>
          withDnsMemo(() =>
            withCheckTag(checker.id, () =>
              Promise.resolve(
                checker.run({
                  domain: domain.name,
                  domainId: domain.id,
                  runId,
                  dkimSelectors: domain.dkimSelectors,
                  sendingIps: domain.sendingIps,
                  previousResults: latest.results,
                  trigger,
                  tools: locateTools(),
                }),
              ),
            ),
          ),
        )
        if (Array.isArray(outcome)) {
          findings.push(...outcome)
        } else {
          findings.push(...outcome.findings)
          payload = outcome.results
        }
      } catch (err) {
        logError(`SPF-scoped check failed for ${domain.name}`, err, "AuditService")
        findings.push({
          id: "spf.error",
          checkId: "spf",
          title: "SPF check errored",
          severity: "warning",
          detail: `The SPF check could not complete: ${err instanceof Error ? err.message : String(err)}`,
          remediation: "Re-run the check. If it keeps failing, this may be a transient DNS issue.",
        })
      }
      // Regression detection against the previous run's SPF findings only (§6.5: the differ skips
      // carried-forward categories, so it can only diff the re-executed category).
      flagNewProblems(
        latest.findings.filter((f) => f.checkId === "spf"),
        findings,
      )
      // Carry the other five categories forward verbatim — minus stale isNew flags, which
      // described the PREVIOUS run's regressions, not this one's.
      const carried = latest.findings
        .filter((f) => f.checkId !== "spf")
        .map(({ isNew: _stale, ...rest }) => rest as Finding)
      const merged = [...carried, ...findings]
      const registryIndex = new Map(CHECKERS.map((c, i) => [c.id, i]))
      merged.sort(
        (a, b) => (registryIndex.get(a.checkId) ?? 99) - (registryIndex.get(b.checkId) ?? 99),
      )
      const { score, status, counts } = summarize(merged, readAppConfig().checks.weights)
      const finishedAt = new Date().toISOString()
      const mergedResults: Record<string, unknown> = {
        ...latest.results,
        ...(payload !== undefined ? { spf: payload } : {}),
      }
      // Fold the SPF category's own tool invocations into results.spf.tool_runs[] (§5).
      attachSpfToolRuns(mergedResults, toolRunLog)
      const result: AuditResult = {
        runId,
        domainId: domain.id,
        domain: domain.name,
        startedAt,
        finishedAt,
        ranAt: finishedAt,
        trigger,
        checks: ["spf"],
        score,
        status,
        findings: merged,
        counts,
        newProblemCount: findings.filter((f) => f.isNew).length,
        results: mergedResults,
      }
      await this.persistResult(result)
      logInfo(`SPF-scoped check finished for ${domain.name}: ${result.status}`, "AuditService")
      return result
    })().finally(() => this.inFlight.delete(domainId))
    this.inFlight.set(domainId, run)
    return run
  }

  /**
   * DNS & Infrastructure scoped re-run (pm/checks/dns.mdx §15.1 / AC 20-21): execute the whole
   * category (all ten `infra.*` family checkers) or ONE family for a domain and write a **new**
   * immutable run file tagged `run.scope: dns` / `dns.<family_key>`. The run body contains only
   * the category's own findings, snapshots, and `tool_runs[]` — an existing run is never mutated.
   * All the full-run discipline applies unchanged: the checker dependency graph, the per-run DNS
   * memo, semaphores inside the checkers, the RDAP daily cache, and `.pending` gating. The
   * Domain-health (newest) roll-up merges per category — the latest cache swaps only the
   * re-executed findings/payloads, so a scoped DNS run advances the DNS cell and never blanks or
   * ages the other five categories (§15.3).
   *
   * @param checkKey the §14.1 kebab-case check key ("reverse-dns") for a single-family run;
   *                 undefined = the whole category. Throws for an unknown key (controller → 404);
   *                 throws RunInFlightError when a run for the domain is in flight (→ 409).
   */
  async runDnsForDomain(
    domainId: string,
    checkKey?: string,
    trigger: AuditTrigger = "manual",
  ): Promise<AuditResult> {
    const familyKey = checkKey === undefined ? undefined : dnsFamilyKeyForCheckKey(checkKey)
    if (checkKey !== undefined && familyKey === null) {
      throw new Error(`Unknown DNS & Infrastructure check "${checkKey}"`)
    }
    // §15.1: 409 while a run for the same domain is in flight — the UI disables the affordance
    // with a reason (§15.2 idle state) rather than joining, so the user never gets a stale scope.
    if (this.inFlight.has(domainId)) {
      throw new RunInFlightError(`A run is already in flight for domain ${domainId}`)
    }
    const scope = (familyKey ? `dns.${familyKey}` : "dns") as AuditResult["scope"]
    const scoped = familyKey
      ? CHECKERS.filter((c) => c.id === `infra.${familyKey}`)
      : CHECKERS.filter((c) => c.id.startsWith("infra."))
    if (scoped.length === 0) throw new Error(`No checker registered for infra.${familyKey}`)
    const run = (async () => {
      const domain = this.domains.get(domainId)
      logInfo(
        `${TRIGGER_LABEL[trigger]} DNS-scoped check (${scope}) started for ${domain.name} (trigger: ${trigger})`,
        "AuditService",
      )
      const startedAt = new Date().toISOString()
      const latest = this.latest(domainId)
      const findings: Finding[] = []
      const results: Record<string, unknown> = {}
      // Upstream map for the dependency graph (pm/run_checks.mdx §2): seeded with the latest
      // run's structured results so a family-scoped run of mta_sts/dane_tlsa still sees the MX
      // list; a category run overwrites each key as its own checker publishes fresh data.
      const upstream: Record<string, unknown> = { ...(latest?.results ?? {}) }
      const deadline = new AbortController()
      const deadlineTimer = setTimeout(() => deadline.abort(), DOMAIN_DEADLINE_MS)
      deadlineTimer.unref?.()
      const ctx = {
        domain: domain.name,
        domainId: domain.id,
        dkimSelectors: domain.dkimSelectors,
        sendingIps: domain.sendingIps,
        previousResults: latest?.results,
        arc: domain.arc,
        bimi: domain.bimi,
        dnsHealth: domain.dnsHealth,
        mx: domain.mx,
        domainReputation: domain.domainReputation,
        dane: domain.dane,
        mtaSts: domain.mtaSts,
        linkUrl: domain.linkUrl,
        listUnsub: domain.listUnsub,
        trigger,
        signal: deadline.signal,
        tools: locateTools(),
        upstream,
      }
      // One checker, fully contained (pm/run_checks.mdx §10) — same containment as a full run.
      const runOne = async (checker: Checker): Promise<void> => {
        if (deadline.signal.aborted) return
        try {
          const outcome = await withCheckTag(checker.id, () => Promise.resolve(checker.run(ctx)))
          if (Array.isArray(outcome)) {
            findings.push(...outcome)
          } else {
            findings.push(...outcome.findings)
            if (outcome.results !== undefined) {
              results[checker.id] = outcome.results
              upstream[checker.id] = outcome.results
            }
          }
        } catch (err) {
          logError(`Checker ${checker.id} failed for ${domain.name}`, err, "AuditService")
          findings.push({
            id: `${checker.id}.error`,
            checkId: checker.id,
            title: `${checker.label} check errored`,
            severity: "warning",
            detail: `The ${checker.label} check could not complete: ${err instanceof Error ? err.message : String(err)}`,
            remediation: "Re-run the check. If it keeps failing, this may be a transient DNS issue.",
          })
        }
      }
      // Dependency-ordered graph over just the scoped checkers, inside the per-run DNS memo, with
      // every external-tool invocation captured verbatim (pm/checks/dns.mdx §3.1).
      const toolRunLog: TaggedToolRun[] = []
      await withToolRunLog(toolRunLog, () => withDnsMemo(() => runCheckerGraph(scoped, runOne)))
      clearTimeout(deadlineTimer)
      const infraToolRuns: ToolRunRecord[] = toolRunLog
        .filter((r) => r.check_id.startsWith("infra."))
        .map(({ check_id: _checkId, ...rest }) => rest)
      if (infraToolRuns.length > 0) results["infra.tool_runs"] = infraToolRuns
      attachSpfToolRuns(results, toolRunLog)
      const registryIndex = new Map(CHECKERS.map((c, i) => [c.id, i]))
      findings.sort(
        (a, b) => (registryIndex.get(a.checkId) ?? 99) - (registryIndex.get(b.checkId) ?? 99),
      )
      // Regression detection against ONLY the re-executed checkers' previous findings (§15.3 —
      // the differ per family always compares within the family's own scope).
      const executedIds = new Set(scoped.map((c) => c.id))
      flagNewProblems(
        (latest?.findings ?? []).filter((f) => executedIds.has(f.checkId)),
        findings,
      )
      const weights = readAppConfig().checks.weights
      const { score, status, counts } = summarize(findings, weights)
      const finishedAt = new Date().toISOString()
      const result: AuditResult = {
        runId: randomUUID(),
        domainId: domain.id,
        domain: domain.name,
        startedAt,
        finishedAt,
        ranAt: finishedAt,
        trigger,
        scope,
        checks: familyKey ? [`infra.${familyKey}`] : ["infra"],
        score,
        status,
        findings,
        counts,
        newProblemCount: findings.filter((f) => f.isNew).length,
        results,
      }
      // Persist: the scoped run is its own immutable run file (run.scope tagged); the latest
      // cache merges surgically — only the re-executed findings/payloads swap (§15.3).
      const write = this.writeChain.then(() => {
        const config = readAppConfig()
        saveRun(result, config.schedule.timezone)
        pruneRuns(config.storage.retentionDays, RUNS_KEPT_PER_DOMAIN)
        const map = this.loadAll()
        const prior = map[domainId]
        if (prior) {
          const mergedFindings = [
            ...prior.findings.filter((f) => !executedIds.has(f.checkId)),
            ...findings,
          ]
          mergedFindings.sort(
            (a, b) => (registryIndex.get(a.checkId) ?? 99) - (registryIndex.get(b.checkId) ?? 99),
          )
          const rollup = summarize(mergedFindings, weights)
          map[domainId] = {
            ...prior,
            findings: mergedFindings,
            score: rollup.score,
            status: rollup.status,
            counts: rollup.counts,
            newProblemCount: mergedFindings.filter((f) => f.isNew).length,
            results: { ...prior.results, ...results },
          }
        } else {
          map[domainId] = result
        }
        this.saveAll(map)
      })
      this.writeChain = write.catch(() => {})
      await write
      logInfo(
        `DNS-scoped check (${scope}) finished for ${domain.name}: ${result.status}`,
        "AuditService",
      )
      return result
    })().finally(() => this.inFlight.delete(domainId))
    this.inFlight.set(domainId, run)
    return run
  }

  /**
   * Re-run exactly ONE Spam & Content family checker for a domain and surgically merge its
   * findings/payload into the domain's latest result (pm/checks/spam_content.mdx §9 — the
   * "Run this check now" affordance on the check-detail and category pages). This generalizes the
   * content-scoring re-score: it runs the one checker with the domain's config and the latest
   * result's `previousResults`, swaps ONLY that checker's findings/payload (matched by the §1
   * id-prefix table via `ownsContentFinding`), keeps every other check untouched, re-summarizes
   * the roll-up, and persists to the latest cache only — the immutable per-run history is never
   * rewritten (pm/storage.mdx §7.2). With no prior run at all, a full audit runs instead (nothing
   * to merge into). A checker crash merges the standing `<checkerId>.error` warning, never a
   * fabricated pass. External tools invoked by the re-run still append `tool_runs[]` entries per
   * §3 into the latest result's execution log.
   *
   * Throws when a run for the same domain is already in flight (→ 409). An unknown `checkerId`
   * throws a plain Error the controller maps to 404.
   */
  async rerunChecker(domainId: string, checkerId: string): Promise<AuditResult> {
    if (!CONTENT_CHECKER_IDS.has(checkerId)) {
      throw new Error(`Unknown Spam & Content checker "${checkerId}"`)
    }
    if (this.inFlight.has(domainId)) {
      throw new RunInFlightError(`A run is already in flight for domain ${domainId}`)
    }
    const latest = this.latest(domainId)
    if (!latest) return this.runForDomain(domainId, "manual")
    const domain = this.domains.get(domainId)
    const checker = CHECKERS.find((c) => c.id === checkerId)
    if (!checker) return latest
    logInfo(`Single-check re-run ${checkerId} started for ${domain.name}`, "AuditService")

    // The other domains' latest DKIM key hashes and every monitored domain — the same cross-run
    // context a full run builds, so report-email attribution and dkim.duplicate_key stay correct.
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
      domainId: domain.id,
      dkimSelectors: domain.dkimSelectors,
      sendingIps: domain.sendingIps,
      peerDkimKeys,
      monitoredDomains: this.domains.list().map((d) => ({ id: d.id, name: d.name })),
      previousResults: latest.results,
      arc: domain.arc,
      bimi: domain.bimi,
      dnsHealth: domain.dnsHealth,
      mx: domain.mx,
      dane: domain.dane,
      mtaSts: domain.mtaSts,
      domainReputation: domain.domainReputation,
      linkUrl: domain.linkUrl,
      listUnsub: domain.listUnsub,
      trigger: "manual" as AuditTrigger,
      tools: locateTools(),
    }

    const findings: Finding[] = []
    let payload: unknown
    // Capture every external-tool invocation this single-check re-run makes (§3 tool_runs[]).
    const toolRunLog: TaggedToolRun[] = []
    try {
      const outcome = await withToolRunLog(toolRunLog, () =>
        withDnsMemo(() =>
          withCheckTag(checker.id, () => Promise.resolve(checker.run(ctx))),
        ),
      )
      if (Array.isArray(outcome)) {
        findings.push(...outcome)
      } else {
        findings.push(...outcome.findings)
        payload = outcome.results
      }
    } catch (err) {
      logError(`Single-check re-run ${checkerId} failed for ${domain.name}`, err, "AuditService")
      findings.push({
        id: `${checkerId}.error`,
        checkId: checkerId,
        title: `${checker.label} check errored`,
        severity: "warning",
        detail: `The ${checker.label} check could not complete: ${err instanceof Error ? err.message : String(err)}`,
        remediation: "Run this check again. If it keeps failing, check the tool installation.",
      })
    }

    // Regression detection against ONLY this checker's previous findings — a single-check re-run
    // must never re-flag the untouched families as new/resolved (pm/checks/spam_content.mdx §9).
    flagNewProblems(
      latest.findings.filter((f) => ownsContentFinding(f, checkerId)),
      findings,
    )

    // Surgical merge: swap only this checker's findings/payload, keep every other check's output.
    const merged = [...latest.findings.filter((f) => !ownsContentFinding(f, checkerId)), ...findings]
    const results = { ...latest.results }
    if (payload !== undefined) results[checkerId] = payload
    // Append this re-run's tool invocations to the latest result's content execution log (§3).
    const contentToolRuns = toolRunLog
      .filter((r) => r.check_id.startsWith("content."))
      .map(({ check_id: _checkId, ...rest }) => rest)
    if (contentToolRuns.length > 0) {
      const prior = Array.isArray(results["content.tool_runs"])
        ? (results["content.tool_runs"] as ToolRunRecord[])
        : []
      results["content.tool_runs"] = [...prior, ...contentToolRuns]
    }
    const { score, status, counts } = summarize(merged, readAppConfig().checks.weights)
    const updated: AuditResult = {
      ...latest,
      findings: merged,
      score,
      status,
      counts,
      results,
      newProblemCount: merged.filter((f) => f.isNew).length,
    }

    // Latest-cache-only persist: refreshes the dashboard/current view but never rewrites the
    // immutable per-run YAML history (pm/storage.mdx §7.2).
    const write = this.writeChain.then(() => {
      const map = this.loadAll()
      map[updated.domainId] = updated
      this.saveAll(map)
    })
    this.writeChain = write.catch(() => {})
    await write
    logInfo(
      `Single-check re-run ${checkerId} finished for ${domain.name}: ${updated.status}`,
      "AuditService",
    )
    return updated
  }

  /**
   * Re-run JUST the content-scoring checker for one domain (pm/checks/content_scoring.mdx §6 — the
   * dedicated "Re-score" action after a sample is uploaded/edited). A thin alias over the
   * generalized single-check re-run (pm/checks/spam_content.mdx §9) so the upload-panel flow keeps
   * working unchanged.
   */
  async rescoreContent(domainId: string): Promise<AuditResult> {
    return this.rerunChecker(domainId, "content.scoring")
  }

  /**
   * Re-run ONE DNS & Infrastructure family checker for a domain and return its findings live —
   * the spot-check endpoint behind the DNS page's ⟳ button and the check-detail explainer page's
   * "run this check now" (pm/checks/dns.mdx §6.2 item 6). Never persisted: run files are
   * immutable history, and a spot check is a fresh observation, not a run.
   */
  async spotCheck(domainId: string, checkKey: string): Promise<SpotCheckResult> {
    if (!DNS_INFRA_FAMILY_KEYS.has(checkKey)) {
      throw new Error(`Unknown DNS & Infrastructure check "${checkKey}"`)
    }
    const checkerId = `infra.${checkKey}`
    const checker = CHECKERS.find((c) => c.id === checkerId)
    if (!checker) throw new Error(`No checker registered for ${checkerId}`)
    const domain = this.domains.get(domainId)
    const latest = this.latest(domainId)
    logInfo(`Spot check ${checkerId} started for ${domain.name}`, "AuditService")

    const startedAt = new Date().toISOString()
    const deadline = new AbortController()
    const deadlineTimer = setTimeout(() => deadline.abort(), SPOT_CHECK_DEADLINE_MS)
    deadlineTimer.unref?.()
    // The same context shape a full run builds (minus peer-domain data the infra families never
    // read); the latest run's structured results stand in as the shared upstream map so families
    // that consume mx_routing's resolved MX list (mta_sts, dane_tlsa) never re-derive it.
    const ctx = {
      domain: domain.name,
      domainId: domain.id,
      dkimSelectors: domain.dkimSelectors,
      sendingIps: domain.sendingIps,
      previousResults: latest?.results,
      arc: domain.arc,
      bimi: domain.bimi,
      dnsHealth: domain.dnsHealth,
      mx: domain.mx,
      domainReputation: domain.domainReputation,
      dane: domain.dane,
      // Per-domain MTA-STS config (pm/checks/mta_sts.mdx §4) — the desired-mode target
      // infra.mta_sts_mode compares the served policy against.
      mtaSts: domain.mtaSts,
      linkUrl: domain.linkUrl,
      // A spot check is always user-initiated — the registration checker bypasses its RDAP cache.
      trigger: "manual" as AuditTrigger,
      signal: deadline.signal,
      tools: locateTools(),
      upstream: { ...(latest?.results ?? {}) },
    }
    const findings: Finding[] = []
    let payload: unknown
    const toolRunLog: TaggedToolRun[] = []
    try {
      const outcome = await withToolRunLog(toolRunLog, () =>
        withDnsMemo(() => withCheckTag(checker.id, () => Promise.resolve(checker.run(ctx)))),
      )
      if (Array.isArray(outcome)) findings.push(...outcome)
      else {
        findings.push(...outcome.findings)
        payload = outcome.results
      }
    } catch (err) {
      logError(`Spot check ${checkerId} failed for ${domain.name}`, err, "AuditService")
      findings.push({
        id: `${checker.id}.error`,
        checkId: checker.id,
        title: `${checker.label} check errored`,
        severity: "warning",
        detail: `The ${checker.label} spot check could not complete: ${err instanceof Error ? err.message : String(err)}`,
        remediation: "Run it again. If it keeps failing, this may be a transient DNS issue.",
      })
    } finally {
      clearTimeout(deadlineTimer)
    }
    const finishedAt = new Date().toISOString()
    logInfo(
      `Spot check ${checkerId} finished for ${domain.name}: ${findings.length} finding(s)`,
      "AuditService",
    )
    return {
      checkId: checkerId,
      domainId: domain.id,
      domain: domain.name,
      startedAt,
      finishedAt,
      findings,
      ...(payload !== undefined ? { results: payload } : {}),
      toolRuns: toolRunLog.map(({ check_id: _checkId, ...rest }) => rest),
    }
  }

  /**
   * On-demand DKIM selector discovery (pm/checks/dkim.mdx §6.2 item 6 — the selectors editor's
   * "Run discovery now" action): probes the MX-guided common-selector wordlist live and returns
   * the hits for one-click import. This is a probe, not a run — nothing is persisted, and a
   * wildcard-TXT domain suppresses the hits (§4 edge case c) rather than reporting junk.
   */
  async dkimDiscovery(domainId: string): Promise<DkimDiscoveryOutcome> {
    const domain = this.domains.get(domainId)
    logInfo(`DKIM selector discovery started for ${domain.name}`, "AuditService")
    const outcome = await discoverDkimSelectors(domain.name)
    logInfo(
      `DKIM selector discovery for ${domain.name}: ${
        outcome.wildcard_shadow
          ? "wildcard TXT shadow — results suppressed"
          : `${outcome.hits.length} hit(s) over ${outcome.probed} probe(s)`
      }`,
      "AuditService",
    )
    return outcome
  }

  private async auditDomain(domain: MonitoredDomain, trigger: AuditTrigger): Promise<AuditResult> {
    // One RUN (pm/dashboard.mdx §1): per domain, stamped with when it started and stopped. The
    // run id is minted at start (timestamp-prefixed, pm/storage.mdx D8) so checkers with their
    // own deep stores can record it and the two copies of a run join (D12).
    const startedAt = new Date().toISOString()
    const runId = makeRunId(startedAt)
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
      // The envelope run id — deep-store writers (blacklist) record it so the copies join (D12).
      runId,
      dkimSelectors: domain.dkimSelectors,
      sendingIps: domain.sendingIps,
      peerDkimKeys,
      // Every monitored domain — the report-email corpus scan routes each report to the matching
      // monitored domain's store by the report's OWN payload domain (pm/emails.mdx §13.1.3).
      monitoredDomains: this.domains.list().map((d) => ({ id: d.id, name: d.name })),
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
      // Per-domain mail-routing expectations (pm/checks/mx_routing.mdx §4) — the receives-mail
      // intent (infra.mx_present / infra.mx_null severity), the expected-MX allow-list
      // (infra.mx_expected_drift), and the skip-SMTP-probe toggle.
      mx: domain.mx,
      // Per-domain registration-reputation config (pm/checks/domain_reputation.mdx §4) — brands,
      // expiry/age thresholds, registrant-public + cousin-scan toggles.
      domainReputation: domain.domainReputation,
      // Per-domain DANE config (pm/checks/dane_tlsa.mdx §4) — the optional pinned expected
      // next-cert SPKI digest that infra.dane_rollover verifies is pre-staged in DNS.
      dane: domain.dane,
      // Per-domain MTA-STS config (pm/checks/mta_sts.mdx §4) — the "Desired MTA-STS mode" target
      // infra.mta_sts_mode compares the served policy's mode: against (absent = enforce).
      mtaSts: domain.mtaSts,
      // Per-domain Link/URL-reputation config (pm/checks/link_url_reputation.mdx §4) — the
      // own/related/allow-listed link domains for content.url_domain_alignment.
      linkUrl: domain.linkUrl,
      // Per-domain list-management config (pm/checks/list_unsubscribe.mdx §3/§4) — the
      // isBulkSender severity escalator and the opt-in probeUnsubEndpoint toggle for the
      // one-click POST probe.
      listUnsub: domain.listUnsub,
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
    // The SPF category persists its own tool invocations inside its own section as
    // `spf.tool_runs[]` (pm/checks/spf.mdx §5 — file-only run forensics, never a verdict input).
    attachSpfToolRuns(results, toolRunLog)
    // The Spam & Content category persists its own tool invocations as `spam_content.tool_runs[]`
    // (pm/checks/spam_content.mdx §3/§4 — the runs-store maps results["content.tool_runs"] to that
    // key). Same append-only evidence-trail contract as the DNS category above.
    const contentToolRuns: ToolRunRecord[] = toolRunLog
      .filter((r) => r.check_id.startsWith("content."))
      .map(({ check_id: _checkId, ...rest }) => rest)
    if (contentToolRuns.length > 0) results["content.tool_runs"] = contentToolRuns
    // Findings complete in graph order, not registry order — restore the registry order so runs
    // are deterministic and diffs/UI grouping are stable.
    const registryIndex = new Map(CHECKERS.map((c, i) => [c.id, i]))
    findings.sort(
      (a, b) => (registryIndex.get(a.checkId) ?? 99) - (registryIndex.get(b.checkId) ?? 99),
    )
    // Regression detection (pm/engineering.mdx §8): diff against the domain's previous run so any
    // finding that newly appears — or worsens in severity — is flagged as a NEW problem and the
    // dashboard can surface it. First run for a domain has no baseline, so nothing is flagged.
    // The count is taken from the findings themselves (not the differ's return) because some
    // checkers flag their own domain-specific regressions — e.g. content scoring marks a band
    // crossing or newly fired high-weight rule as new even when the finding id/severity is
    // unchanged (pm/checks/content_scoring.mdx §6 / §8 AC 9).
    flagNewProblems(all[domain.id]?.findings, findings)
    const newProblemCount = findings.filter((f) => f.isNew).length
    // Score with the operator-configured severity weights (config.yaml → checks.weights,
    // pm/settings.mdx §2) so the roll-up reflects real-world impact (pm/spam_checks.mdx).
    const { score, status, counts } = summarize(findings, readAppConfig().checks.weights)
    const finishedAt = new Date().toISOString()
    return {
      runId,
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
