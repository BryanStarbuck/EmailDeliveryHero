import { existsSync, readdirSync, rmSync, unlinkSync } from "node:fs"
import { join } from "node:path"
import { readJson } from "@shared/json-store"
import { logError, logInfo, logWarn } from "@shared/logging"
import { resolveStateDir, stateSubdir } from "@shared/state-dir"
import { readYaml, writeYaml } from "@shared/yaml-store"
import type { AuditResult, Finding, Severity } from "./checks/types"

/**
 * The run-history store (pm/storage.mdx §7). Every health-check run — one execution of all checks
 * for one domain — persists as ONE human-readable YAML file under the state root:
 *
 *   ~/.email_delivery_hero/runs/<domain>/<YYYY_MM_DD_hh_mm{AM|PM}>.yaml
 *
 * * One subdirectory per domain, the domain name lowercased verbatim (defensively sanitized like
 *   the users/<email> folder key), created lazily on the domain's first run.
 * * The filename is the run's START time rendered in the app's configured local timezone
 *   (config.yaml → schedule.timezone): 4-digit year, 2-digit month/day, 2-digit 12-HOUR-clock
 *   hour, 2-digit minutes — zero-padded, underscore-joined — then AM/PM (uppercase), then .yaml.
 *   Midnight 00:xx → 12_xxAM; noon 12:xx → 12_xxPM. A same-minute collision for the same domain
 *   appends _2 (_3, …) before .yaml.
 * * Written ONCE, atomically (unique-temp-then-rename via yaml-store); a run file is immutable
 *   history and is never edited afterward. Pruning deletes whole files, never rewrites them.
 * * The file body keeps precise ISO-8601 UTC instants; only the filename is local-time.
 *
 * File shape (pm/storage.mdx §7.3): a `run:` metadata block, then one top-level key per test
 * category — spf, dkim, dmarc, blacklists, dns_infra, spam_content. Each category section's
 * exact shape is owned by that category's pm/checks/*.mdx spec; this module owns only the
 * envelope, mapping the checker payloads (AuditResult.results, keyed by checker id) in and out:
 *
 *   spf          ← results["spf"]
 *   dkim         ← results["dkim"]
 *   dmarc        ← results["dmarc"]  (+ results["arc"] nested under its `arc` key —
 *                  ARC is DMARC's advisory companion, pm/checks/arc.mdx §5)
 *   blacklists   ← results["blacklist"]
 *   dns_infra    ← { <id minus "infra.">: results["infra.<id>"], … }
 *   spam_content ← { <id minus "content.">: results["content.<id>"], … }
 *
 * A legacy single-file runs.json from an earlier install is split into per-run YAML files on
 * first use (mirroring the domains.json → domains.yaml migration in domains.service.ts).
 */

/** The six locked category keys, in run-file order (pm/storage.mdx §7.3). */
const _CATEGORY_KEYS = ["spf", "dkim", "dmarc", "blacklists", "dns_infra", "spam_content"] as const

/** The `run:` metadata block — snake_case on disk (pm/storage.mdx §7.3). */
interface RunBlock {
  run_id: string
  domain_id: string
  domain: string
  started_at: string
  finished_at: string
  score: number
  status: Severity
  counts: Record<Severity, number>
  new_problem_count?: number
  /**
   * Category scope (pm/checks/blacklists.mdx §21/AC 26): "blacklists" on a category-scoped
   * re-run; absent on a full run of all six categories.
   */
  scope?: "blacklists"
  /**
   * Category prefixes a scoped re-run executed (pm/checks/spf.mdx §6.5 — `checks: [spf]` on a
   * `?checks=spf` run); absent on a full run. Powers the Runs-table "SPF only" badge.
   */
  checks?: string[]
  /** The flat finding list (the per-sub-test rows), kept verbatim for the run report API. */
  findings: Finding[]
}

interface RunFile {
  run: RunBlock
  [category: string]: unknown
}

function runsRoot(): string {
  return join(resolveStateDir(), "runs")
}

/**
 * Domain name → directory name (pm/storage.mdx §7.1): lowercased verbatim, defensively sanitized
 * with the same policy as the users/<email> key — strip `/`, `\`, `..`, NUL before the value is
 * ever used as a path segment.
 */
export function sanitizeDomainDir(name: string): string {
  const cleaned = (name ?? "")
    .trim()
    .toLowerCase()
    // biome-ignore lint/suspicious/noControlCharactersInRegex: NUL must never reach a path segment
    .replace(/[/\\\u0000]/g, "")
    .replace(/\.\./g, "")
  return cleaned.length > 0 ? cleaned : "unknown"
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

// ------------------------------------------------------------------------------------------------
// The dns_infra category section extras (pm/checks/dns.mdx §5, pm/storage.mdx §7.3): alongside the
// structured snapshots and tool_runs[], the section carries its worst-severity `status` and the
// per-sub-test `tests[]` rows (result: pass|fail|warn|info ⇔ severity ok|critical|warning|info,
// `family` derived from the finding id per the §2 prefix table). `families` and `problem_states`
// are derived at render time and never stored.
// ------------------------------------------------------------------------------------------------

const SEVERITY_RANK: Record<Severity, number> = { ok: 0, info: 1, warning: 2, critical: 3 }

/** severity ok|critical|warning|info ⇔ tests[].result pass|fail|warn|info (pm/checks/dns.mdx §5). */
const SEVERITY_TO_RESULT: Record<Severity, "pass" | "fail" | "warn" | "info"> = {
  ok: "pass",
  critical: "fail",
  warning: "warn",
  info: "info",
}

/**
 * Finding-id prefix (after "infra.") → family key (pm/checks/dns.mdx §2). Many ids carry a
 * `.<host>` / `.<ip>` suffix so matching is by prefix, longest/most-specific first (e.g.
 * `dnssec_ds_at_registrar` belongs to the registration family even though it starts `dnssec_`).
 * Mirrors the frontend's lib/dns-families.ts — keep the two in lockstep.
 */
const DNS_INFRA_FAMILY_PREFIXES: { prefix: string; family: string }[] = [
  { prefix: "mx_", family: "mx_routing" },
  { prefix: "backup_mx_hygiene", family: "mx_routing" },
  { prefix: "ptr_", family: "reverse_dns" },
  { prefix: "fcrdns", family: "reverse_dns" },
  { prefix: "helo_match", family: "reverse_dns" },
  { prefix: "reverse_dns", family: "reverse_dns" },
  { prefix: "tls_transport", family: "tls_transport" },
  { prefix: "mta_sts", family: "mta_sts" },
  { prefix: "tls_rpt", family: "tls_rpt" },
  { prefix: "dane_", family: "dane_tlsa" },
  { prefix: "dnssec_ds_at_registrar", family: "domain_reputation" },
  { prefix: "dnssec_", family: "dnssec" },
  // Bare checker-scoped ids (infra.dnssec.error / .did_not_complete) — after dnssec_* by length.
  { prefix: "dnssec", family: "dnssec" },
  { prefix: "ns_", family: "dns_health" },
  { prefix: "soa_", family: "dns_health" },
  { prefix: "ttl_sanity", family: "dns_health" },
  { prefix: "wildcard", family: "dns_health" },
  { prefix: "cname_at_apex", family: "dns_health" },
  { prefix: "multi_txt_spf", family: "dns_health" },
  { prefix: "txt_bloat", family: "dns_health" },
  { prefix: "glue_records", family: "dns_health" },
  { prefix: "recursion_open", family: "dns_health" },
  { prefix: "zone_transfer", family: "dns_health" },
  { prefix: "dangling_", family: "dns_health" },
  { prefix: "dns_health", family: "dns_health" },
  { prefix: "domain_", family: "domain_reputation" },
  { prefix: "registrar_", family: "domain_reputation" },
  { prefix: "registrant_privacy", family: "domain_reputation" },
  { prefix: "auto_renew", family: "domain_reputation" },
  { prefix: "hold_status", family: "domain_reputation" },
  { prefix: "pending_delete", family: "domain_reputation" },
  { prefix: "recent_transfer", family: "domain_reputation" },
  { prefix: "record_available", family: "domain_reputation" },
  { prefix: "parked", family: "domain_reputation" },
  { prefix: "parking_nameservers", family: "domain_reputation" },
  { prefix: "tld_risk", family: "domain_reputation" },
  { prefix: "name_similarity", family: "domain_reputation" },
  { prefix: "idn_homograph", family: "domain_reputation" },
  { prefix: "update_lock", family: "domain_reputation" },
  { prefix: "delete_lock", family: "domain_reputation" },
  { prefix: "smtp_security", family: "smtp_security" },
].sort((a, b) => b.prefix.length - a.prefix.length)

/** Which of the ten §2 families an `infra.*` finding id rolls into (null when unrecognized). */
function dnsInfraFamilyOf(findingId: string): string | null {
  const bare = findingId.startsWith("infra.") ? findingId.slice("infra.".length) : findingId
  for (const { prefix, family } of DNS_INFRA_FAMILY_PREFIXES) {
    if (bare.startsWith(prefix)) return family
  }
  return null
}

/** One dns_infra.tests[] row (pm/checks/dns.mdx §5) — the finding, in on-disk vocabulary. */
interface DnsInfraTestRow {
  id: string
  family: string | null
  title: string
  result: "pass" | "fail" | "warn" | "info"
  detail?: string
  evidence?: string
  fix?: string
}

function encodeDnsInfraTest(finding: Finding): DnsInfraTestRow {
  return {
    id: finding.id,
    family: dnsInfraFamilyOf(finding.id),
    title: finding.title,
    result: SEVERITY_TO_RESULT[finding.severity] ?? "info",
    ...(finding.detail ? { detail: finding.detail } : {}),
    ...(finding.evidence ? { evidence: finding.evidence } : {}),
    ...(finding.remediation ? { fix: finding.remediation } : {}),
  }
}

/** dns_infra keys that are projections of the run's findings — never re-hydrated into `results`. */
const DNS_INFRA_DERIVED_KEYS = new Set(["status", "tests", "families", "problem_states"])

/**
 * Render the run's start instant as the filename timestamp (pm/storage.mdx §7.2):
 * YYYY_MM_DD_hh_mm{AM|PM} in the given IANA timezone, 12-hour clock, zero-padded.
 */
export function runFileTimestamp(startedAtIso: string, timezone: string): string {
  const date = new Date(startedAtIso)
  const instant = Number.isNaN(date.getTime()) ? new Date() : date
  let parts: Intl.DateTimeFormatPart[]
  try {
    parts = new Intl.DateTimeFormat("en-US", {
      timeZone: timezone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: true,
    }).formatToParts(instant)
  } catch {
    // An invalid configured timezone must never break persisting a run — fall back to system tz.
    parts = new Intl.DateTimeFormat("en-US", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: true,
    }).formatToParts(instant)
  }
  const get = (type: Intl.DateTimeFormatPart["type"]): string =>
    parts.find((p) => p.type === type)?.value ?? ""
  const pad2 = (v: string): string => v.padStart(2, "0")
  const dayPeriod = get("dayPeriod").toUpperCase().startsWith("P") ? "PM" : "AM"
  return `${get("year")}_${pad2(get("month"))}_${pad2(get("day"))}_${pad2(get("hour"))}_${pad2(get("minute"))}${dayPeriod}`
}

/** Encode an AuditResult into the on-disk run-file envelope (pm/storage.mdx §7.3). */
function encodeRunFile(result: AuditResult): RunFile {
  const results = result.results ?? {}
  const doc: RunFile = {
    run: {
      run_id: result.runId,
      domain_id: result.domainId,
      domain: result.domain,
      started_at: result.startedAt,
      finished_at: result.finishedAt,
      score: result.score,
      status: result.status,
      counts: result.counts,
      ...(result.newProblemCount !== undefined
        ? { new_problem_count: result.newProblemCount }
        : {}),
      ...(result.scope !== undefined ? { scope: result.scope } : {}),
      findings: result.findings,
    },
  }
  const dnsInfra: Record<string, unknown> = {}
  const spamContent: Record<string, unknown> = {}
  // The dns_infra section's own status + per-sub-test rows (pm/checks/dns.mdx §5): worst severity
  // across every `infra.*` finding, then the tests[] projection of those findings. Written before
  // the snapshots so the section reads verdict-first.
  const infraFindings = (result.findings ?? []).filter((f) => f.checkId.startsWith("infra."))
  if (infraFindings.length > 0) {
    let worst: Severity = "ok"
    for (const f of infraFindings) {
      if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) worst = f.severity
    }
    dnsInfra.status = worst
  }
  for (const [id, payload] of Object.entries(results)) {
    if (id.startsWith("infra.")) dnsInfra[id.slice("infra.".length)] = payload
    else if (id.startsWith("content.")) spamContent[id.slice("content.".length)] = payload
  }
  if (infraFindings.length > 0) dnsInfra.tests = infraFindings.map(encodeDnsInfraTest)
  const dmarcBase = results.dmarc
  const arcPayload = results.arc
  const dmarcSection =
    arcPayload !== undefined
      ? { ...(isPlainObject(dmarcBase) ? dmarcBase : {}), arc: arcPayload }
      : (dmarcBase ?? {})
  doc.spf = results.spf ?? {}
  doc.dkim = results.dkim ?? {}
  doc.dmarc = dmarcSection
  doc.blacklists = results.blacklist ?? {}
  doc.dns_infra = dnsInfra
  doc.spam_content = spamContent
  return doc
}

/** Decode a run file back to the in-memory/API AuditResult shape. */
function decodeRunFile(doc: unknown): AuditResult | null {
  if (!isPlainObject(doc) || !isPlainObject(doc.run)) return null
  const run = doc.run as unknown as RunBlock
  if (typeof run.run_id !== "string" || typeof run.domain !== "string") return null
  const results: Record<string, unknown> = {}
  const addSection = (key: string, value: unknown): void => {
    if (value === undefined || value === null) return
    if (isPlainObject(value) && Object.keys(value).length === 0) return
    results[key] = value
  }
  addSection("spf", doc.spf)
  addSection("dkim", doc.dkim)
  addSection("blacklist", doc.blacklists)
  if (isPlainObject(doc.dmarc) && "arc" in doc.dmarc) {
    const { arc, ...rest } = doc.dmarc
    addSection("arc", arc)
    addSection("dmarc", rest)
  } else {
    addSection("dmarc", doc.dmarc)
  }
  if (isPlainObject(doc.dns_infra)) {
    for (const [key, payload] of Object.entries(doc.dns_infra)) {
      // status/tests (and any derived keys) are projections of run.findings — the findings list
      // is the source of truth in memory, so they never round-trip into `results`.
      if (DNS_INFRA_DERIVED_KEYS.has(key)) continue
      addSection(`infra.${key}`, payload)
    }
  }
  if (isPlainObject(doc.spam_content)) {
    for (const [key, payload] of Object.entries(doc.spam_content))
      addSection(`content.${key}`, payload)
  }
  return {
    runId: run.run_id,
    domainId: run.domain_id ?? "",
    domain: run.domain,
    startedAt: run.started_at ?? "",
    finishedAt: run.finished_at ?? "",
    ranAt: run.finished_at ?? "",
    score: typeof run.score === "number" ? run.score : 0,
    status: run.status ?? "info",
    findings: Array.isArray(run.findings) ? run.findings : [],
    counts: run.counts ?? { ok: 0, info: 0, warning: 0, critical: 0 },
    ...(run.new_problem_count !== undefined ? { newProblemCount: run.new_problem_count } : {}),
    ...(run.scope !== undefined ? { scope: run.scope } : {}),
    ...(Object.keys(results).length > 0 ? { results } : {}),
  }
}

/** List every run-file path (absolute), across all domain directories. */
function listRunFiles(domainDir?: string): string[] {
  const root = runsRoot()
  if (!existsSync(root)) return []
  const dirs = domainDir
    ? [domainDir]
    : readdirSync(root, { withFileTypes: true })
        .filter((e) => e.isDirectory())
        .map((e) => e.name)
  const files: string[] = []
  for (const dir of dirs) {
    const abs = join(root, dir)
    if (!existsSync(abs)) continue
    for (const entry of readdirSync(abs, { withFileTypes: true })) {
      if (entry.isFile() && entry.name.endsWith(".yaml")) files.push(join(abs, entry.name))
    }
  }
  return files
}

/**
 * Persist one finished run as its own YAML file (written once, atomically — pm/storage.mdx §7.4).
 * `timezone` is the configured schedule.timezone; it only shapes the human-facing filename.
 */
export function saveRun(result: AuditResult, timezone: string): void {
  const dir = stateSubdir("runs", sanitizeDomainDir(result.domain))
  const stamp = runFileTimestamp(result.startedAt, timezone)
  // Collision rule (pm/storage.mdx §7.2): same domain + same minute → append _2, _3, …
  let path = join(dir, `${stamp}.yaml`)
  for (let n = 2; existsSync(path); n++) path = join(dir, `${stamp}_${n}.yaml`)
  writeYaml(path, encodeRunFile(result))
}

/** All kept runs (optionally one domain's, by monitored-domain id), newest startedAt first. */
export function listRuns(domainId?: string): AuditResult[] {
  const runs: AuditResult[] = []
  for (const file of listRunFiles()) {
    const decoded = decodeRunFile(readYaml<unknown>(file, null))
    if (decoded) runs.push(decoded)
    else logWarn(`Skipping malformed run file ${file}`, "RunsStore")
  }
  const filtered = domainId ? runs.filter((r) => r.domainId === domainId) : runs
  // Sort on the ISO started_at in the body — never string-sort the AM/PM filenames
  // across noon/midnight (pm/storage.mdx §7.2).
  return filtered.sort((a, b) => (b.startedAt ?? "").localeCompare(a.startedAt ?? ""))
}

/** One run in full, by run id — what GET /api/audit/runs/:runId resolves. */
export function getRun(runId: string): AuditResult | null {
  const file = findRunFile(runId)
  return file ? decodeRunFile(readYaml<unknown>(file, null)) : null
}

function findRunFile(runId: string): string | null {
  for (const file of listRunFiles()) {
    const doc = readYaml<unknown>(file, null)
    if (isPlainObject(doc) && isPlainObject(doc.run) && doc.run.run_id === runId) return file
  }
  return null
}

/** Remove one run from history by deleting its whole file (never a rewrite). */
export function deleteRun(runId: string): void {
  const file = findRunFile(runId)
  if (!file) return
  try {
    unlinkSync(file)
  } catch (err) {
    logError(`Failed to delete run file ${file}`, err, "RunsStore")
    throw err
  }
}

/** Deleting a domain removes its whole runs/<domain>/ directory (pm/storage.mdx §7.4). */
export function deleteDomainRuns(domainName: string): void {
  const dir = join(runsRoot(), sanitizeDomainDir(domainName))
  try {
    rmSync(dir, { recursive: true, force: true })
  } catch (err) {
    // Best-effort: a failed history cleanup must never block deleting the domain itself.
    logError(`Failed to remove run history at ${dir}`, err, "RunsStore")
  }
}

/**
 * Same as deleteDomainRuns, but resolved by the monitored-domain id — used when the domain record
 * (and its name) is already gone by the time the purge runs. Scans each runs/<domain>/ directory's
 * files for a matching run.domain_id and removes the whole directory.
 */
export function deleteDomainRunsById(domainId: string): void {
  const root = runsRoot()
  if (!existsSync(root) || !domainId) return
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    const owns = listRunFiles(entry.name).some((file) => {
      const doc = readYaml<unknown>(file, null)
      return isPlainObject(doc) && isPlainObject(doc.run) && doc.run.domain_id === domainId
    })
    if (owns) deleteDomainRuns(entry.name)
  }
}

/**
 * Retention (pm/storage.mdx §7.4): delete run files older than `retentionDays`, and keep at most
 * the newest `keepPerDomain` runs per domain. Whole-file deletes only.
 */
export function pruneRuns(retentionDays: number, keepPerDomain: number): void {
  const root = runsRoot()
  if (!existsSync(root)) return
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString()
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    const rows: { file: string; startedAt: string }[] = []
    for (const file of listRunFiles(entry.name)) {
      const doc = readYaml<unknown>(file, null)
      const startedAt =
        isPlainObject(doc) && isPlainObject(doc.run) && typeof doc.run.started_at === "string"
          ? doc.run.started_at
          : ""
      rows.push({ file, startedAt })
    }
    rows.sort((a, b) => b.startedAt.localeCompare(a.startedAt))
    rows.forEach(({ file, startedAt }, index) => {
      if (startedAt >= cutoff && index < keepPerDomain) return
      try {
        unlinkSync(file)
      } catch (err) {
        logError(`Failed to prune run file ${file}`, err, "RunsStore")
      }
    })
  }
}

/**
 * One-time migration: split a legacy single-file runs.json (pre-§7 installs) into per-run YAML
 * files, then remove it so the state root matches the spec layout. Safe to call on every boot —
 * a no-op once the legacy file is gone.
 */
export function migrateLegacyRunsJson(timezone: string): void {
  const legacy = join(resolveStateDir(), "runs.json")
  if (!existsSync(legacy)) return
  const runs = readJson<AuditResult[]>(legacy, [])
  const known = new Set(listRuns().map((r) => r.runId))
  let migrated = 0
  for (const run of runs) {
    if (!run || typeof run !== "object" || !run.domain) continue
    if (run.runId && known.has(run.runId)) continue
    saveRun(run, timezone)
    migrated++
  }
  try {
    unlinkSync(legacy)
  } catch (err) {
    logError("Failed to remove legacy runs.json after migration", err, "RunsStore")
    return
  }
  logInfo(`Migrated ${migrated} run(s) from runs.json to the runs/ YAML tree`, "RunsStore")
}
