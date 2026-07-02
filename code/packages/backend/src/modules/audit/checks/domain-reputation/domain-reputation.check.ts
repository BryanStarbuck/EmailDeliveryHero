import { request as httpsRequest } from "node:https"
import { domainToUnicode } from "node:url"
import { withResource } from "@shared/concurrency"
import { readAppConfig } from "@shared/config-store"
import { resolveNs } from "../dns-util"
import type { CheckOutcome, Checker, DomainReputationConfig, Finding } from "../types"

/**
 * Domain Registration Reputation (WHOIS/RDAP) — pm/checks/domain_reputation.mdx. Reads each
 * sending domain's registration record via RDAP-over-HTTPS (RFC 9082/9083, IANA bootstrap RFC
 * 7484) and reports registration age, expiry runway, EPP transfer/delete/update locks,
 * hold/pending-delete lifecycle states, DNSSEC delegation at the registrar, registrant privacy,
 * parking-nameserver delegation, registrar/TLD reputation, recent-transfer (possible hijack), and
 * IDN/homograph risk.
 *
 * All findings share checkId "infra" (sub-family domain-reputation). Each run also persists one
 * structured `domain_registration` snapshot (spec §5 — snake_case, the target Postgres columns) as
 * the checker's `results` payload. Because registration data changes over days/years, the snapshot
 * is cached: a scheduled run within the configured TTL (config.yaml →
 * domain_reputation.cache_ttl_hours, default 24h) re-derives its findings from the previous run's
 * `raw_record` instead of re-querying RDAP; a manual run-now always bypasses the cache (spec §6).
 *
 * First-round sub-checks are pure RDAP-JSON parsing + local reference-list / string analysis.
 * WHOIS fallback, the HTTP landing-page "parked" probe, registrar-API auto-renew confirmation, and
 * the active cousin-domain scan are future — emitted only as info.
 */

const CHECK_ID = "infra"
const HTTP_TIMEOUT_MS = 6000
const DAY = 86_400_000

/** Fallback defaults mirroring config.yaml → domain_reputation (pm/checks/domain_reputation.mdx §5). */
const DEFAULT_CACHE_TTL_HOURS = 24
const DEFAULT_RDAP_REQUEST_BUDGET = 5

/** One registrar-watchlist entry (config.yaml → domain_reputation.registrar_reputation). */
export interface RegistrarWatchlistEntry {
  match_type: "registrar_iana_id" | "registrar_name" | "tld"
  match_value: string
  note?: string
}

/**
 * The persisted registration snapshot (`results["infra.domain_reputation"]`) — one object per run
 * with exactly the `domain_registration` columns of pm/checks/domain_reputation.mdx §5 (dates as
 * ISO strings, statuses/nameservers/raw_record as nested JSON). The move to Postgres is a
 * store-module swap; these names are the target shape.
 */
export interface DomainRegistrationResults {
  registrar: string | null
  registrar_iana_id: number | null
  created_date: string | null
  expiry_date: string | null
  updated_date: string | null
  transfer_date: string | null
  /** Normalized camelCase EPP status codes, e.g. ["clientTransferProhibited"]. */
  statuses: string[]
  privacy_enabled: boolean | null
  dnssec_at_registrar: boolean | null
  /** null = unknown (registrar-API confirmation is a future round). */
  auto_renew: boolean | null
  /** null = the HTTP landing-page classification is a future round. */
  parked: boolean | null
  parking_nameservers: boolean | null
  nameservers: string[]
  age_days: number | null
  days_to_expiry: number | null
  source: "rdap" | "whois"
  /** Full RDAP JSON for the audit trail — also what the TTL-cached re-derivation parses. */
  raw_record: unknown
  checked_at: string
}

// Two-label public suffixes so we take the correct registrable apex (best-effort without the PSL).
const MULTI_SUFFIX = new Set([
  "co.uk",
  "org.uk",
  "gov.uk",
  "ac.uk",
  "me.uk",
  "com.au",
  "net.au",
  "org.au",
  "co.nz",
  "co.jp",
  "co.za",
  "com.br",
  "co.in",
  "com.mx",
  "com.sg",
  "com.hk",
])

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))

/** Strip subdomains down to the registrable apex (best-effort, small multi-label-suffix table). */
export function apexOf(domain: string): string {
  const labels = domain.trim().replace(/\.$/, "").toLowerCase().split(".")
  if (labels.length <= 2) return labels.join(".")
  const lastTwo = labels.slice(-2).join(".")
  if (MULTI_SUFFIX.has(lastTwo)) return labels.slice(-3).join(".")
  return lastTwo
}

interface HttpResult {
  status: number
  body: string
  headers: Record<string, string | string[] | undefined>
  error?: string
}

function httpGet(url: string, headers: Record<string, string>): Promise<HttpResult> {
  // RDAP/IANA fetches go through the process-global `http` semaphore (pm/run_checks.mdx §3.1)
  // shared with every other outbound HTTPS consumer across all in-flight domains.
  return withResource("http", () => httpGetNow(url, headers))
}

function httpGetNow(url: string, headers: Record<string, string>): Promise<HttpResult> {
  return new Promise<HttpResult>((resolve) => {
    let settled = false
    const done = (r: HttpResult) => {
      if (!settled) {
        settled = true
        resolve(r)
      }
    }
    try {
      const req = httpsRequest(url, { method: "GET", headers, timeout: HTTP_TIMEOUT_MS }, (res) => {
        const chunks: Buffer[] = []
        res.on("data", (c) => chunks.push(c as Buffer))
        res.on("end", () =>
          done({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
            headers: res.headers,
          }),
        )
      })
      req.on("timeout", () => {
        req.destroy()
        done({ status: 0, body: "", headers: {}, error: "ETIMEOUT" })
      })
      req.on("error", (e) =>
        done({
          status: 0,
          body: "",
          headers: {},
          error: (e as NodeJS.ErrnoException).code ?? e.message,
        }),
      )
      req.end()
    } catch (e) {
      done({ status: 0, body: "", headers: {}, error: e instanceof Error ? e.message : String(e) })
    }
  })
}

/** RDAP GET with a shared per-run request budget, 429/Retry-After back-off, and redirect follow. */
async function rdapGet(url: string, budget: { n: number }): Promise<HttpResult> {
  let attempt = 0
  let redirects = 0
  let target = url
  while (true) {
    if (budget.n <= 0) return { status: 0, body: "", headers: {}, error: "budget_exhausted" }
    budget.n--
    const res = await httpGet(target, {
      Accept: "application/rdap+json",
      "User-Agent": "EmailDeliveryHero-RDAP/1",
    })
    if (res.status === 429 && attempt < 2) {
      const ra = Number(res.headers["retry-after"])
      const wait = Number.isFinite(ra) && ra > 0 ? Math.min(ra * 1000, 4000) : 500 * 2 ** attempt
      await sleep(wait)
      attempt++
      continue
    }
    const loc = res.headers.location
    if ([301, 302, 307, 308].includes(res.status) && typeof loc === "string" && redirects < 3) {
      target = new URL(loc, target).toString()
      redirects++
      continue
    }
    return res
  }
}

/**
 * The IANA RDAP bootstrap file (RFC 7484), cached module-wide with a long TTL so it is shared
 * across every domain in a run and across runs (spec §6 "share the IANA bootstrap cache across
 * domains"). On refresh failure the stale copy keeps serving.
 */
const BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000
let bootstrapCache: { fetchedAt: number; services: [string[], string[]][] } | null = null

async function bootstrapServices(): Promise<[string[], string[]][] | null> {
  const now = Date.now()
  if (bootstrapCache && now - bootstrapCache.fetchedAt < BOOTSTRAP_TTL_MS) {
    return bootstrapCache.services
  }
  const res = await httpGet("https://data.iana.org/rdap/dns.json", { Accept: "application/json" })
  if (res.status === 200) {
    try {
      const services = (JSON.parse(res.body).services ?? []) as [string[], string[]][]
      bootstrapCache = { fetchedAt: now, services }
      return services
    } catch {
      // fall through to the stale copy
    }
  }
  return bootstrapCache?.services ?? null
}

/** Test seam: prime/clear the module-level bootstrap cache. */
export function primeBootstrapCache(services: [string[], string[]][] | null): void {
  bootstrapCache = services ? { fetchedAt: Date.now(), services } : null
}

/** Resolve the RDAP base URL for a TLD from the IANA bootstrap file (RFC 7484). */
async function rdapBaseForTld(tld: string): Promise<string | null> {
  const services = await bootstrapServices()
  if (!services) return null
  for (const [tlds, urls] of services) {
    if (tlds.map((t) => t.toLowerCase()).includes(tld)) {
      const base = urls.find((u) => u.startsWith("https://")) ?? urls[0]
      return base ? base.replace(/\/$/, "") : null
    }
  }
  return null
}

// -- RDAP JSON parsing helpers -------------------------------------------------

// biome-ignore lint/suspicious/noExplicitAny: RDAP JSON is dynamically shaped.
type Rdap = any

function eventDate(events: Rdap[], action: string): string | undefined {
  for (const e of events ?? [])
    if (e?.eventAction === action && typeof e.eventDate === "string") return e.eventDate
  return undefined
}

/** Normalize an RDAP space-separated status ("client transfer prohibited") to EPP camelCase. */
export function normStatus(s: string): string {
  const words = String(s).trim().toLowerCase().split(/\s+/).filter(Boolean)
  return words.map((w, i) => (i === 0 ? w : w[0].toUpperCase() + w.slice(1))).join("")
}

function findEntity(entities: Rdap[], role: string): Rdap | undefined {
  for (const e of entities ?? []) {
    if (Array.isArray(e?.roles) && e.roles.includes(role)) return e
    const nested = findEntity(e?.entities, role)
    if (nested) return nested
  }
  return undefined
}

function vcardField(entity: Rdap, field: string): string | undefined {
  const arr = entity?.vcardArray?.[1]
  if (!Array.isArray(arr)) return undefined
  for (const item of arr) {
    if (Array.isArray(item) && item[0] === field) {
      const v = item[3]
      if (typeof v === "string") return v
      if (Array.isArray(v)) return v.filter(Boolean).join(" ")
    }
  }
  return undefined
}

function ianaId(entity: Rdap): number | undefined {
  for (const p of entity?.publicIds ?? []) {
    if (typeof p?.type === "string" && /iana/i.test(p.type)) {
      const n = Number(p.identifier)
      if (Number.isFinite(n)) return n
    }
  }
  return undefined
}

/** Damerau-Levenshtein edit distance (for lookalike / cousin-brand detection). */
export function damerau(a: string, b: string): number {
  const m = a.length
  const n = b.length
  const d: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0))
  for (let i = 0; i <= m; i++) d[i][0] = i
  for (let j = 0; j <= n; j++) d[0][j] = j
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1)
      }
    }
  }
  return d[m][n]
}

// -- Registration-record parsing + finding derivation (pure — unit-testable) ----

/** The parsed registration record every RDAP-derived sub-check reads. */
export interface RegData {
  registrar?: string
  registrarIanaId?: number
  /** ISO event dates straight from RDAP `events[]`. */
  created?: string
  expiry?: string
  updated?: string
  transfer?: string
  /** Normalized camelCase EPP status codes. */
  statuses: string[]
  dnssecSigned: boolean
  privacyEnabled: boolean
  /** The exposed registrant name/email when privacy is off (detail only). */
  registrantContact?: string
  abuseContact?: string
  /** true when the EPP autoRenewPeriod status was observed; null = unknown. */
  autoRenew: boolean | null
}

/** Parse an RDAP domain JSON document into the RegData every sub-check reads. */
export function parseRdap(rdap: Rdap): RegData {
  const events: Rdap[] = Array.isArray(rdap?.events) ? rdap.events : []
  const statuses: string[] = (Array.isArray(rdap?.status) ? rdap.status : []).map((s: string) =>
    normStatus(s),
  )
  const registrant = findEntity(rdap?.entities, "registrant")
  const registrantName = registrant ? vcardField(registrant, "fn") : undefined
  const registrantEmail = registrant ? vcardField(registrant, "email") : undefined
  const redactedTop = Array.isArray(rdap?.redacted) && rdap.redacted.length > 0
  const piiExposed = !redactedTop && (Boolean(registrantEmail) || Boolean(registrantName))
  const registrar = findEntity(rdap?.entities, "registrar")
  const abuse = findEntity(rdap?.entities, "abuse")
  const abuseEmail = abuse ? vcardField(abuse, "email") : undefined
  const abuseTel = abuse ? vcardField(abuse, "tel") : undefined
  return {
    registrar: registrar ? vcardField(registrar, "fn") : undefined,
    registrarIanaId: registrar ? ianaId(registrar) : undefined,
    created: eventDate(events, "registration"),
    expiry: eventDate(events, "expiration"),
    updated: eventDate(events, "last changed"),
    transfer: eventDate(events, "transfer"),
    statuses,
    dnssecSigned: rdap?.secureDNS?.delegationSigned === true,
    privacyEnabled: !piiExposed,
    ...(piiExposed ? { registrantContact: registrantName ?? registrantEmail } : {}),
    ...(abuseEmail || abuseTel ? { abuseContact: abuseEmail ?? abuseTel } : {}),
    // EPP autoRenewPeriod is only partial evidence (spec §7): its presence proves auto-renew
    // fired; its absence proves nothing — registrar-API confirmation is a future round.
    autoRenew: statuses.includes("autoRenewPeriod") ? true : null,
  }
}

/** Thresholds + toggles the RDAP-derived sub-checks honor (spec §4 per-domain config inputs). */
export interface DeriveOptions {
  /** Days-to-expiry below which infra.domain_expiry warns (default 30). */
  expiryWarnDays: number
  /** Age (days) below which infra.domain_age warns (default 30); 30–89 stays info by spec. */
  ageWarnDays: number
  /** Registrant contact is deliberately public — silences infra.registrant_privacy. */
  registrantPublicIntentional: boolean
  /** Curated abuse-tolerant registrar watchlist (config.yaml → domain_reputation.registrar_reputation). */
  registrarWatchlist: RegistrarWatchlistEntry[]
  /** Injectable clock for tests. */
  now?: number
}

/**
 * Derive every RDAP-fed sub-check finding (spec §2 rows domain_expiry … registrar_abuse_contact)
 * from a parsed registration record. Pure — no network, no config reads — so the TTL-cached path
 * re-derives identical findings from the previous run's raw_record.
 */
export function deriveRegistrationFindings(
  apex: string,
  reg: RegData,
  opts: DeriveOptions,
): Finding[] {
  const findings: Finding[] = []
  const now = opts.now ?? Date.now()
  const statusSet = new Set(reg.statuses)

  // infra.domain_expiry — critical when past expiry, warning under the threshold (default 30d).
  const expiry = reg.expiry ? Date.parse(reg.expiry) : NaN
  if (Number.isFinite(expiry)) {
    const days = Math.floor((expiry - now) / DAY)
    const dateOnly = reg.expiry?.slice(0, 10)
    if (days < 0) {
      findings.push({
        id: "infra.domain_expiry",
        checkId: CHECK_ID,
        title: "Domain has expired",
        severity: "critical",
        detail: `${apex} expired on ${dateOnly} (${-days} days ago). All mail stops when the domain lapses — SPF/DKIM/DMARC/MX all disappear.`,
        remediation: `Renew ${apex} now at your registrar (expiry ${dateOnly}). All mail stops if the domain lapses.`,
        evidence: reg.expiry,
      })
    } else if (days < opts.expiryWarnDays) {
      findings.push({
        id: "infra.domain_expiry",
        checkId: CHECK_ID,
        title: "Domain expires soon",
        severity: "warning",
        detail: `${apex} expires on ${dateOnly} (in ${days} days). A silent lapse takes down all mail at once.`,
        remediation: `Renew ${apex} now at your registrar (current expiry ${dateOnly}). All mail stops if the domain lapses.`,
        evidence: reg.expiry,
      })
    } else {
      findings.push({
        id: "infra.domain_expiry",
        checkId: CHECK_ID,
        title: "Domain not expiring soon",
        severity: "ok",
        detail: `${apex} expires ${dateOnly} (in ${days} days).`,
        evidence: reg.expiry,
      })
    }
  }

  // infra.domain_age — warning under the age threshold (default 30d), info at 30–89d.
  const created = reg.created ? Date.parse(reg.created) : NaN
  if (Number.isFinite(created)) {
    const ageDays = Math.floor((now - created) / DAY)
    const dateOnly = reg.created?.slice(0, 10)
    if (ageDays < opts.ageWarnDays) {
      findings.push({
        id: "infra.domain_age",
        checkId: CHECK_ID,
        title: "Domain is newly registered",
        severity: "warning",
        detail: `${apex} was registered ${ageDays} days ago (${dateOnly}). New domains have no sending history and are treated as high-risk.`,
        remediation: `${apex} was registered ${ageDays} days ago; warm up sending slowly and expect throttling until ~30-day age. If unexpected, verify no one hijacked/re-registered the name.`,
        evidence: reg.created,
      })
    } else if (ageDays < 90) {
      findings.push({
        id: "infra.domain_age",
        checkId: CHECK_ID,
        title: "Domain is relatively young",
        severity: "info",
        detail: `${apex} is ${ageDays} days old (registered ${dateOnly}); reputation is still building.`,
        remediation:
          "Continue warming up sending volume; receiver throttling eases as the domain ages past ~90 days.",
        evidence: reg.created,
      })
    } else {
      findings.push({
        id: "infra.domain_age",
        checkId: CHECK_ID,
        title: "Domain has sending-age history",
        severity: "ok",
        detail: `${apex} is ${ageDays} days old (registered ${dateOnly}).`,
        evidence: reg.created,
      })
    }
  }

  // infra.registrar_lock
  if (statusSet.has("clientTransferProhibited")) {
    findings.push({
      id: "infra.registrar_lock",
      checkId: CHECK_ID,
      title: "Registrar transfer lock set",
      severity: "ok",
      detail: `${apex} has clientTransferProhibited — protected against unauthorized transfers.`,
    })
  } else {
    findings.push({
      id: "infra.registrar_lock",
      checkId: CHECK_ID,
      title: "Registrar transfer lock missing",
      severity: "warning",
      detail: `${apex} does not have clientTransferProhibited; an unauthorized transfer (hijack) becomes trivial if registrar credentials leak.`,
      remediation:
        "Enable Registrar Lock (clientTransferProhibited) in your registrar control panel to block unauthorized transfers.",
      evidence: reg.statuses.join(", "),
    })
  }

  // infra.delete_lock
  if (statusSet.has("clientDeleteProhibited")) {
    findings.push({
      id: "infra.delete_lock",
      checkId: CHECK_ID,
      title: "Delete lock set",
      severity: "ok",
      detail: `${apex} has clientDeleteProhibited.`,
    })
  } else {
    findings.push({
      id: "infra.delete_lock",
      checkId: CHECK_ID,
      title: "Delete lock missing",
      severity: "info",
      detail: `${apex} lacks clientDeleteProhibited.`,
      remediation:
        "Enable clientDeleteProhibited at your registrar to prevent accidental/malicious deletion of the mail domain.",
    })
  }

  // infra.update_lock
  if (statusSet.has("clientUpdateProhibited") || statusSet.has("serverUpdateProhibited")) {
    findings.push({
      id: "infra.update_lock",
      checkId: CHECK_ID,
      title: "Update lock set",
      severity: "ok",
      detail: `${apex} has an update-prohibited lock.`,
    })
  } else {
    findings.push({
      id: "infra.update_lock",
      checkId: CHECK_ID,
      title: "Update lock missing",
      severity: "info",
      detail: `${apex} has no update-prohibited lock.`,
      remediation:
        "For a brand-critical mail domain, request Registry Lock (serverTransferProhibited/serverUpdateProhibited) from your registrar.",
    })
  }

  // infra.hold_status — critical: DNS is suppressed by the registrar/registry.
  const holds = reg.statuses.filter((s) => s === "serverHold" || s === "clientHold")
  if (holds.length > 0) {
    findings.push({
      id: "infra.hold_status",
      checkId: CHECK_ID,
      title: "Domain is on HOLD (DNS suppressed)",
      severity: "critical",
      detail: `${apex} has ${holds.join(", ")} — the registrar/registry has removed it from DNS. Mail and DNS are down.`,
      remediation:
        "Domain is on HOLD (DNS removed by registrar/registry). Contact your registrar immediately — mail and DNS are down.",
      evidence: holds.join(", "),
    })
  } else {
    findings.push({
      id: "infra.hold_status",
      checkId: CHECK_ID,
      title: "Domain not on hold",
      severity: "ok",
      detail: `${apex} has no serverHold/clientHold status.`,
    })
  }

  // infra.pending_delete — critical: the last window before total loss.
  const lifecycle = reg.statuses.filter((s) => s === "pendingDelete" || s === "redemptionPeriod")
  if (lifecycle.length > 0) {
    findings.push({
      id: "infra.pending_delete",
      checkId: CHECK_ID,
      title: "Domain in redemption/pending-delete",
      severity: "critical",
      detail: `${apex} has ${lifecycle.join(", ")} — this is the last window before total loss of the domain.`,
      remediation: `${apex} is in redemptionPeriod — restore it via your registrar before it drops. This is the last window before total loss.`,
      evidence: lifecycle.join(", "),
    })
  } else {
    findings.push({
      id: "infra.pending_delete",
      checkId: CHECK_ID,
      title: "Domain not pending delete",
      severity: "ok",
      detail: `${apex} is not in pendingDelete/redemptionPeriod.`,
    })
  }

  // infra.recent_transfer — RDAP transfer / last-changed events vs now (< 30 days).
  const transferStr = reg.transfer ?? reg.updated
  const transferred = transferStr ? Date.parse(transferStr) : NaN
  if (Number.isFinite(transferred) && now - transferred < 30 * DAY) {
    findings.push({
      id: "infra.recent_transfer",
      checkId: CHECK_ID,
      title: "Recent registrar/owner change",
      severity: "info",
      detail: `${apex} changed registrar/owner on ${transferStr?.slice(0, 10)} (< 30 days ago); reputation may reset and this can indicate a hijack.`,
      remediation:
        "Verify this registrar/owner change was authorized; reputation may reset — warm up and monitor bounce rates.",
      evidence: transferStr,
    })
  } else {
    findings.push({
      id: "infra.recent_transfer",
      checkId: CHECK_ID,
      title: "No recent transfer",
      severity: "ok",
      detail: `${apex} has no registrar/owner change in the last 30 days.`,
    })
  }

  // infra.dnssec_ds_at_registrar — cross-ref ./dnssec.mdx (the zone-signing side).
  if (reg.dnssecSigned) {
    findings.push({
      id: "infra.dnssec_ds_at_registrar",
      checkId: CHECK_ID,
      title: "DNSSEC signed at registrar",
      severity: "ok",
      detail: `${apex} has a signed delegation (secureDNS.delegationSigned = true).`,
    })
  } else {
    findings.push({
      id: "infra.dnssec_ds_at_registrar",
      checkId: CHECK_ID,
      title: "Delegation unsigned at registrar",
      severity: "info",
      detail: `${apex} has no DS record / signed delegation at the registrar (secureDNS.delegationSigned is not true).`,
      remediation:
        "Publish a DS record at your registrar to complete DNSSEC. See ./dnssec.mdx for the zone-signing side.",
    })
  }

  // infra.registrant_privacy — GDPR redaction counts as privacy present, not missing data.
  if (!reg.privacyEnabled && opts.registrantPublicIntentional) {
    findings.push({
      id: "infra.registrant_privacy",
      checkId: CHECK_ID,
      title: "Registrant intentionally public",
      severity: "ok",
      detail: `${apex} exposes registrant contact data, and the domain is configured as "registrant is intentionally public".`,
    })
  } else if (!reg.privacyEnabled) {
    findings.push({
      id: "infra.registrant_privacy",
      checkId: CHECK_ID,
      title: "Registrant PII exposed",
      severity: "info",
      detail: `${apex} exposes registrant contact data${reg.registrantContact ? ` (${reg.registrantContact})` : ""} in RDAP.`,
      remediation:
        "Enable WHOIS privacy/redaction at your registrar to reduce spear-phishing of the registrant contact, unless public contact is a deliberate policy.",
    })
  } else {
    findings.push({
      id: "infra.registrant_privacy",
      checkId: CHECK_ID,
      title: "Registrant privacy present",
      severity: "ok",
      detail: `${apex} registrant data is redacted/private (GDPR redaction or a privacy service).`,
    })
  }

  // infra.registrar_reputation — IANA id / name matched against the curated watchlist.
  const flagged = opts.registrarWatchlist.find(
    (r) =>
      (r.match_type === "registrar_iana_id" &&
        reg.registrarIanaId !== undefined &&
        String(reg.registrarIanaId) === r.match_value) ||
      (r.match_type === "registrar_name" &&
        reg.registrar?.toLowerCase().includes(r.match_value.toLowerCase())),
  )
  if (flagged) {
    findings.push({
      id: "infra.registrar_reputation",
      checkId: CHECK_ID,
      title: "Registrar flagged for abuse tolerance",
      severity: "info",
      detail: `${apex}'s registrar (${reg.registrar ?? "unknown"}, IANA ${reg.registrarIanaId ?? "?"}) is on the abuse-reputation watchlist${flagged.note ? `: ${flagged.note}` : ""}.`,
      remediation: `Your registrar (IANA ID ${reg.registrarIanaId ?? "?"}) appears on abuse-reputation lists; consider transferring brand-critical mail domains to a reputable registrar.`,
    })
  } else {
    findings.push({
      id: "infra.registrar_reputation",
      checkId: CHECK_ID,
      title: "Registrar not on abuse watchlist",
      severity: "ok",
      detail: `${apex}'s registrar (${reg.registrar ?? "unknown"}, IANA ${reg.registrarIanaId ?? "?"}) is not flagged.`,
    })
  }

  // infra.registrar_abuse_contact — RFC 9083 abuse entity vCard.
  if (reg.abuseContact) {
    findings.push({
      id: "infra.registrar_abuse_contact",
      checkId: CHECK_ID,
      title: "Registrar abuse contact published",
      severity: "ok",
      detail: `Registrar publishes an abuse contact (${reg.abuseContact}).`,
    })
  } else {
    findings.push({
      id: "infra.registrar_abuse_contact",
      checkId: CHECK_ID,
      title: "No registrar abuse contact",
      severity: "info",
      detail: `${apex}'s registrar publishes no abuse contact in RDAP.`,
      remediation:
        "Registrar lacks a published abuse contact — advisory only; relevant for reporting hijacks.",
    })
  }

  // infra.auto_renew — RDAP autoRenewPeriod is partial; registrar-API confirmation is future.
  if (reg.autoRenew === true) {
    findings.push({
      id: "infra.auto_renew",
      checkId: CHECK_ID,
      title: "Auto-renew observed",
      severity: "ok",
      detail: `${apex} shows the EPP autoRenewPeriod status — the registry auto-renewed it. Keep the billing card on file valid.`,
    })
  } else {
    findings.push({
      id: "infra.auto_renew",
      checkId: CHECK_ID,
      title: "Auto-renew not confirmed",
      severity: "info",
      detail:
        "Auto-renew can only be confirmed via a registrar API (a future round); RDAP's autoRenewPeriod is partial and does not prove billing is valid.",
      remediation:
        "Turn on auto-renew and ensure the billing card on file is valid so the domain cannot silently lapse.",
    })
  }

  return findings
}

/** Assemble the persisted §5 snapshot from the parsed record + live NS observation. */
export function buildSnapshot(
  reg: RegData,
  rawRecord: unknown,
  nameservers: string[],
  parkingNs: boolean | null,
  checkedAt: string,
  now = Date.now(),
): DomainRegistrationResults {
  const created = reg.created ? Date.parse(reg.created) : NaN
  const expiry = reg.expiry ? Date.parse(reg.expiry) : NaN
  return {
    registrar: reg.registrar ?? null,
    registrar_iana_id: reg.registrarIanaId ?? null,
    created_date: reg.created?.slice(0, 10) ?? null,
    expiry_date: reg.expiry?.slice(0, 10) ?? null,
    updated_date: reg.updated?.slice(0, 10) ?? null,
    transfer_date: reg.transfer?.slice(0, 10) ?? null,
    statuses: reg.statuses,
    privacy_enabled: reg.privacyEnabled,
    dnssec_at_registrar: reg.dnssecSigned,
    auto_renew: reg.autoRenew,
    parked: null, // HTTP landing-page classification is a future round (spec §7)
    parking_nameservers: parkingNs,
    nameservers,
    age_days: Number.isFinite(created) ? Math.floor((now - created) / DAY) : null,
    days_to_expiry: Number.isFinite(expiry) ? Math.floor((expiry - now) / DAY) : null,
    source: "rdap",
    raw_record: rawRecord,
    checked_at: checkedAt,
  }
}

/** A best-effort read of the previous run's snapshot (`previousResults["infra.domain_reputation"]`). */
function previousSnapshot(previous: unknown): DomainRegistrationResults | null {
  if (typeof previous !== "object" || previous === null) return null
  const snap = previous as Partial<DomainRegistrationResults>
  if (typeof snap.checked_at !== "string" || snap.raw_record == null) return null
  return snap as DomainRegistrationResults
}

// -- The checker ---------------------------------------------------------------

export const domainReputationCheck: Checker = {
  id: "infra.domain_reputation",
  label: "Domain Registration Reputation",
  async run(ctx): Promise<CheckOutcome> {
    const findings: Finding[] = []
    const apex = apexOf(ctx.domain)
    const tld = apex.slice(apex.lastIndexOf(".") + 1)

    // Admin reference lists + budgets (config.yaml → domain_reputation, spec §5) and the
    // per-domain config inputs (brands/thresholds/toggles, spec §4).
    const cfg = readAppConfig().domain_reputation ?? {
      cache_ttl_hours: DEFAULT_CACHE_TTL_HOURS,
      rdap_request_budget: DEFAULT_RDAP_REQUEST_BUDGET,
      parking_nameservers: [],
      high_abuse_tlds: [],
      registrar_reputation: [],
    }
    const per: DomainReputationConfig = ctx.domainReputation ?? { brands: [] }
    const deriveOpts: DeriveOptions = {
      expiryWarnDays: per.expiryWarnDays ?? 30,
      ageWarnDays: per.ageWarnDays ?? 30,
      registrantPublicIntentional: per.registrantPublicIntentional ?? false,
      registrarWatchlist: cfg.registrar_reputation ?? [],
    }
    const budget = { n: cfg.rdap_request_budget || DEFAULT_RDAP_REQUEST_BUDGET }

    // --- Non-RDAP first-round sub-checks (run live every audit, regardless of RDAP/cache) --------

    // infra.idn_homograph — punycode / mixed-script apex.
    const hasPunycode = apex.split(".").some((l) => l.startsWith("xn--"))
    const decoded = domainToUnicode(apex)
    const hasNonAscii = [...decoded].some((ch) => (ch.codePointAt(0) ?? 0) > 127)
    if (hasPunycode || hasNonAscii) {
      findings.push({
        id: "infra.idn_homograph",
        checkId: CHECK_ID,
        title: "IDN / homograph risk",
        severity: "info",
        detail: `${apex} uses internationalized/mixed-script characters (decodes to "${decoded}"). Confusable/homograph domains trigger phishing filters.`,
        remediation:
          "Confirm this internationalized/punycode domain is intentional; homograph domains trigger phishing filters. If unexpected, treat as a possible impersonation domain.",
        evidence: apex,
      })
    } else {
      findings.push({
        id: "infra.idn_homograph",
        checkId: CHECK_ID,
        title: "No IDN/homograph risk",
        severity: "ok",
        detail: `${apex} is plain ASCII with no punycode (xn--) or mixed-script labels.`,
      })
    }

    // infra.name_similarity — lookalike/cousin of a configured brand (Damerau-Levenshtein <= 2).
    const brands = (per.brands ?? []).map((b) => b.toLowerCase()).filter(Boolean)
    const cousin = brands
      .filter((b) => b !== apex)
      .find((b) => damerau(apex.split(".")[0], b.split(".")[0]) <= 2)
    if (cousin) {
      findings.push({
        id: "infra.name_similarity",
        checkId: CHECK_ID,
        title: "Lookalike / cousin-domain risk",
        severity: "info",
        detail: `${apex} is within edit-distance 2 of the configured brand "${cousin}" — a lookalike/cousin that can poison the brand's reputation.`,
        remediation:
          "Register defensive lookalikes or monitor them, and publish DMARC p=reject on the real brand domain so impersonating cousins cannot pass alignment.",
        evidence: `${apex} ~ ${cousin}`,
      })
    } else {
      findings.push({
        id: "infra.name_similarity",
        checkId: CHECK_ID,
        title: "No lookalike-brand risk",
        severity: "ok",
        detail: brands.length
          ? `${apex} is not a close lookalike of any configured brand.`
          : "No brand strings configured for lookalike comparison (domain settings → brand strings).",
      })
    }

    // infra.tld_risk — apex TLD on the high-abuse list (plus any watchlist `tld` rows).
    const highAbuseTlds = new Set([
      ...(cfg.high_abuse_tlds ?? []).map((t) => t.toLowerCase().replace(/^\./, "")),
      ...(cfg.registrar_reputation ?? [])
        .filter((r) => r.match_type === "tld")
        .map((r) => r.match_value.toLowerCase().replace(/^\./, "")),
    ])
    if (highAbuseTlds.has(tld)) {
      findings.push({
        id: "infra.tld_risk",
        checkId: CHECK_ID,
        title: "High-abuse TLD",
        severity: "info",
        detail: `.${tld} has elevated abuse rates (Spamhaus TLD stats); expect stricter receiver filtering for ${apex}.`,
        remediation:
          "No direct fix beyond building strong SPF/DKIM/DMARC and sending history; consider a lower-abuse TLD for brand-critical mail.",
        evidence: `.${tld}`,
      })
    } else {
      findings.push({
        id: "infra.tld_risk",
        checkId: CHECK_ID,
        title: "TLD not high-abuse",
        severity: "ok",
        detail: `.${tld} is not on the high-abuse TLD watchlist.`,
      })
    }

    // infra.parking_nameservers — NS delegated to a known parking provider (config reference list).
    const parkingList = (cfg.parking_nameservers ?? []).map((p) => p.toLowerCase())
    const ns = await resolveNs(apex)
    let parkingNsFlag: boolean | null = null
    if (ns.error) {
      findings.push({
        id: "infra.parking_nameservers",
        checkId: CHECK_ID,
        title: "Could not read nameservers",
        severity: "info",
        detail: `NS lookup for ${apex} failed (${ns.error}); parking-nameserver classification skipped. Retry later.`,
        remediation:
          "Retry the audit; if it persists, verify the domain's authoritative nameservers.",
      })
    } else {
      const parkNs = ns.records.filter((h) =>
        parkingList.some((p) => h.toLowerCase() === p || h.toLowerCase().endsWith(`.${p}`)),
      )
      parkingNsFlag = parkNs.length > 0
      if (parkingNsFlag) {
        findings.push({
          id: "infra.parking_nameservers",
          checkId: CHECK_ID,
          title: "Nameservers point to a parking service",
          severity: "warning",
          detail: `${apex} delegates DNS to a domain-parking provider (${parkNs.join(", ")}). SPF/DKIM/DMARC cannot be authoritative from a parking nameserver.`,
          remediation:
            "Move DNS to your real provider so SPF/DKIM/DMARC are authoritative; parked mail domains raise spam scores.",
          evidence: ns.records.join(", "),
        })
      } else {
        findings.push({
          id: "infra.parking_nameservers",
          checkId: CHECK_ID,
          title: "Nameservers not a parking service",
          severity: "ok",
          detail: `${apex} nameservers are not on the parking-provider list.`,
          evidence: ns.records.join(", "),
        })
      }
    }

    // --- Registration record: long-TTL cache, else RDAP fetch (spec §3/§6, acceptance #10) -------

    // A manual run-now always bypasses the cache; scheduled/API runs within the TTL reuse the
    // previous snapshot's raw_record instead of re-querying RDAP (registration data is
    // stale-tolerant — default 24h vs the 6h DNS cadence).
    const prev = previousSnapshot(
      (ctx.previousResults as Record<string, unknown> | undefined)?.["infra.domain_reputation"],
    )
    const ttlMs = (cfg.cache_ttl_hours || DEFAULT_CACHE_TTL_HOURS) * 60 * 60 * 1000
    const prevAge = prev ? Date.now() - Date.parse(prev.checked_at) : Number.POSITIVE_INFINITY
    const useCache =
      ctx.trigger !== "manual" && prev !== null && Number.isFinite(prevAge) && prevAge < ttlMs

    let rdap: Rdap | null = null
    let checkedAt = new Date().toISOString()
    let cached = false
    if (useCache && prev) {
      rdap = prev.raw_record
      checkedAt = prev.checked_at
      cached = true
    } else {
      const base = await rdapBaseForTld(tld)
      let rdapTransient = false
      if (base) {
        const res = await rdapGet(`${base}/domain/${encodeURIComponent(apex)}`, budget)
        if (res.status === 200 && res.body) {
          try {
            rdap = JSON.parse(res.body)
          } catch {
            rdap = null
          }
        } else if (res.error || res.status === 429 || res.status >= 500 || res.status === 0) {
          rdapTransient = true
        }
        // 404 / other 4xx => genuinely no RDAP record (falls through to record_available warning).
      }
      if (!rdap) {
        if (rdapTransient) {
          findings.push({
            id: "infra.record_available",
            checkId: CHECK_ID,
            title: "Registration lookup temporarily unavailable",
            severity: "info",
            detail: `RDAP for ${apex} was rate-limited or timed out; registration data was not read this run. This is transient.`,
            remediation:
              "Retry the audit later; RDAP endpoints rate-limit aggressively. Results are cached for 24h.",
          })
        } else {
          findings.push({
            id: "infra.record_available",
            checkId: CHECK_ID,
            title: "No registration record obtainable",
            severity: "warning",
            detail: `Could not read RDAP registration data for ${apex} (no IANA bootstrap entry or the registry returned no record). WHOIS fallback is a future round.`,
            remediation: `Could not read registration data for ${apex} (RDAP/WHOIS unavailable). Verify the domain exists and is registered; some ccTLDs restrict lookups.`,
          })
        }
        pushParkedFuture(findings)
        // No registration record this run — nothing to persist (no §5 snapshot row).
        return { findings }
      }
    }

    // --- RDAP-derived sub-checks (identical for the fresh and TTL-cached paths) ------------------

    findings.push({
      id: "infra.record_available",
      checkId: CHECK_ID,
      title: "Registration record read",
      severity: "ok",
      detail: cached
        ? `Reusing the cached RDAP registration snapshot for ${apex} (source=rdap, as of ${checkedAt}; TTL ${cfg.cache_ttl_hours || DEFAULT_CACHE_TTL_HOURS}h — a manual run refreshes it).`
        : `Read RDAP registration data for ${apex} (source=rdap).`,
    })

    const reg = parseRdap(rdap)
    findings.push(...deriveRegistrationFindings(apex, reg, deriveOpts))
    pushParkedFuture(findings)

    const snapshot = buildSnapshot(
      reg,
      rdap,
      ns.error ? (cached ? (prev?.nameservers ?? []) : []) : ns.records,
      parkingNsFlag ?? (cached ? (prev?.parking_nameservers ?? null) : null),
      checkedAt,
    )
    return { findings, results: snapshot }
  },
}

/** The HTTP landing-page parked/for-sale probe is future (spec §7): info-only, never fails. */
function pushParkedFuture(findings: Finding[]): void {
  findings.push({
    id: "infra.parked",
    checkId: CHECK_ID,
    title: "Parked/for-sale landing check pending",
    severity: "info",
    detail:
      "The HTTP(S) landing-page classification (parked / for-sale page) is a future round; a live fetch + content classifier will confirm it.",
    remediation:
      "If the domain serves a parking/for-sale page, point it at real infrastructure; parked mail domains raise spam scores.",
  })
}
