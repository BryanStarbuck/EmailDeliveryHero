import { request as httpsRequest } from "node:https"
import { domainToUnicode } from "node:url"
import { resolveNs } from "../dns-util"
import type { Checker, Finding } from "../types"

/**
 * Domain Registration Reputation (WHOIS/RDAP). Reads each sending domain's registration record via
 * RDAP-over-HTTPS (RFC 9082/9083, IANA bootstrap RFC 7484) and reports registration age, expiry
 * runway, EPP transfer/delete/update locks, hold/pending-delete lifecycle states, DNSSEC delegation
 * at the registrar, registrant privacy, parking-nameserver delegation, registrar/TLD reputation,
 * recent-transfer (possible hijack), and IDN/homograph risk.
 *
 * All findings share checkId "infra" (sub-family domain-reputation). First-round sub-checks are pure
 * RDAP-JSON parsing + local reference-list / string analysis. WHOIS fallback, the HTTP landing-page
 * "parked" probe, and registrar-API auto-renew confirmation are future — emitted only as info.
 */

const CHECK_ID = "infra"
const RDAP_REQUEST_BUDGET = 5 // hard cap on RDAP HTTP requests per run (rate-limit protection)
const HTTP_TIMEOUT_MS = 6000

// Reference lists (config.yaml domain_reputation.* in production; inlined here, admin-editable later).
const PARKING_NAMESERVERS = [
  "sedoparking.com",
  "bodis.com",
  "above.com",
  "parkingcrew.net",
  "dan.com",
  "afternic.com",
  "cashparking.com",
  "hugedomains.com",
  "sedo.com",
  "parklogic.com",
  "namedrive.com",
  "voodoo.com",
]
const HIGH_ABUSE_TLDS = new Set([
  "top",
  "xyz",
  "click",
  "link",
  "work",
  "gq",
  "ml",
  "cf",
  "ga",
  "tk",
  "zip",
  "mov",
  "rest",
  "cyou",
  "sbs",
  "icu",
  "buzz",
])
// Advisory registrar-abuse watchlist. match by IANA id or case-insensitive name substring.
const REGISTRAR_REPUTATION: { type: "iana_id" | "name"; value: string; note: string }[] = []
// Per-domain brand strings for lookalike comparison (wired from domain settings in production).
const BRANDS: string[] = []

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
const DAY = 86_400_000

/** Strip subdomains down to the registrable apex (best-effort, small multi-label-suffix table). */
function apexOf(domain: string): string {
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

/** Resolve the RDAP base URL for a TLD from the IANA bootstrap file (RFC 7484). */
async function rdapBaseForTld(tld: string, budget: { n: number }): Promise<string | null> {
  if (budget.n <= 0) return null
  budget.n--
  const res = await httpGet("https://data.iana.org/rdap/dns.json", { Accept: "application/json" })
  if (res.status !== 200) return null
  try {
    const services = (JSON.parse(res.body).services ?? []) as [string[], string[]][]
    for (const [tlds, urls] of services) {
      if (tlds.map((t) => t.toLowerCase()).includes(tld)) {
        const base = urls.find((u) => u.startsWith("https://")) ?? urls[0]
        return base ? base.replace(/\/$/, "") : null
      }
    }
  } catch {
    return null
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
function normStatus(s: string): string {
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
function damerau(a: string, b: string): number {
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

// -- The checker ---------------------------------------------------------------

export const domainReputationCheck: Checker = {
  id: "infra.domain_reputation",
  label: "Domain Registration Reputation",
  async run(ctx): Promise<Finding[]> {
    const findings: Finding[] = []
    const apex = apexOf(ctx.domain)
    const tld = apex.slice(apex.lastIndexOf(".") + 1)
    const budget = { n: RDAP_REQUEST_BUDGET }

    // --- Non-RDAP first-round sub-checks (run regardless of RDAP availability) -------------------

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
    const cousin = BRANDS.map((b) => b.toLowerCase())
      .filter((b) => b && b !== apex)
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
        detail: BRANDS.length
          ? `${apex} is not a close lookalike of any configured brand.`
          : "No brand strings configured for lookalike comparison.",
      })
    }

    // infra.tld_risk — apex TLD on the high-abuse list.
    if (HIGH_ABUSE_TLDS.has(tld)) {
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

    // infra.parking_nameservers — NS delegated to a known parking provider.
    const ns = await resolveNs(apex)
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
        PARKING_NAMESERVERS.some((p) => h.toLowerCase() === p || h.toLowerCase().endsWith(`.${p}`)),
      )
      if (parkNs.length > 0) {
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

    // --- RDAP fetch --------------------------------------------------------------------------------

    const base = await rdapBaseForTld(tld, budget)
    let rdap: Rdap | null = null
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
      pushFutureInfo(findings)
      return findings
    }

    // --- RDAP-derived first-round sub-checks -------------------------------------------------------

    findings.push({
      id: "infra.record_available",
      checkId: CHECK_ID,
      title: "Registration record read",
      severity: "ok",
      detail: `Read RDAP registration data for ${apex} (source=rdap).`,
    })

    const events: Rdap[] = Array.isArray(rdap.events) ? rdap.events : []
    const statuses: string[] = (Array.isArray(rdap.status) ? rdap.status : []).map((s: string) =>
      normStatus(s),
    )
    const statusSet = new Set(statuses)
    const now = Date.now()

    // infra.domain_expiry
    const expiryStr = eventDate(events, "expiration")
    const expiry = expiryStr ? Date.parse(expiryStr) : NaN
    if (Number.isFinite(expiry)) {
      const days = Math.floor((expiry - now) / DAY)
      const dateOnly = expiryStr?.slice(0, 10)
      if (days < 0) {
        findings.push({
          id: "infra.domain_expiry",
          checkId: CHECK_ID,
          title: "Domain has expired",
          severity: "critical",
          detail: `${apex} expired on ${dateOnly} (${-days} days ago). All mail stops when the domain lapses — SPF/DKIM/DMARC/MX all disappear.`,
          remediation: `Renew ${apex} now at your registrar (expiry ${dateOnly}). All mail stops if the domain lapses.`,
          evidence: expiryStr,
        })
      } else if (days < 30) {
        findings.push({
          id: "infra.domain_expiry",
          checkId: CHECK_ID,
          title: "Domain expires soon",
          severity: "warning",
          detail: `${apex} expires on ${dateOnly} (in ${days} days). A silent lapse takes down all mail at once.`,
          remediation: `Renew ${apex} now at your registrar (current expiry ${dateOnly}). All mail stops if the domain lapses.`,
          evidence: expiryStr,
        })
      } else {
        findings.push({
          id: "infra.domain_expiry",
          checkId: CHECK_ID,
          title: "Domain not expiring soon",
          severity: "ok",
          detail: `${apex} expires ${dateOnly} (in ${days} days).`,
          evidence: expiryStr,
        })
      }
    }

    // infra.domain_age
    const createdStr = eventDate(events, "registration")
    const created = createdStr ? Date.parse(createdStr) : NaN
    if (Number.isFinite(created)) {
      const ageDays = Math.floor((now - created) / DAY)
      const dateOnly = createdStr?.slice(0, 10)
      if (ageDays < 30) {
        findings.push({
          id: "infra.domain_age",
          checkId: CHECK_ID,
          title: "Domain is newly registered",
          severity: "warning",
          detail: `${apex} was registered ${ageDays} days ago (${dateOnly}). New domains have no sending history and are treated as high-risk.`,
          remediation: `${apex} was registered ${ageDays} days ago; warm up sending slowly and expect throttling until ~30-day age. If unexpected, verify no one hijacked/re-registered the name.`,
          evidence: createdStr,
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
          evidence: createdStr,
        })
      } else {
        findings.push({
          id: "infra.domain_age",
          checkId: CHECK_ID,
          title: "Domain has sending-age history",
          severity: "ok",
          detail: `${apex} is ${ageDays} days old (registered ${dateOnly}).`,
          evidence: createdStr,
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
        evidence: statuses.join(", "),
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

    // infra.hold_status
    const holds = statuses.filter((s) => s === "serverHold" || s === "clientHold")
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

    // infra.pending_delete
    const lifecycle = statuses.filter((s) => s === "pendingDelete" || s === "redemptionPeriod")
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

    // infra.recent_transfer
    const transferStr = eventDate(events, "transfer") ?? eventDate(events, "last changed")
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

    // infra.dnssec_ds_at_registrar
    const delegationSigned = rdap.secureDNS?.delegationSigned === true
    if (delegationSigned) {
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

    // infra.registrant_privacy
    const registrant = findEntity(rdap.entities, "registrant")
    const registrantName = registrant ? vcardField(registrant, "fn") : undefined
    const registrantEmail = registrant ? vcardField(registrant, "email") : undefined
    const redactedTop = Array.isArray(rdap.redacted) && rdap.redacted.length > 0
    const piiExposed = !redactedTop && (Boolean(registrantEmail) || Boolean(registrantName))
    if (piiExposed) {
      findings.push({
        id: "infra.registrant_privacy",
        checkId: CHECK_ID,
        title: "Registrant PII exposed",
        severity: "info",
        detail: `${apex} exposes registrant contact data (${registrantName ?? registrantEmail}) in RDAP.`,
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

    // infra.registrar_reputation + infra.registrar_abuse_contact
    const registrar = findEntity(rdap.entities, "registrar")
    const registrarName = registrar ? vcardField(registrar, "fn") : undefined
    const registrarIana = registrar ? ianaId(registrar) : undefined
    const flagged = REGISTRAR_REPUTATION.find(
      (r) =>
        (r.type === "iana_id" &&
          registrarIana !== undefined &&
          String(registrarIana) === r.value) ||
        (r.type === "name" && registrarName?.toLowerCase().includes(r.value.toLowerCase())),
    )
    if (flagged) {
      findings.push({
        id: "infra.registrar_reputation",
        checkId: CHECK_ID,
        title: "Registrar flagged for abuse tolerance",
        severity: "info",
        detail: `${apex}'s registrar (${registrarName ?? "unknown"}, IANA ${registrarIana ?? "?"}) is on the abuse-reputation watchlist: ${flagged.note}.`,
        remediation: `Your registrar (IANA ID ${registrarIana ?? "?"}) appears on abuse-reputation lists; consider transferring brand-critical mail domains to a reputable registrar.`,
      })
    } else {
      findings.push({
        id: "infra.registrar_reputation",
        checkId: CHECK_ID,
        title: "Registrar not on abuse watchlist",
        severity: "ok",
        detail: `${apex}'s registrar (${registrarName ?? "unknown"}, IANA ${registrarIana ?? "?"}) is not flagged.`,
      })
    }

    const abuse = findEntity(rdap.entities, "abuse")
    const abuseEmail = abuse ? vcardField(abuse, "email") : undefined
    const abuseTel = abuse ? vcardField(abuse, "tel") : undefined
    if (abuseEmail || abuseTel) {
      findings.push({
        id: "infra.registrar_abuse_contact",
        checkId: CHECK_ID,
        title: "Registrar abuse contact published",
        severity: "ok",
        detail: `Registrar publishes an abuse contact (${abuseEmail ?? abuseTel}).`,
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

    pushFutureInfo(findings)
    return findings
  },
}

/** Future sub-checks (registrar-API auto-renew, HTTP landing-page parked probe): info-only, never fail. */
function pushFutureInfo(findings: Finding[]): void {
  findings.push({
    id: "infra.auto_renew",
    checkId: CHECK_ID,
    title: "Auto-renew not yet confirmed",
    severity: "info",
    detail:
      "Auto-renew can only be confirmed via a registrar API (a future round); RDAP's autoRenewPeriod is partial and does not prove billing is valid.",
    remediation:
      "Turn on auto-renew and ensure the billing card on file is valid so the domain cannot silently lapse.",
  })
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
