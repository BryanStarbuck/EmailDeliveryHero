import { resolve4, resolveTxt } from "./dns-util"
import type { Checker, Finding } from "./types"

/**
 * Link / URL Reputation (content.url_*). Extracts every link from a sample message, reduces each
 * host to its Public-Suffix registrable domain, and queries URI/RHSBL blocklists (Spamhaus DBL,
 * SURBL multi, URIBL multi) on the *link* domain — the RHSBL half of RFC 5782 (queried directly,
 * with no reversal). It also flags link-hygiene problems (URL shorteners, raw-IP hosts,
 * punycode/homograph hosts, http-not-https links, off-brand links) that filters penalize even when
 * SPF/DKIM/DMARC pass.
 *
 * A message body is required to run. `CheckContext` does not yet plumb a sample through (that store
 * — content_sample_messages — is owned by content_scoring), so this checker reads an OPTIONAL sample
 * off the context (forward-compatible with the runner wiring). With no sample it emits exactly one
 * `info` "add a sample" finding — never a false pass or false listing (spec §3, AC#2).
 *
 * FUTURE (never emit warning/critical here): redirect-chain / reachability (outbound HTTP probe),
 * Google Safe Browsing (API key), and Invaluement ivmURI (paid feed) each degrade to one `info`.
 */

const CHECK_ID = "content"

// ---------------------------------------------------------------------------------------------
// Sample plumbing (optional; widened off ctx until the runner wires content_sample_messages in).
// ---------------------------------------------------------------------------------------------

interface SampleObject {
  html?: string
  text?: string
  raw?: string
  id?: number | string
}
type SampleInput = string | SampleObject

interface SampleBody {
  body: string
  htmlish: boolean
  id?: number | string
}

function readSample(ctx: unknown): SampleBody | null {
  const c = ctx as { sample?: SampleInput; sampleMessage?: SampleInput }
  const raw = c.sample ?? c.sampleMessage
  if (!raw) return null
  if (typeof raw === "string") {
    const body = raw.trim()
    return body ? { body, htmlish: /<[a-z!]/i.test(body) } : null
  }
  const parts = [raw.html, raw.text, raw.raw].filter((p): p is string => typeof p === "string")
  const body = parts.join("\n").trim()
  if (!body) return null
  return { body, htmlish: Boolean(raw.html) || /<[a-z!]/i.test(body), id: raw.id }
}

// ---------------------------------------------------------------------------------------------
// URL extraction + normalization.
// ---------------------------------------------------------------------------------------------

// Common second-level public suffixes so foo.bar.co.uk reduces to bar.co.uk, not co.uk. This is a
// compact first-round stand-in for the full Public Suffix List (bundle+refresh the real PSL later —
// see spec maintenance notes); it covers the overwhelming majority of real-world links.
const MULTI_PART_SUFFIXES = new Set([
  "co.uk",
  "org.uk",
  "gov.uk",
  "ac.uk",
  "me.uk",
  "ltd.uk",
  "plc.uk",
  "net.uk",
  "sch.uk",
  "com.au",
  "net.au",
  "org.au",
  "edu.au",
  "gov.au",
  "id.au",
  "co.jp",
  "or.jp",
  "ne.jp",
  "ac.jp",
  "go.jp",
  "com.br",
  "net.br",
  "org.br",
  "gov.br",
  "co.nz",
  "net.nz",
  "org.nz",
  "govt.nz",
  "co.za",
  "org.za",
  "co.in",
  "net.in",
  "org.in",
  "gen.in",
  "firm.in",
  "co.kr",
  "or.kr",
  "com.sg",
  "com.hk",
  "com.tw",
  "com.mx",
  "com.cn",
  "net.cn",
  "org.cn",
  "gov.cn",
])

// Well-known public URL shorteners that hide (and cannot vouch for) their destination.
const SHORTENERS = new Set([
  "bit.ly",
  "t.co",
  "tinyurl.com",
  "ow.ly",
  "buff.ly",
  "goo.gl",
  "is.gd",
  "rebrand.ly",
  "lnkd.in",
  "t.ly",
  "cutt.ly",
  "rb.gy",
  "shorturl.at",
  "bl.ink",
  "tiny.cc",
  "soo.gd",
  "s.id",
  "trib.al",
  "dlvr.it",
  "shar.es",
  "mcaf.ee",
  "adf.ly",
  "clck.ru",
])

interface LinkUrl {
  url: string
  linkDomain: string
  isHttps: boolean
  isIpLiteral: boolean
  isPunycode: boolean
  isShortener: boolean
}

const ATTR_URL_RE = /(?:href|src|background)\s*=\s*["']?\s*([^"'\s>]+)/gi
const CSS_URL_RE = /url\(\s*['"]?\s*([^'")\s]+)/gi
const TEXT_URL_RE = /\bhttps?:\/\/[^\s"'<>()[\]{}]+/gi

function isIpv4(host: string): boolean {
  const parts = host.split(".")
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)
}

/** PSL-registrable domain of a host: last two labels, or three when the last two are a public suffix. */
function registrableDomain(host: string): string {
  const h = host.replace(/\.+$/, "").toLowerCase()
  const labels = h.split(".").filter(Boolean)
  if (labels.length <= 2) return h
  const lastTwo = labels.slice(-2).join(".")
  if (MULTI_PART_SUFFIXES.has(lastTwo)) return labels.slice(-3).join(".")
  return lastTwo
}

function collectRawUrls(sample: SampleBody): string[] {
  const found = new Set<string>()
  const add = (re: RegExp, body: string) => {
    re.lastIndex = 0
    let m: RegExpExecArray | null
    // biome-ignore lint/suspicious/noAssignInExpressions: standard regex-exec loop
    while ((m = re.exec(body)) !== null) found.add(m[1])
  }
  if (sample.htmlish) {
    add(ATTR_URL_RE, sample.body)
    add(CSS_URL_RE, sample.body)
  }
  add(TEXT_URL_RE, sample.body)
  return [...found]
}

/** Parse one raw URL string into a normalized LinkUrl, or null when it is not a reputation-bearing http(s) URL. */
function parseLink(raw: string): LinkUrl | null {
  const trimmed = raw.trim()
  // Skip non-reputation schemes and fragments/anchors.
  if (/^(mailto:|tel:|data:|cid:|javascript:|#)/i.test(trimmed)) return null
  let parsed: URL
  try {
    parsed = new URL(trimmed)
  } catch {
    return null
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null
  // new URL() lowercases and IDNA-encodes the host; IPv6 hosts come back bracketed.
  const bracketed = parsed.hostname.startsWith("[") && parsed.hostname.endsWith("]")
  const host = bracketed ? parsed.hostname.slice(1, -1) : parsed.hostname
  const isIpLiteral = bracketed || isIpv4(host)
  const linkDomain = isIpLiteral ? host : registrableDomain(host)
  return {
    url: trimmed,
    linkDomain,
    isHttps: parsed.protocol === "https:",
    isIpLiteral,
    isPunycode: !isIpLiteral && /(^|\.)xn--/.test(host),
    isShortener: !isIpLiteral && SHORTENERS.has(linkDomain),
  }
}

// ---------------------------------------------------------------------------------------------
// URI/RHSBL zones and return-code decoding.
// ---------------------------------------------------------------------------------------------

interface Listing {
  zone: string
  code: string
  bit: string
  severity: "warning" | "critical"
}

interface UriZone {
  id: string // finding-id sub-check, e.g. "content.url_dbl"
  zone: string
  name: string
  delistUrl: string
  decode(codes: string[]): Listing | null // null = not listed; returns null for blocked/error codes
}

function lastOctet(code: string): number {
  const parts = code.split(".")
  return parts.length === 4 ? Number(parts[3]) : Number.NaN
}

// Spamhaus DBL: 127.0.1.2-.6 = spam/phish/malware/botnet/abused-spam (critical); 127.0.1.102-.106 =
// abused-legit (warning); 127.255.255.x = error/blocked resolver (not a listing).
const DBL_BITS: Record<number, string> = {
  2: "spam",
  3: "abused-legit-spam",
  4: "phish",
  5: "malware",
  6: "botnet",
}

const dblZone: UriZone = {
  id: "content.url_dbl",
  zone: "dbl.spamhaus.org",
  name: "Spamhaus DBL",
  delistUrl: "https://www.spamhaus.org/dbl/removal/",
  decode(codes) {
    for (const code of codes) {
      const octets = code.split(".").map(Number)
      if (octets.length !== 4 || octets[0] !== 127) continue
      if (octets[1] === 255) return null // 127.255.255.x = query error / blocked resolver
      const n = octets[3]
      if (n >= 2 && n <= 6) {
        return { zone: this.zone, code, bit: DBL_BITS[n] ?? "listed", severity: "critical" }
      }
      if (n >= 102 && n <= 106) {
        return { zone: this.zone, code, bit: "abused-legit", severity: "warning" }
      }
    }
    return null
  },
}

// SURBL multi bitmask (last octet): 0x08 phishing, 0x10 malware (critical); 0x40 abuse, 0x80 cracked (warning).
const surblZone: UriZone = {
  id: "content.url_surbl",
  zone: "multi.surbl.org",
  name: "SURBL multi",
  delistUrl: "https://www.surbl.org/surbl-analysis",
  decode(codes) {
    for (const code of codes) {
      const n = lastOctet(code)
      if (!Number.isFinite(n)) continue
      if (n & 0x08) return { zone: this.zone, code, bit: "phishing", severity: "critical" }
      if (n & 0x10) return { zone: this.zone, code, bit: "malware", severity: "critical" }
      if (n & 0x40) return { zone: this.zone, code, bit: "abuse", severity: "warning" }
      if (n & 0x80) return { zone: this.zone, code, bit: "cracked", severity: "warning" }
    }
    return null
  },
}

// URIBL multi bitmask (last octet): 2 black (critical), 4 grey (warning), 8 red (warning);
// 127.0.0.1 = blocked/blacklisted resolver (not a listing).
const uriblZone: UriZone = {
  id: "content.url_uribl",
  zone: "multi.uribl.com",
  name: "URIBL multi",
  delistUrl: "https://admin.uribl.com/",
  decode(codes) {
    for (const code of codes) {
      const n = lastOctet(code)
      if (!Number.isFinite(n) || n === 1) continue
      if (n & 2) return { zone: this.zone, code, bit: "black", severity: "critical" }
      if (n & 4) return { zone: this.zone, code, bit: "grey", severity: "warning" }
      if (n & 8) return { zone: this.zone, code, bit: "red", severity: "warning" }
    }
    return null
  },
}

const URI_ZONES: UriZone[] = [dblZone, surblZone, uriblZone]

// ---------------------------------------------------------------------------------------------
// The engine.
// ---------------------------------------------------------------------------------------------

function noSampleFinding(): Finding {
  return {
    id: "content.url_extract",
    checkId: CHECK_ID,
    title: "No sample message to check link reputation",
    severity: "info",
    detail:
      "Link/URL reputation needs a message body to inspect. No sample message is attached to this domain, so no links were extracted and no URI blocklists were queried (no false pass).",
    remediation:
      "Add a sample: paste or upload a raw .eml, paste an HTML/text snippet, or send a real campaign to this domain's ingest/seed address, then re-run the audit.",
  }
}

type Severity = Finding["severity"]

const SEVERITY_RANK: Record<Severity, number> = { ok: 0, info: 1, warning: 2, critical: 3 }

/**
 * RFC 5782 test point (once per zone per audit): 2.0.0.127.<zone> must answer 127.0.0.2 and
 * 1.0.0.127.<zone> must be NXDOMAIN. On failure the zone is inconclusive (info), never false-listed.
 */
async function zoneUsable(zone: string): Promise<{ usable: boolean; reason?: string }> {
  const positive = await resolve4(`2.0.0.127.${zone}`)
  if (positive.error) return { usable: false, reason: `test point unreachable (${positive.error})` }
  if (positive.records.length === 0) {
    return { usable: false, reason: "test point 2.0.0.127 not listed (mirror/resolver blocked)" }
  }
  const negative = await resolve4(`1.0.0.127.${zone}`)
  if (negative.records.length > 0) {
    return { usable: false, reason: "test point 1.0.0.127 wrongly listed (resolver intercepting)" }
  }
  return { usable: true }
}

async function analyzeSample(sample: SampleBody, ctx: { domain: string }): Promise<Finding[]> {
  const findings: Finding[] = []
  const orgDomain = registrableDomain(ctx.domain)

  // --- content.url_extract -------------------------------------------------------------------
  const parsed = collectRawUrls(sample)
    .map(parseLink)
    .filter((l): l is LinkUrl => l !== null)
  // Dedupe by url.
  const links = [...new Map(parsed.map((l) => [l.url, l])).values()]
  const linkDomains = [...new Set(links.filter((l) => !l.isIpLiteral).map((l) => l.linkDomain))]

  if (links.length === 0) {
    findings.push({
      id: "content.url_extract",
      checkId: CHECK_ID,
      title: sample.htmlish ? "HTML message has no parseable links" : "No links in sample",
      severity: sample.htmlish ? "warning" : "info",
      detail: sample.htmlish
        ? "The sample is HTML but no parseable links were found. If links are present but malformed, receivers cannot resolve them either."
        : "No http(s) links were found in the sample; nothing to check against URI blocklists.",
      remediation: sample.htmlish
        ? "Fix malformed href/encoded URLs so links parse (and so receivers can follow them)."
        : undefined,
    })
  } else {
    findings.push({
      id: "content.url_extract",
      checkId: CHECK_ID,
      title: `${linkDomains.length} unique link domain(s) found`,
      severity: "info",
      detail: `Extracted ${links.length} link(s) reducing to ${linkDomains.length} unique registrable domain(s).`,
      evidence: linkDomains.join(", ") || links.map((l) => l.url).join(", "),
    })
  }

  // --- Hygiene flags (content.url_https / _ip_literal / _punycode / _shortener) ---------------
  const httpLinks = links.filter((l) => !l.isHttps)
  if (httpLinks.length > 0) {
    findings.push({
      id: "content.url_https",
      checkId: CHECK_ID,
      title: `${httpLinks.length} link(s) use http:// (not https)`,
      severity: "warning",
      detail:
        "One or more links use http://, an interception/downgrade risk and a classic phishing signal that raises spam score.",
      remediation:
        "Change these links to https:// and ensure the landing site has a valid TLS certificate so https does not break.",
      evidence: httpLinks.map((l) => l.url).join(", "),
    })
  } else if (links.length > 0) {
    findings.push({
      id: "content.url_https",
      checkId: CHECK_ID,
      title: "All links use https",
      severity: "ok",
      detail: `All ${links.length} link(s) use https.`,
    })
  }

  const ipLinks = links.filter((l) => l.isIpLiteral)
  if (ipLinks.length > 0) {
    findings.push({
      id: "content.url_ip_literal",
      checkId: CHECK_ID,
      title: `${ipLinks.length} link(s) use a raw IP host`,
      severity: "critical",
      detail:
        "One or more links use a raw IP-literal host (e.g. http://203.0.113.9/...). This is a strong phishing/malware signal and a near-guaranteed spam-score hit.",
      remediation:
        "Replace the IP-literal with a proper hostname on an authenticated domain you control.",
      evidence: ipLinks.map((l) => l.url).join(", "),
    })
  } else if (links.length > 0) {
    findings.push({
      id: "content.url_ip_literal",
      checkId: CHECK_ID,
      title: "No raw-IP links",
      severity: "ok",
      detail: "No link uses a raw IP-literal host.",
    })
  }

  const punyLinks = links.filter((l) => l.isPunycode)
  if (punyLinks.length > 0) {
    findings.push({
      id: "content.url_punycode",
      checkId: CHECK_ID,
      title: `${punyLinks.length} punycode/IDN link host(s)`,
      severity: "warning",
      detail:
        "One or more link hosts are punycode (xn-- labels), a common homograph/lookalike phishing technique.",
      remediation:
        "Use the real ASCII domain. If the IDN is intentional and legitimate, confirm it is not a lookalike of a protected brand.",
      evidence: punyLinks.map((l) => l.url).join(", "),
    })
  }

  const shortenerLinks = links.filter((l) => l.isShortener)
  if (shortenerLinks.length > 0) {
    const domains = [...new Set(shortenerLinks.map((l) => l.linkDomain))]
    findings.push({
      id: "content.url_shortener",
      checkId: CHECK_ID,
      title: `${shortenerLinks.length} link(s) go through a URL shortener`,
      severity: "warning",
      detail: `Message routes recipients through public shortener(s) (${domains.join(", ")}) that hide — and cannot vouch for — the true destination; filters penalize this on principle.`,
      remediation:
        "Replace shortener links with the full destination URL, or use a branded/custom-domain shortener you authenticate; the true final domain will then be re-checked (content.url_redirect_chain, future-round).",
      evidence: shortenerLinks.map((l) => l.url).join(", "),
    })
  }

  // --- content.url_domain_alignment (advisory) ------------------------------------------------
  if (linkDomains.length > 0) {
    const offBrand = linkDomains.filter(
      (d) => d !== orgDomain && !d.endsWith(`.${orgDomain}`) && !orgDomain.endsWith(`.${d}`),
    )
    if (offBrand.length > linkDomains.length / 2) {
      findings.push({
        id: "content.url_domain_alignment",
        checkId: CHECK_ID,
        title: `${offBrand.length}/${linkDomains.length} link domains are off-brand`,
        severity: "warning",
        detail: `Most links point at domains unrelated to ${orgDomain}, which looks forwarded/spoofed to filters.`,
        remediation:
          "Link primarily to your own authenticated domains; register tracking/click domains under your org and align them (see content_scoring).",
        evidence: offBrand.join(", "),
      })
    } else {
      findings.push({
        id: "content.url_domain_alignment",
        checkId: CHECK_ID,
        title: "Links are mostly on-brand",
        severity: "info",
        detail: `${linkDomains.length - offBrand.length}/${linkDomains.length} link domains align with ${orgDomain}.`,
      })
    }
  }

  // --- content.url_count ----------------------------------------------------------------------
  if (links.length > 25 || linkDomains.length > 15) {
    findings.push({
      id: "content.url_count",
      checkId: CHECK_ID,
      title: "Link volume looks spam-shaped",
      severity: "warning",
      detail: `Message has ${links.length} links across ${linkDomains.length} distinct domains; high link counts and many off-domain hosts correlate with spam.`,
      remediation:
        "Reduce the link count, consolidate to your own domain, and balance text vs. links.",
    })
  }

  // --- RHSBL / URI zones (content.url_dbl / _surbl / _uribl; content.url_dnsbl_cross covered here) ---
  const usable = new Map<string, { usable: boolean; reason?: string }>()
  for (const z of URI_ZONES) usable.set(z.zone, await zoneUsable(z.zone))
  for (const z of URI_ZONES) {
    const u = usable.get(z.zone)
    if (u && !u.usable) {
      findings.push({
        id: `${z.id}.inconclusive`,
        checkId: CHECK_ID,
        title: `${z.name} unavailable this run`,
        severity: "info",
        detail: `${z.name} (${z.zone}) failed its RFC 5782 test point (${u.reason}); its results are inconclusive, not treated as clean or listed.`,
        remediation: `Query ${z.name} from a dedicated non-public resolver (public resolvers like 8.8.8.8/1.1.1.1 and high-volume clients are blocked) or register/license access, then re-run.`,
      })
    }
  }

  let anyListed = false
  let transient = false
  for (const domain of linkDomains) {
    for (const z of URI_ZONES) {
      if (!usable.get(z.zone)?.usable) continue
      const query = `${domain}.${z.zone}`
      const a = await resolve4(query)
      if (a.error) {
        transient = true
        continue
      }
      if (a.records.length === 0) continue // NXDOMAIN / no data = not listed
      const listing = z.decode(a.records)
      if (!listing) continue // blocked/error return code, not a real listing
      anyListed = true
      const txt = await resolveTxt(query)
      findings.push({
        id: `${z.id}:${domain}`,
        checkId: CHECK_ID,
        title: `Linked domain ${domain} is listed on ${z.name} (${listing.bit})`,
        severity: listing.severity,
        detail: `The link domain ${domain} is on ${z.name} (${z.zone} returned ${listing.code} = ${listing.bit}). Filters (SpamAssassin URIBL_*, Rspamd SURBL_*/DBL, commercial gateways) weight body-URL reputation heavily, so this can spam-file the whole message even with perfect SPF/DKIM/DMARC.`,
        remediation: `Stop linking ${domain}. If it is yours, secure the compromised site/shortener first, then request removal at ${z.delistUrl} (return code ${listing.code} = ${listing.bit}).`,
        evidence: txt.records.length > 0 ? `${query} TXT: ${txt.records.join(" | ")}` : query,
      })
    }
  }

  if (linkDomains.length > 0 && URI_ZONES.some((z) => usable.get(z.zone)?.usable)) {
    if (!anyListed) {
      findings.push({
        id: "content.url_reputation.clean",
        checkId: CHECK_ID,
        title: "All link domains clean on checked URI blocklists",
        severity: "ok",
        detail: `Checked ${linkDomains.length} link domain(s) against Spamhaus DBL, SURBL, and URIBL — none listed.`,
        evidence: linkDomains.join(", "),
      })
    }
    if (transient) {
      findings.push({
        id: "content.url_reputation.transient",
        checkId: CHECK_ID,
        title: "Some URI-zone lookups failed transiently",
        severity: "info",
        detail:
          "One or more URI-blocklist lookups returned SERVFAIL/timeout; those domains were not conclusively cleared.",
        remediation: "Retry the audit later; if it persists, use a dedicated non-public resolver.",
      })
    }
  }

  // --- FUTURE sub-checks: one info each, never warning/critical (spec §7, AC#8) ----------------
  findings.push({
    id: "content.url_ivmuri",
    checkId: CHECK_ID,
    title: "Invaluement ivmURI check pending (paid feed)",
    severity: "info",
    detail:
      "ivmURI (uri.invaluement.com) requires a paid subscription and a licensed resolver, so link domains were not checked against it this round.",
    remediation:
      "Once licensed, listed domains are removed via https://www.invaluement.com/lookup/ — configure the ivmURI resolver/key to enable this check.",
  })
  findings.push({
    id: "content.url_redirect_chain",
    checkId: CHECK_ID,
    title: "Redirect-chain expansion disabled (first round)",
    severity: "info",
    detail:
      "Following shortener/redirect hops to reveal the true final domain needs an outbound HTTP probe (bounded hops + timeout, no cookies/JS), which is off in the first round; final_domain is null and shortener destinations were not expanded.",
    remediation:
      "Enable the bounded redirect probe to expand shorteners and re-check the final landing domain against the URI zones.",
  })
  findings.push({
    id: "content.url_reachable",
    checkId: CHECK_ID,
    title: "Link reachability check disabled (first round)",
    severity: "info",
    detail:
      "Classifying dead/parked/NXDOMAIN destinations needs an outbound HTTP HEAD probe, off in the first round.",
    remediation:
      "Enable the reachability probe to flag broken/parked links that hurt engagement and look spammy.",
  })
  findings.push({
    id: "content.url_safe_browsing",
    checkId: CHECK_ID,
    title: "Google Safe Browsing check pending (API key required)",
    severity: "info",
    detail:
      "Checking link/final domains against Google Safe Browsing (malware/phishing/unwanted) needs a Safe Browsing API key, which is not configured.",
    remediation:
      "Add a Google Safe Browsing API key (secrets.safe_browsing_key) to enable phishing/malware screening of body links.",
  })

  // --- content.url_aggregate: worst weighted severity roll-up ---------------------------------
  let worst: Severity = "ok"
  for (const f of findings) {
    if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) worst = f.severity
  }
  // Advisory info alone must not turn the Spam & Content cell amber (spec §3 severity mapping).
  const aggregateSeverity: Severity = worst === "critical" || worst === "warning" ? worst : "ok"
  findings.push({
    id: "content.url_aggregate",
    checkId: CHECK_ID,
    title:
      aggregateSeverity === "ok"
        ? "Link/URL reputation clean"
        : `Link/URL reputation: ${aggregateSeverity} issue(s) found`,
    severity: aggregateSeverity,
    detail:
      aggregateSeverity === "ok"
        ? "No URI listing, raw-IP, homograph, shortener, http, or alignment problem fired for this sample."
        : "One or more link/URL problems fired; fix the highest-weight listing/link first (each finding above carries its delisting URL or exact hygiene edit).",
    remediation:
      aggregateSeverity === "ok"
        ? undefined
        : "Work the prioritized list above: resolve any critical URI listing / raw-IP / homograph link first, then shortener/http/alignment warnings.",
  })

  return findings
}

export const linkUrlReputationCheck: Checker = {
  id: "content.link_url",
  label: "Link / URL Reputation",
  async run(ctx): Promise<Finding[]> {
    try {
      const sample = readSample(ctx)
      if (!sample) return [noSampleFinding()]
      return await analyzeSample(sample, ctx)
    } catch (err) {
      // Never throw out of run(): degrade to a retryable info finding.
      const msg = err instanceof Error ? err.message : String(err)
      return [
        {
          id: "content.url_extract",
          checkId: CHECK_ID,
          title: "Link/URL reputation check could not complete",
          severity: "info",
          detail: `The link/URL reputation check hit an unexpected error (${msg}).`,
          remediation: "Retry the audit; if it persists, verify the sample message and resolver.",
        },
      ]
    }
  },
}
