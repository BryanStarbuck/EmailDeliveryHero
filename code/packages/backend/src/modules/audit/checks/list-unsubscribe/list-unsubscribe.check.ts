import { request as httpsRequest } from "node:https"
import type { TLSSocket } from "node:tls"
import { withResource } from "@shared/concurrency"
import { readAppConfig } from "@shared/config-store"
import { getActiveSample, readSampleRaw } from "../content-scoring/sample-store"
import type { LinkUrlResults } from "../link-url-reputation/link-url-reputation.check"
import { DEFAULT_SHORTENERS, registrableDomain } from "../link-url-reputation/url-extract"
import type { Checker, CheckOutcome, Finding, Severity } from "../types"

/**
 * List-Unsubscribe (RFC 2369) & one-click unsubscribe (RFC 8058) — pm/checks/list_unsubscribe.mdx.
 *
 * Since Feb 2024 Gmail and Yahoo require every bulk sender (> 5,000 msgs/day) to ship a working
 * `List-Unsubscribe-Post: List-Unsubscribe=One-Click` header alongside an https unsubscribe URI,
 * offer a body unsubscribe link, and honor requests within 2 days. This checker parses the domain's
 * captured sample message (the shared `content_sample_messages` store owned by content_scoring)
 * and audits the whole list-management family: header presence/one-click/https/mailto/syntax,
 * From-domain SPF/DKIM alignment (relaxed, org-domain), precedence & priority hygiene, List-Id,
 * cross-header brand consistency, the per-recipient-token heuristic, and — opt-in per domain
 * (`probeUnsubEndpoint`, default off) and globally permitted (`config.yaml →
 * checks.listUnsub.probeAllowed`) — a live RFC 8058 §3.2 one-click POST probe of the https
 * endpoint plus the §4 GET-safety probe and TLS validity.
 *
 * Severity policy (spec §3): the bulk-sender flag (`isBulkSender`, per-domain) escalates the
 * one-click / https / missing-header gaps from warning to critical. With no sample the checker
 * emits exactly one `info` advisory and never a false critical (§8 AC 1). The probe issues at most
 * ONE unsubscribe POST per endpoint per audit and is throttled to the probe cadence
 * (`probeCadenceHours`, default 24h) across runs (§6, AC 10) — a throttled run carries the
 * previous probe observation forward instead of re-POSTing.
 *
 * The structured payload lands at `results["content.list_unsubscribe"]` — the audit-JSON
 * `results.content.listUnsubscribe` observation of spec §5, mapping 1:1 onto the future
 * `list_unsub_check_results` row (AC 12).
 */

/** All findings share the checker id so the run-detail List-management sub-group can gather them. */
const CHECK_ID = "content.list_unsubscribe"

/** Fallback defaults mirroring config.yaml → checks.listUnsub (pm/checks/list_unsubscribe.mdx §4). */
const DEFAULT_PROBE_TIMEOUT_MS = 5000
const DEFAULT_PROBE_CADENCE_HOURS = 24
const DEFAULT_BULK_THRESHOLD_PER_DAY = 5000

/** Cap how much of a GET confirmation page we read while looking for "you are unsubscribed". */
const GET_BODY_CAP_BYTES = 64 * 1024

/** The descriptive probe User-Agent (spec §3 "a descriptive User-Agent"). */
const PROBE_USER_AGENT =
  "EmailDeliveryHero/1 (list-unsubscribe audit; +https://github.com/BryanStarbuck/EmailDeliveryHero)"

// ─────────────────────────────────────────────────────────────────────────────
// Structured results payload — spec §5 `results.content.listUnsubscribe` (camelCase JSON example).
// ─────────────────────────────────────────────────────────────────────────────

/** The raw header lines the §4 "Sample headers" disclosure shows verbatim. */
export interface ListUnsubRawHeaders {
  listUnsubscribe: string | null
  listUnsubscribePost: string | null
  from: string | null
  returnPath: string | null
  dkimSignature: string | null
  precedence: string | null
  autoSubmitted: string | null
  xPriority: string | null
  priority: string | null
  importance: string | null
  listId: string | null
}

/**
 * One audit run's parsed list-management observation — the `list_unsub_check_results` row of spec
 * §5 in its file-store (camelCase) shape. `endpointOk`/`endpointStatus`/`getSafe`/`tlsValid` stay
 * null until the opt-in endpoint probe runs; `probedAt` powers the §6 probe-cadence throttle.
 */
export interface ListUnsubResults {
  sampleId: string | null
  hasHeader: boolean
  hasOneclick: boolean
  hasHttps: boolean
  hasMailto: boolean
  httpsUri: string | null
  mailtoUri: string | null
  endpointOk: boolean | null
  endpointStatus: number | null
  getSafe: boolean | null
  tlsValid: boolean | null
  fromAligned: boolean
  fromSpfAligned: boolean
  fromDkimAligned: boolean
  precedenceBulk: boolean
  priorityAbuse: boolean
  listId: string | null
  isBulkSender: boolean
  checkedAt: string
  /** When the one-click POST probe last actually fired (null = never) — drives the §6 throttle. */
  probedAt: string | null
  /** POST round-trip latency in ms (§4 "Endpoint probe" panel); null = not probed. */
  probeLatencyMs: number | null
  /** RFC 2369 grammar verdict backing content.list_unsub_syntax. */
  syntaxOk: boolean
  /** The §4 "Sample headers" disclosure content — the raw header values verbatim. */
  rawHeaders: ListUnsubRawHeaders
}

// ─────────────────────────────────────────────────────────────────────────────
// RFC 5322 header parsing (unfolding continuation lines into a case-insensitive multimap).
// ─────────────────────────────────────────────────────────────────────────────

export interface ParsedHeader {
  name: string
  value: string
}

/** Parse the raw message's header block (ends at the first blank line), unfolding folded lines. */
export function parseHeaderBlock(raw: string): ParsedHeader[] {
  const block = raw.split(/\r?\n\r?\n/, 1)[0] ?? ""
  const lines = block.split(/\r?\n/)
  const headers: ParsedHeader[] = []
  for (const line of lines) {
    if (/^[ \t]/.test(line)) {
      // RFC 5322 folding: a continuation line belongs to the previous header.
      if (headers.length > 0) headers[headers.length - 1].value += ` ${line.trim()}`
      continue
    }
    const idx = line.indexOf(":")
    if (idx <= 0) continue
    headers.push({ name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() })
  }
  return headers
}

function firstHeader(headers: ParsedHeader[], name: string): string | null {
  const lower = name.toLowerCase()
  return headers.find((h) => h.name.toLowerCase() === lower)?.value ?? null
}

function allHeaders(headers: ParsedHeader[], name: string): string[] {
  const lower = name.toLowerCase()
  return headers.filter((h) => h.name.toLowerCase() === lower).map((h) => h.value)
}

// ─────────────────────────────────────────────────────────────────────────────
// List-Unsubscribe grammar (RFC 2369): angle-bracketed URIs, comma-separated at top level.
// ─────────────────────────────────────────────────────────────────────────────

export interface ListUnsubParse {
  /** Every https URI in header order. */
  httpsUris: string[]
  /** Every mailto URI in header order. */
  mailtoUris: string[]
  /** Insecure http: URIs (warning — one-click needs https). */
  httpUris: string[]
  /** RFC 2369 grammar violations, each a human-readable description. */
  syntaxIssues: string[]
}

/** Split a List-Unsubscribe value on TOP-LEVEL commas (commas inside `<...>` don't split). */
export function splitTopLevelCommas(value: string): string[] {
  const tokens: string[] = []
  let depth = 0
  let current = ""
  for (const ch of value) {
    if (ch === "<") depth++
    else if (ch === ">") depth = Math.max(0, depth - 1)
    if (ch === "," && depth === 0) {
      tokens.push(current.trim())
      current = ""
    } else {
      current += ch
    }
  }
  if (current.trim() !== "") tokens.push(current.trim())
  return tokens.filter((t) => t !== "")
}

/** Unrendered template/merge tags an ESP left in the header ({{x}}, *|X|*, %%x%%, [[x]]). */
const MERGE_TAG_RE = /\{\{[^{}]*\}\}|\*\|[^|]+\|\*|%%[^%]+%%|\[\[[^\]]+\]\]/

/** Parse one List-Unsubscribe header value into its URI methods + grammar issues (spec §3). */
export function parseListUnsubscribe(value: string): ListUnsubParse {
  const parse: ListUnsubParse = { httpsUris: [], mailtoUris: [], httpUris: [], syntaxIssues: [] }
  if (MERGE_TAG_RE.test(value)) {
    parse.syntaxIssues.push(
      `unrendered merge tag left in the header (${value.match(MERGE_TAG_RE)?.[0]}) — providers ignore the whole header`,
    )
  }
  const tokens = splitTopLevelCommas(value)
  if (tokens.length === 0) parse.syntaxIssues.push("header is present but empty")
  for (const token of tokens) {
    const bracketed = token.match(/^<([^<>]*)>$/)
    if (!bracketed) {
      parse.syntaxIssues.push(
        `"${token}" is not wrapped in angle brackets — RFC 2369 requires <...> around every URI`,
      )
      continue
    }
    const uri = bracketed[1].trim()
    if (uri === "") {
      parse.syntaxIssues.push("empty <> URI token")
      continue
    }
    const scheme = uri.match(/^([a-z][a-z0-9+.-]*):/i)?.[1]?.toLowerCase() ?? null
    if (scheme === "https") {
      try {
        // Validate URL grammar; merge tags in braces are tolerated by new URL(), caught above.
        new URL(uri)
        parse.httpsUris.push(uri)
      } catch {
        parse.syntaxIssues.push(`"${uri}" is not a valid https URL`)
      }
    } else if (scheme === "http") {
      parse.httpUris.push(uri)
    } else if (scheme === "mailto") {
      const addr = uri.slice("mailto:".length).split("?", 1)[0]
      if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(addr)) parse.mailtoUris.push(uri)
      else parse.syntaxIssues.push(`"${uri}" is not a valid mailto: address`)
    } else if (scheme === null) {
      parse.syntaxIssues.push(`"${uri}" has no URI scheme (expected https: or mailto:)`)
    } else {
      parse.syntaxIssues.push(
        `"${uri}" uses unsupported scheme "${scheme}:" (expected https: or mailto:)`,
      )
    }
  }
  return parse
}

// ─────────────────────────────────────────────────────────────────────────────
// From / SPF / DKIM identifier extraction for content.from_alignment (spec §3 "Alignment").
// ─────────────────────────────────────────────────────────────────────────────

/** Extract the addr-spec from a display-name header value ("Ada <a@b.com>" → "a@b.com"). */
export function addressIn(headerValue: string | null): string | null {
  if (!headerValue) return null
  const angled = headerValue.match(/<([^<>]+)>/)
  const candidate = angled ? angled[1] : headerValue
  const m = candidate.match(/[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9.-]+/)
  return m ? m[0].toLowerCase() : null
}

function domainOfAddress(addr: string | null): string | null {
  if (!addr) return null
  const at = addr.lastIndexOf("@")
  if (at <= 0 || at === addr.length - 1) return null
  return addr
    .slice(at + 1)
    .replace(/\.+$/, "")
    .toLowerCase()
}

/** The SPF envelope-from domain: Return-Path first, Authentication-Results smtp.mailfrom fallback. */
function spfDomainFrom(headers: ParsedHeader[]): string | null {
  const returnPath = firstHeader(headers, "Return-Path")
  const rpDomain = domainOfAddress(addressIn(returnPath))
  if (rpDomain) return rpDomain
  for (const ar of allHeaders(headers, "Authentication-Results")) {
    const m = ar.match(/smtp\.mailfrom=([^;\s]+)/i)
    if (m) {
      const value = m[1].toLowerCase()
      return value.includes("@") ? domainOfAddress(value) : value.replace(/\.+$/, "")
    }
  }
  return null
}

/** Every DKIM signing domain: DKIM-Signature d= tags plus Authentication-Results header.d. */
function dkimDomainsFrom(headers: ParsedHeader[]): string[] {
  const domains = new Set<string>()
  for (const sig of allHeaders(headers, "DKIM-Signature")) {
    const m = sig.match(/(?:^|;)\s*d=([^;\s]+)/i)
    if (m) domains.add(m[1].replace(/\.+$/, "").toLowerCase())
  }
  for (const ar of allHeaders(headers, "Authentication-Results")) {
    for (const m of ar.matchAll(/header\.d=([^;\s]+)/gi)) {
      domains.add(m[1].replace(/\.+$/, "").toLowerCase())
    }
  }
  return [...domains]
}

/** Relaxed alignment (spec §3): the org-domains (PSL-registrable) match. */
function relaxedAligned(a: string | null, b: string | null): boolean {
  if (!a || !b) return false
  return registrableDomain(a) === registrableDomain(b)
}

// ─────────────────────────────────────────────────────────────────────────────
// The opt-in HTTPS endpoint probe (RFC 8058 §3.2 POST / §4 GET-safety / TLS validity).
// ─────────────────────────────────────────────────────────────────────────────

interface HttpProbeResponse {
  status: number | null
  location: string | null
  body: string
  /** true = handshake completed against a valid CA-issued cert; false = TLS failure; null = never connected. */
  tlsValid: boolean | null
  error: string | null
}

/** Whether an error code names a TLS/certificate failure (drives content.list_unsub_tls). */
function isTlsError(code: string): boolean {
  return /CERT|TLS|SSL|ALTNAME|SELF_SIGNED|UNABLE_TO_VERIFY|HANDSHAKE/i.test(code)
}

function requestOnce(
  url: string,
  method: "POST" | "GET",
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<HttpProbeResponse> {
  return new Promise<HttpProbeResponse>((resolve) => {
    let settled = false
    const done = (r: HttpProbeResponse) => {
      if (!settled) {
        settled = true
        resolve(r)
      }
    }
    if (signal?.aborted) {
      done({ status: null, location: null, body: "", tlsValid: null, error: "aborted" })
      return
    }
    try {
      const body = method === "POST" ? "List-Unsubscribe=One-Click" : null
      const req = httpsRequest(
        url,
        {
          method,
          timeout: timeoutMs,
          signal,
          headers: {
            "User-Agent": PROBE_USER_AGENT,
            ...(body !== null
              ? {
                  "Content-Type": "application/x-www-form-urlencoded",
                  "Content-Length": String(Buffer.byteLength(body)),
                }
              : {}),
          },
        },
        (res) => {
          const socket = res.socket as TLSSocket
          const tlsValid = typeof socket.authorized === "boolean" ? socket.authorized : null
          const chunks: Buffer[] = []
          let bytes = 0
          res.on("data", (c: Buffer) => {
            bytes += c.length
            if (bytes <= GET_BODY_CAP_BYTES) chunks.push(c)
            else res.destroy() // confirmation pages are small — cap the read
          })
          res.on("end", () =>
            done({
              status: res.statusCode ?? null,
              location: typeof res.headers.location === "string" ? res.headers.location : null,
              body: Buffer.concat(chunks).toString("utf8"),
              tlsValid,
              error: null,
            }),
          )
          res.on("error", () =>
            done({
              status: res.statusCode ?? null,
              location: null,
              body: Buffer.concat(chunks).toString("utf8"),
              tlsValid,
              error: null,
            }),
          )
        },
      )
      req.on("timeout", () => {
        req.destroy()
        done({ status: null, location: null, body: "", tlsValid: null, error: "timeout" })
      })
      req.on("error", (e) => {
        const code = (e as NodeJS.ErrnoException).code ?? e.message
        done({
          status: null,
          location: null,
          body: "",
          tlsValid: isTlsError(code) ? false : null,
          error: code,
        })
      })
      if (body !== null) req.write(body)
      req.end()
    } catch (e) {
      done({
        status: null,
        location: null,
        body: "",
        tlsValid: null,
        error: e instanceof Error ? e.message : String(e),
      })
    }
  })
}

/** One probe result — the raw material for the reachable / get-safe / tls findings and the §4 panel. */
interface EndpointProbeOutcome {
  endpointOk: boolean
  endpointStatus: number | null
  /** null = GET probe could not run/complete (unknown), true = safe, false = GET unsubscribes. */
  getSafe: boolean | null
  tlsValid: boolean | null
  latencyMs: number
  error: string | null
  redirected: boolean
}

/** Body phrases that mean a bare GET already unsubscribed the recipient (RFC 8058 §4 violation). */
const GET_UNSUBSCRIBED_RE =
  /\b(you\s+(have\s+been|are|['’]re)\s+(now\s+)?unsubscribed|(successfully|has\s+been)\s+unsubscribed|unsubscribed\s+successfully|removed\s+from\s+(our|the|this)\s+(mailing\s+)?list)\b/i

/**
 * The RFC 8058 probe: ONE one-click `POST` (body `List-Unsubscribe=One-Click`,
 * `application/x-www-form-urlencoded`), following at most one redirect, then a bare `GET` to the
 * original URI to verify link-scanners can't accidentally unsubscribe users (§4). Runs through the
 * process-global `http` semaphore like every other outbound HTTPS consumer.
 */
async function probeEndpoint(
  httpsUri: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<EndpointProbeOutcome> {
  return withResource("http", async () => {
    const started = Date.now()
    let redirected = false
    let post = await requestOnce(httpsUri, "POST", timeoutMs, signal)
    // Follow at most ONE redirect (spec §3); a redirect target must still be https.
    if (post.status !== null && [301, 302, 303, 307, 308].includes(post.status) && post.location) {
      const target = new URL(post.location, httpsUri).toString()
      if (target.startsWith("https:")) {
        redirected = true
        post = await requestOnce(target, "POST", timeoutMs, signal)
      }
    }
    const latencyMs = Date.now() - started
    const endpointOk = post.status !== null && post.status >= 200 && post.status < 300
    let getSafe: boolean | null = null
    if (post.error === null || post.error === "timeout") {
      // §4 GET-safety: a bare GET must NOT report the unsubscribe as done.
      const get = await requestOnce(httpsUri, "GET", timeoutMs, signal)
      if (get.status !== null) {
        getSafe = !(get.status >= 200 && get.status < 300 && GET_UNSUBSCRIBED_RE.test(get.body))
      }
    }
    return {
      endpointOk,
      endpointStatus: post.status,
      getSafe,
      tlsValid: post.tlsValid,
      latencyMs,
      error: post.error,
      redirected,
    }
  })
}

// ─────────────────────────────────────────────────────────────────────────────
// The checker.
// ─────────────────────────────────────────────────────────────────────────────

/** Escalate warning → critical for bulk senders (spec §3 "Bulk-sender scope"). */
function bulkSeverity(isBulkSender: boolean): Severity {
  return isBulkSender ? "critical" : "warning"
}

/** The registrable host of an https URI (for shortener / brand-consistency checks). */
function httpsHost(uri: string | null): string | null {
  if (!uri) return null
  try {
    return new URL(uri).hostname.toLowerCase()
  } catch {
    return null
  }
}

/** The domain inside a List-Id value: "Weekly news <newsletter.example.com>" → "newsletter.example.com". */
function listIdDomain(listId: string | null): string | null {
  if (!listId) return null
  const inner = listId.match(/<([^<>]+)>/)?.[1] ?? listId.trim()
  const candidate = inner.trim().replace(/\.+$/, "").toLowerCase()
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(candidate)
    ? candidate
    : null
}

/** Heuristic for content.list_unsub_per_recipient: does the URI carry an opaque per-recipient token? */
export function looksPerRecipient(httpsUri: string | null, mailtoUri: string | null): boolean {
  if (httpsUri) {
    try {
      const url = new URL(httpsUri)
      for (const value of url.searchParams.values()) {
        if (value.length >= 8 && /[a-z]/i.test(value) && /[0-9]/.test(value)) return true
        if (value.length >= 16) return true
      }
      const segments = url.pathname.split("/").filter(Boolean)
      if (
        segments.some(
          (s) => s.length >= 10 && /[a-z]/i.test(s) && /[0-9]/.test(s) && !/^[a-z-]+$/i.test(s),
        )
      ) {
        return true
      }
    } catch {
      /* malformed URL — fall through to the mailto heuristic */
    }
  }
  if (mailtoUri) {
    // A tokenized subject/local-part ("unsub-8f3a91" / "u+8f3a91@") counts as per-recipient.
    if (/(subject|body)=[^&]*[0-9a-f]{6,}/i.test(mailtoUri)) return true
    if (/^mailto:[^@?]*[+=][^@?]*[0-9][^@?]*@/i.test(mailtoUri)) return true
  }
  return false
}

export const listUnsubscribeCheck: Checker = {
  id: "content.list_unsubscribe",
  label: "List-Unsubscribe & One-Click",
  async run(ctx): Promise<Finding[] | CheckOutcome> {
    const listUnsubConfig = readAppConfig().checks.listUnsub
    const bulkThreshold = listUnsubConfig?.bulkThresholdPerDay ?? DEFAULT_BULK_THRESHOLD_PER_DAY
    const probeTimeoutMs = listUnsubConfig?.probeTimeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS
    const probeAllowedGlobally = listUnsubConfig?.probeAllowed ?? true
    const probeCadenceMs =
      (listUnsubConfig?.probeCadenceHours ?? DEFAULT_PROBE_CADENCE_HOURS) * 60 * 60 * 1000
    const isBulkSender = ctx.listUnsub?.isBulkSender ?? false
    const probeOptedIn = ctx.listUnsub?.probeUnsubEndpoint ?? false

    // §3 / §8 AC 1: no captured sample → exactly ONE info advisory, never a false critical.
    const sample = ctx.domainId ? getActiveSample(ctx.domainId) : null
    if (!sample) {
      return [
        {
          id: "content.list_unsubscribe.no_sample",
          checkId: CHECK_ID,
          title: "No sample message — upload one to run list-management checks",
          severity: "info",
          detail:
            "The List-Unsubscribe / one-click audit inspects a captured bulk message's headers (RFC 2369 List-Unsubscribe, RFC 8058 List-Unsubscribe-Post one-click, From-domain SPF/DKIM alignment, Precedence and priority hygiene), but no sample message has been captured for this domain yet. " +
            `Gmail and Yahoo require bulk senders (> ${bulkThreshold.toLocaleString()} msgs/day) to ship a working one-click unsubscribe since Feb 2024, so this is a hard bulk-deliverability gate.`,
          remediation:
            'Upload a sample of a real bulk campaign (.eml) for this domain via the "Upload sample message" control on the Spam & Content page. Set the isBulkSender toggle if you send > 5,000 msgs/day so a missing one-click header escalates to critical, and (optionally) enable probeUnsubEndpoint to live-test that the https endpoint answers the one-click POST with a 2xx. Publish the headers now regardless: List-Unsubscribe: <https://unsub.' +
            `${ctx.domain}/u/{token}>, <mailto:unsubscribe@${ctx.domain}?subject=unsub-{token}> and List-Unsubscribe-Post: List-Unsubscribe=One-Click.`,
        },
      ]
    }

    const raw = readSampleRaw(sample)
    if (raw === null) {
      return [
        {
          id: "content.list_unsubscribe.sample_unreadable",
          checkId: CHECK_ID,
          title: "Stored sample message could not be read",
          severity: "warning",
          detail: `The active sample (uploaded ${sample.uploadedAt}) is missing from the file store, so the list-management checks were skipped.`,
          remediation: "Upload the sample .eml again to re-enable the list-management checks.",
          evidence: sample.rawPath ?? "(no stored path)",
        },
      ]
    }

    // ── Parse the RFC 5322 header block into a case-insensitive multimap (spec §3). ──
    const headers = parseHeaderBlock(raw)
    const listUnsubHeaders = allHeaders(headers, "List-Unsubscribe")
    const listUnsubHeader = listUnsubHeaders[0] ?? null
    const listUnsubPost = firstHeader(headers, "List-Unsubscribe-Post")
    const fromHeader = firstHeader(headers, "From")
    const returnPath = firstHeader(headers, "Return-Path")
    const dkimSignature = firstHeader(headers, "DKIM-Signature")
    const precedence = firstHeader(headers, "Precedence")
    const autoSubmitted = firstHeader(headers, "Auto-Submitted")
    const xPriority = firstHeader(headers, "X-Priority")
    const priorityHeader = firstHeader(headers, "Priority")
    const importance = firstHeader(headers, "Importance")
    const listId = firstHeader(headers, "List-Id")

    const parse = listUnsubHeader
      ? parseListUnsubscribe(listUnsubHeaders.join(", "))
      : { httpsUris: [], mailtoUris: [], httpUris: [], syntaxIssues: [] }
    const hasHeader = listUnsubHeader !== null
    const httpsUri = parse.httpsUris[0] ?? null
    const mailtoUri = parse.mailtoUris[0] ?? null
    const hasHttps = httpsUri !== null
    const hasMailto = mailtoUri !== null
    const hasOneclick =
      listUnsubPost !== null &&
      listUnsubPost.replace(/\s+/g, "").toLowerCase() === "list-unsubscribe=one-click"

    // ── From-alignment (spec §3 "Alignment" — relaxed, org-domain). ──
    const fromDomain = domainOfAddress(addressIn(fromHeader))
    const spfDomain = spfDomainFrom(headers)
    const dkimDomains = dkimDomainsFrom(headers)
    const fromSpfAligned = relaxedAligned(fromDomain, spfDomain)
    const fromDkimAligned = dkimDomains.some((d) => relaxedAligned(fromDomain, d))
    const fromAligned = fromSpfAligned || fromDkimAligned

    // ── Precedence / priority hygiene. ──
    const precedenceValue = precedence?.trim().toLowerCase() ?? null
    const precedenceBulk =
      precedenceValue !== null && ["bulk", "list", "junk"].includes(precedenceValue)
    const autoSubmittedSet = autoSubmitted !== null && autoSubmitted.trim().toLowerCase() !== "no"
    const priorityAbuse =
      /^\s*[12]\b/.test(xPriority ?? "") ||
      /urgent|high/i.test(priorityHeader ?? "") ||
      /high/i.test(importance ?? "")

    // ── The opt-in RFC 8058 endpoint probe (spec §3 "Endpoint probe", §6 throttle, AC 10). ──
    const previous = ctx.previousResults?.[CHECK_ID] as ListUnsubResults | undefined
    let endpointOk: boolean | null = null
    let endpointStatus: number | null = null
    let getSafe: boolean | null = null
    let tlsValid: boolean | null = null
    let probedAt: string | null = null
    let probeLatencyMs: number | null = null
    let probeError: string | null = null
    let probeCarriedForward = false
    const probeEnabled = probeOptedIn && probeAllowedGlobally && hasHttps
    if (probeEnabled && httpsUri) {
      const previousProbeFresh =
        previous?.probedAt != null &&
        previous.httpsUri === httpsUri &&
        Date.now() - Date.parse(previous.probedAt) < probeCadenceMs
      if (previousProbeFresh && previous) {
        // Throttled (§6): at most one unsubscribe POST per endpoint per probe cadence — reuse the
        // previous observation instead of re-firing a live unsubscribe. Doubles as back-off: a
        // failed probe is not retried until the next cadence window.
        endpointOk = previous.endpointOk
        endpointStatus = previous.endpointStatus
        getSafe = previous.getSafe
        tlsValid = previous.tlsValid
        probedAt = previous.probedAt
        probeLatencyMs = previous.probeLatencyMs
        probeCarriedForward = true
      } else {
        const outcome = await probeEndpoint(httpsUri, probeTimeoutMs, ctx.signal)
        endpointOk = outcome.endpointOk
        endpointStatus = outcome.endpointStatus
        getSafe = outcome.getSafe
        tlsValid = outcome.tlsValid
        probedAt = new Date().toISOString()
        probeLatencyMs = outcome.latencyMs
        probeError = outcome.error
      }
    }

    // ── Emit the findings (spec §2 sub-check table; ok rows are explicit passes). ──
    const findings: Finding[] = []
    const push = (
      id: string,
      title: string,
      severity: Severity,
      detail: string,
      remediation?: string,
      evidence?: string,
    ) =>
      findings.push({
        id,
        checkId: CHECK_ID,
        title,
        severity,
        detail,
        ...(severity !== "ok" && remediation ? { remediation } : {}),
        ...(evidence ? { evidence } : {}),
      })

    const exampleHeader = `List-Unsubscribe: <https://unsub.${ctx.domain}/u/{token}>, <mailto:unsubscribe@${ctx.domain}?subject=unsub-{token}>`
    const oneClickHeader = "List-Unsubscribe-Post: List-Unsubscribe=One-Click"

    // content.list_unsubscribe — RFC 2369 header present with at least one valid URI.
    if (hasHeader && (hasHttps || hasMailto)) {
      push(
        "content.list_unsubscribe",
        "List-Unsubscribe header present",
        "ok",
        `A List-Unsubscribe header (RFC 2369) is present with ${[hasHttps ? "an https" : null, hasMailto ? "a mailto:" : null].filter(Boolean).join(" and ")} method.`,
        undefined,
        listUnsubHeader ?? undefined,
      )
    } else if (hasHeader) {
      // Header exists but yielded no usable URI — the syntax finding below carries the specifics.
      push(
        "content.list_unsubscribe",
        "List-Unsubscribe header present but unusable",
        bulkSeverity(isBulkSender),
        "A List-Unsubscribe header is present but contains no valid https or mailto: URI, so providers cannot offer their built-in Unsubscribe button.",
        `Publish valid angle-bracketed URIs: ${exampleHeader}`,
        listUnsubHeader ?? undefined,
      )
    } else {
      push(
        "content.list_unsubscribe",
        "No List-Unsubscribe header",
        bulkSeverity(isBulkSender),
        `The sample ${isBulkSender ? "bulk " : ""}message carries no List-Unsubscribe header (RFC 2369), so Gmail/Yahoo cannot offer their native Unsubscribe button — users click "Report spam" instead.`,
        `Add the header to every bulk campaign: ${exampleHeader}`,
        "(header absent)",
      )
    }

    // content.list_unsub_oneclick — RFC 8058 List-Unsubscribe-Post (the hard Gmail/Yahoo gate).
    if (hasOneclick && hasHttps) {
      push(
        "content.list_unsub_oneclick",
        "One-click unsubscribe (RFC 8058) present",
        "ok",
        "List-Unsubscribe-Post: List-Unsubscribe=One-Click is present alongside an https URI — the Gmail/Yahoo Feb-2024 bulk requirement.",
        undefined,
        listUnsubPost ?? undefined,
      )
    } else if (hasOneclick && !hasHttps) {
      push(
        "content.list_unsub_oneclick",
        "One-click header present but no https target",
        bulkSeverity(isBulkSender),
        "List-Unsubscribe-Post is present, but the List-Unsubscribe header offers no https URI for the provider's automated POST — one-click cannot work.",
        `Add an https URI to the List-Unsubscribe header, e.g. ${exampleHeader}`,
        `List-Unsubscribe: ${listUnsubHeader ?? "(absent)"}; List-Unsubscribe-Post: ${listUnsubPost}`,
      )
    } else if (listUnsubPost !== null) {
      push(
        "content.list_unsub_oneclick",
        "List-Unsubscribe-Post has the wrong value",
        bulkSeverity(isBulkSender),
        `List-Unsubscribe-Post is present but its value is "${listUnsubPost}" — RFC 8058 requires the exact value "List-Unsubscribe=One-Click", so providers ignore it.`,
        `Publish the header verbatim: ${oneClickHeader}`,
        `List-Unsubscribe-Post: ${listUnsubPost}`,
      )
    } else {
      push(
        "content.list_unsub_oneclick",
        "No one-click unsubscribe (List-Unsubscribe-Post missing)",
        bulkSeverity(isBulkSender),
        (hasHeader
          ? `List-Unsubscribe is present (${hasHttps ? "https" : hasMailto ? "mailto: only" : "no valid URI"}), but the List-Unsubscribe-Post header is absent`
          : "Neither List-Unsubscribe nor List-Unsubscribe-Post is present") +
          ` — the sender has RFC 2369 but not RFC 8058. ${isBulkSender ? "This fails the Gmail/Yahoo Feb-2024 bulk-sender rules: the campaign is rate-limited, spam-foldered, or rejected." : "Gmail/Yahoo require this for bulk senders (> 5,000 msgs/day)."}`,
        `Add the header verbatim alongside an https List-Unsubscribe URI: ${oneClickHeader}`,
        `List-Unsubscribe: ${listUnsubHeader ?? "(absent)"}; List-Unsubscribe-Post: (absent)`,
      )
    }

    // The remaining unsub-header sub-checks only make sense when the header exists at all.
    if (hasHeader) {
      // content.list_unsub_https — at least one https method (mailto:-only can't do one-click).
      if (hasHttps) {
        push(
          "content.list_unsub_https",
          "https unsubscribe method present",
          "ok",
          `An https unsubscribe URI is published: ${httpsUri}`,
          undefined,
          httpsUri ?? undefined,
        )
      } else if (parse.httpUris.length > 0) {
        push(
          "content.list_unsub_https",
          "Unsubscribe URL uses insecure http:",
          "warning",
          `The List-Unsubscribe URI ${parse.httpUris[0]} uses insecure http: — RFC 8058 one-click requires an https target, and providers may refuse to POST to plain http.`,
          `Serve the unsubscribe endpoint over https and publish it: List-Unsubscribe: <${parse.httpUris[0].replace(/^http:/, "https:")}>${hasMailto ? `, <${mailtoUri}>` : ""}`,
          listUnsubHeader ?? undefined,
        )
      } else {
        push(
          "content.list_unsub_https",
          "List-Unsubscribe is mailto:-only — one-click impossible",
          bulkSeverity(isBulkSender),
          "The List-Unsubscribe header lists only a mailto: method. RFC 8058 one-click requires an https URI the provider can POST to, so the native Unsubscribe button cannot work.",
          `Add an https unsubscribe URL and keep the mailto: as a secondary method: List-Unsubscribe: <https://unsub.${ctx.domain}/u/{token}>${hasMailto ? `, <${mailtoUri}>` : ""}`,
          listUnsubHeader ?? undefined,
        )
      }

      // content.list_unsub_mailto — the belt-and-suspenders mailto: fallback.
      if (hasMailto) {
        push(
          "content.list_unsub_mailto",
          "mailto: unsubscribe fallback present",
          "ok",
          `A mailto: unsubscribe method is also offered: ${mailtoUri}`,
          undefined,
          mailtoUri ?? undefined,
        )
      } else {
        push(
          "content.list_unsub_mailto",
          "No mailto: unsubscribe fallback",
          "warning",
          "The List-Unsubscribe header offers no mailto: method. Some clients and older providers prefer (or only support) the mailto: form.",
          `Add a mailto: alongside the https URI: List-Unsubscribe: ${httpsUri ? `<${httpsUri}>, ` : ""}<mailto:unsubscribe@${ctx.domain}?subject=unsubscribe>`,
          listUnsubHeader ?? undefined,
        )
      }

      // content.list_unsub_syntax — RFC 2369 grammar.
      if (parse.syntaxIssues.length === 0) {
        push(
          "content.list_unsub_syntax",
          "List-Unsubscribe grammar is RFC 2369-conformant",
          "ok",
          "Every URI is wrapped in angle brackets, the list is comma-separated, and no unrendered merge tags remain.",
          undefined,
          listUnsubHeader ?? undefined,
        )
      } else {
        push(
          "content.list_unsub_syntax",
          "Malformed List-Unsubscribe header",
          "critical",
          `The header violates RFC 2369 grammar, so providers ignore it entirely: ${parse.syntaxIssues.join("; ")}.`,
          `Wrap each URI in angle brackets, comma-separate them, and render merge tags to a real per-recipient URL before sending: ${exampleHeader}`,
          listUnsubHeader ?? undefined,
        )
      }
    }

    // Endpoint probe findings (content.list_unsub_reachable / _https_get_safe / _tls).
    if (probeEnabled && httpsUri) {
      const probeNote = probeCarriedForward
        ? ` (probe throttled to once per ${listUnsubConfig?.probeCadenceHours ?? DEFAULT_PROBE_CADENCE_HOURS}h — showing the ${probedAt} observation)`
        : ""
      if (endpointOk) {
        push(
          "content.list_unsub_reachable",
          `One-click endpoint answered ${endpointStatus}`,
          "ok",
          `The HTTPS POST (body List-Unsubscribe=One-Click) to ${httpsUri} returned ${endpointStatus} in ${probeLatencyMs ?? "?"} ms — RFC 8058 §3.2 satisfied${probeNote}.`,
          undefined,
          `POST ${httpsUri} → ${endpointStatus}`,
        )
      } else {
        const observed =
          endpointStatus !== null
            ? endpointStatus >= 300 && endpointStatus < 400
              ? `returned ${endpointStatus} (redirect — likely a login/confirmation page)`
              : `returned ${endpointStatus}`
            : probeError === "timeout"
              ? `timed out after ${probeTimeoutMs} ms`
              : `failed (${probeError ?? "no response"})`
        push(
          "content.list_unsub_reachable",
          "One-click endpoint does not answer the POST with 2xx",
          "critical",
          `The one-click HTTPS POST to ${httpsUri} ${observed}. Providers' automated unsubscribe fails, so users click "Report spam" instead${probeNote}.`,
          "Make the endpoint accept an unauthenticated POST with body List-Unsubscribe=One-Click (Content-Type: application/x-www-form-urlencoded) and return 200/204 — no cookies, JavaScript, login, or confirmation click.",
          `POST ${httpsUri} → ${endpointStatus ?? probeError ?? "no response"}`,
        )
      }

      if (getSafe === false) {
        push(
          "content.list_unsub_https_get_safe",
          "Endpoint unsubscribes on a bare GET",
          "warning",
          `A bare GET to ${httpsUri} reported the unsubscribe as already done — anti-virus and prefetch link-scanners will silently unsubscribe recipients (RFC 8058 §4)${probeNote}.`,
          "Only perform the unsubscribe on the RFC 8058 POST (body List-Unsubscribe=One-Click); make GET render a confirmation page that requires a click.",
          `GET ${httpsUri} → unsubscribe-confirmed body`,
        )
      } else if (getSafe === true) {
        push(
          "content.list_unsub_https_get_safe",
          "Endpoint is GET-safe",
          "ok",
          `A bare GET to the unsubscribe URL does not complete an unsubscribe (RFC 8058 §4) — link scanners cannot accidentally remove recipients${probeNote}.`,
        )
      }

      if (tlsValid === false) {
        push(
          "content.list_unsub_tls",
          "Unsubscribe endpoint TLS certificate invalid",
          "warning",
          `The TLS handshake with ${httpsHost(httpsUri) ?? httpsUri} failed certificate validation (self-signed, expired, or hostname mismatch)${probeError ? ` — ${probeError}` : ""}. Providers may refuse to POST to it${probeNote}.`,
          "Serve the unsubscribe endpoint behind a valid CA-issued certificate matching the URL hostname (e.g. Let's Encrypt).",
          `TLS ${httpsHost(httpsUri) ?? httpsUri}: ${probeError ?? "not authorized"}`,
        )
      } else if (tlsValid === true) {
        push(
          "content.list_unsub_tls",
          "Unsubscribe endpoint TLS certificate valid",
          "ok",
          `${httpsHost(httpsUri) ?? httpsUri} presented a valid, CA-issued certificate for its hostname${probeNote}.`,
        )
      }
    } else if (hasHttps) {
      // The probe never runs when the per-domain opt-in (or the global permission) is off (§3 Safety, AC 10).
      push(
        "content.list_unsub_reachable",
        "Endpoint probe not run",
        "info",
        probeOptedIn && !probeAllowedGlobally
          ? "The domain opted into the one-click endpoint probe, but the probe is globally disabled in Settings → Admin (checks.listUnsub.probeAllowed)."
          : "The live one-click POST probe is opt-in per domain (probeUnsubEndpoint, default off) because POSTing to a real unsubscribe URL may unsubscribe the sampled recipient. Reachability, GET-safety, and TLS validity were not verified.",
        "Enable the probeUnsubEndpoint toggle on the domain (ideally with a seed/test recipient's sample) to verify the endpoint answers the RFC 8058 POST with a 2xx.",
        `https URI (not probed): ${httpsUri}`,
      )
    }

    // content.list_unsub_honored — advisory; needs a suppression-list/attestation feed (future).
    push(
      "content.list_unsub_honored",
      "Unsubscribe honored within 2 days — cannot verify",
      "info",
      "Gmail/Yahoo require unsubscribe requests to be honored within 2 days. Verifying actual suppression needs an attestation, a suppression-list export, or a seed-address follow-up over audit history — a future round; it cannot be measured from the sample alone.",
      "Suppress unsubscribed addresses within 2 days (ideally immediately) across every list and campaign.",
    )

    // content.list_unsub_url_reputation — shortener / blocklisted unsubscribe host (spec §2).
    if (httpsUri) {
      const host = httpsHost(httpsUri)
      const unsubOrg = host ? registrableDomain(host) : null
      const shorteners = new Set(
        (readAppConfig().checks.content?.url?.shorteners?.length
          ? readAppConfig().checks.content.url?.shorteners
          : DEFAULT_SHORTENERS
        )?.map((s) => s.toLowerCase()) ?? DEFAULT_SHORTENERS,
      )
      // Cross-check against the link_url_reputation run (spec §2 — reuses content.url's URI-zone
      // answers when the same registrable domain appeared in the body's link scan).
      const upstreamUrl = ctx.upstream?.["content.url"] as LinkUrlResults | undefined
      const listedZones =
        unsubOrg && upstreamUrl
          ? [
              ...new Set(
                upstreamUrl.links
                  .filter((l) => l.linkDomain === unsubOrg)
                  .flatMap((l) => l.listings.filter((z) => z.listed).map((z) => z.zone)),
              ),
            ]
          : []
      if (unsubOrg && listedZones.length > 0) {
        push(
          "content.list_unsub_url_reputation",
          "Unsubscribe host is on a URI blocklist",
          "warning",
          `The unsubscribe host domain ${unsubOrg} is listed on ${listedZones.join(", ")} — providers distrust the whole message when its unsubscribe link is blocklisted.`,
          `Host the unsubscribe link on your own authenticated domain (e.g. unsub.${ctx.domain}) and pursue delisting of ${unsubOrg}.`,
          `${unsubOrg} listed on: ${listedZones.join(", ")}`,
        )
      } else if (unsubOrg && shorteners.has(unsubOrg)) {
        push(
          "content.list_unsub_url_reputation",
          "Unsubscribe URL uses a public link shortener",
          "warning",
          `The unsubscribe URL is hosted on the public shortener ${unsubOrg} — shortener domains carry shared (often poor) reputation and hide the real destination from providers.`,
          `Host the unsubscribe link on your own authenticated domain, e.g. https://unsub.${ctx.domain}/u/{token}, not a bare link-shortener.`,
          httpsUri,
        )
      } else if (unsubOrg) {
        push(
          "content.list_unsub_url_reputation",
          "Unsubscribe host reputation OK",
          "ok",
          `The unsubscribe host ${unsubOrg} is not a public shortener${upstreamUrl ? " and is not on a queried URI blocklist" : ""}.`,
        )
      }
    }

    // content.precedence — bulk/automated mail declares itself (spec §2).
    if (precedenceBulk || autoSubmittedSet) {
      push(
        "content.precedence",
        "Bulk/auto-submitted precedence declared",
        "ok",
        precedenceBulk
          ? `Precedence: ${precedenceValue} is set, so auto-responders and vacation replies stay quiet.`
          : `Auto-Submitted: ${autoSubmitted} is set, so auto-responders and vacation replies stay quiet.`,
        undefined,
        precedence ? `Precedence: ${precedence}` : `Auto-Submitted: ${autoSubmitted}`,
      )
    } else if (precedenceValue !== null) {
      push(
        "content.precedence",
        "Non-standard Precedence value",
        "info",
        `Precedence: ${precedence} is non-standard — the conventional values are bulk, list, or junk.`,
        "Set Precedence: bulk on bulk campaigns (or Auto-Submitted: auto-generated on automated system mail).",
        `Precedence: ${precedence}`,
      )
    } else {
      push(
        "content.precedence",
        "Bulk mail missing Precedence: bulk",
        "warning",
        "The sample carries neither a Precedence: bulk/list header nor Auto-Submitted:, so vacation auto-replies and auto-responders will answer the campaign.",
        "Set Precedence: bulk on bulk campaigns and Auto-Submitted: auto-generated on automated system mail.",
        "(Precedence and Auto-Submitted absent)",
      )
    }

    // content.from_alignment — the message-level Gmail/Yahoo auth gate (spec §3 "Alignment").
    const alignmentEvidence = `From: ${fromDomain ?? "(unparseable)"}; SPF (Return-Path): ${spfDomain ?? "(none)"}; DKIM d=: ${dkimDomains.join(", ") || "(none)"}`
    if (!fromDomain) {
      push(
        "content.from_alignment",
        "From: domain could not be parsed",
        "warning",
        "The sample's From: header yielded no parseable address/domain, so identifier alignment could not be evaluated.",
        "Send with a standard RFC 5322 From: header, e.g. From: Newsletter <news@yourdomain.com>.",
        `From: ${fromHeader ?? "(absent)"}`,
      )
    } else if (spfDomain === null && dkimDomains.length === 0) {
      push(
        "content.from_alignment",
        "Cannot verify From alignment — no auth identifiers in sample",
        "info",
        "The sample carries neither a Return-Path nor a DKIM-Signature/Authentication-Results header, so SPF/DKIM alignment could not be evaluated. Capture the sample from a real received copy (which includes these headers) rather than a pre-send template.",
        "Upload a sample captured at a receiving mailbox so Return-Path and DKIM-Signature headers are present.",
        alignmentEvidence,
      )
    } else if (fromSpfAligned && fromDkimAligned) {
      push(
        "content.from_alignment",
        "From aligns with SPF and DKIM",
        "ok",
        `The visible From: org-domain (${registrableDomain(fromDomain)}) aligns (relaxed) with both the SPF envelope-from and a DKIM d= domain — the 2024 Gmail/Yahoo auth gate passes.`,
        undefined,
        alignmentEvidence,
      )
    } else if (fromSpfAligned || fromDkimAligned) {
      const alignedWith = fromSpfAligned ? "SPF (Return-Path)" : "DKIM (d=)"
      const missing = fromSpfAligned ? "DKIM d=" : "SPF Return-Path"
      push(
        "content.from_alignment",
        `From aligns with ${fromSpfAligned ? "SPF" : "DKIM"} only`,
        "warning",
        `The From: org-domain (${registrableDomain(fromDomain)}) aligns with ${alignedWith} but not with ${missing}. One aligned identifier passes DMARC, but both aligned is the robust configuration (forwarding breaks SPF; some middleboxes break DKIM).`,
        fromSpfAligned
          ? `Also sign with DKIM d=${registrableDomain(fromDomain)} (or a subdomain) so DKIM alignment holds when forwarding breaks SPF.`
          : `Also align the SPF Return-Path: use a bounce domain under ${registrableDomain(fromDomain)} (e.g. bounces.${registrableDomain(fromDomain)}).`,
        alignmentEvidence,
      )
    } else {
      push(
        "content.from_alignment",
        "From aligns with neither SPF nor DKIM",
        "critical",
        `The visible From: org-domain (${registrableDomain(fromDomain)}) aligns with neither the SPF envelope-from (${spfDomain ?? "none"}) nor any DKIM d= domain (${dkimDomains.join(", ") || "none"}) under relaxed alignment — the message fails the Gmail/Yahoo auth gate regardless of its unsubscribe headers.`,
        `Send from a From: whose org-domain matches your DKIM d= (and/or SPF Return-Path) domain — e.g. sign with d=${registrableDomain(fromDomain)}.`,
        alignmentEvidence,
      )
    }

    // content.no_priority_abuse — forced high priority on routine bulk mail (spec §2).
    if (priorityAbuse) {
      const offenders = [
        xPriority && /^\s*[12]\b/.test(xPriority) ? `X-Priority: ${xPriority}` : null,
        priorityHeader && /urgent|high/i.test(priorityHeader)
          ? `Priority: ${priorityHeader}`
          : null,
        importance && /high/i.test(importance) ? `Importance: ${importance}` : null,
      ].filter((s): s is string => s !== null)
      push(
        "content.no_priority_abuse",
        "Forced high priority on bulk/routine mail",
        "warning",
        `The sample forces high priority (${offenders.join("; ")}) on a routine/bulk message — a classic spam signal that content filters score.`,
        "Remove the X-Priority/Priority/Importance headers from bulk mail; reserve high priority for genuinely urgent transactional messages.",
        offenders.join("; "),
      )
    } else {
      push(
        "content.no_priority_abuse",
        "No priority-header abuse",
        "ok",
        "The sample does not force X-Priority: 1, Priority: urgent, or Importance: High.",
      )
    }

    // content.list_id — RFC 2919 stable list identifier (info-only).
    if (listId) {
      push(
        "content.list_id",
        "List-Id present",
        "ok",
        `A stable List-Id (RFC 2919) identifies the list: ${listId}`,
        undefined,
        `List-Id: ${listId}`,
      )
    } else {
      push(
        "content.list_id",
        "No List-Id header",
        "info",
        "No List-Id (RFC 2919) header is present. A stable List-Id helps clients filter the list and providers group its reputation.",
        `Add List-Id: <newsletter.${ctx.domain}> so clients and providers can group and filter the list.`,
        "(List-Id absent)",
      )
    }

    // content.list_headers_consistent — unsub host / List-Id / From on the same brand org-domain.
    const fromOrg = fromDomain ? registrableDomain(fromDomain) : null
    const unsubHost = httpsHost(httpsUri) ?? domainOfAddress(addressIn(mailtoUri))
    const unsubOrg2 = unsubHost ? registrableDomain(unsubHost) : null
    const listIdOrg = listIdDomain(listId)
      ? registrableDomain(listIdDomain(listId) as string)
      : null
    if (fromOrg && (unsubOrg2 || listIdOrg)) {
      const mismatches: string[] = []
      if (unsubOrg2 && unsubOrg2 !== fromOrg) {
        mismatches.push(`unsubscribe host ${unsubOrg2} ≠ From org-domain ${fromOrg}`)
      }
      if (listIdOrg && listIdOrg !== fromOrg) {
        mismatches.push(`List-Id domain ${listIdOrg} ≠ From org-domain ${fromOrg}`)
      }
      if (mismatches.length > 0) {
        push(
          "content.list_headers_consistent",
          "List headers use a different domain than the sending brand",
          "warning",
          `The list-management headers are not mutually consistent: ${mismatches.join("; ")}. Copy-pasted vendor/competitor domains left in templates erode trust and can break one-click.`,
          `Align List-Unsubscribe, List-Id, and From: on the same brand org-domain (${fromOrg}), e.g. https://unsub.${fromOrg}/… and List-Id: <newsletter.${fromOrg}>.`,
          `From: ${fromOrg}; unsubscribe: ${unsubOrg2 ?? "(none)"}; List-Id: ${listIdOrg ?? "(none)"}`,
        )
      } else {
        push(
          "content.list_headers_consistent",
          "List headers are brand-consistent",
          "ok",
          `The unsubscribe host${listIdOrg ? ", List-Id," : ""} and From: all sit on the ${fromOrg} org-domain.`,
        )
      }
    }

    // content.list_unsub_per_recipient — per-recipient token heuristic (advisory).
    if (hasHttps || hasMailto) {
      if (looksPerRecipient(httpsUri, mailtoUri)) {
        push(
          "content.list_unsub_per_recipient",
          "Unsubscribe link looks per-recipient",
          "ok",
          "The unsubscribe URI carries an opaque per-recipient token, so a POST unsubscribes exactly one address.",
        )
      } else {
        push(
          "content.list_unsub_per_recipient",
          "Unsubscribe link looks shared/static",
          "info",
          "The unsubscribe URI carries no obvious per-recipient token — a single shared link is harder to honor per-address and easier to abuse.",
          "Embed a per-recipient opaque token in the unsubscribe URL (e.g. https://unsub.example.com/u/{token}) so a POST unsubscribes exactly one address.",
          httpsUri ?? mailtoUri ?? undefined,
        )
      }
    }

    // ── Persist the parsed observation (spec §5, AC 12). ──
    const results: ListUnsubResults = {
      sampleId: sample.id,
      hasHeader,
      hasOneclick,
      hasHttps,
      hasMailto,
      httpsUri,
      mailtoUri,
      endpointOk,
      endpointStatus,
      getSafe,
      tlsValid,
      fromAligned,
      fromSpfAligned,
      fromDkimAligned,
      precedenceBulk,
      priorityAbuse,
      listId,
      isBulkSender,
      checkedAt: new Date().toISOString(),
      probedAt,
      probeLatencyMs,
      syntaxOk: !hasHeader || parse.syntaxIssues.length === 0,
      rawHeaders: {
        listUnsubscribe: listUnsubHeader,
        listUnsubscribePost: listUnsubPost,
        from: fromHeader,
        returnPath,
        dkimSignature,
        precedence,
        autoSubmitted,
        xPriority,
        priority: priorityHeader,
        importance,
        listId,
      },
    }
    return { findings, results }
  },
}
