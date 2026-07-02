import { createHash } from "node:crypto"
import { request as httpsRequest } from "node:https"
import { withResource } from "@shared/concurrency"

/**
 * MTA-STS served-policy fetch + parse (RFC 8461 §3.2/§3.3), the one bounded HTTPS fetch this
 * category makes in the first round (pm/checks/dns.mdx §4 rule 1: "Families 4 and 5 add one bounded
 * HTTPS fetch (the MTA-STS policy file)"). The fetch is SAFE and non-intrusive: a single HTTPS GET
 * to the well-known URL, SNI = the policy host, redirects NOT followed (RFC 8461 §3.3 forbids
 * them), a hard timeout, and a small body cap so a hostile endpoint cannot balloon the heap. It runs
 * under the process-global `http` semaphore shared with every other outbound HTTPS consumer.
 *
 * The HTTPS handshake itself is the certificate check: node's https validates the chain against the
 * bundled Mozilla CA store and enforces the SNI hostname, so a successful fetch means the cert is
 * publicly trusted AND covers `mta-sts.<domain>`. A TLS failure surfaces as a distinct error code
 * (CERT_HAS_EXPIRED, ERR_TLS_CERT_ALTNAME_INVALID, SELF_SIGNED_CERT_IN_CHAIN, …) that the checker
 * maps to `infra.mta_sts_https_cert`.
 */

/** Hard per-fetch wall-clock budget. */
const HTTP_TIMEOUT_MS = 10_000
/** RFC 8461 policies are tiny; cap the body so a misbehaving endpoint can't balloon the heap. */
const MAX_BODY_BYTES = 64 * 1024

export interface PolicyFetch {
  /** HTTP status line code (200 on success; 0 when the request never completed). */
  status: number
  /** Raw policy body (truncated to MAX_BODY_BYTES). */
  body: string
  /** Lower-cased Content-Type header value, header params stripped (e.g. "text/plain"). */
  contentType: string | null
  /** True when the server answered with a 3xx redirect (which RFC 8461 forbids for the policy). */
  redirected: boolean
  /** The Location target when redirected (diagnostic only — never followed). */
  location: string | null
  /** TLS/transport error code when the fetch failed (cert invalid, timeout, connection refused). */
  error: string | null
}

/**
 * The parsed MTA-STS policy body (RFC 8461 §3.2): newline-delimited `key: value` lines. `mode` and
 * `max_age` are single-valued; `mx` may repeat. Unknown keys are ignored (forward compatible).
 */
export interface ParsedPolicy {
  version: string | null
  mode: string | null
  maxAge: number | null
  /** All `mx:` patterns in file order (may include a leading-label wildcard, e.g. "*.example.com"). */
  mx: string[]
  /** True when a `max_age:` line was present but not a non-negative integer. */
  maxAgeMalformed: boolean
}

/** Fetch the served MTA-STS policy. Never throws — a transport failure comes back as `error`. */
export function fetchMtaStsPolicy(domain: string): Promise<PolicyFetch> {
  const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`
  return withResource("http", () => fetchNow(url))
}

function fetchNow(url: string): Promise<PolicyFetch> {
  return new Promise<PolicyFetch>((resolve) => {
    let settled = false
    const done = (r: PolicyFetch) => {
      if (!settled) {
        settled = true
        resolve(r)
      }
    }
    try {
      const req = httpsRequest(
        url,
        {
          method: "GET",
          timeout: HTTP_TIMEOUT_MS,
          headers: { "User-Agent": "EmailDeliveryHero-MTASTS/1", Accept: "text/plain" },
        },
        (res) => {
          const status = res.statusCode ?? 0
          const location = res.headers.location
          const redirected = status >= 300 && status < 400
          if (redirected) {
            // RFC 8461 §3.3: senders MUST NOT follow redirects. Record it and stop reading.
            res.destroy()
            done({
              status,
              body: "",
              contentType: headerType(res.headers["content-type"]),
              redirected: true,
              location: typeof location === "string" ? location : null,
              error: null,
            })
            return
          }
          const chunks: Buffer[] = []
          let total = 0
          res.on("data", (c: Buffer) => {
            total += c.length
            if (total <= MAX_BODY_BYTES) chunks.push(c)
            else res.destroy() // over the cap — take what we have
          })
          const finish = () =>
            done({
              status,
              body: Buffer.concat(chunks).toString("utf8").slice(0, MAX_BODY_BYTES),
              contentType: headerType(res.headers["content-type"]),
              redirected: false,
              location: null,
              error: null,
            })
          res.on("end", finish)
          res.on("close", finish)
        },
      )
      req.on("timeout", () => {
        req.destroy()
        done({
          status: 0,
          body: "",
          contentType: null,
          redirected: false,
          location: null,
          error: "ETIMEOUT",
        })
      })
      req.on("error", (e) =>
        done({
          status: 0,
          body: "",
          contentType: null,
          redirected: false,
          location: null,
          error: (e as NodeJS.ErrnoException).code ?? e.message,
        }),
      )
      req.end()
    } catch (e) {
      done({
        status: 0,
        body: "",
        contentType: null,
        redirected: false,
        location: null,
        error: e instanceof Error ? e.message : String(e),
      })
    }
  })
}

function headerType(v: string | string[] | undefined): string | null {
  const raw = Array.isArray(v) ? v[0] : v
  if (!raw) return null
  return raw.split(";")[0].trim().toLowerCase()
}

/** Parse an MTA-STS policy body into structured fields (RFC 8461 §3.2). */
export function parsePolicy(body: string): ParsedPolicy {
  const policy: ParsedPolicy = {
    version: null,
    mode: null,
    maxAge: null,
    mx: [],
    maxAgeMalformed: false,
  }
  // RFC 8461 lines are CRLF-delimited "key: value"; tolerate bare LF too.
  for (const line of body.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed) continue
    const colon = trimmed.indexOf(":")
    if (colon === -1) continue
    const key = trimmed.slice(0, colon).trim().toLowerCase()
    const value = trimmed.slice(colon + 1).trim()
    switch (key) {
      case "version":
        if (policy.version === null) policy.version = value
        break
      case "mode":
        if (policy.mode === null) policy.mode = value.toLowerCase()
        break
      case "max_age": {
        if (/^\d+$/.test(value)) policy.maxAge = Number(value)
        else policy.maxAgeMalformed = true
        break
      }
      case "mx":
        if (value) policy.mx.push(value.toLowerCase())
        break
      default:
        break
    }
  }
  return policy
}

/**
 * Does an MX hostname match an MTA-STS `mx:` pattern (RFC 8461 §4.1)? A pattern may carry a single
 * leading `*` label wildcard that matches exactly one hostname label (e.g. `*.example.com` matches
 * `mx1.example.com` but not `a.b.example.com` and not the apex `example.com`). Comparison is
 * case-insensitive with any trailing dot stripped from both sides.
 */
export function mxMatchesPattern(host: string, pattern: string): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, "")
  const p = pattern.trim().toLowerCase().replace(/\.$/, "")
  if (!p) return false
  if (p.startsWith("*.")) {
    const suffix = p.slice(1) // ".example.com"
    if (!h.endsWith(suffix)) return false
    const label = h.slice(0, h.length - suffix.length)
    // Exactly one label: non-empty and containing no dot.
    return label.length > 0 && !label.includes(".")
  }
  return h === p
}

/** SHA-256 of the normalized policy body — the change-detector for `infra.mta_sts_id_freshness`. */
export function policyHash(body: string): string {
  // Normalize line endings so a CRLF↔LF reformat alone is not treated as a policy change.
  return createHash("sha256").update(body.replace(/\r\n/g, "\n").trim()).digest("hex")
}
