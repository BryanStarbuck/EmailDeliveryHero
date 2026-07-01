import { promises as dns } from "node:dns"

/**
 * Thin wrappers around node:dns/promises used by the checkers. Each returns a normalized result and
 * never throws for the common "no such record" (ENOTFOUND / ENODATA) case — that is a legitimate
 * finding, not an error. A future enhancement can swap these for shelling out to Brew-installed
 * `dig` (see pm/engineering.mdx); the checkers only depend on this small surface.
 */

export interface DnsLookup<T> {
  /** The records found (empty array when none). */
  records: T[]
  /** True when the name genuinely has no such record (NXDOMAIN / no data). */
  empty: boolean
  /** Set when the lookup failed for a reason other than "no record" (timeout, servfail). */
  error?: string
}

function classify(err: unknown): { empty: boolean; error?: string } {
  const code = (err as NodeJS.ErrnoException)?.code
  if (code === "ENOTFOUND" || code === "ENODATA") return { empty: true }
  return { empty: false, error: code ?? (err instanceof Error ? err.message : String(err)) }
}

/** Resolve TXT records, flattening each record's string chunks into one string. */
export async function resolveTxt(name: string): Promise<DnsLookup<string>> {
  try {
    const chunks = await dns.resolveTxt(name)
    return { records: chunks.map((parts) => parts.join("")), empty: chunks.length === 0 }
  } catch (err) {
    return { records: [], ...classify(err) }
  }
}

export interface MxRecord {
  exchange: string
  priority: number
}

export async function resolveMx(name: string): Promise<DnsLookup<MxRecord>> {
  try {
    const records = await dns.resolveMx(name)
    return { records, empty: records.length === 0 }
  } catch (err) {
    return { records: [], ...classify(err) }
  }
}

export async function resolve4(name: string): Promise<DnsLookup<string>> {
  try {
    const records = await dns.resolve4(name)
    return { records, empty: records.length === 0 }
  } catch (err) {
    return { records: [], ...classify(err) }
  }
}

/** Reverse-DNS (PTR) lookup for an IP. */
export async function reverse(ip: string): Promise<DnsLookup<string>> {
  try {
    const records = await dns.reverse(ip)
    return { records, empty: records.length === 0 }
  } catch (err) {
    return { records: [], ...classify(err) }
  }
}

/** Reverse an IPv4 address for DNSBL queries: 1.2.3.4 → 4.3.2.1. Returns null for non-IPv4. */
export function reverseIpv4(ip: string): string | null {
  const parts = ip.trim().split(".")
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null
  return parts.reverse().join(".")
}

/** Resolve AAAA (IPv6) records. */
export async function resolve6(name: string): Promise<DnsLookup<string>> {
  try {
    const records = await dns.resolve6(name)
    return { records, empty: records.length === 0 }
  } catch (err) {
    return { records: [], ...classify(err) }
  }
}

/** Resolve CNAME records for a name. */
export async function resolveCname(name: string): Promise<DnsLookup<string>> {
  try {
    const records = await dns.resolveCname(name)
    return { records, empty: records.length === 0 }
  } catch (err) {
    return { records: [], ...classify(err) }
  }
}

/** Resolve NS records for a zone. */
export async function resolveNs(name: string): Promise<DnsLookup<string>> {
  try {
    const records = await dns.resolveNs(name)
    return { records, empty: records.length === 0 }
  } catch (err) {
    return { records: [], ...classify(err) }
  }
}

/** Resolve CAA records for a name. */
export async function resolveCaa(name: string): Promise<DnsLookup<import("node:dns").CaaRecord>> {
  try {
    const records = await dns.resolveCaa(name)
    return { records, empty: records.length === 0 }
  } catch (err) {
    return { records: [], ...classify(err) }
  }
}

/** Resolve the SOA record for a zone (single record, or null when absent/error). */
export async function resolveSoa(
  name: string,
): Promise<{ record: import("node:dns").SoaRecord | null; empty: boolean; error?: string }> {
  try {
    const record = await dns.resolveSoa(name)
    return { record, empty: false }
  } catch (err) {
    return { record: null, ...classify(err) }
  }
}

/**
 * Shell out to the Brew-installed `dig` for record types node:dns cannot query directly (TLSA, DS,
 * DNSKEY, RRSIG, SVCB, SMIMEA, etc.). Returns the `+short` answer lines. Never throws: on a missing
 * `dig` binary, timeout, or NXDOMAIN it returns an empty record set with `empty: true` so callers can
 * emit a graceful finding rather than crash. First-round checkers should degrade to an `info`
 * finding when `error` is set (transient) and treat `empty` as "no such record".
 */
export async function dig(name: string, type: string): Promise<DnsLookup<string>> {
  const { execFile } = await import("node:child_process")
  return await new Promise<DnsLookup<string>>((resolve) => {
    execFile(
      "dig",
      // Tight budget: healthy resolvers answer in well under a second; a query that stalls past ~3s
      // is treated as transient (error set) so a single slow/hung lookup can't blow the audit budget.
      ["+short", "+time=3", "+tries=1", type, name],
      { timeout: 4000 },
      (err, stdout) => {
        if (err) {
          // ENOENT = dig not installed; treat as transient/unknown, not "no record".
          const code = (err as NodeJS.ErrnoException).code
          resolve({ records: [], empty: false, error: code ?? err.message })
          return
        }
        const records = stdout
          .split("\n")
          .map((l) => l.trim())
          .filter(Boolean)
          // dig may emit CNAME chase lines; keep everything, callers parse per type.
          .filter((l) => !l.startsWith(";"))
        resolve({ records, empty: records.length === 0 })
      },
    )
  })
}
