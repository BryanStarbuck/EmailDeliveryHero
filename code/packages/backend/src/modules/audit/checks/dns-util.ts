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
