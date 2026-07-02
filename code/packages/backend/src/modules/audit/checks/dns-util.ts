import { AsyncLocalStorage } from "node:async_hooks"
import { promises as dns } from "node:dns"

/**
 * Thin wrappers around node:dns/promises used by the checkers. Each returns a normalized result and
 * never throws for the common "no such record" (ENOTFOUND / ENODATA) case — that is a legitimate
 * finding, not an error. A future enhancement can swap these for shelling out to Brew-installed
 * `dig` (see pm/engineering.mdx); the checkers only depend on this small surface.
 *
 * Two run-level behaviors live here so every checker gets them for free (pm/run_checks.mdx):
 *  - The PER-RUN DNS MEMO (§2 Stage 0): the audit runner wraps one domain's run in `withDnsMemo`,
 *    and every lookup inside is deduped by `<TYPE>:<name>` — ten checkers asking for the same
 *    TXT/MX record cost one query, and mx_routing's MX list is resolved once per run.
 *  - The LOOKUP BUDGET (§10): one DNS lookup gets 5s and one retry on a transient failure
 *    (SERVFAIL / timeout); on breach the caller sees `error` set and degrades to an `info`
 *    "inconclusive" finding — never a false critical.
 */

export interface DnsLookup<T> {
  /** The records found (empty array when none). */
  records: T[]
  /** True when the name genuinely has no such record (NXDOMAIN / no data). */
  empty: boolean
  /** Set when the lookup failed for a reason other than "no record" (timeout, servfail). */
  error?: string
}

/**
 * One external-tool invocation, recorded verbatim for the run file's per-category `tool_runs[]`
 * audit trail (pm/checks/dns.mdx §3.1/§5): `command` is exactly the argv `execFile` ran (arguments
 * never elided), `output_format` is what we REQUESTED, a timeout stores `exit_code: null` plus a
 * non-null `error`, and a parse failure keeps the raw text under `parsed` with `error` set —
 * failures are recorded, never silently dropped or promoted to fabricated findings.
 */
export interface ToolRunRecord {
  tool: string
  command: string
  started_at: string
  duration_ms: number
  exit_code: number | null
  output_format: "json" | "text"
  parsed: unknown
  error: string | null
}

/** A tool run tagged with the checker that triggered it, so categories persist only their own. */
export interface TaggedToolRun extends ToolRunRecord {
  check_id: string
}

/** Per-run collector for the tool_runs audit trail. Absent outside `withToolRunLog` → no-op. */
const toolLogStorage = new AsyncLocalStorage<TaggedToolRun[]>()
/** Which checker is currently executing (set by the audit runner around each `checker.run`). */
const checkTagStorage = new AsyncLocalStorage<string>()

/**
 * Run `fn` with a per-run tool-run log: every external-tool invocation made inside (dig, …)
 * appends one entry to `records` in execution order (pm/checks/dns.mdx §3.1). Memoized lookups
 * append once per actual invocation — one tool run may feed several sub-tests, but each entry
 * appears once.
 */
export function withToolRunLog<T>(records: TaggedToolRun[], fn: () => Promise<T>): Promise<T> {
  return toolLogStorage.run(records, fn)
}

/** Tag every tool run made inside `fn` with the given checker id (e.g. "infra.dnssec"). */
export function withCheckTag<T>(checkId: string, fn: () => Promise<T>): Promise<T> {
  return checkTagStorage.run(checkId, fn)
}

function recordToolRun(rec: ToolRunRecord): void {
  const log = toolLogStorage.getStore()
  if (!log) return
  log.push({ check_id: checkTagStorage.getStore() ?? "", ...rec })
}

function classify(err: unknown): { empty: boolean; error?: string } {
  const code = (err as NodeJS.ErrnoException)?.code
  if (code === "ENOTFOUND" || code === "ENODATA") return { empty: true }
  return { empty: false, error: code ?? (err instanceof Error ? err.message : String(err)) }
}

/** One DNS lookup's wall-clock budget (pm/run_checks.mdx §10). */
const DNS_TIMEOUT_MS = 5_000

/** The run-scoped memo store. Absent outside `withDnsMemo` (e.g. unit tests) → no caching. */
const memoStorage = new AsyncLocalStorage<Map<string, Promise<unknown>>>()

/**
 * Run `fn` with a fresh per-run DNS memo (pm/run_checks.mdx §2 Stage 0). Every dns-util lookup
 * made inside (across all concurrently-running checkers of one domain) is deduped by record key.
 */
export function withDnsMemo<T>(fn: () => Promise<T>): Promise<T> {
  return memoStorage.run(new Map(), fn)
}

function memo<T>(key: string, compute: () => Promise<T>): Promise<T> {
  const store = memoStorage.getStore()
  if (!store) return compute()
  const hit = store.get(key)
  if (hit) return hit as Promise<T>
  const started = compute()
  store.set(key, started)
  return started
}

/** Race `compute` against the 5s budget; on expiry resolve to the caller-shaped timeout value. */
function raceTimeout<T>(compute: () => Promise<T>, onTimeout: () => T): Promise<T> {
  let timer: NodeJS.Timeout | undefined
  const expiry = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(onTimeout()), DNS_TIMEOUT_MS)
    timer.unref?.()
  })
  return Promise.race([compute(), expiry]).finally(() => clearTimeout(timer))
}

/**
 * The shared lookup pipeline: per-run memo → 5s budget → ONE retry on a transient failure
 * (`error` set: SERVFAIL, timeout, refused). NXDOMAIN/no-data (`empty`) is a real answer and is
 * never retried.
 */
function lookup<T>(
  key: string,
  compute: () => Promise<DnsLookup<T>>,
  retryable: (r: DnsLookup<T>) => boolean = (r) => Boolean(r.error),
): Promise<DnsLookup<T>> {
  const timeoutValue = (): DnsLookup<T> => ({ records: [], empty: false, error: "timeout" })
  return memo(key, async () => {
    const once = () => raceTimeout(compute, timeoutValue)
    const first = await once()
    return retryable(first) ? once() : first
  })
}

/** Resolve TXT records, flattening each record's string chunks into one string. */
export function resolveTxt(name: string): Promise<DnsLookup<string>> {
  return lookup(`TXT:${name}`, async () => {
    try {
      const chunks = await dns.resolveTxt(name)
      return { records: chunks.map((parts) => parts.join("")), empty: chunks.length === 0 }
    } catch (err) {
      return { records: [], ...classify(err) }
    }
  })
}

export interface MxRecord {
  exchange: string
  priority: number
}

export function resolveMx(name: string): Promise<DnsLookup<MxRecord>> {
  return lookup(`MX:${name}`, async () => {
    try {
      const records = await dns.resolveMx(name)
      return { records, empty: records.length === 0 }
    } catch (err) {
      return { records: [], ...classify(err) }
    }
  })
}

export function resolve4(name: string): Promise<DnsLookup<string>> {
  return lookup(`A:${name}`, async () => {
    try {
      const records = await dns.resolve4(name)
      return { records, empty: records.length === 0 }
    } catch (err) {
      return { records: [], ...classify(err) }
    }
  })
}

/** Reverse-DNS (PTR) lookup for an IP. */
export function reverse(ip: string): Promise<DnsLookup<string>> {
  return lookup(`PTR:${ip}`, async () => {
    try {
      const records = await dns.reverse(ip)
      return { records, empty: records.length === 0 }
    } catch (err) {
      return { records: [], ...classify(err) }
    }
  })
}

/** Reverse an IPv4 address for DNSBL queries: 1.2.3.4 → 4.3.2.1. Returns null for non-IPv4. */
export function reverseIpv4(ip: string): string | null {
  const parts = ip.trim().split(".")
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null
  return parts.reverse().join(".")
}

/** Resolve AAAA (IPv6) records. */
export function resolve6(name: string): Promise<DnsLookup<string>> {
  return lookup(`AAAA:${name}`, async () => {
    try {
      const records = await dns.resolve6(name)
      return { records, empty: records.length === 0 }
    } catch (err) {
      return { records: [], ...classify(err) }
    }
  })
}

/** Resolve CNAME records for a name. */
export function resolveCname(name: string): Promise<DnsLookup<string>> {
  return lookup(`CNAME:${name}`, async () => {
    try {
      const records = await dns.resolveCname(name)
      return { records, empty: records.length === 0 }
    } catch (err) {
      return { records: [], ...classify(err) }
    }
  })
}

/** Resolve NS records for a zone. */
export function resolveNs(name: string): Promise<DnsLookup<string>> {
  return lookup(`NS:${name}`, async () => {
    try {
      const records = await dns.resolveNs(name)
      return { records, empty: records.length === 0 }
    } catch (err) {
      return { records: [], ...classify(err) }
    }
  })
}

/** Resolve CAA records for a name. */
export function resolveCaa(name: string): Promise<DnsLookup<import("node:dns").CaaRecord>> {
  return lookup(`CAA:${name}`, async () => {
    try {
      const records = await dns.resolveCaa(name)
      return { records, empty: records.length === 0 }
    } catch (err) {
      return { records: [], ...classify(err) }
    }
  })
}

/** Resolve the SOA record for a zone (single record, or null when absent/error). */
export function resolveSoa(
  name: string,
): Promise<{ record: import("node:dns").SoaRecord | null; empty: boolean; error?: string }> {
  type SoaResult = { record: import("node:dns").SoaRecord | null; empty: boolean; error?: string }
  const compute = async (): Promise<SoaResult> => {
    try {
      const record = await dns.resolveSoa(name)
      return { record, empty: false }
    } catch (err) {
      return { record: null, ...classify(err) }
    }
  }
  // Same memo + budget + one-retry pipeline as `lookup`, for the single-record SOA shape.
  return memo(`SOA:${name}`, async () => {
    const once = () =>
      raceTimeout(compute, (): SoaResult => ({ record: null, empty: false, error: "timeout" }))
    const first = await once()
    return first.error ? once() : first
  })
}

/**
 * Shell out to the Brew-installed `dig` for record types node:dns cannot query directly (TLSA, DS,
 * DNSKEY, RRSIG, SVCB, SMIMEA, etc.). Returns the `+short` answer lines. Never throws: on a missing
 * `dig` binary, timeout, or NXDOMAIN it returns an empty record set with `empty: true` so callers can
 * emit a graceful finding rather than crash. First-round checkers should degrade to an `info`
 * finding when `error` is set (transient) and treat `empty` as "no such record".
 */
export function dig(name: string, type: string): Promise<DnsLookup<string>> {
  // Same per-run memo + one-retry-on-transient pipeline as the node:dns wrappers; a missing `dig`
  // binary (ENOENT) is a capability downgrade, not a transient — never retried.
  return lookup(
    `DIG:${type}:${name}`,
    () => digOnce(name, type),
    (r) => Boolean(r.error) && r.error !== "ENOENT",
  )
}

/** Classify an execFile error for the tool_runs trail: numeric exit code + human error string. */
function classifyExecError(
  err: Error,
  timeoutMs: number,
): { exitCode: number | null; error: string } {
  const e = err as NodeJS.ErrnoException & { killed?: boolean; signal?: NodeJS.Signals | null }
  if (e.killed === true || e.signal === "SIGTERM" || e.signal === "SIGKILL") {
    // Timeout expiry: exit_code null + "timeout after <n> ms" (pm/checks/dns.mdx §3.1 rule 3).
    return { exitCode: null, error: `timeout after ${timeoutMs} ms` }
  }
  const exitCode = typeof e.code === "number" ? e.code : null
  return { exitCode, error: typeof e.code === "string" ? e.code : e.message }
}

async function digOnce(name: string, type: string): Promise<DnsLookup<string>> {
  const { execFile } = await import("node:child_process")
  const args = ["+short", "+time=3", "+tries=1", type, name]
  const command = ["dig", ...args].join(" ")
  const startedAt = new Date().toISOString()
  const t0 = Date.now()
  return await new Promise<DnsLookup<string>>((resolve) => {
    execFile(
      "dig",
      // Tight budget: healthy resolvers answer in well under a second; a query that stalls past ~3s
      // is treated as transient (error set) so a single slow/hung lookup can't blow the audit budget.
      args,
      { timeout: 4000 },
      (err, stdout) => {
        if (err) {
          // ENOENT = dig not installed; treat as transient/unknown, not "no record".
          const code = (err as NodeJS.ErrnoException).code
          const { exitCode, error } = classifyExecError(err, 4000)
          recordToolRun({
            tool: "dig",
            command,
            started_at: startedAt,
            duration_ms: Date.now() - t0,
            exit_code: exitCode,
            output_format: "text",
            parsed: stdout ? { raw: stdout } : null,
            error,
          })
          resolve({ records: [], empty: false, error: code ?? err.message })
          return
        }
        const records = stdout
          .split("\n")
          .map((l) => l.trim())
          .filter(Boolean)
          // dig may emit CNAME chase lines; keep everything, callers parse per type.
          .filter((l) => !l.startsWith(";"))
        recordToolRun({
          tool: "dig",
          command,
          started_at: startedAt,
          duration_ms: Date.now() - t0,
          exit_code: 0,
          output_format: "text",
          parsed: { answers: records },
          error: null,
        })
        resolve({ records, empty: records.length === 0 })
      },
    )
  })
}

/** One RR from a full `dig +noall +answer` response — includes the TTL that `+short` hides. */
export interface DigAnswer {
  /** Owner name, trailing dot stripped. */
  name: string
  ttl: number
  /** RR type as printed by dig (e.g. "TLSA"). */
  type: string
  /** The presentation-format RDATA, tokens re-joined with single spaces. */
  rdata: string
}

/**
 * Full-answer variant of `dig` for checkers that need the record TTL and/or must distinguish a
 * SERVFAIL from an empty answer (pm/checks/dane_tlsa.mdx §3: `SERVFAIL` on a DNSSEC-signed zone
 * signals a validation failure and must NOT be treated as "no record"). Parses the `;; ... status:`
 * comment line: any status other than NOERROR/NXDOMAIN with an empty answer surfaces as `error`.
 * Only RRs of the requested type are returned (CNAME-chase lines are skipped). Same per-run memo +
 * one-retry pipeline as `dig`; a missing binary (ENOENT) is never retried.
 */
export function digAnswer(name: string, type: string): Promise<DnsLookup<DigAnswer>> {
  return lookup(
    `DIGANS:${type}:${name}`,
    () => digAnswerOnce(name, type),
    (r) => Boolean(r.error) && r.error !== "ENOENT",
  )
}

async function digAnswerOnce(name: string, type: string): Promise<DnsLookup<DigAnswer>> {
  const { execFile } = await import("node:child_process")
  const args = ["+time=3", "+tries=1", "+noall", "+comments", "+answer", type, name]
  const command = ["dig", ...args].join(" ")
  const startedAt = new Date().toISOString()
  const t0 = Date.now()
  return await new Promise<DnsLookup<DigAnswer>>((resolve) => {
    execFile("dig", args, { timeout: 4000 }, (err, stdout) => {
      if (err) {
        const code = (err as NodeJS.ErrnoException).code
        const { exitCode, error } = classifyExecError(err, 4000)
        recordToolRun({
          tool: "dig",
          command,
          started_at: startedAt,
          duration_ms: Date.now() - t0,
          exit_code: exitCode,
          output_format: "text",
          parsed: stdout ? { raw: stdout } : null,
          error,
        })
        resolve({ records: [], empty: false, error: code ?? err.message })
        return
      }
      const status = /status: ([A-Z]+)/.exec(stdout)?.[1]
      const records = parseDigAnswer(stdout, type)
      recordToolRun({
        tool: "dig",
        command,
        started_at: startedAt,
        duration_ms: Date.now() - t0,
        exit_code: 0,
        output_format: "text",
        parsed: { answers: records, ...(status ? { rcode: status } : {}) },
        error: null,
      })
      if (records.length === 0 && status && status !== "NOERROR" && status !== "NXDOMAIN") {
        // SERVFAIL / REFUSED / etc. — a lookup failure, not "no such record" (spec AC10).
        resolve({ records: [], empty: false, error: status })
        return
      }
      resolve({ records, empty: records.length === 0 })
    })
  })
}

/** Parse `dig +noall +answer` output lines into DigAnswer RRs of the requested type (exported for tests). */
export function parseDigAnswer(stdout: string, type: string): DigAnswer[] {
  const records: DigAnswer[] = []
  for (const line of stdout.split("\n")) {
    const l = line.trim()
    if (!l || l.startsWith(";")) continue
    const tok = l.split(/\s+/)
    if (tok.length < 5) continue
    const [owner, ttl, cls, rtype] = tok
    if (cls !== "IN" || rtype.toUpperCase() !== type.toUpperCase()) continue
    const ttlNum = Number(ttl)
    if (!Number.isInteger(ttlNum) || ttlNum < 0) continue
    records.push({
      name: owner.replace(/\.$/, ""),
      ttl: ttlNum,
      type: rtype,
      rdata: tok.slice(4).join(" "),
    })
  }
  return records
}
