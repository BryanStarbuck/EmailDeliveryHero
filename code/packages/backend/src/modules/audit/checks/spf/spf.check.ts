import { dig, resolve4, resolve6, resolveMx, resolveTxt } from "./dns-util"
import type { Checker, CheckOutcome, Finding } from "./types"

/**
 * SPF (pm/checks/spf.mdx). Fetches the domain's `v=spf1` TXT record and runs the first-round
 * sub-check set: presence, single-record, RFC 7208 grammar + macro validation, the recursive
 * include/a/mx/exists/redirect expansion with 10-lookup and 2-void accounting, all-qualifier
 * sanity, deprecated ptr, CIDR scope, record length, duplicate mechanisms, and coverage of the
 * domain's configured sending IPs against the expanded pass-set. Returns findings plus the
 * structured `results.spf` payload (parsed mechanisms + the include tree) that the SPF detail
 * page renders.
 */

const MECHANISMS = new Set(["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"])
/** Mechanisms/modifiers that cost one of the 10 allowed DNS lookups (RFC 7208 §4.6.4). */
const LOOKUP_TERMS = new Set(["include", "a", "mx", "ptr", "exists", "redirect"])
const QUALIFIERS = new Set(["+", "-", "~", "?"])
/** Macro letters valid in a domain-spec (RFC 7208 §7.2; c/r/t are exp-only but tolerated). */
const MACRO_LETTERS = new Set([..."slodipvhcrt"])

export interface SpfMechanism {
  qualifier: "+" | "-" | "~" | "?"
  /** ip4 | ip6 | a | mx | ptr | exists | include | all | redirect | exp | unknown. */
  type: string
  value: string | null
  /** Whether evaluating this term costs a DNS lookup. */
  lookup: boolean
  raw: string
}

/** One node of the recursively expanded include/redirect graph (results.spf.include_tree). */
export interface SpfTreeNode {
  /** The term this node represents — `v=spf1 …` at depth 0, else e.g. `include:_spf.google.com`. */
  term: string
  depth: number
  cost_lookups: number
  is_void: boolean
  /** What the term resolved to: child raw record, IPs, or a note (cycle, macro, not expanded). */
  resolved_to: string[]
  children: SpfTreeNode[]
}

export interface SpfIpCoverage {
  ip: string
  covered: boolean
  /** The pass-set entry that covered it, e.g. "ip4:203.0.113.0/24 (via include:_spf.x.com)". */
  matched_by: string | null
}

/** Structured payload persisted as `results.spf` (field names per pm/checks/spf.mdx §5). */
export interface SpfResults {
  query_name: string
  record_found: boolean
  record_count: number
  raw_record: string | null
  mechanisms: SpfMechanism[]
  lookup_count: number
  void_count: number
  all_qualifier: "-all" | "~all" | "?all" | "+all" | null
  has_redirect: boolean
  byte_length: number
  /** valid | permerror | temperror | none. */
  eval_result: string
  include_tree: SpfTreeNode | null
  /** The concrete ip4/ip6 CIDRs the record authorizes, each with its source term. */
  pass_set: { cidr: string; source: string }[]
  ip_coverage: SpfIpCoverage[]
}

/* ------------------------------------------------------------------------------------------------
 * Parsing (pure — unit-tested in spf.check.spec.ts)
 * ---------------------------------------------------------------------------------------------- */

export interface ParsedSpf {
  mechanisms: SpfMechanism[]
  /** Grammar violations (term + why); any entry ⇒ PermError. */
  syntaxErrors: string[]
  /** Malformed %-macros (term + why); any entry ⇒ PermError. */
  macroErrors: string[]
  redirect: string | null
  exp: string | null
}

/** True when the IPv4 dotted-quad is well-formed. */
function isIpv4(s: string): boolean {
  const parts = s.split(".")
  return (
    parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255 && p !== "")
  )
}

/** Loose IPv6 shape check (full validation happens in ipv6ToBigInt). */
function isIpv6(s: string): boolean {
  return /^[0-9a-f:.]+$/i.test(s) && s.includes(":") && ipv6ToBigInt(s) !== null
}

/**
 * Validate the %-macros in a domain-spec. Every `%` must begin `%%`, `%_`, `%-`, or
 * `%{<letter><digits?><r?><delimiters?>}` with a known macro letter (RFC 7208 §7).
 */
export function findMacroError(value: string): string | null {
  for (let i = 0; i < value.length; i++) {
    if (value[i] !== "%") continue
    const next = value[i + 1]
    if (next === "%" || next === "_" || next === "-") {
      i++
      continue
    }
    if (next !== "{") return `stray "%" at position ${i}`
    const close = value.indexOf("}", i)
    if (close === -1) return `unterminated macro "${value.slice(i)}"`
    const body = value.slice(i + 2, close)
    const m = /^([a-z])(\d*)(r?)([.\-+,/_=]*)$/i.exec(body)
    if (!m || !MACRO_LETTERS.has(m[1].toLowerCase())) return `invalid macro "%{${body}}"`
    i = close
  }
  return null
}

/** Domain-spec sanity once macros are stripped: hostname characters only. */
function isDomainSpecish(value: string): boolean {
  const stripped = value.replace(/%\{[^}]*\}|%%|%_|%-/g, "x")
  return /^[a-z0-9._-]+$/i.test(stripped)
}

/** Tokenize + grammar-check one raw `v=spf1 …` record (RFC 7208 §4/§5/§7). */
export function parseSpfRecord(raw: string): ParsedSpf {
  const out: ParsedSpf = {
    mechanisms: [],
    syntaxErrors: [],
    macroErrors: [],
    redirect: null,
    exp: null,
  }
  const terms = raw.trim().split(/\s+/)
  for (const term of terms.slice(1) /* skip v=spf1 */) {
    if (!term) continue

    // Modifiers: name=value (redirect=, exp=; unknown modifiers are ignored per §6).
    const modMatch = /^([a-z][a-z0-9._-]*)=(.*)$/i.exec(term)
    if (modMatch && !QUALIFIERS.has(term[0])) {
      const name = modMatch[1].toLowerCase()
      const value = modMatch[2]
      if (name === "redirect" || name === "exp") {
        if (out[name]) out.syntaxErrors.push(`duplicate ${name}= modifier`)
        if (!value || !isDomainSpecish(value)) {
          out.syntaxErrors.push(`${name}= has an invalid target "${value}"`)
        }
        const macroErr = findMacroError(value)
        if (macroErr) out.macroErrors.push(`${term}: ${macroErr}`)
        out[name] = value || null
        out.mechanisms.push({
          qualifier: "+",
          type: name,
          value: value || null,
          lookup: name === "redirect",
          raw: term,
        })
      }
      // Unknown modifiers are legal and ignored.
      continue
    }

    // Mechanisms: [qualifier]name[:value][/cidr].
    let qualifier: SpfMechanism["qualifier"] = "+"
    let body = term
    if (QUALIFIERS.has(term[0])) {
      qualifier = term[0] as SpfMechanism["qualifier"]
      body = term.slice(1)
    }
    const colon = body.indexOf(":")
    const name = (colon === -1 ? body : body.slice(0, colon)).toLowerCase()
    let value = colon === -1 ? null : body.slice(colon + 1)

    // a/mx may carry a dual-cidr suffix directly on the name: a/24, mx/24//64.
    let bareName = name
    if (colon === -1 && name.includes("/")) bareName = name.slice(0, name.indexOf("/"))

    if (!MECHANISMS.has(bareName)) {
      out.syntaxErrors.push(`unknown mechanism "${term}"`)
      out.mechanisms.push({ qualifier, type: "unknown", value, lookup: false, raw: term })
      continue
    }

    if (colon === -1 && name.includes("/")) value = name.slice(name.indexOf("/"))

    switch (bareName) {
      case "ip4": {
        const [ip, prefix, extra] = (value ?? "").split("/")
        if (!value || !isIpv4(ip) || extra !== undefined) {
          out.syntaxErrors.push(`malformed ip4 term "${term}"`)
        } else if (prefix !== undefined && (!/^\d+$/.test(prefix) || Number(prefix) > 32)) {
          out.syntaxErrors.push(`ip4 prefix out of range in "${term}" (0–32)`)
        }
        break
      }
      case "ip6": {
        const [ip, prefix, extra] = (value ?? "").split("/")
        if (!value || !isIpv6(ip) || extra !== undefined) {
          out.syntaxErrors.push(`malformed ip6 term "${term}"`)
        } else if (prefix !== undefined && (!/^\d+$/.test(prefix) || Number(prefix) > 128)) {
          out.syntaxErrors.push(`ip6 prefix out of range in "${term}" (0–128)`)
        }
        break
      }
      case "include":
      case "exists": {
        if (!value) {
          out.syntaxErrors.push(`${bareName} requires a domain: "${term}"`)
        } else {
          const macroErr = findMacroError(value)
          if (macroErr) out.macroErrors.push(`${term}: ${macroErr}`)
          else if (!isDomainSpecish(value)) out.syntaxErrors.push(`invalid domain in "${term}"`)
        }
        break
      }
      case "a":
      case "mx": {
        // Optional domain, optional /cidr and //cidr6 suffixes.
        const domainPart = value?.replace(/\/\/?\d*$/g, "").replace(/\/\d+(\/\/\d+)?$/, "")
        if (domainPart) {
          const macroErr = findMacroError(domainPart)
          if (macroErr) out.macroErrors.push(`${term}: ${macroErr}`)
          else if (!/^\//.test(domainPart) && !isDomainSpecish(domainPart)) {
            out.syntaxErrors.push(`invalid domain in "${term}"`)
          }
        }
        break
      }
      case "all": {
        if (value !== null) out.syntaxErrors.push(`"all" takes no value: "${term}"`)
        break
      }
      case "ptr":
        break
    }

    out.mechanisms.push({
      qualifier,
      type: bareName,
      value,
      lookup: LOOKUP_TERMS.has(bareName),
      raw: term,
    })
  }
  return out
}

/* ------------------------------------------------------------------------------------------------
 * CIDR matching (pure)
 * ---------------------------------------------------------------------------------------------- */

function ipv4ToInt(ip: string): number | null {
  if (!isIpv4(ip)) return null
  return ip.split(".").reduce((acc, p) => acc * 256 + Number(p), 0)
}

/** Expand an IPv6 string (incl. `::` and IPv4-mapped tails) to a BigInt, or null when malformed. */
export function ipv6ToBigInt(ip: string): bigint | null {
  let s = ip.trim().toLowerCase()
  // IPv4-mapped tail: ::ffff:1.2.3.4 → convert the dotted quad to two hex groups.
  const v4 = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s)
  if (v4) {
    const n = ipv4ToInt(v4[2])
    if (n === null) return null
    s = `${v4[1]}${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`
  }
  const doubles = s.split("::")
  if (doubles.length > 2) return null
  const head = doubles[0] ? doubles[0].split(":") : []
  const tail = doubles.length === 2 && doubles[1] ? doubles[1].split(":") : []
  const groups =
    doubles.length === 2
      ? [...head, ...Array(8 - head.length - tail.length).fill("0"), ...tail]
      : head
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(Number.parseInt(g, 16)), 0n)
}

/** True when `ip` (v4 or v6) falls inside `cidr` (e.g. "203.0.113.0/24", "2001:db8::/32"). */
export function ipInCidr(ip: string, cidr: string): boolean {
  const [base, prefixStr] = cidr.split("/")
  if (isIpv4(base)) {
    const ipN = ipv4ToInt(ip)
    const baseN = ipv4ToInt(base)
    if (ipN === null || baseN === null) return false
    const prefix = prefixStr === undefined ? 32 : Number(prefixStr)
    if (Number.isNaN(prefix) || prefix < 0 || prefix > 32) return false
    if (prefix === 0) return true
    const mask = prefix === 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0
    return (ipN & mask) >>> 0 === (baseN & mask) >>> 0
  }
  const ipB = ipv6ToBigInt(ip)
  const baseB = ipv6ToBigInt(base)
  if (ipB === null || baseB === null) return false
  const prefix = prefixStr === undefined ? 128 : Number(prefixStr)
  if (Number.isNaN(prefix) || prefix < 0 || prefix > 128) return false
  if (prefix === 0) return true
  const mask = ((1n << BigInt(prefix)) - 1n) << BigInt(128 - prefix)
  return (ipB & mask) === (baseB & mask)
}

/* ------------------------------------------------------------------------------------------------
 * Recursive expansion (RFC 7208 §4.6.4 lookup/void accounting)
 * ---------------------------------------------------------------------------------------------- */

interface ExpandState {
  lookups: number
  voids: number
  /** include/redirect targets already entered this run (cycle guard + memo). */
  visited: Set<string>
  passSet: { cidr: string; source: string }[]
  findings: Finding[]
  cycle: boolean
  /** Stop descending once the lookup budget is blown (we still report the overrun count). */
  overBudget: boolean
}

const MAX_DEPTH = 10

/** Expand one already-fetched record's terms, appending child nodes under `node`. */
async function expandTerms(
  domain: string,
  parsed: ParsedSpf,
  depth: number,
  state: ExpandState,
  node: SpfTreeNode,
): Promise<void> {
  for (const mech of parsed.mechanisms) {
    if (!mech.lookup) {
      if (mech.type === "ip4" || mech.type === "ip6") {
        state.passSet.push({ cidr: mech.value ?? "", source: `${mech.raw} (via ${node.term})` })
      }
      continue
    }
    if (state.overBudget) return
    state.lookups++
    const child: SpfTreeNode = {
      term: mech.raw,
      depth: depth + 1,
      cost_lookups: 1,
      is_void: false,
      resolved_to: [],
      children: [],
    }
    node.children.push(child)
    if (state.lookups > 10) {
      state.overBudget = true
      child.resolved_to.push("not expanded — 10-lookup budget already exceeded")
      return
    }

    const target = mech.value && !mech.value.startsWith("/") ? mech.value : domain

    switch (mech.type) {
      case "include":
      case "redirect": {
        if (target.includes("%")) {
          child.resolved_to.push("macro target — not expanded (needs a live message)")
          break
        }
        if (state.visited.has(target)) {
          state.cycle = true
          child.resolved_to.push("cycle — this domain is already being evaluated")
          state.findings.push({
            id: "spf.recursion_depth",
            checkId: "spf",
            title: `SPF ${mech.type} loop via ${target}`,
            severity: "critical",
            detail: `${mech.raw} recurses into a domain already on the evaluation path — receivers treat an include/redirect loop as PermError, so SPF fails for all mail.`,
            remediation: `Break the loop: restructure the records so ${target} does not reference back into the chain.`,
            evidence: mech.raw,
          })
          break
        }
        if (depth + 1 > MAX_DEPTH) {
          child.resolved_to.push("not expanded — nesting too deep")
          break
        }
        state.visited.add(target)
        const lookup = await resolveTxt(target)
        const spf = lookup.records.filter((r) => r.toLowerCase().startsWith("v=spf1"))
        if (lookup.error) {
          child.is_void = false
          child.resolved_to.push(`lookup failed (${lookup.error})`)
          state.findings.push({
            id: "spf.include_resolves",
            checkId: "spf",
            title: `Could not resolve ${mech.raw}`,
            severity: "warning",
            detail: `TXT lookup for ${target} failed (${lookup.error}) — transient failures here evaluate as TempError at receivers.`,
            remediation: `Re-run the audit; if it persists, verify ${target}'s nameservers.`,
            evidence: mech.raw,
          })
          break
        }
        if (spf.length === 0) {
          state.voids++
          child.is_void = true
          child.resolved_to.push("void — no v=spf1 record at the target")
          state.findings.push({
            id: "spf.include_resolves",
            checkId: "spf",
            title: `${mech.raw} points at a domain with no SPF record`,
            severity: "critical",
            detail: `${target} publishes no v=spf1 TXT record; per RFC 7208 an include/redirect whose target has no SPF is a PermError — the whole record fails.`,
            remediation: `Remove ${mech.raw} (a decommissioned vendor?) or fix the SPF record at ${target}.`,
            evidence: mech.raw,
          })
          break
        }
        if (spf.length > 1) {
          child.resolved_to.push(`broken — ${spf.length} v=spf1 records at the target`)
          state.findings.push({
            id: "spf.include_resolves",
            checkId: "spf",
            title: `${mech.raw} target publishes ${spf.length} SPF records`,
            severity: "critical",
            detail: `${target} has multiple v=spf1 records, which is a PermError there — and it propagates up into this record.`,
            remediation: `Contact the operator of ${target} (or drop the ${mech.type}) — exactly one v=spf1 record must remain.`,
            evidence: spf.join(" | "),
          })
          break
        }
        child.resolved_to.push(spf[0])
        const childParsed = parseSpfRecord(spf[0])
        if (childParsed.syntaxErrors.length > 0 || childParsed.macroErrors.length > 0) {
          state.findings.push({
            id: "spf.include_resolves",
            checkId: "spf",
            title: `${mech.raw} target has a syntax-invalid SPF record`,
            severity: "critical",
            detail: `${target}: ${[...childParsed.syntaxErrors, ...childParsed.macroErrors].join("; ")}`,
            remediation: `Fix or remove ${mech.raw}; a nested PermError fails the whole record.`,
            evidence: spf[0],
          })
        }
        await expandTerms(target, childParsed, depth + 1, state, child)
        break
      }
      case "a": {
        const [v4, v6] = await Promise.all([resolve4(target), resolve6(target)])
        const cidr4 = /\/(\d+)(?:\/\/|$)/.exec(mech.value ?? "")?.[1]
        const cidr6 = /\/\/(\d+)$/.exec(mech.value ?? "")?.[1]
        for (const ip of v4.records)
          state.passSet.push({ cidr: cidr4 ? `${ip}/${cidr4}` : ip, source: mech.raw })
        for (const ip of v6.records)
          state.passSet.push({ cidr: cidr6 ? `${ip}/${cidr6}` : ip, source: mech.raw })
        child.resolved_to.push(...v4.records, ...v6.records)
        if (v4.records.length === 0 && v6.records.length === 0 && !v4.error && !v6.error) {
          state.voids++
          child.is_void = true
          child.resolved_to.push("void — no A/AAAA records")
        }
        break
      }
      case "mx": {
        const mx = await resolveMx(target)
        if (mx.records.length === 0) {
          if (!mx.error) {
            state.voids++
            child.is_void = true
            child.resolved_to.push("void — no MX records")
          } else {
            child.resolved_to.push(`lookup failed (${mx.error})`)
          }
          break
        }
        // RFC 7208 caps the MX host expansion at 10 names; those A lookups are not budget-counted.
        for (const rec of mx.records.slice(0, 10)) {
          const ips = await resolve4(rec.exchange)
          for (const ip of ips.records) state.passSet.push({ cidr: ip, source: mech.raw })
          child.resolved_to.push(`${rec.exchange} → ${ips.records.join(", ") || "(no A)"}`)
        }
        break
      }
      case "exists": {
        if (target.includes("%")) {
          child.resolved_to.push("macro target — counted, not resolved")
          break
        }
        const probe = await resolve4(target)
        if (probe.records.length === 0 && !probe.error) {
          state.voids++
          child.is_void = true
          child.resolved_to.push("void — name does not resolve")
        } else {
          child.resolved_to.push(...probe.records)
        }
        break
      }
      case "ptr": {
        // Deprecated (§5.5): costs a lookup but cannot be pre-evaluated without a connecting IP.
        child.resolved_to.push("ptr — counted, not evaluated (deprecated mechanism)")
        break
      }
    }
  }
}

/* ------------------------------------------------------------------------------------------------
 * Apex-level analysis (pure parts exported for tests)
 * ---------------------------------------------------------------------------------------------- */

/** The terminal all qualifier of a parsed record, e.g. "~all" (null when no all term). */
export function allQualifierOf(parsed: ParsedSpf): SpfResults["all_qualifier"] {
  const all = parsed.mechanisms.find((m) => m.type === "all")
  return all ? (`${all.qualifier}all` as SpfResults["all_qualifier"]) : null
}

/** Syntax/policy findings that need no DNS: grammar, macros, all-qualifier, ptr, dup, cidr scope. */
export function analyzeSpfTerms(domain: string, raw: string, parsed: ParsedSpf): Finding[] {
  const findings: Finding[] = []

  if (parsed.syntaxErrors.length > 0) {
    findings.push({
      id: "spf.syntax",
      checkId: "spf",
      title: `SPF record has ${parsed.syntaxErrors.length} syntax error${parsed.syntaxErrors.length === 1 ? "" : "s"}`,
      severity: "critical",
      detail: `RFC 7208 grammar violations (each one is a PermError — receivers ignore the whole record): ${parsed.syntaxErrors.join("; ")}.`,
      remediation: "Fix the offending terms and re-run; the record must parse cleanly end to end.",
      evidence: raw,
    })
  }
  if (parsed.macroErrors.length > 0) {
    findings.push({
      id: "spf.macro",
      checkId: "spf",
      title: "SPF record contains malformed macros",
      severity: "critical",
      detail: `Invalid %-macro sequences (PermError): ${parsed.macroErrors.join("; ")}.`,
      remediation:
        "Correct the macro to a valid %{letter…} form (s l o d i p v h), or remove it if not needed.",
      evidence: raw,
    })
  }
  if (parsed.syntaxErrors.length === 0 && parsed.macroErrors.length === 0) {
    findings.push({
      id: "spf.syntax",
      checkId: "spf",
      title: "Record parses cleanly",
      severity: "ok",
      detail: "Every term matches the RFC 7208 grammar; macros (if any) are well-formed.",
      evidence: raw,
    })
  }

  // Terminal all qualifier.
  const allQ = allQualifierOf(parsed)
  if (allQ === "+all") {
    findings.push({
      id: "spf.all",
      checkId: "spf",
      title: "SPF ends in +all — authorizes the entire internet",
      severity: "critical",
      detail:
        "+all makes every host on the internet an authorized sender for this domain: SPF provides zero protection and some receivers score it as a spam signal in itself.",
      remediation:
        'Change "+all" to "~all" (softfail) now, and to "-all" once coverage is confirmed.',
      evidence: raw,
    })
  } else if (allQ === null && !parsed.redirect) {
    findings.push({
      id: "spf.all",
      checkId: "spf",
      title: "No terminal all mechanism",
      severity: "warning",
      detail:
        "Without an all term the default result is neutral — receivers get no policy for unlisted senders, weakening the record's value.",
      remediation: 'Append "~all" (softfail) or "-all" (hardfail) as the last term.',
      evidence: raw,
    })
  } else if (allQ === "?all") {
    findings.push({
      id: "spf.all",
      checkId: "spf",
      title: "Neutral policy (?all)",
      severity: "warning",
      detail:
        "?all explicitly tells receivers to treat unlisted senders as neutral — functionally close to having no SPF at all.",
      remediation: 'Use "~all" during rollout and "-all" once every legitimate source is listed.',
      evidence: raw,
    })
  } else if (allQ) {
    findings.push({
      id: "spf.all",
      checkId: "spf",
      title: `Sane default policy (${allQ})`,
      severity: "ok",
      detail:
        allQ === "-all"
          ? "-all: unlisted senders hard-fail — strongest without DMARC, and right for non-sending domains. With DMARC enforcing, ~all is gentler on forwarded mail."
          : "~all: unlisted senders soft-fail — the recommended terminal when DMARC is deployed (forwarded mail still gets evaluated by DKIM/DMARC instead of being rejected at SMTP time).",
      evidence: raw,
    })
  }

  // all must be terminal: anything after it never evaluates.
  const mechOnly = parsed.mechanisms.filter((m) => m.type !== "redirect" && m.type !== "exp")
  const allIdx = mechOnly.findIndex((m) => m.type === "all")
  if (allIdx !== -1 && allIdx < mechOnly.length - 1) {
    const dead = mechOnly
      .slice(allIdx + 1)
      .map((m) => m.raw)
      .join(" ")
    findings.push({
      id: "spf.all_terminal",
      checkId: "spf",
      title: "Mechanisms after all are never evaluated",
      severity: "warning",
      detail: `Evaluation stops at "${mechOnly[allIdx].raw}"; the trailing terms are dead: ${dead}.`,
      remediation: `Move "${mechOnly[allIdx].raw}" to the end of the record (or delete the unreachable terms).`,
      evidence: raw,
    })
  }
  // redirect is ignored when an all term exists (§6.1).
  if (parsed.redirect && allIdx !== -1) {
    findings.push({
      id: "spf.redirect",
      checkId: "spf",
      title: "redirect= is ignored because an all term exists",
      severity: "warning",
      detail: `RFC 7208 §6.1: when the record contains an all mechanism, the redirect= modifier is ignored — redirect=${parsed.redirect} does nothing.`,
      remediation:
        "Remove the redirect= modifier, or remove the all term if the redirect is intended.",
      evidence: raw,
    })
  }

  // Deprecated ptr.
  if (parsed.mechanisms.some((m) => m.type === "ptr")) {
    findings.push({
      id: "spf.ptr",
      checkId: "spf",
      title: "Deprecated ptr mechanism in use",
      severity: "warning",
      detail:
        "RFC 7208 §5.5 says ptr SHOULD NOT be used: it is slow, unreliable, and burns a DNS lookup; several large receivers skip it entirely (treated as no-match).",
      remediation:
        "Delete ptr and replace it with explicit ip4:/ip6: ranges or the sender's include:.",
      evidence: raw,
    })
  }

  // Duplicate terms (copy-paste rot; each dup include also wastes a lookup).
  const seen = new Map<string, number>()
  for (const m of parsed.mechanisms)
    seen.set(m.raw.toLowerCase(), (seen.get(m.raw.toLowerCase()) ?? 0) + 1)
  const dups = [...seen.entries()].filter(([, n]) => n > 1).map(([t]) => t)
  if (dups.length > 0) {
    findings.push({
      id: "spf.dup_mechanisms",
      checkId: "spf",
      title: `Duplicate mechanism${dups.length === 1 ? "" : "s"}: ${dups.join(", ")}`,
      severity: "warning",
      detail:
        "The same term appears more than once — harmless to evaluation but each duplicate include/a/mx also burns one of the 10 lookups.",
      remediation: "Remove the duplicates; each network or vendor should appear exactly once.",
      evidence: raw,
    })
  }

  // Absurdly broad CIDR ranges.
  for (const m of parsed.mechanisms) {
    if (m.type !== "ip4" && m.type !== "ip6") continue
    const prefix = /\/(\d+)$/.exec(m.value ?? "")?.[1]
    if (prefix === undefined) continue
    const p = Number(prefix)
    if ((m.type === "ip4" && p === 0) || (m.type === "ip6" && p === 0)) {
      findings.push({
        id: "spf.cidr_scope",
        checkId: "spf",
        title: `${m.raw} authorizes every address (equivalent to +all)`,
        severity: "critical",
        detail: `A /0 range matches the whole internet — the record is trivially spoofable regardless of its all qualifier.`,
        remediation: `Replace ${m.raw} with the actual sending ranges.`,
        evidence: raw,
      })
    } else if ((m.type === "ip4" && p < 8) || (m.type === "ip6" && p < 16)) {
      findings.push({
        id: "spf.cidr_scope",
        checkId: "spf",
        title: `Unusually broad range ${m.raw}`,
        severity: "warning",
        detail: `${m.raw} authorizes an enormous block (${m.type}/${p}). Verify the range really is yours and really all sends mail for ${domain}.`,
        remediation: "Narrow the CIDR to the actual sending ranges.",
        evidence: raw,
      })
    }
  }

  // Record length: >450 bytes risks UDP truncation and TempErrors at strict resolvers.
  const byteLength = Buffer.byteLength(raw, "utf8")
  if (byteLength > 450) {
    findings.push({
      id: "spf.length",
      checkId: "spf",
      title: `Record is very long (${byteLength} bytes)`,
      severity: "warning",
      detail:
        "Records past ~450 bytes must be split into multiple 255-byte TXT strings and can outgrow a 512-byte UDP DNS answer, causing truncation/TCP fallback (TempError at some receivers).",
      remediation:
        "Shorten the record: drop unused includes, replace a/mx with explicit ranges, or flatten.",
      evidence: raw,
    })
  }

  return findings
}

/* ------------------------------------------------------------------------------------------------
 * The checker
 * ---------------------------------------------------------------------------------------------- */

function emptyResults(domain: string): SpfResults {
  return {
    query_name: domain,
    record_found: false,
    record_count: 0,
    raw_record: null,
    mechanisms: [],
    lookup_count: 0,
    void_count: 0,
    all_qualifier: null,
    has_redirect: false,
    byte_length: 0,
    eval_result: "none",
    include_tree: null,
    pass_set: [],
    ip_coverage: [],
  }
}

export const spfCheck: Checker = {
  id: "spf",
  label: "SPF record",
  async run(ctx): Promise<CheckOutcome> {
    const lookup = await resolveTxt(ctx.domain)
    if (lookup.error) {
      return {
        findings: [
          {
            id: "spf.lookup_failed",
            checkId: "spf",
            title: "Could not look up SPF",
            severity: "warning",
            detail: `DNS lookup for TXT ${ctx.domain} failed (${lookup.error}).`,
            remediation:
              "Retry the audit. If it persists, check the domain's authoritative nameservers.",
          },
        ],
        results: { ...emptyResults(ctx.domain), eval_result: "temperror" },
      }
    }

    const spf = lookup.records.filter((r) => r.toLowerCase().startsWith("v=spf1"))
    if (spf.length === 0) {
      return {
        findings: [
          {
            id: "spf.missing",
            checkId: "spf",
            title: "No SPF record",
            severity: "critical",
            detail: `${ctx.domain} has no v=spf1 TXT record. Receivers cannot verify which servers may send for this domain, so mail is likely to be spam-foldered or rejected — and SPF can never contribute to DMARC.`,
            remediation: `Publish a TXT record at the apex: "v=spf1 include:_spf.google.com ~all" (swap the include: for your sending provider). Move to "-all" once every legitimate source is listed.`,
          },
        ],
        results: emptyResults(ctx.domain),
      }
    }

    if (spf.length > 1) {
      return {
        findings: [
          {
            id: "spf.multiple",
            checkId: "spf",
            title: "Multiple SPF records",
            severity: "critical",
            detail: `${ctx.domain} publishes ${spf.length} v=spf1 records. Per RFC 7208 §4.5 this is a PermError — receivers ignore SPF entirely, so the domain is effectively unprotected.`,
            remediation:
              "Merge them into a single TXT record with one v=spf1 prefix and one terminating all mechanism, then delete the extras.",
            evidence: spf.join(" | "),
          },
        ],
        results: {
          ...emptyResults(ctx.domain),
          record_found: true,
          record_count: spf.length,
          raw_record: spf.join(" | "),
          eval_result: "permerror",
        },
      }
    }

    const raw = spf[0]
    const parsed = parseSpfRecord(raw)
    const findings: Finding[] = [
      {
        id: "spf.present",
        checkId: "spf",
        title: "SPF record found",
        severity: "ok",
        detail: `A single v=spf1 record is published at ${ctx.domain}.`,
        evidence: raw,
      },
      ...analyzeSpfTerms(ctx.domain, raw, parsed),
    ]

    // Recursive expansion with lookup/void accounting.
    const tree: SpfTreeNode = {
      term: `v=spf1 (${ctx.domain})`,
      depth: 0,
      cost_lookups: 0,
      is_void: false,
      resolved_to: [raw],
      children: [],
    }
    const state: ExpandState = {
      lookups: 0,
      voids: 0,
      visited: new Set([ctx.domain]),
      passSet: [],
      findings: [],
      cycle: false,
      overBudget: false,
    }
    await expandTerms(ctx.domain, parsed, 0, state, tree)
    findings.push(...state.findings)

    // Lookup budget (§4.6.4: max 10 DNS-querying terms).
    if (state.lookups > 10) {
      findings.push({
        id: "spf.lookups",
        checkId: "spf",
        title: `Too many DNS lookups (${state.lookups} > 10)`,
        severity: "critical",
        detail:
          "RFC 7208 §4.6.4 allows at most 10 DNS-querying mechanisms (include, a, mx, ptr, exists, redirect) across the whole expansion. Receivers return PermError — SPF fails for ALL mail from this domain, valid record or not.",
        remediation:
          "Cut lookups: replace a/mx with explicit ip4:/ip6: ranges, delete unused vendor includes, or flatten nested includes into pinned IP ranges.",
        evidence: raw,
      })
    } else if (state.lookups >= 8) {
      findings.push({
        id: "spf.lookups",
        checkId: "spf",
        title: `Near the lookup ceiling (${state.lookups}/10)`,
        severity: "warning",
        detail:
          "One more vendor include can push the record over the 10-lookup limit and break SPF for all mail. ESP includes also grow without notice.",
        remediation:
          "Trim now: drop unused includes or replace a/mx with explicit ip4:/ip6: ranges before the budget is blown.",
        evidence: raw,
      })
    } else {
      findings.push({
        id: "spf.lookups",
        checkId: "spf",
        title: `Within the lookup budget (${state.lookups}/10)`,
        severity: "ok",
        detail: "The recursive expansion stays under the RFC 7208 10-lookup limit.",
      })
    }

    // Void-lookup budget (§4.6.4: more than 2 void lookups is PermError).
    if (state.voids > 2) {
      findings.push({
        id: "spf.void",
        checkId: "spf",
        title: `Too many void lookups (${state.voids} > 2)`,
        severity: "critical",
        detail:
          "More than two mechanisms resolved to nothing (NXDOMAIN / empty answer). RFC 7208 lets receivers return PermError at this point — and each void term is dead weight anyway.",
        remediation:
          "Remove the include:/a:/mx: terms pointing at names with no records (usually a decommissioned vendor) — the include tree shows exactly which.",
        evidence: raw,
      })
    } else if (state.voids > 0) {
      findings.push({
        id: "spf.void",
        checkId: "spf",
        title: `${state.voids} void lookup${state.voids === 1 ? "" : "s"} (limit 2)`,
        severity: "warning",
        detail:
          "A mechanism resolved to nothing (NXDOMAIN / empty answer) — dead weight that counts toward the 2-void PermError limit and usually marks a stale vendor entry.",
        remediation: "Check the include tree for the void node and delete the stale term.",
        evidence: raw,
      })
    }

    // redirect= target must itself publish a valid record (checked during expansion); here we only
    // verify exp= (not lookup-counted, but the explanation TXT must exist when triggered).
    if (parsed.exp && !parsed.exp.includes("%")) {
      const expLookup = await resolveTxt(parsed.exp)
      if (expLookup.records.length === 0) {
        findings.push({
          id: "spf.exp",
          checkId: "spf",
          title: `exp= target ${parsed.exp} has no TXT record`,
          severity: "warning",
          detail:
            "The exp= modifier names a TXT record whose text is shown to senders on SPF fail; the target does not resolve, so the explanation is never delivered.",
          remediation: `Publish a TXT record at ${parsed.exp}, or drop the exp= modifier.`,
          evidence: raw,
        })
      }
    }

    // Stale deprecated SPF type-99 RR next to the TXT (Brew dig; degrades gracefully when absent).
    const type99 = await dig(ctx.domain, "SPF")
    if (type99.records.length > 0) {
      findings.push({
        id: "spf.dns_type",
        checkId: "spf",
        title: "Deprecated SPF type-99 record still published",
        severity: "info",
        detail:
          "RFC 7208 dropped the DNS SPF (type 99) record type; receivers only read the TXT record, so the type-99 copy is stale config that can drift out of sync.",
        remediation: "Delete the SPF-type (99) record at your DNS console; publish TXT only.",
        evidence: type99.records.join(" | "),
      })
    }

    // Sending-IP coverage against the expanded pass-set.
    const ipCoverage: SpfIpCoverage[] = []
    for (const ip of ctx.sendingIps) {
      const hit = state.passSet.find((p) => ipInCidr(ip, p.cidr))
      ipCoverage.push({ ip, covered: Boolean(hit), matched_by: hit ? hit.source : null })
      if (!hit) {
        const mech = ip.includes(":") ? `ip6:${ip}` : `ip4:${ip}`
        findings.push({
          id: "spf.ip_coverage",
          checkId: "spf",
          title: `Sending IP ${ip} is not covered`,
          severity: "critical",
          detail: `${ip} is configured as a sending IP for ${ctx.domain} but no ip4/ip6/include in the expanded record authorizes it — mail from that host fails SPF.`,
          remediation: `Add "${mech}" (or the sending vendor's include:) before the all term.`,
          evidence: raw,
        })
      }
    }
    if (ctx.sendingIps.length > 0 && ipCoverage.every((c) => c.covered)) {
      findings.push({
        id: "spf.ip_coverage",
        checkId: "spf",
        title: `All ${ctx.sendingIps.length} sending IP${ctx.sendingIps.length === 1 ? "" : "s"} covered`,
        severity: "ok",
        detail: "Every configured sending IP falls inside the record's expanded pass-set.",
      })
    }

    const permerror =
      parsed.syntaxErrors.length > 0 ||
      parsed.macroErrors.length > 0 ||
      state.lookups > 10 ||
      state.voids > 2 ||
      state.cycle ||
      state.findings.some((f) => f.id === "spf.include_resolves" && f.severity === "critical")

    const results: SpfResults = {
      query_name: ctx.domain,
      record_found: true,
      record_count: 1,
      raw_record: raw,
      mechanisms: parsed.mechanisms,
      lookup_count: state.lookups,
      void_count: state.voids,
      all_qualifier: allQualifierOf(parsed),
      has_redirect: Boolean(parsed.redirect),
      byte_length: Buffer.byteLength(raw, "utf8"),
      eval_result: permerror ? "permerror" : "valid",
      include_tree: tree,
      pass_set: state.passSet,
      ip_coverage: ipCoverage,
    }
    return { findings, results }
  },
}
