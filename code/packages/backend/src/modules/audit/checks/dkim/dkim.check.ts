import { createHash, createPublicKey, randomBytes } from "node:crypto"
import { mapLimit } from "@shared/concurrency"
import { readAppConfig } from "@shared/config-store"
import { resolveCname, resolveMx, resolveTxt } from "../dns-util"
import type { Checker, CheckOutcome, Finding, Severity } from "../types"
import { DkimToolBench, type DkimToolRun } from "./dkim-tools"

/**
 * DKIM (pm/checks/dkim.mdx). Audits the DNS-published key side of DKIM per selector: presence
 * (TXT or CNAME→TXT), record parse + key decode (RSA modulus bits via node:crypto; raw-32-byte
 * Ed25519), revocation (empty p=), key strength (RFC 8301), test flag, SHA-1 restriction, tag
 * sanity, single-record rule (RFC 6376 §3.6.2.2), record size, CNAME delegation health — plus the
 * domain-scoped checks: working-selector count, Ed25519-only, duplicate keys (within the run and
 * against the other monitored domains), rotation age, wildcard-TXT shadowing, and MX-guided
 * common-selector discovery when no selectors are configured. Returns findings plus the structured
 * `results.dkim` payload (pm/checks/dkim.mdx §5) that the DKIM detail page renders.
 */

/** M3AAWG rotation guidance: warn past ~6 months, note when approaching. */
const ROTATION_WARN_DAYS = 180
/** The "approaching the window" info fires this many days before the warning. */
const ROTATION_INFO_LEAD_DAYS = 30

/**
 * The configured rotation window (pm/checks/dkim.mdx §2.2 `dkim.rotation` — "config window default
 * 180 days"): `config.yaml → checks.dkim.rotationWindowDays`, falling back to the M3AAWG default.
 */
function rotationWindowDays(): number {
  try {
    const days = readAppConfig().checks.dkim?.rotationWindowDays
    return typeof days === "number" && days > 0 ? days : ROTATION_WARN_DAYS
  } catch {
    return ROTATION_WARN_DAYS
  }
}

/** Bounded fan-out for discovery probes (pm/checks/dkim.mdx §4 — polite, not brute force). */
const DISCOVERY_CONCURRENCY = 6

/**
 * The curated common-selector wordlist (pm/checks/dkim.mdx §4): generic names first, then ESP
 * conventions (SendGrid s1/s2, Mailchimp k1–k3, M365 selector1/2, Google google, HubSpot hs1/hs2,
 * Klaviyo km1/km2, Brevo brevo1/2, Zendesk, Constant Contact ctct1/2, Zoho, Proton, iCloud sig1…).
 * SES random tokens and custom selectors escape any wordlist by design.
 */
export const COMMON_SELECTORS = [
  "default",
  "dkim",
  "dkim1",
  "dkim2",
  "mail",
  "email",
  "smtp",
  "selector",
  "selector1",
  "selector2",
  "key1",
  "key2",
  "k1",
  "k2",
  "k3",
  "s1",
  "s2",
  "smtpapi",
  "s1024",
  "mx",
  "google",
  "mandrill",
  "mte1",
  "mte2",
  "mailjet",
  "pm",
  "hs1",
  "hs2",
  "km1",
  "km2",
  "brevo1",
  "brevo2",
  "zendesk1",
  "zendesk2",
  "ctct1",
  "ctct2",
  "zoho",
  "zmail",
  "protonmail",
  "protonmail2",
  "protonmail3",
  "sig1",
  "sfdc",
  "everlytickey1",
  "everlytickey2",
  "pdk1",
  "mailo",
]

/** MX host → likely selectors, probed first (pm/checks/dkim.mdx §4 MX-guided discovery). */
const MX_SELECTOR_HINTS: { pattern: RegExp; selectors: string[] }[] = [
  { pattern: /google(mail)?\.com$/i, selectors: ["google"] },
  { pattern: /protection\.outlook\.com$/i, selectors: ["selector1", "selector2"] },
  { pattern: /zoho(mail)?\.(com|eu|in)$/i, selectors: ["zoho", "zmail"] },
]

/** One row of `results.dkim.selectors[]` — field names per pm/checks/dkim.mdx §5/§10. */
export interface DkimSelectorResult {
  selector: string
  query_name: string
  source: "configured" | "discovered"
  resolved_via: "txt" | "cname" | "none"
  cname_target: string | null
  present: boolean
  parses: boolean
  raw_record: string | null
  dkim_version: string | null
  key_type: string | null
  key_bits: number | null
  key_sha256: string | null
  has_test_flag: boolean
  has_strict_flag: boolean
  is_revoked: boolean
  txt_record_count: number
  oversize_chunk: boolean
  flags: Record<string, string>
  first_seen_at: string | null
}

/** One per-sub-test row of §5's `tests:` list (`result` ⇔ finding severity ok/critical/warning/info). */
export interface DkimTestRow {
  id: string
  /** Present on per-selector rows (finding ids are suffixed `.<selector>`). */
  selector?: string
  title: string
  result: "pass" | "fail" | "warn" | "info"
  detail?: string
  evidence?: string
  fix?: string
}

/**
 * The whole `dkim:` section of the run YAML (pm/checks/dkim.mdx §5) — the category `status`, the
 * structured per-selector observation, the `tool_runs[]` capture, the per-sub-test `tests[]` rows,
 * and the derived §9 `problem_states`. Persisted verbatim as `results.dkim` under the run file's
 * top-level `dkim` key.
 */
export interface DkimResults {
  /** Worst severity across the tests below (the §5 category status). */
  status: Severity
  selectors_configured: string[]
  discovery_ran: boolean
  working_selectors: number
  wildcard_shadow: boolean
  duplicate_keys: { key_sha256: string; seen_on: string[] }[]
  selectors: DkimSelectorResult[]
  /** Every external tool invocation this run made, in execution order (§3 capture contract). */
  tool_runs: DkimToolRun[]
  /** The per-sub-test rows (§5 `tests[]`) — the findings mapped 1:1, pass and fail alike. */
  tests: DkimTestRow[]
  /** Matched §9 problem-state ids (PS-00…PS-12), derived from the finding ids — never stored separately. */
  problem_states: string[]
}

/** Tokenize a raw DKIM key record into a tag map (names lower-cased, first occurrence wins). */
export function parseDkimRecord(raw: string): Record<string, string> {
  const map: Record<string, string> = {}
  for (const token of raw.split(";")) {
    const t = token.trim()
    if (!t) continue
    const eq = t.indexOf("=")
    const name = (eq === -1 ? t : t.slice(0, eq)).trim().toLowerCase()
    const value = eq === -1 ? "" : t.slice(eq + 1).trim()
    if (name && !(name in map)) map[name] = value
  }
  return map
}

export interface DecodedKey {
  valid: boolean
  keyBits: number | null
  keySha256: string | null
  error?: string
}

/**
 * Base64-decode a p= value and read the key facts. RSA keys are DER SubjectPublicKeyInfo (modulus
 * bits via crypto.createPublicKey); DKIM Ed25519 keys are a raw 32-byte public key (RFC 8463), not
 * DER — accept both raw and SPKI forms. The sha256 of the decoded bytes is the duplicate-key join.
 */
export function decodeDkimKey(p: string, keyType: string): DecodedKey {
  const clean = p.replace(/\s+/g, "")
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) {
    return { valid: false, keyBits: null, keySha256: null, error: "p= is not valid base64" }
  }
  const der = Buffer.from(clean, "base64")
  if (der.length === 0) {
    return { valid: false, keyBits: null, keySha256: null, error: "p= decodes to zero bytes" }
  }
  const keySha256 = createHash("sha256").update(der).digest("hex")
  if (keyType === "ed25519") {
    // Raw 32-byte key is the RFC 8463 shape; a 44-byte DER SPKI also occurs in the wild.
    if (der.length === 32) return { valid: true, keyBits: null, keySha256 }
    try {
      const key = createPublicKey({ key: der, format: "der", type: "spki" })
      if (key.asymmetricKeyType === "ed25519") return { valid: true, keyBits: null, keySha256 }
    } catch {
      /* fall through to invalid below */
    }
    return {
      valid: false,
      keyBits: null,
      keySha256,
      error: `ed25519 key is ${der.length} bytes (expected a raw 32-byte key)`,
    }
  }
  try {
    const key = createPublicKey({ key: der, format: "der", type: "spki" })
    const bits = key.asymmetricKeyDetails?.modulusLength ?? null
    return { valid: true, keyBits: bits, keySha256 }
  } catch (err) {
    return {
      valid: false,
      keyBits: null,
      keySha256,
      error: `p= does not parse as a public key (${err instanceof Error ? err.message : String(err)})`,
    }
  }
}

const KNOWN_TAGS = new Set(["v", "k", "p", "t", "s", "h", "g", "n"])

interface SelectorAnalysis {
  findings: Finding[]
  result: DkimSelectorResult
}

/** Does a TXT string look like a DKIM key record at all? */
function looksLikeDkim(record: string): boolean {
  return /(^|;)\s*v\s*=\s*dkim1/i.test(record) || /(^|;)\s*p\s*=/i.test(record)
}

/**
 * Pure analysis of one selector's fetched TXT record(s) — everything that needs no further DNS.
 * `chunkLengths` are the raw character-string lengths of the evaluated record (record_size check).
 */
export function analyzeSelectorRecord(
  domain: string,
  selector: string,
  source: "configured" | "discovered",
  records: string[],
  opts: {
    resolvedVia: "txt" | "cname"
    cnameTarget: string | null
    chunkLengths: number[]
  },
): SelectorAnalysis {
  const findings: Finding[] = []
  const name = `${selector}._domainkey.${domain}`
  const record = records.find(looksLikeDkim) ?? records[0]
  const tags = parseDkimRecord(record)

  const result: DkimSelectorResult = {
    selector,
    query_name: name,
    source,
    resolved_via: opts.resolvedVia,
    cname_target: opts.cnameTarget,
    present: true,
    parses: false,
    raw_record: record,
    dkim_version: tags.v ?? null,
    key_type: null,
    key_bits: null,
    key_sha256: null,
    has_test_flag: false,
    has_strict_flag: false,
    is_revoked: false,
    txt_record_count: records.length,
    oversize_chunk: opts.chunkLengths.some((l) => l > 255),
    flags: {},
    first_seen_at: null,
  }
  for (const [k, v] of Object.entries(tags)) if (k !== "p") result.flags[k] = v

  const push = (
    sub: string,
    severity: Finding["severity"],
    title: string,
    detail: string,
    remediation?: string,
    evidence?: string,
  ) =>
    findings.push({
      id: `dkim.${sub}.${selector}`,
      checkId: "dkim",
      title,
      severity,
      detail,
      remediation,
      evidence,
    })

  findings.push({
    id: `dkim.present.${selector}`,
    checkId: "dkim",
    title: `DKIM selector "${selector}" present`,
    severity: "ok",
    detail:
      opts.resolvedVia === "cname"
        ? `A DKIM record is published at ${name} via CNAME to ${opts.cnameTarget}.`
        : `A DKIM record is published at ${name}.`,
    evidence: record.slice(0, 120) + (record.length > 120 ? "…" : ""),
  })

  // Single-record rule (RFC 6376 §3.6.2.2): multiple TXT RRs at one selector → undefined results.
  if (records.length > 1) {
    push(
      "single_record",
      "warning",
      `${records.length} TXT records at selector "${selector}"`,
      `RFC 6376 §3.6.2.2: multiple TXT records at one selector name make verifier results undefined — some receivers will pick the wrong one. Evaluating the first DKIM-shaped record.`,
      `Delete the extra TXT record(s) at ${name} so exactly one remains.`,
      records.join(" | "),
    )
  }

  // v= must be DKIM1 when present.
  if (tags.v !== undefined && tags.v.toUpperCase() !== "DKIM1") {
    push(
      "parses",
      "critical",
      `Selector "${selector}" has an invalid v= tag`,
      `The record's v= tag is "${tags.v}" — RFC 6376 requires v=DKIM1 when the tag is present; verifiers return permerror.`,
      `Set v=DKIM1 (or remove the v= tag) at ${name}.`,
      record,
    )
    return { findings, result }
  }

  // p= — required; empty means revoked (RFC 6376 §3.6.1).
  if (tags.p === undefined) {
    push(
      "parses",
      "critical",
      `Selector "${selector}" record has no p= tag`,
      "A DKIM key record without a p= tag is unusable — verifiers return permerror (key syntax error).",
      `Republish the record at ${name} with the p= public key exactly as your provider exported it.`,
      record,
    )
    return { findings, result }
  }
  if (tags.p === "") {
    result.is_revoked = true
    if (source === "configured") {
      push(
        "revoked",
        "critical",
        `Selector "${selector}" has an empty key (revoked)`,
        "An empty p= means this key is revoked (RFC 6376 §3.6.1). Every message still signed with this selector hard-fails at every receiver.",
        `Point the signer at a live selector, or republish a valid public key at ${name} if the revocation was accidental.`,
        record,
      )
    } else {
      push(
        "revoked",
        "info",
        `Discovered selector "${selector}" is revoked (empty p=)`,
        "An empty p= is the correct final step of a key rotation. Nothing to do unless mail still signs with this selector.",
        undefined,
        record,
      )
    }
    return { findings, result }
  }

  const keyType = (tags.k ?? "rsa").toLowerCase()
  result.key_type = keyType
  if (keyType !== "rsa" && keyType !== "ed25519") {
    push(
      "algorithm",
      "warning",
      `Unknown key type k=${keyType} on selector "${selector}"`,
      "Verifiers only understand k=rsa and k=ed25519; an unknown key type is treated as no key.",
      `Set k=rsa (with an RSA key) or k=ed25519 at ${name}.`,
      record,
    )
    return { findings, result }
  }

  const decoded = decodeDkimKey(tags.p, keyType)
  result.key_sha256 = decoded.keySha256
  result.key_bits = decoded.keyBits
  if (!decoded.valid) {
    push(
      "parses",
      "critical",
      `Selector "${selector}" key does not parse`,
      `${decoded.error}. The classic causes are pasted PEM armor (-----BEGIN…), smart quotes, or line breaks injected mid-key; verifiers return permerror (bad base64 / key syntax error).`,
      `Republish the key at ${name} exactly as exported — one logical string, no PEM header/footer, no quotes-in-quotes, no newlines.`,
      record,
    )
    return { findings, result }
  }
  result.parses = true

  // Key strength (RFC 8301): >=1024 required, >=2048 recommended; Ed25519 fixed-strength.
  if (keyType === "rsa" && decoded.keyBits !== null) {
    if (decoded.keyBits < 1024) {
      push(
        "keylength",
        "critical",
        `${decoded.keyBits}-bit RSA key on selector "${selector}"`,
        `Keys under 1024 bits are practically factorable (the 2012 Google 512-bit incident) and rejected by many receivers — RFC 8301 forbids them.`,
        "Generate a 2048-bit RSA key, publish it on a NEW selector, switch signing to it, then retire this selector.",
        record,
      )
    } else if (decoded.keyBits < 2048) {
      push(
        "keylength",
        "warning",
        `${decoded.keyBits}-bit RSA key on selector "${selector}" (upgrade to 2048)`,
        "RFC 8301 requires ≥1024 and recommends ≥2048 bits; 1024-bit keys are a negative trust signal at large receivers.",
        "Generate a 2048-bit RSA key, publish it on a new selector, switch signing, then retire this selector.",
        record,
      )
    } else {
      push(
        "keylength",
        "ok",
        `${decoded.keyBits}-bit RSA key on selector "${selector}"`,
        "Meets the RFC 8301 recommendation (≥2048 bits).",
      )
    }
  } else if (keyType === "ed25519") {
    push(
      "keylength",
      "ok",
      `Ed25519 key on selector "${selector}"`,
      "Ed25519 keys are fixed-strength (RFC 8463). Make sure an RSA selector exists alongside — Gmail/Microsoft/Yahoo cannot verify Ed25519 alone.",
    )
  }

  // t= flags: y = test mode (treated as unsigned), s = strict (no subdomain identities).
  const tFlags = (tags.t ?? "")
    .split(":")
    .map((f) => f.trim().toLowerCase())
    .filter(Boolean)
  result.has_test_flag = tFlags.includes("y")
  result.has_strict_flag = tFlags.includes("s")
  if (result.has_test_flag) {
    push(
      "testflag",
      "warning",
      `Selector "${selector}" is in test mode (t=y)`,
      "t=y tells verifiers to treat mail from this domain as UNSIGNED — no DMARC credit, no reputation benefit.",
      `Remove the y flag from the t= tag (or drop t= entirely) at ${name} once signing is confirmed working.`,
      record,
    )
  } else {
    push(
      "testflag",
      "ok",
      `No test flag on selector "${selector}"`,
      "The record is not in t=y test mode.",
    )
  }
  if (result.has_strict_flag) {
    push(
      "flags",
      "info",
      `Strict flag (t=s) on selector "${selector}"`,
      "t=s forbids subdomain identities (i= must match d= exactly). Fine unless you sign as subdomains.",
    )
  }

  // h= hash restriction: SHA-1-only is forbidden (RFC 8301).
  if (tags.h !== undefined) {
    const hashes = tags.h
      .split(":")
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean)
    if (hashes.length > 0 && hashes.every((h) => h === "sha1")) {
      push(
        "algorithm",
        "critical",
        `Selector "${selector}" restricts hashing to SHA-1 (h=sha1)`,
        "RFC 8301 forbids SHA-1 in DKIM — signatures restricted to it have permanently failed evaluation at modern receivers.",
        `Remove h=sha1 from ${name} and make sure the signer uses rsa-sha256.`,
        record,
      )
    }
  }

  // s= service type must cover email.
  if (tags.s !== undefined) {
    const services = tags.s.split(":").map((s) => s.trim().toLowerCase())
    if (!services.includes("*") && !services.includes("email")) {
      push(
        "flags",
        "warning",
        `Selector "${selector}" service type excludes email (s=${tags.s})`,
        "The s= service type must include email (or *) for the key to apply to mail.",
        `Set s=email (or s=*, or remove the tag) at ${name}.`,
        record,
      )
    }
  }

  // Deprecated g= granularity: anything but * / empty risks not matching the signing identity.
  if (tags.g !== undefined && tags.g !== "*" && tags.g !== "") {
    push(
      "flags",
      "warning",
      `Deprecated g= granularity on selector "${selector}" (g=${tags.g})`,
      "The g= tag was dropped from DKIM; a restrictive value can make verifiers reject the key for the identities you actually sign with.",
      `Remove the g= tag at ${name}.`,
      record,
    )
  }

  // Unknown tags — ignored by verifiers, but usually a typo.
  const unknown = Object.keys(tags).filter((t) => !KNOWN_TAGS.has(t))
  if (unknown.length > 0) {
    push(
      "flags",
      "info",
      `Unknown tag${unknown.length === 1 ? "" : "s"} on selector "${selector}": ${unknown.join(", ")}`,
      "Unknown tags are ignored by receivers but usually indicate a typo.",
      `Remove or correct the unknown tag(s) at ${name}.`,
      record,
    )
  }

  // Record size: each character-string must be ≤255 bytes (bigger strings are rejected by some
  // providers; oversize answers risk UDP truncation → intermittent temperror).
  if (result.oversize_chunk) {
    push(
      "record_size",
      "warning",
      `A TXT string at selector "${selector}" exceeds 255 bytes`,
      "DNS character-strings are capped at 255 bytes; oversize strings are rejected by some providers and oversize answers risk UDP truncation (intermittent temperror).",
      `Split the p= value into ≤255-byte quoted strings at ${name} (most DNS consoles do this automatically); prefer 2048-bit RSA over 4096.`,
      record,
    )
  }

  return { findings, result }
}

export const dkimCheck: Checker = {
  id: "dkim",
  label: "DKIM keys",
  async run(ctx): Promise<CheckOutcome> {
    const findings: Finding[] = []
    // Trailing-dot and case normalization before building any query name (§4 edge case e).
    const domain = normalizeDomain(ctx.domain)
    // The evidence bench (§3): doggo/kdig/openssl/dnsx captures recorded into tool_runs[]. The
    // runs array is shared by reference so entries land in the results as they are captured.
    const bench = new DkimToolBench(ctx.signal, ctx.tools)
    const results: DkimResults = {
      status: "ok",
      selectors_configured: [...ctx.dkimSelectors],
      discovery_ran: false,
      working_selectors: 0,
      wildcard_shadow: false,
      duplicate_keys: [],
      selectors: [],
      tool_runs: bench.runs,
      tests: [],
      problem_states: [],
    }

    // Wildcard-TXT guard (dkim.underscore_label): if a random selector that cannot exist answers,
    // every probe on this domain "resolves" with junk — receivers permerror and discovery is
    // unreliable. The label is `zz-<random8>` per pm/checks/dkim.mdx §3 row 5 / §4 edge case (c).
    const wildcardSelector = `zz-${randomBytes(4).toString("hex")}`
    const wildcardName = `${wildcardSelector}._domainkey.${domain}`
    const wildcardProbe = await resolveTxt(wildcardName)
    await bench.doggoTxt(wildcardName) // §3 row 5 — evidence capture, once per domain
    if (wildcardProbe.records.length > 0) {
      results.wildcard_shadow = true
      findings.push({
        id: "dkim.underscore_label",
        checkId: "dkim",
        title: "A wildcard TXT record shadows _domainkey",
        severity: "warning",
        detail: `A TXT lookup for a selector that cannot exist (${wildcardName}) returned an answer — a wildcard *.${domain} TXT is answering every DKIM query with non-DKIM data. Receivers get permerror junk and selector discovery is unreliable.`,
        remediation: `Publish explicit records under _domainkey and remove or scope the wildcard TXT so it no longer covers *._domainkey.${domain}.`,
        evidence: wildcardProbe.records[0],
      })
    }

    // Which selectors to probe: configured, or (when none) MX-guided discovery over the wordlist.
    let probeList: { selector: string; source: "configured" | "discovered" }[] =
      ctx.dkimSelectors.map((s) => ({ selector: s, source: "configured" as const }))

    if (probeList.length === 0) {
      findings.push({
        id: "dkim.no_selectors",
        checkId: "dkim",
        title: "No DKIM selectors configured",
        severity: "info",
        detail:
          "DKIM selectors are provider-specific and cannot be enumerated from DNS. No selectors were provided for this domain, so discovery probed a curated list of common selector names.",
        remediation:
          'Add your sending provider\'s selector(s) to the domain (e.g. "google" for Google Workspace, "selector1"/"selector2" for Microsoft 365, "s1"/"s2" for SendGrid) so DKIM is audited precisely every run.',
      })
      if (!results.wildcard_shadow) {
        results.discovery_ran = true
        const ordered = await discoveryOrder(domain)
        // §3 row 6 — the dnsx sweep evidence capture (the decision engine stays node:dns below).
        await bench.dnsxSweep(ordered.map((s) => `${s}._domainkey.${domain}`))
        const hits = await mapLimit(ordered, DISCOVERY_CONCURRENCY, async (selector) => {
          const lookup = await resolveTxt(`${selector}._domainkey.${domain}`)
          return lookup.records.some(looksLikeDkim) ? selector : null
        })
        probeList = hits
          .filter((s): s is string => s !== null)
          .map((selector) => ({ selector, source: "discovered" as const }))
        for (const { selector } of probeList) {
          findings.push({
            id: `dkim.selector_discovery.${selector}`,
            checkId: "dkim",
            title: `Discovered DKIM selector "${selector}"`,
            severity: "info",
            detail: `A published DKIM key was found at ${selector}._domainkey.${domain} that is not in this domain's monitored selector list.`,
            remediation: `Add "${selector}" to the domain's selectors so it is audited on every run.`,
          })
        }
        if (probeList.length === 0) {
          findings.push({
            id: "dkim.unsigned",
            checkId: "dkim",
            title: "No DKIM selectors detected — mail is likely unsigned",
            severity: "warning",
            detail:
              "Discovery probed the common-selector wordlist and found no published keys. Either the domain does not sign at all (Gmail/Yahoo bulk-sender rules and Microsoft's 2025 outlook.com enforcement penalize this) or it signs with a custom selector the wordlist cannot know.",
            remediation:
              'Send yourself a message and read the DKIM-Signature header\'s s= tag in Gmail "Show original" — that is the definitive selector — then add it here. If there is no DKIM-Signature at all, enable DKIM at your provider.',
          })
        }
      }
    }

    // Probe every selector (bounded — configured lists are small, discovery lists already filtered).
    const analyses = await mapLimit(probeList, DISCOVERY_CONCURRENCY, ({ selector, source }) =>
      probeSelector(domain, selector, source, bench),
    )
    for (const a of analyses) {
      findings.push(...a.findings)
      if (a.result) results.selectors.push(a.result)
    }

    // Rotation age: carry first_seen_at forward from the previous run when the same key is still
    // published on the same selector; a new key (or first run) starts the clock now.
    const previous = (ctx.previousResults?.dkim as DkimResults | undefined)?.selectors ?? []
    const nowIso = new Date().toISOString()
    const rotationWarnDays = rotationWindowDays()
    const rotationInfoDays = Math.max(1, rotationWarnDays - ROTATION_INFO_LEAD_DAYS)
    for (const sel of results.selectors) {
      if (!sel.key_sha256) continue
      const prev = previous.find(
        (p) => p.selector === sel.selector && p.key_sha256 === sel.key_sha256,
      )
      sel.first_seen_at = prev?.first_seen_at ?? nowIso
      const ageDays = Math.floor((Date.now() - Date.parse(sel.first_seen_at)) / 86_400_000)
      if (ageDays >= rotationWarnDays) {
        findings.push({
          id: `dkim.rotation.${sel.selector}`,
          checkId: "dkim",
          title: `Key on selector "${sel.selector}" is ${ageDays} days old`,
          severity: "warning",
          detail: `M3AAWG guidance is to rotate DKIM keys at least every 6 months; this key has been published unchanged for ${ageDays} days.`,
          remediation:
            "Rotate: publish a fresh key on a new selector ≥48h ahead, switch signing to it, keep the old record 7–30 days, then revoke it (empty p=).",
        })
      } else if (ageDays >= rotationInfoDays) {
        findings.push({
          id: `dkim.rotation.${sel.selector}`,
          checkId: "dkim",
          title: `Key on selector "${sel.selector}" is approaching the rotation window (${ageDays} days)`,
          severity: "info",
          detail: `M3AAWG guidance is ~6-month rotation; plan the next key now so the cutover is unhurried.`,
        })
      }
    }

    // Domain-scoped: working-selector count (rotation headroom).
    const working = results.selectors.filter(
      (s) => s.present && s.parses && (s.key_type === "ed25519" || (s.key_bits ?? 0) >= 1024),
    )
    results.working_selectors = working.length
    if (probeList.length > 0) {
      if (working.length === 0) {
        findings.push({
          id: "dkim.multi",
          checkId: "dkim",
          title: "No working DKIM selector",
          severity: "critical",
          detail:
            "Every probed selector is missing, revoked, unparseable, or too weak — mail from this domain cannot pass DKIM.",
          remediation:
            "Fix the failing selector(s) above; at least one healthy ≥2048-bit key must be published.",
        })
      } else if (working.length === 1) {
        findings.push({
          id: "dkim.multi",
          checkId: "dkim",
          title: "Only 1 working selector (no rotation headroom)",
          severity: "warning",
          detail:
            "With a single selector, the next key rotation is an outage instead of a cutover (compare Microsoft 365's selector1/selector2 pattern).",
          remediation:
            "Publish a second selector now (even before activating it) so rotation is a switch, not a gap.",
        })
      } else {
        findings.push({
          id: "dkim.multi",
          checkId: "dkim",
          title: `${working.length} working selectors`,
          severity: "ok",
          detail: "Multiple healthy selectors give rotation headroom.",
        })
      }
    }

    // Domain-scoped: Ed25519-only (Gmail neutral / Microsoft error / Yahoo permfail — dual-sign).
    if (working.length > 0 && working.every((s) => s.key_type === "ed25519")) {
      findings.push({
        id: "dkim.ed25519_only",
        checkId: "dkim",
        title: "Only Ed25519 keys published (no RSA fallback)",
        severity: "warning",
        detail:
          "Gmail treats Ed25519 signatures as neutral, Microsoft 365 errors on them, and Yahoo permfails — an Ed25519-only domain is effectively unsigned at the big three receivers.",
        remediation:
          "Add an RSA-2048 selector and dual-sign: verifiers accept a message if ANY signature validates, so Ed25519 stays as the modern secondary.",
      })
    }

    // Duplicate keys: same decoded public key on several selectors/domains = one private key
    // signing them all (shared blast radius + shared reputation).
    const seenOn = new Map<string, string[]>()
    for (const sel of results.selectors) {
      if (!sel.key_sha256) continue
      seenOn.set(sel.key_sha256, [
        ...(seenOn.get(sel.key_sha256) ?? []),
        `${domain}/${sel.selector}`,
      ])
    }
    for (const peer of ctx.peerDkimKeys ?? []) {
      if (seenOn.has(peer.keySha256)) {
        seenOn.set(peer.keySha256, [
          ...(seenOn.get(peer.keySha256) ?? []),
          `${peer.domain}/${peer.selector}`,
        ])
      }
    }
    for (const [hash, sightings] of seenOn) {
      if (sightings.length < 2) continue
      results.duplicate_keys.push({ key_sha256: hash, seen_on: sightings })
      findings.push({
        id: "dkim.duplicate_key",
        checkId: "dkim",
        title: "The same DKIM key is published in more than one place",
        severity: "warning",
        detail: `The identical public key appears at: ${sightings.join(", ")}. One private key signs them all — one compromise (or one bad neighbor) spoofs every one of them.`,
        remediation:
          "Generate a unique key pair per domain (and per rotation generation); never copy a private key across brands or domains.",
        evidence: `sha256(p=) ${hash.slice(0, 16)}…`,
      })
    }

    // ---- The §5 `dkim:` section tail — status (worst severity), tests[], problem_states ------
    results.status = worstDkimSeverity(findings)
    results.tests = buildDkimTests(findings, new Set(results.selectors.map((s) => s.selector)))
    results.problem_states = deriveDkimProblemStates(findings, results)

    return { findings, results }
  },
}

const SEVERITY_RANK: Record<Severity, number> = { ok: 0, info: 1, warning: 2, critical: 3 }

/** Finding severity ⇔ §5 `tests[].result` (ok→pass, critical→fail, warning→warn, info→info). */
const RESULT_OF: Record<Severity, DkimTestRow["result"]> = {
  ok: "pass",
  critical: "fail",
  warning: "warn",
  info: "info",
}

/** Worst severity across the run's DKIM findings — the §5 category `status`. */
export function worstDkimSeverity(findings: Finding[]): Severity {
  let worst: Severity = "ok"
  for (const f of findings) if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) worst = f.severity
  return worst
}

/**
 * Findings → §5 `tests[]` rows, pass and fail alike, so the DKIM run page renders one explicit
 * row per sub-test instance. Per-selector finding ids keep their `.<selector>` suffix and the row
 * carries the selector explicitly (the §5 example shape).
 */
export function buildDkimTests(findings: Finding[], selectors: Set<string>): DkimTestRow[] {
  return findings.map((f) => {
    const suffix = f.id.split(".").slice(2).join(".")
    const selector = suffix && selectors.has(suffix) ? suffix : undefined
    return {
      id: f.id,
      ...(selector ? { selector } : {}),
      title: f.title,
      result: RESULT_OF[f.severity],
      ...(f.detail ? { detail: f.detail } : {}),
      ...(f.evidence ? { evidence: f.evidence } : {}),
      ...(f.remediation ? { fix: f.remediation } : {}),
    }
  })
}

/**
 * The §9 problem-state mapping: finding ids at warning/critical severity, matched on their
 * `dkim.<subcheck>` prefix (per-selector ids keep their suffix), → PS ids. PS-00 is the healthy
 * goal state (no open warnings/criticals and ≥1 working selector); PS-13…PS-16 are FUTURE
 * (message/rua layers) and never derived here.
 */
export function deriveDkimProblemStates(findings: Finding[], results: DkimResults): string[] {
  const failing: string[] = []
  for (const f of findings) {
    if (f.severity === "warning" || f.severity === "critical") failing.push(f.id)
  }
  const has = (...prefixes: string[]): boolean =>
    prefixes.some((p) => failing.some((id) => id === p || id.startsWith(`${p}.`)))
  const out: string[] = []
  if (has("dkim.present", "dkim.cname_delegation")) out.push("PS-01")
  if (has("dkim.parses")) out.push("PS-02")
  if (has("dkim.revoked")) out.push("PS-03")
  if (has("dkim.keylength")) out.push("PS-04")
  if (has("dkim.testflag")) out.push("PS-05")
  if (has("dkim.algorithm")) out.push("PS-06")
  if (has("dkim.cname_delegation")) out.push("PS-07")
  if (has("dkim.single_record", "dkim.record_size", "dkim.underscore_label")) out.push("PS-08")
  if (has("dkim.multi", "dkim.rotation")) out.push("PS-09")
  if (has("dkim.duplicate_key")) out.push("PS-10")
  if (has("dkim.ed25519_only")) out.push("PS-11")
  if (has("dkim.unsigned")) out.push("PS-12")
  if (out.length === 0 && failing.length === 0 && results.working_selectors >= 1) out.push("PS-00")
  return out
}

/** One hit from an on-demand discovery probe (the selectors editor's "Run discovery now"). */
export interface DkimDiscoveryHit {
  selector: string
  query_name: string
  key_type: string | null
  key_bits: number | null
  is_revoked: boolean
}

/** The on-demand discovery outcome returned to the selectors editor (pm/checks/dkim.mdx §6.2 item 6). */
export interface DkimDiscoveryOutcome {
  /** True when a wildcard TXT answers every selector — hits are suppressed (§4 edge case c). */
  wildcard_shadow: boolean
  /** How many candidate names were probed (0 when the wildcard guard fired). */
  probed: number
  hits: DkimDiscoveryHit[]
}

/**
 * On-demand selector discovery for the selectors editor's "Run discovery now" action
 * (pm/checks/dkim.mdx §6.2 item 6): probes the §4 MX-guided wordlist regardless of whether
 * selectors are configured, and returns the hits for one-click import. Same politeness rules as
 * the in-run discovery (wildcard guard first, bounded concurrency, curated list — never brute
 * force). This is a live probe, not a run — nothing is persisted.
 */
export async function discoverDkimSelectors(rawDomain: string): Promise<DkimDiscoveryOutcome> {
  const domain = normalizeDomain(rawDomain)
  // Wildcard guard: a wildcard TXT would make every candidate "resolve" with junk (§4 edge case c).
  const wildcardProbe = await resolveTxt(
    `zz-${randomBytes(4).toString("hex")}._domainkey.${domain}`,
  )
  if (wildcardProbe.records.length > 0) return { wildcard_shadow: true, probed: 0, hits: [] }

  const ordered = await discoveryOrder(domain)
  const probes = await mapLimit(
    ordered,
    DISCOVERY_CONCURRENCY,
    async (selector): Promise<DkimDiscoveryHit | null> => {
      const queryName = `${selector}._domainkey.${domain}`
      let records = (await resolveTxt(queryName)).records
      if (!records.some(looksLikeDkim)) {
        // CNAME-delegated selectors whose target the local resolver did not chase.
        const target = (await resolveCname(queryName)).records[0]
        if (!target) return null
        records = (await resolveTxt(target)).records
      }
      const record = records.find(looksLikeDkim)
      if (!record) return null
      const tags = parseDkimRecord(record)
      const keyType = (tags.k ?? "rsa").toLowerCase()
      const decoded = tags.p ? decodeDkimKey(tags.p, keyType) : null
      return {
        selector,
        query_name: queryName,
        key_type: keyType,
        key_bits: decoded?.keyBits ?? null,
        is_revoked: tags.p === "",
      } satisfies DkimDiscoveryHit
    },
  )
  return {
    wildcard_shadow: false,
    probed: ordered.length,
    hits: probes.filter((h): h is DkimDiscoveryHit => h !== null),
  }
}

/** Trailing-dot and case normalization on the domain before building names (§4 edge case e). */
function normalizeDomain(domain: string): string {
  return domain.trim().replace(/\.+$/, "").toLowerCase()
}

/** MX-guided discovery order: provider-hinted selectors first, then the rest of the wordlist. */
async function discoveryOrder(domain: string): Promise<string[]> {
  const hinted: string[] = []
  const mx = await resolveMx(domain)
  for (const record of mx.records) {
    for (const hint of MX_SELECTOR_HINTS) {
      if (hint.pattern.test(record.exchange)) hinted.push(...hint.selectors)
    }
  }
  return [...new Set([...hinted, ...COMMON_SELECTORS])]
}

/**
 * Extract and base64-decode the record's p= value for the openssl cross-check (§3 row 4). Returns
 * null when there is nothing decodable (absent/empty/corrupt p=).
 */
function decodedKeyBytes(rawRecord: string | null): Buffer | null {
  if (!rawRecord) return null
  const p = parseDkimRecord(rawRecord).p
  if (!p) return null
  const clean = p.replace(/\s+/g, "")
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) return null
  const der = Buffer.from(clean, "base64")
  return der.length > 0 ? der : null
}

/**
 * The per-selector evidence captures (§3 rows 1–4) around the node:dns decision result: doggo TXT
 * (CNAME fallback only when TXT was empty), the kdig public-resolver cross-check — a disagreement
 * appends a propagation NOTE to the dkim.present.<selector> finding, never a fabricated critical —
 * and the openssl decode of a parseable key.
 */
async function captureSelectorEvidence(
  bench: DkimToolBench,
  name: string,
  selector: string,
  localTxtCount: number,
  analysis: { findings: Finding[]; result: DkimSelectorResult | null },
): Promise<void> {
  const doggoAnswers = await bench.doggoTxt(name) // §3 row 1
  if ((doggoAnswers?.length ?? 0) === 0 && localTxtCount === 0) {
    await bench.doggoCname(name) // §3 row 2 — CNAME fallback, only when no TXT answered
  }
  const agrees = await bench.kdigCrossCheck(name, localTxtCount) // §3 row 3
  if (agrees === false) {
    const present = analysis.findings.find((f) => f.id === `dkim.present.${selector}`)
    if (present) {
      present.detail += ` Note: the public resolver 8.8.8.8 answers differently from the local resolver for ${name} — propagation lag or resolver-dependent visibility (see the kdig tool run).`
    }
  }
  if (analysis.result?.parses) {
    const der = decodedKeyBytes(analysis.result.raw_record)
    if (der) await bench.opensslDecode(selector, der) // §3 row 4
  }
}

/**
 * String-validate a selector before building `<selector>._domainkey.<domain>` (pm/checks/dkim.mdx
 * §2.2 `dkim.underscore_label` — "the fixed `_domainkey` label present, selector not doubled or
 * misspelled"). Returns the human-readable problem, or null when the selector is a sane DNS name.
 */
export function invalidSelectorReason(selector: string): string | null {
  if (!selector) return "the selector is empty"
  if (/\s/.test(selector)) return "the selector contains whitespace"
  if (selector.toLowerCase().split(".").includes("_domainkey")) {
    return 'the selector repeats the fixed "_domainkey" label (it would be queried doubled)'
  }
  for (const label of selector.split(".")) {
    if (!label) return "the selector has an empty DNS label (leading/trailing or doubled dot)"
    if (label.length > 63) return `the DNS label "${label.slice(0, 24)}…" exceeds 63 octets`
    if (!/^[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?$/.test(label)) {
      return `the DNS label "${label}" contains characters that are not valid in a DNS name`
    }
  }
  return null
}

/** Resolve one selector (TXT, falling back through a CNAME delegation) and analyze the record. */
async function probeSelector(
  domain: string,
  selector: string,
  source: "configured" | "discovered",
  bench: DkimToolBench,
): Promise<{ findings: Finding[]; result: DkimSelectorResult | null }> {
  const name = `${selector}._domainkey.${domain}`
  const emptyResult = (resolvedVia: "none" | "cname", cnameTarget: string | null) => ({
    selector,
    query_name: name,
    source,
    resolved_via: resolvedVia,
    cname_target: cnameTarget,
    present: false,
    parses: false,
    raw_record: null,
    dkim_version: null,
    key_type: null,
    key_bits: null,
    key_sha256: null,
    has_test_flag: false,
    has_strict_flag: false,
    is_revoked: false,
    txt_record_count: 0,
    oversize_chunk: false,
    flags: {},
    first_seen_at: null,
  })

  // §2.2 dkim.underscore_label — string-validate the constructed query name before any DNS: a
  // doubled "_domainkey", stray dot, or junk character would otherwise surface as a misleading
  // "selector missing" critical when the real problem is the selector string itself.
  const invalidReason = invalidSelectorReason(selector)
  if (invalidReason) {
    return {
      findings: [
        {
          id: `dkim.underscore_label.${selector}`,
          checkId: "dkim",
          title: `Selector "${selector}" is not a valid DNS name`,
          severity: "warning",
          detail: `The configured selector cannot form a valid query name (${invalidReason}). The key must live at exactly <selector>._domainkey.${domain} — verifiers would never find a record at "${name}".`,
          remediation: `Fix the selector string in the domain's selector list — enter only the selector label(s) (e.g. "s1"), never the full "_domainkey" name; copy the exact selector from your provider's dashboard or the s= tag of a real DKIM-Signature header.`,
          evidence: name,
        } satisfies Finding,
      ],
      result: emptyResult("none", null),
    }
  }

  const lookup = await rawResolveTxt(name)
  if (lookup.error) {
    // Transient failure — never fabricate a "missing" critical (pm/checks/dkim.mdx §4 edge case d).
    const analysis = {
      findings: [
        {
          id: `dkim.lookup_failed.${selector}`,
          checkId: "dkim",
          title: `Could not look up DKIM selector "${selector}"`,
          severity: "warning",
          detail: `DNS lookup for TXT ${name} failed (${lookup.error}) — could not determine whether the key is published.`,
          remediation:
            "Retry the audit; if it persists, verify the domain's nameservers respond for _domainkey names.",
        } satisfies Finding,
      ],
      result: emptyResult("none", null),
    }
    await captureSelectorEvidence(bench, name, selector, 0, analysis)
    return analysis
  }

  if (lookup.records.length > 0) {
    // node:dns follows CNAME chains transparently, so a healthy delegation still answers the TXT
    // query — probe the CNAME separately so the delegation is recorded (and rotated-by-ESP noted).
    const viaCname = await resolveCname(name)
    const delegatedTo = viaCname.records[0] ?? null
    const analysis = analyzeSelectorRecord(domain, selector, source, lookup.records, {
      resolvedVia: delegatedTo ? "cname" : "txt",
      cnameTarget: delegatedTo,
      chunkLengths: lookup.chunkLengths,
    })
    if (delegatedTo) {
      analysis.findings.push({
        id: `dkim.cname_delegation.${selector}`,
        checkId: "dkim",
        title: `Selector "${selector}" is delegated via CNAME`,
        severity: "ok",
        detail: `${name} → ${delegatedTo}, which resolves to a key. The ESP rotates this key for you.`,
      })
    }
    await captureSelectorEvidence(bench, name, selector, lookup.records.length, analysis)
    return analysis
  }

  // No TXT — check for a CNAME delegation (the SendGrid / M365 / Mailchimp / SES shape).
  const cname = await resolveCname(name)
  const target = cname.records[0] ?? null
  if (target) {
    const targetLookup = await rawResolveTxt(target)
    if (targetLookup.records.length > 0) {
      const analysis = analyzeSelectorRecord(domain, selector, source, targetLookup.records, {
        resolvedVia: "cname",
        cnameTarget: target,
        chunkLengths: targetLookup.chunkLengths,
      })
      analysis.findings.push({
        id: `dkim.cname_delegation.${selector}`,
        checkId: "dkim",
        title: `Selector "${selector}" is delegated via CNAME`,
        severity: "ok",
        detail: `${name} → ${target}, which resolves to a key. The ESP rotates this key for you.`,
      })
      await captureSelectorEvidence(bench, name, selector, 0, analysis)
      await bench.doggoTxt(target) // §3 row 2 tail — #1 re-run against the CNAME target
      return analysis
    }
    // Dangling delegation: the CNAME exists, the target does not answer.
    const analysis = {
      findings: [
        {
          id: `dkim.cname_delegation.${selector}`,
          checkId: "dkim",
          title: `Dangling CNAME on selector "${selector}"`,
          severity: "critical",
          detail: `${name} is a CNAME to ${target}, but the target has no TXT record${targetLookup.error ? ` (lookup: ${targetLookup.error})` : " (NXDOMAIN)"}. Every message signed with this selector fails with permerror — and a stale vendor CNAME is a subdomain-takeover risk.`,
          remediation: `Re-point the CNAME at ${name} to the exact target your ESP's dashboard lists, or remove it if that ESP is decommissioned.`,
          evidence: `${name} CNAME ${target} → no key`,
        } satisfies Finding,
      ],
      result: emptyResult("cname", target),
    }
    await captureSelectorEvidence(bench, name, selector, 0, analysis)
    return analysis
  }

  const missingFinding: Finding = {
    id: `dkim.present.${selector}`,
    checkId: "dkim",
    title: `DKIM selector "${selector}" not found`,
    severity: source === "configured" ? "critical" : "info",
    detail: `No DKIM public key (and no CNAME) is published at ${name}. Mail signed with this selector fails DKIM at every receiver (permerror "no key for signature") — worse than not signing at all.`,
    remediation: `Publish the DKIM TXT record your provider gives you at ${name} (or the CNAME your ESP specifies), or correct the selector name.`,
  }
  const analysis = { findings: [missingFinding], result: emptyResult("none", null) }
  await captureSelectorEvidence(bench, name, selector, 0, analysis)
  return analysis
}

/**
 * Like dns-util's resolveTxt but keeps the raw character-string lengths so the record_size check
 * can spot >255-byte strings (dns-util joins the chunks and loses that information). Transient
 * failures (ESERVFAIL/timeout — anything that is not a definitive ENOTFOUND/ENODATA) are retried
 * ONCE before being surfaced, per pm/checks/dkim.mdx §11 "retry-once-then-warning" — a resolver
 * hiccup must never fabricate a "missing" critical or poison the scheduler's regression diff.
 */
async function rawResolveTxt(
  name: string,
  retried = false,
): Promise<{ records: string[]; chunkLengths: number[]; error?: string }> {
  const { promises: dns } = await import("node:dns")
  try {
    const chunks = await dns.resolveTxt(name)
    return {
      records: chunks.map((parts) => parts.join("")),
      chunkLengths: chunks.flatMap((parts) => parts.map((p) => Buffer.byteLength(p))),
    }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code
    if (code === "ENOTFOUND" || code === "ENODATA") return { records: [], chunkLengths: [] }
    if (!retried) return rawResolveTxt(name, true)
    return {
      records: [],
      chunkLengths: [],
      error: code ?? (err instanceof Error ? err.message : String(err)),
    }
  }
}
