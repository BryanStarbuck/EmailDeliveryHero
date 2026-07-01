import { resolve4, resolve6, resolveCname, resolveTxt } from "./dns-util"
import type { Checker, Finding } from "./types"

/**
 * BIMI (Brand Indicators for Message Identification). Looks up the `default._bimi.<domain>` TXT
 * record and validates everything answerable from DNS (and the domain's DMARC state): the record's
 * presence, its `v=BIMI1` tag grammar, that exactly one record exists, that DMARC is at enforcement
 * (BIMI's hard prerequisite — the logo renders nowhere on `p=none`), that the `l=` (SVG logo) and
 * `a=` (VMC/CMC) tags are present, and that each URL is a syntactically valid HTTPS URL whose host
 * resolves. Fetching the SVG body or the VMC certificate over HTTPS — SVG Tiny-PS profile
 * validation, certificate chain/issuer/expiry checks, and logo-hash matching — is a future round
 * (gated behind the shared HTTPS/TLS probe); those are surfaced here as a single `info` placeholder,
 * never as a warning/critical.
 */

const CHECK_ID = "content.bimi"

interface BimiTags {
  tags: Map<string, string>
  firstTag: string | null
  strayTokens: string[]
  unknownTags: string[]
}

/** Tokenize a BIMI TXT record on `;` into a tag map, tracking ordering and malformed/unknown tokens. */
function parseTags(record: string): BimiTags {
  const tags = new Map<string, string>()
  const strayTokens: string[] = []
  const unknownTags: string[] = []
  const known = new Set(["v", "l", "a"])
  let firstTag: string | null = null
  const parts = record
    .split(";")
    .map((p) => p.trim())
    .filter((p) => p.length > 0)
  for (const part of parts) {
    const eq = part.indexOf("=")
    if (eq === -1) {
      strayTokens.push(part)
      continue
    }
    const key = part.slice(0, eq).trim().toLowerCase()
    const value = part.slice(eq + 1).trim()
    if (firstTag === null) firstTag = key
    if (!known.has(key)) unknownTags.push(key)
    if (!tags.has(key)) tags.set(key, value)
  }
  return { tags, firstTag, strayTokens, unknownTags }
}

/** Resolve a host over A then AAAA. "ok" = at least one address; "empty" = genuinely none; "error" = transient. */
async function hostResolves(host: string): Promise<"ok" | "empty" | "error"> {
  const v4 = await resolve4(host)
  if (v4.records.length > 0) return "ok"
  if (v4.error) return "error"
  const v6 = await resolve6(host)
  if (v6.records.length > 0) return "ok"
  if (v6.error) return "error"
  return "empty"
}

/** Parse a URL string, returning the URL and lowercased scheme (no trailing colon), or nulls if unparseable. */
function parseUrl(value: string): { url: URL | null; scheme: string | null } {
  try {
    const url = new URL(value)
    return { url, scheme: url.protocol.replace(/:$/, "").toLowerCase() }
  } catch {
    return { url: null, scheme: null }
  }
}

/**
 * Validate a `l=`/`a=` URL: it must be a syntactically valid HTTPS URL whose host resolves.
 * `http://`, an unparseable value, or an unresolvable host is `critical`; a transient resolver
 * error degrades to `info`; success is `ok`. (The `200`-status body fetch is a future round.)
 */
async function urlFinding(
  id: string,
  label: string,
  value: string,
  publishRemediation: string,
): Promise<Finding> {
  const { url, scheme } = parseUrl(value)
  if (!url) {
    return {
      id,
      checkId: CHECK_ID,
      title: `${label} is not a valid URL`,
      severity: "critical",
      detail: `The ${label} value "${value}" is not a parseable URL, so receivers cannot fetch it.`,
      remediation: publishRemediation,
      evidence: value,
    }
  }
  if (scheme !== "https") {
    return {
      id,
      checkId: CHECK_ID,
      title: `${label} is not HTTPS`,
      severity: "critical",
      detail: `The ${label} value uses "${scheme}://"; receivers reject non-HTTPS BIMI URLs and will not display the logo.`,
      remediation: publishRemediation,
      evidence: value,
    }
  }
  const state = await hostResolves(url.hostname)
  if (state === "error") {
    return {
      id,
      checkId: CHECK_ID,
      title: `${label} host could not be resolved`,
      severity: "info",
      detail: `A transient DNS error occurred resolving "${url.hostname}" (the ${label} host). Retry the audit later.`,
      remediation:
        "Retry the audit; if it persists, verify the host's authoritative nameservers respond.",
      evidence: value,
    }
  }
  if (state === "empty") {
    return {
      id,
      checkId: CHECK_ID,
      title: `${label} host does not resolve`,
      severity: "critical",
      detail: `The ${label} host "${url.hostname}" has no A/AAAA record, so receivers cannot fetch it and the logo will not render.`,
      remediation: publishRemediation,
      evidence: value,
    }
  }
  return {
    id,
    checkId: CHECK_ID,
    title: `${label} is a valid HTTPS URL`,
    severity: "ok",
    detail: `${label} is an HTTPS URL whose host "${url.hostname}" resolves. (Body fetch / 200-status validation is a future round.)`,
    evidence: value,
  }
}

/** Read `_dmarc.<domain>` and return whether DMARC is published at an enforcing policy. */
async function dmarcEnforcement(domain: string): Promise<{
  state: "enforcing" | "not_enforcing" | "error"
  policy: string | null
  record?: string
}> {
  const { records, error } = await resolveTxt(`_dmarc.${domain}`)
  if (error) return { state: "error", policy: null }
  const dmarc = records.filter((r) => r.toLowerCase().startsWith("v=dmarc1"))
  if (dmarc.length === 0) return { state: "not_enforcing", policy: null }
  const record = dmarc[0]
  const policy = /\bp\s*=\s*(none|quarantine|reject)\b/i.exec(record)?.[1]?.toLowerCase() ?? null
  const enforcing = policy === "quarantine" || policy === "reject"
  return { state: enforcing ? "enforcing" : "not_enforcing", policy, record }
}

export const bimiCheck: Checker = {
  id: "content.bimi",
  label: "BIMI",
  async run(ctx): Promise<Finding[]> {
    const name = `default._bimi.${ctx.domain}`
    const publishRecord = `v=BIMI1; l=https://${ctx.domain}/bimi/logo.svg; a=https://${ctx.domain}/bimi/vmc.pem`
    const publishRemediation = `Publish a single TXT record at ${name}: ${publishRecord}`

    const { records, error } = await resolveTxt(name)

    // Transient resolver failure — distinct from a genuinely-absent record.
    if (error) {
      return [
        {
          id: "content.bimi_present",
          checkId: CHECK_ID,
          title: "Could not look up BIMI",
          severity: "info",
          detail: `DNS lookup for TXT ${name} failed (${error}). Retry the audit later.`,
          remediation:
            "Retry the audit; if it persists, verify the domain's authoritative nameservers respond for _bimi.",
        },
      ]
    }

    const bimiRecords = records.filter((r) => r.trim().toLowerCase().startsWith("v=bimi1"))

    // No BIMI record at all → warning (a brand that should have one), never critical. (§8.1)
    if (bimiRecords.length === 0) {
      return [
        {
          id: "content.bimi_present",
          checkId: CHECK_ID,
          title: "No BIMI record",
          severity: "warning",
          detail: `${name} has no v=BIMI1 TXT record, so supporting receivers (Gmail, Apple Mail, Yahoo, Fastmail) show a generic avatar instead of your brand logo.`,
          remediation: publishRemediation,
        },
      ]
    }

    const findings: Finding[] = []

    findings.push({
      id: "content.bimi_present",
      checkId: CHECK_ID,
      title: "BIMI record present",
      severity: "ok",
      detail: `Found a v=BIMI1 TXT record at ${name}.`,
      evidence: bimiRecords[0],
    })

    // Exactly one record at the _bimi name. (§8.6)
    if (bimiRecords.length > 1) {
      findings.push({
        id: "content.bimi_single",
        checkId: CHECK_ID,
        title: "Multiple BIMI records",
        severity: "warning",
        detail: `${name} publishes ${bimiRecords.length} v=BIMI1 records; multiple records are ambiguous and receivers may ignore BIMI.`,
        remediation:
          "Delete the extra TXT so exactly one v=BIMI1 record remains at the _bimi name.",
        evidence: bimiRecords.join(" | "),
      })
    } else {
      findings.push({
        id: "content.bimi_single",
        checkId: CHECK_ID,
        title: "Single BIMI record",
        severity: "ok",
        detail: "Exactly one v=BIMI1 TXT record is published.",
      })
    }

    const record = bimiRecords[0]
    const { tags, firstTag, strayTokens, unknownTags } = parseTags(record)
    const l = tags.get("l")
    const a = tags.get("a")

    // Syntax: v=BIMI1 must be first, only known tags (v/l/a), no stray tokens. (§8 — malformed → critical)
    const vValue = tags.get("v")
    const syntaxProblems: string[] = []
    if (firstTag !== "v" || (vValue ?? "").toUpperCase() !== "BIMI1") {
      syntaxProblems.push("v=BIMI1 must be the first tag")
    }
    if (strayTokens.length > 0) {
      syntaxProblems.push(`stray token(s): ${strayTokens.join(", ")}`)
    }
    if (unknownTags.length > 0) {
      syntaxProblems.push(`unknown tag(s): ${unknownTags.join(", ")}`)
    }
    if (syntaxProblems.length > 0) {
      findings.push({
        id: "content.bimi_syntax",
        checkId: CHECK_ID,
        title: "Malformed BIMI record",
        severity: "critical",
        detail: `The BIMI record does not parse cleanly (${syntaxProblems.join("; ")}); receivers will ignore it.`,
        remediation:
          'Fix the offending tag so the record reads like "v=BIMI1; l=https://…/logo.svg; a=https://…/vmc.pem" — v=BIMI1 must be first and l= must be a valid HTTPS URL.',
        evidence: record,
      })
    } else {
      findings.push({
        id: "content.bimi_syntax",
        checkId: CHECK_ID,
        title: "BIMI record syntax valid",
        severity: "ok",
        detail:
          "The record parses: v=BIMI1 first, only known tags, valid ;-separated tag=value pairs.",
        evidence: record,
      })
    }

    // Declined record (v=BIMI1; l=; a=;) is intentionally "no logo" → info, not a failure. (§3)
    const declined = tags.has("l") && (l ?? "") === "" && (a ?? "") === ""
    if (declined) {
      findings.push({
        id: "content.bimi_l_present",
        checkId: CHECK_ID,
        title: "BIMI declined (empty l=)",
        severity: "info",
        detail:
          "This is a valid declined BIMI record (empty l=), meaning the domain intentionally publishes no logo.",
        evidence: record,
      })
      return findings
    }

    // DMARC-at-enforcement prerequisite. Record present + DMARC not enforcing → critical. (§8.2/8.3)
    const dmarc = await dmarcEnforcement(ctx.domain)
    if (dmarc.state === "error") {
      findings.push({
        id: "content.bimi_dmarc_prereq",
        checkId: CHECK_ID,
        title: "Could not determine DMARC state",
        severity: "info",
        detail: `A transient DNS error prevented reading _dmarc.${ctx.domain}, so BIMI's DMARC prerequisite could not be confirmed. Retry the audit later.`,
        remediation:
          "Retry the audit; if it persists, verify the domain's nameservers respond for _dmarc.",
      })
    } else if (dmarc.state === "enforcing") {
      findings.push({
        id: "content.bimi_dmarc_prereq",
        checkId: CHECK_ID,
        title: `DMARC enforcing (p=${dmarc.policy})`,
        severity: "ok",
        detail: `DMARC is published at p=${dmarc.policy}, satisfying BIMI's hard prerequisite so the logo can render.`,
        evidence: dmarc.record,
      })
    } else {
      const stateText = dmarc.policy ? `p=${dmarc.policy}` : "absent"
      findings.push({
        id: "content.bimi_dmarc_prereq",
        checkId: CHECK_ID,
        title: "BIMI ignored: DMARC not at enforcement",
        severity: "critical",
        detail: `A BIMI record is published but DMARC is ${stateText}. Receivers ignore BIMI unless DMARC is p=quarantine or p=reject, so the logo renders nowhere.`,
        remediation: `Move DMARC to p=quarantine then p=reject (see ./dmarc.mdx) — e.g. publish "v=DMARC1; p=quarantine; rua=mailto:dmarc@${ctx.domain}" at _dmarc.${ctx.domain} and tighten to p=reject. Until then BIMI will never render.`,
        evidence: dmarc.record,
      })
    }

    // l= (SVG logo URL) presence. (§8 — bimi_l_present)
    if (!tags.has("l") || (l ?? "") === "") {
      findings.push({
        id: "content.bimi_l_present",
        checkId: CHECK_ID,
        title: "BIMI l= (logo URL) missing",
        severity: "warning",
        detail:
          "The record has no non-empty l= tag, so no logo will show even where DMARC and the VMC are in place.",
        remediation: `Set l= to the HTTPS URL of your SVG Tiny-PS logo, e.g. l=https://${ctx.domain}/bimi/logo.svg`,
        evidence: record,
      })
    } else {
      findings.push({
        id: "content.bimi_l_present",
        checkId: CHECK_ID,
        title: "BIMI l= (logo URL) present",
        severity: "ok",
        detail: "The l= (SVG logo URL) tag is present.",
        evidence: l,
      })
      findings.push(
        await urlFinding(
          "content.bimi_svg_url",
          "l= (SVG logo URL)",
          l as string,
          `Host the SVG at an https:// URL that returns 200, e.g. l=https://${ctx.domain}/bimi/logo.svg`,
        ),
      )
    }

    // a= (VMC/CMC URL) presence — Gmail/Apple won't render a logo without a verified mark. (§8.5)
    if (!tags.has("a") || (a ?? "") === "") {
      findings.push({
        id: "content.bimi_vmc",
        checkId: CHECK_ID,
        title: "No VMC/CMC (a= tag missing)",
        severity: "warning",
        detail:
          "The record has l= but no a= tag. Gmail and Apple Mail will not show a logo without a valid Verified Mark Certificate (VMC) or Common Mark Certificate (CMC).",
        remediation:
          "Obtain a VMC (registered trademark) or CMC (non-trademark mark) from a Mark Verifying Authority (e.g. DigiCert or Entrust) and publish its PEM URL in a=, e.g. a=https://" +
          ctx.domain +
          "/bimi/vmc.pem",
        evidence: record,
      })
    } else {
      findings.push({
        id: "content.bimi_vmc",
        checkId: CHECK_ID,
        title: "VMC/CMC (a= tag) present",
        severity: "ok",
        detail: "The a= (VMC/CMC certificate URL) tag is present.",
        evidence: a,
      })
      findings.push(
        await urlFinding(
          "content.bimi_vmc_url",
          "a= (VMC/CMC URL)",
          a as string,
          `Host the VMC PEM at an https:// URL returning 200, e.g. a=https://${ctx.domain}/bimi/vmc.pem`,
        ),
      )
    }

    // DNS health: a dangling CNAME on the _bimi name means the record silently disappears. (§8 — bimi_dns_health)
    const cname = await resolveCname(name)
    if (cname.records.length > 0) {
      const target = cname.records[0]
      const targetState = await hostResolves(target)
      if (targetState === "empty") {
        findings.push({
          id: "content.bimi_dns_health",
          checkId: CHECK_ID,
          title: "Dangling CNAME on _bimi",
          severity: "warning",
          detail: `${name} is a CNAME to "${target}", which does not resolve — the BIMI record depends on an unclaimed/dead host.`,
          remediation: `Point ${name} directly at the TXT record or a claimed host; remove the dangling CNAME to "${target}".`,
          evidence: `${name} CNAME ${target}`,
        })
      } else {
        findings.push({
          id: "content.bimi_dns_health",
          checkId: CHECK_ID,
          title: "BIMI _bimi name resolves cleanly",
          severity: "ok",
          detail: `${name} is a CNAME to "${target}", which resolves.`,
          evidence: `${name} CNAME ${target}`,
        })
      }
    } else {
      findings.push({
        id: "content.bimi_dns_health",
        checkId: CHECK_ID,
        title: "BIMI _bimi name resolves cleanly",
        severity: "ok",
        detail: `${name} resolves directly to a TXT record with no dangling CNAME.`,
      })
    }

    // Future round: SVG body (Tiny-PS profile / square viewBox) and VMC certificate (chain, MVA
    // allow-list, expiry, logo-hash match) all require an HTTPS fetch. Never emitted as warn/critical.
    findings.push({
      id: "content.bimi_future_validation",
      checkId: CHECK_ID,
      title: "Logo & certificate validation pending (future round)",
      severity: "info",
      detail:
        "A future round will fetch the l= SVG over HTTPS to validate the SVG Tiny-PS profile (baseProfile=tiny-ps, square viewBox, no scripts/external refs/animation, size cap) and fetch the a= VMC PEM to verify its chain against the Mark Verifying Authority allow-list, its expiry, and that its embedded logotype matches the served SVG. These are not checked in the first (DNS-only) round.",
    })

    return findings
  },
}
