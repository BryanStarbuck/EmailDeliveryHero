import { resolveTxt } from "../dns-util"
import type { Checker, CheckOutcome, Finding } from "../types"

/**
 * DMARC (pm/checks/dmarc.mdx). Resolves `_dmarc.<domain>`, parses the full tag map, and runs the
 * first-round sub-check set: presence, single-record, syntax/order, policy enforcement (p/sp/np),
 * alignment (adkim/aspf), deprecated pct, reporting (rua/ruf/fo/ri/rf), per-URI size suffixes,
 * external-report authorization (`<domain>._report._dmarc.<report-domain>`), and org-domain walk-up
 * coverage. Returns findings plus the structured `results.dmarc` payload (the parsed record) that
 * the DMARC detail page renders.
 */

const POLICIES = ["none", "quarantine", "reject"] as const
type Policy = (typeof POLICIES)[number]
const POLICY_RANK: Record<Policy, number> = { none: 0, quarantine: 1, reject: 2 }

/**
 * All tags we parse: the DMARCbis set (RFC 9989 adds np/psd/t) plus the legacy RFC 7489 tags that
 * DMARCbis removed (pct/rf/ri) — still parsed, but flagged as obsolete.
 */
const KNOWN_TAGS = new Set([
  "v",
  "p",
  "sp",
  "np",
  "psd",
  "t",
  "adkim",
  "aspf",
  "pct",
  "rua",
  "ruf",
  "fo",
  "ri",
  "rf",
])
const OBSOLETE_TAGS = new Set(["pct", "rf", "ri"])

export interface DmarcExternalAuth {
  report_kind: "rua" | "ruf"
  report_uri: string
  report_domain: string
  /** The name that must hold a v=DMARC1 TXT: `<audited>._report._dmarc.<report-domain>`. */
  auth_name: string
  authorized: boolean
}

/** Structured payload persisted as `results.dmarc` (field names per pm/checks/dmarc.mdx §5). */
export interface DmarcResults {
  query_name: string
  record_found: boolean
  record_count: number
  /** Where the effective record lives — `_dmarc.<domain>` or a parent when covered via walk-up. */
  found_at: string | null
  raw_record: string | null
  parsed: Record<string, string> | null
  policy: Policy | null
  /** Effective subdomain policy (sp=, defaulting to p=). */
  subdomain_policy: Policy | null
  np_policy: string | null
  pct: number | null
  adkim: string
  aspf: string
  rua_uris: string[]
  ruf_uris: string[]
  fo: string | null
  ri: number | null
  is_enforcing: boolean
  external_reports_authorized: boolean | null
  external_report_auth: DmarcExternalAuth[]
}

interface ParsedTag {
  name: string
  value: string
}

/** Tokenize a raw DMARC record into ordered tag/value pairs (names lower-cased, values trimmed). */
export function parseDmarcRecord(raw: string): ParsedTag[] {
  return raw
    .split(";")
    .map((t) => t.trim())
    .filter(Boolean)
    .map((token) => {
      const eq = token.indexOf("=")
      if (eq === -1) return { name: token.toLowerCase(), value: "" }
      return { name: token.slice(0, eq).trim().toLowerCase(), value: token.slice(eq + 1).trim() }
    })
}

/** Split a rua/ruf value into URIs, stripping an optional `!<size>` suffix. */
function splitReportUris(value: string): { uri: string; size: string | null; raw: string }[] {
  return value
    .split(",")
    .map((u) => u.trim())
    .filter(Boolean)
    .map((raw) => {
      const bang = raw.lastIndexOf("!")
      if (bang > 0) return { uri: raw.slice(0, bang), size: raw.slice(bang + 1), raw }
      return { uri: raw, size: null, raw }
    })
}

/** The mail domain of a mailto: report URI (null for non-mailto or malformed). */
function reportDomainOf(uri: string): string | null {
  const m = /^mailto:[^@]+@([a-z0-9.-]+)/i.exec(uri.trim())
  return m ? m[1].toLowerCase().replace(/\.$/, "") : null
}

/** True when `child` equals `parent` or is a subdomain of it (report URI on our own domain). */
function sameOrSubdomainOf(child: string, parent: string): boolean {
  return child === parent || child.endsWith(`.${parent}`)
}

interface Analysis {
  findings: Finding[]
  results: DmarcResults
  /** Distinct external report domains (kind + uri) still needing the _report._dmarc probe. */
  externalReports: { kind: "rua" | "ruf"; uri: string; domain: string }[]
}

/**
 * Pure analysis of one DMARC record for one audited domain — everything that needs no further DNS.
 * `foundAt` is the DNS name the record was read from (own `_dmarc` or a parent via walk-up).
 */
export function analyzeDmarcRecord(domain: string, raw: string, foundAt: string): Analysis {
  const findings: Finding[] = []
  const tags = parseDmarcRecord(raw)
  const map: Record<string, string> = {}
  for (const t of tags) if (!(t.name in map)) map[t.name] = t.value

  // Syntax / ordering: v=DMARC1 must be the first tag; p= should be the second (RFC 7489).
  if (tags.length === 0 || tags[0].name !== "v" || tags[0].value.toUpperCase() !== "DMARC1") {
    findings.push({
      id: "dmarc.syntax",
      checkId: "dmarc",
      title: "DMARC record does not start with v=DMARC1",
      severity: "critical",
      detail:
        "Receivers ignore a DMARC record whose first tag is not v=DMARC1 — the domain is treated as having no policy.",
      remediation: "Rewrite the record so it begins exactly with v=DMARC1; followed by p=.",
      evidence: raw,
    })
  } else if (tags.length < 2 || tags[1].name !== "p") {
    findings.push({
      id: "dmarc.syntax_p_position",
      checkId: "dmarc",
      title: "p= is not the second tag",
      severity: "warning",
      detail:
        "RFC 7489 requires the p= tag immediately after v=DMARC1. Most receivers tolerate it elsewhere, but some strict parsers discard the record.",
      remediation: `Reorder the record: v=DMARC1; p=${map.p ?? "quarantine"}; …`,
      evidence: raw,
    })
  }

  // Policy (p=).
  const policyRaw = map.p?.toLowerCase()
  const policy = (POLICIES as readonly string[]).includes(policyRaw ?? "")
    ? (policyRaw as Policy)
    : null
  if (!policyRaw) {
    findings.push({
      id: "dmarc.no_policy",
      checkId: "dmarc",
      title: "DMARC record has no p= tag",
      severity: "critical",
      detail:
        "Without a policy tag the record is invalid and receivers treat the domain as unprotected.",
      remediation: 'Add a policy, e.g. "; p=quarantine" (or p=none to start monitoring).',
      evidence: raw,
    })
  } else if (!policy) {
    findings.push({
      id: "dmarc.policy",
      checkId: "dmarc",
      title: `Invalid DMARC policy "p=${policyRaw}"`,
      severity: "critical",
      detail: "p= must be none, quarantine, or reject; anything else invalidates the record.",
      remediation: "Set p=none (monitor), p=quarantine, or p=reject.",
      evidence: raw,
    })
  } else if (policy === "none") {
    findings.push({
      id: "dmarc.p_none",
      checkId: "dmarc",
      title: "DMARC policy is monitor-only (p=none)",
      severity: "warning",
      detail:
        "p=none collects reports but tells receivers to deliver failing (spoofed) mail normally — zero protection.",
      remediation:
        "Once aggregate (rua) reports show legitimate mail passing aligned, raise to p=quarantine, then p=reject.",
      evidence: raw,
    })
  } else {
    findings.push({
      id: "dmarc.policy_ok",
      checkId: "dmarc",
      title: `DMARC enforced (p=${policy})`,
      severity: "ok",
      detail: `Receivers are instructed to ${policy} mail that fails DMARC alignment.`,
      evidence: raw,
    })
  }

  // Subdomain policy (sp=, defaults to p=) and np= (DMARCbis non-existent-subdomain policy).
  const spRaw = map.sp?.toLowerCase()
  const sp = (POLICIES as readonly string[]).includes(spRaw ?? "") ? (spRaw as Policy) : null
  const effectiveSp = sp ?? policy
  if (spRaw && !sp) {
    findings.push({
      id: "dmarc.subdomain",
      checkId: "dmarc",
      title: `Invalid subdomain policy "sp=${spRaw}"`,
      severity: "warning",
      detail: "sp= must be none, quarantine, or reject.",
      remediation: "Fix the sp= value, or remove it to inherit p=.",
      evidence: raw,
    })
  } else if (
    policy &&
    POLICY_RANK[policy] > 0 &&
    effectiveSp &&
    POLICY_RANK[effectiveSp] < POLICY_RANK[policy]
  ) {
    findings.push({
      id: "dmarc.subdomain",
      checkId: "dmarc",
      title: `Subdomains weaker than the org policy (sp=${effectiveSp})`,
      severity: "warning",
      detail: `p=${policy} protects the exact domain but sp=${effectiveSp} leaves every subdomain (e.g. anything@foo.${domain}) spoofable.`,
      remediation: `Set sp=${policy} (or remove sp= so subdomains inherit p=${policy}).`,
      evidence: raw,
    })
  } else if (policy && POLICY_RANK[policy] > 0) {
    findings.push({
      id: "dmarc.subdomain_ok",
      checkId: "dmarc",
      title: `Subdomains covered (effective sp=${effectiveSp})`,
      severity: "ok",
      detail: sp
        ? "An explicit sp= covers all subdomains."
        : `No sp= tag, so subdomains inherit p=${policy}.`,
    })
  }
  if (policy && POLICY_RANK[policy] > 0 && !map.np) {
    findings.push({
      id: "dmarc.np",
      checkId: "dmarc",
      title: "No np= (non-existent subdomain) policy",
      severity: "info",
      detail:
        "DMARCbis adds np= so mail from subdomains that do not exist in DNS can be rejected outright.",
      remediation: "If you never send from subdomains, add np=reject.",
    })
  }

  // Alignment modes (adkim / aspf, default relaxed).
  const adkim = (map.adkim ?? "r").toLowerCase()
  const aspf = (map.aspf ?? "r").toLowerCase()
  for (const [tag, value] of [
    ["adkim", adkim],
    ["aspf", aspf],
  ] as const) {
    if (value !== "r" && value !== "s") {
      findings.push({
        id: "dmarc.alignment",
        checkId: "dmarc",
        title: `Invalid alignment mode ${tag}=${value}`,
        severity: "warning",
        detail: `${tag} must be r (relaxed) or s (strict).`,
        remediation: `Set ${tag}=r (or remove the tag; relaxed is the default).`,
        evidence: raw,
      })
    } else if (value === "s") {
      findings.push({
        id: `dmarc.${tag}_strict`,
        checkId: "dmarc",
        title: `Strict ${tag === "adkim" ? "DKIM" : "SPF"} alignment (${tag}=s)`,
        severity: "warning",
        detail: `Strict alignment requires the ${tag === "adkim" ? "DKIM d=" : "Return-Path"} domain to exactly equal the From: domain — mail sent from subdomains or many ESPs will fail DMARC.`,
        remediation: `Use ${tag}=r (relaxed) unless every sender uses the exact From: domain.`,
        evidence: raw,
      })
    }
  }

  // pct= — deprecated in DMARCbis; pct<100 also masks a partial rollout.
  let pct: number | null = null
  if (map.pct !== undefined) {
    pct = /^\d+$/.test(map.pct) ? Number(map.pct) : null
    if (pct === null || pct > 100) {
      findings.push({
        id: "dmarc.pct",
        checkId: "dmarc",
        title: `Invalid pct=${map.pct}`,
        severity: "warning",
        detail: "pct must be an integer 0–100 — and is deprecated in DMARCbis anyway.",
        remediation: "Remove the pct tag.",
        evidence: raw,
      })
    } else if (pct < 100) {
      findings.push({
        id: "dmarc.pct",
        checkId: "dmarc",
        title: `Policy applies to only ${pct}% of mail (pct=${pct})`,
        severity: "warning",
        detail: `Receivers apply the policy to a ${pct}% sample; the rest of failing mail is delivered. DMARCbis deprecates pct entirely — receivers may ignore it.`,
        remediation:
          "Finish the rollout: remove the pct tag so the policy applies to 100% of mail.",
        evidence: raw,
      })
    } else {
      findings.push({
        id: "dmarc.pct",
        checkId: "dmarc",
        title: "Deprecated pct= tag present",
        severity: "info",
        detail: "pct=100 is the default; the tag is deprecated in DMARCbis and can be removed.",
        remediation: "Remove pct=100 at the next DNS edit.",
        evidence: raw,
      })
    }
  }

  // Aggregate reporting (rua=).
  const ruaEntries = map.rua ? splitReportUris(map.rua) : []
  const rufEntries = map.ruf ? splitReportUris(map.ruf) : []
  if (ruaEntries.length === 0) {
    findings.push({
      id: "dmarc.rua",
      checkId: "dmarc",
      title: "No aggregate reporting (rua=)",
      severity: "warning",
      detail:
        "Without rua= you get no visibility into who is sending as your domain or whether legitimate mail is failing alignment.",
      remediation: `Add rua=mailto:dmarc@${domain} (or your report-analytics mailbox).`,
      evidence: raw,
    })
  } else {
    const bad = ruaEntries.filter((e) => !reportDomainOf(e.uri))
    if (bad.length > 0) {
      findings.push({
        id: "dmarc.rua_invalid",
        checkId: "dmarc",
        title: "Invalid rua= report URI",
        severity: "warning",
        detail: `These rua entries are not valid mailto: URIs: ${bad.map((b) => b.raw).join(", ")}`,
        remediation: `Use comma-separated mailto: URIs, e.g. rua=mailto:dmarc@${domain}`,
        evidence: map.rua,
      })
    } else {
      findings.push({
        id: "dmarc.rua_ok",
        checkId: "dmarc",
        title: `Aggregate reports requested (${ruaEntries.length} destination${ruaEntries.length === 1 ? "" : "s"})`,
        severity: "ok",
        detail: `rua=${map.rua}`,
      })
    }
  }
  if (rufEntries.length === 0) {
    findings.push({
      id: "dmarc.ruf",
      checkId: "dmarc",
      title: "No failure reports (ruf=) — optional",
      severity: "info",
      detail:
        "ruf= per-failure samples are optional and privacy-sensitive; most receivers redact or skip them.",
      remediation: `Optionally add ruf=mailto:forensics@${domain}; fo=1.`,
    })
  }

  // fo / ri / rf sanity.
  if (map.fo !== undefined) {
    const tokens = map.fo.split(":").map((t) => t.trim().toLowerCase())
    if (tokens.some((t) => !["0", "1", "d", "s"].includes(t))) {
      findings.push({
        id: "dmarc.fo",
        checkId: "dmarc",
        title: `Invalid fo=${map.fo}`,
        severity: "info",
        detail: "fo tokens must be 0, 1, d, or s (colon-separated).",
        remediation: "Set fo=1 to get a report when either SPF or DKIM fails alignment.",
        evidence: raw,
      })
    }
  } else if (rufEntries.length > 0) {
    findings.push({
      id: "dmarc.fo",
      checkId: "dmarc",
      title: "ruf= set but fo= defaults to 0",
      severity: "info",
      detail:
        "With fo=0 (the default) failure reports are sent only when BOTH SPF and DKIM fail — you miss single-mechanism breakage.",
      remediation: "Add fo=1.",
      evidence: raw,
    })
  }
  let ri: number | null = null
  if (map.ri !== undefined) {
    ri = /^\d+$/.test(map.ri) ? Number(map.ri) : null
    if (ri === null) {
      findings.push({
        id: "dmarc.ri",
        checkId: "dmarc",
        title: `Invalid ri=${map.ri}`,
        severity: "info",
        detail: "ri must be a number of seconds (default 86400 = daily).",
        remediation: "Remove ri or set ri=86400.",
        evidence: raw,
      })
    } else if (ri < 3600) {
      findings.push({
        id: "dmarc.ri",
        checkId: "dmarc",
        title: `Report interval unrealistically low (ri=${ri})`,
        severity: "info",
        detail:
          "Most receivers send aggregate reports daily regardless; very low ri values are ignored.",
        remediation: "Set ri=86400 (or remove the tag).",
        evidence: raw,
      })
    }
  }
  if (map.rf !== undefined && map.rf.toLowerCase() !== "afrf") {
    findings.push({
      id: "dmarc.rf",
      checkId: "dmarc",
      title: `Non-standard report format rf=${map.rf}`,
      severity: "info",
      detail: "The only registered failure-report format is afrf.",
      remediation: "Remove rf (afrf is the default) or set rf=afrf.",
      evidence: raw,
    })
  }

  // Malformed !size suffixes on report URIs.
  const badSizes = [...ruaEntries, ...rufEntries].filter(
    (e) => e.size !== null && !/^\d+[kmgt]?$/i.test(e.size),
  )
  if (badSizes.length > 0) {
    findings.push({
      id: "dmarc.report_uri_size",
      checkId: "dmarc",
      title: "Malformed !size suffix on a report URI",
      severity: "info",
      detail: `Bad size limit on: ${badSizes.map((b) => b.raw).join(", ")} (expected e.g. !10m).`,
      remediation: "Fix the suffix or drop it (plain mailto: is fine).",
    })
  }

  // Unknown / deprecated tags.
  const unknown = tags.filter((t) => !KNOWN_TAGS.has(t.name)).map((t) => t.name)
  if (unknown.length > 0) {
    findings.push({
      id: "dmarc.deprecated_tags",
      checkId: "dmarc",
      title: `Unknown DMARC tag${unknown.length === 1 ? "" : "s"}: ${unknown.join(", ")}`,
      severity: "info",
      detail: "Unknown tags are ignored by receivers but usually indicate a typo.",
      remediation: "Remove or correct the unknown tags.",
      evidence: raw,
    })
  }
  const obsolete = tags
    .filter((t) => OBSOLETE_TAGS.has(t.name) && t.name !== "pct")
    .map((t) => t.name)
  if (obsolete.length > 0) {
    findings.push({
      id: "dmarc.deprecated_tags",
      checkId: "dmarc",
      title: `Obsolete tag${obsolete.length === 1 ? "" : "s"}: ${obsolete.join(", ")}`,
      severity: "info",
      detail: "These tags were removed in DMARCbis (RFC 9989); receivers ignore them.",
      remediation: "Drop the obsolete tags at the next DNS edit.",
      evidence: raw,
    })
  }

  // t=y (RFC 9989 testing flag — the pct=0 replacement): the policy is advisory only.
  if (map.t?.toLowerCase() === "y") {
    findings.push({
      id: "dmarc.testing",
      checkId: "dmarc",
      title: "Record is in testing mode (t=y)",
      severity: "warning",
      detail: `t=y tells receivers the policy is being tested and should not be enforced — effectively p=none regardless of p=${policy ?? "?"}.`,
      remediation: "Remove t=y (or set t=n) once you are ready to enforce the published policy.",
      evidence: raw,
    })
  }

  // External report destinations that need a _report._dmarc authorization probe.
  const externalReports: Analysis["externalReports"] = []
  const seen = new Set<string>()
  for (const [kind, entries] of [
    ["rua", ruaEntries],
    ["ruf", rufEntries],
  ] as const) {
    for (const e of entries) {
      const rd = reportDomainOf(e.uri)
      if (!rd || sameOrSubdomainOf(rd, domain)) continue
      const key = `${kind}:${rd}`
      if (seen.has(key)) continue
      seen.add(key)
      externalReports.push({ kind, uri: e.uri, domain: rd })
    }
  }

  const results: DmarcResults = {
    query_name: `_dmarc.${domain}`,
    record_found: true,
    record_count: 1,
    found_at: foundAt,
    raw_record: raw,
    parsed: map,
    policy,
    subdomain_policy: effectiveSp,
    np_policy: map.np?.toLowerCase() ?? null,
    pct,
    adkim,
    aspf,
    rua_uris: ruaEntries.map((e) => e.uri),
    ruf_uris: rufEntries.map((e) => e.uri),
    fo: map.fo ?? null,
    ri,
    is_enforcing: policy === "quarantine" || policy === "reject",
    external_reports_authorized: null,
    external_report_auth: [],
  }
  return { findings, results, externalReports }
}

/** Parent names to try when the domain itself has no record (approximate org-domain walk-up). */
export function walkUpCandidates(domain: string): string[] {
  const labels = domain.split(".").filter(Boolean)
  const out: string[] = []
  for (let i = 1; i <= labels.length - 2; i++) out.push(labels.slice(i).join("."))
  return out
}

export const dmarcCheck: Checker = {
  id: "dmarc",
  label: "DMARC record",
  async run(ctx): Promise<CheckOutcome> {
    const name = `_dmarc.${ctx.domain}`
    const lookup = await resolveTxt(name)
    if (lookup.error) {
      return {
        findings: [
          {
            id: "dmarc.lookup_failed",
            checkId: "dmarc",
            title: "Could not look up DMARC",
            severity: "warning",
            detail: `DNS lookup for TXT ${name} failed (${lookup.error}).`,
            remediation:
              "Retry the audit; if it persists, verify the domain's nameservers respond for _dmarc.",
          },
        ],
      }
    }

    let dmarc = lookup.records.filter((r) => r.toLowerCase().startsWith("v=dmarc1"))
    let foundAt = name

    // Walk up toward the org domain: a subdomain with no record of its own is still covered by the
    // parent's sp= (RFC 7489 org-domain discovery).
    if (dmarc.length === 0) {
      for (const parent of walkUpCandidates(ctx.domain)) {
        const parentLookup = await resolveTxt(`_dmarc.${parent}`)
        const parentRecords = parentLookup.records.filter((r) =>
          r.toLowerCase().startsWith("v=dmarc1"),
        )
        if (parentRecords.length > 0) {
          dmarc = parentRecords
          foundAt = `_dmarc.${parent}`
          break
        }
      }
    }

    if (dmarc.length === 0) {
      return {
        findings: [
          {
            id: "dmarc.missing",
            checkId: "dmarc",
            title: "No DMARC record",
            severity: "critical",
            detail: `${name} has no v=DMARC1 record (and no parent domain covers it). Anyone can spoof the exact From: domain, and Gmail/Yahoo bulk-sender rules penalize senders without DMARC.`,
            remediation: `Publish a TXT record at _dmarc.${ctx.domain} — start with "v=DMARC1; p=none; rua=mailto:dmarc@${ctx.domain}" to collect reports, then move to p=quarantine and finally p=reject.`,
          },
        ],
        results: {
          query_name: name,
          record_found: false,
          record_count: 0,
          found_at: null,
          raw_record: null,
          parsed: null,
          policy: null,
          subdomain_policy: null,
          np_policy: null,
          pct: null,
          adkim: "r",
          aspf: "r",
          rua_uris: [],
          ruf_uris: [],
          fo: null,
          ri: null,
          is_enforcing: false,
          external_reports_authorized: null,
          external_report_auth: [],
        } satisfies DmarcResults,
      }
    }

    if (dmarc.length > 1) {
      return {
        findings: [
          {
            id: "dmarc.multiple",
            checkId: "dmarc",
            title: "Multiple DMARC records",
            severity: "critical",
            detail:
              "More than one v=DMARC1 record is published; per the spec receivers discard ALL of them, so the domain has no effective policy.",
            remediation: `Delete the extra TXT record(s) so exactly one v=DMARC1 string remains at ${foundAt}.`,
            evidence: dmarc.join(" | "),
          },
        ],
        results: {
          query_name: name,
          record_found: true,
          record_count: dmarc.length,
          found_at: foundAt,
          raw_record: dmarc.join(" | "),
          parsed: null,
          policy: null,
          subdomain_policy: null,
          np_policy: null,
          pct: null,
          adkim: "r",
          aspf: "r",
          rua_uris: [],
          ruf_uris: [],
          fo: null,
          ri: null,
          is_enforcing: false,
          external_reports_authorized: null,
          external_report_auth: [],
        } satisfies DmarcResults,
      }
    }

    const analysis = analyzeDmarcRecord(ctx.domain, dmarc[0], foundAt)
    const { findings, results } = analysis

    if (foundAt !== name) {
      findings.unshift({
        id: "dmarc.present",
        checkId: "dmarc",
        title: `Covered by the parent record at ${foundAt}`,
        severity: "info",
        detail: `${name} has no record of its own; receivers fall back to ${foundAt}, whose subdomain policy (sp=${results.subdomain_policy ?? "none"}) governs this domain.`,
        remediation: `Publish a dedicated record at ${name} if this subdomain needs its own policy or reporting.`,
        evidence: dmarc[0],
      })
    } else {
      findings.unshift({
        id: "dmarc.present",
        checkId: "dmarc",
        title: "DMARC record found",
        severity: "ok",
        detail: `A single v=DMARC1 record is published at ${name}.`,
        evidence: dmarc[0],
      })
    }

    // External-report authorization: for every rua/ruf destination on a foreign domain, the
    // receiver domain must publish `<audited>._report._dmarc.<report-domain>` = v=DMARC1, or the
    // reports are silently dropped.
    for (const ext of analysis.externalReports) {
      const authName = `${ctx.domain}._report._dmarc.${ext.domain}`
      const probe = await resolveTxt(authName)
      const authorized = probe.records.some((r) => r.toLowerCase().startsWith("v=dmarc1"))
      results.external_report_auth.push({
        report_kind: ext.kind,
        report_uri: ext.uri,
        report_domain: ext.domain,
        auth_name: authName,
        authorized,
      })
      if (probe.error && !authorized) {
        findings.push({
          id: "dmarc.external_report_auth",
          checkId: "dmarc",
          title: `Could not verify report authorization for ${ext.domain}`,
          severity: "info",
          detail: `Lookup of ${authName} failed (${probe.error}); re-run to confirm the ${ext.kind} destination is authorized.`,
        })
      } else if (!authorized) {
        findings.push({
          id: "dmarc.external_report_auth",
          checkId: "dmarc",
          title: `Report destination ${ext.domain} is not authorized`,
          severity: "critical",
          detail: `${ext.kind}= points at ${ext.uri}, but ${authName} has no v=DMARC1 TXT record — ${ext.domain} will silently discard your reports.`,
          remediation: `Have ${ext.domain} publish TXT ${authName} = "v=DMARC1" (report providers document this), or point ${ext.kind}= at a mailbox on ${ctx.domain}.`,
        })
      }
    }
    if (analysis.externalReports.length > 0) {
      const allAuthorized = results.external_report_auth.every((a) => a.authorized)
      results.external_reports_authorized = allAuthorized
      if (allAuthorized) {
        findings.push({
          id: "dmarc.external_report_auth_ok",
          checkId: "dmarc",
          title: "External report destinations authorized",
          severity: "ok",
          detail: `All ${results.external_report_auth.length} external report domain(s) publish the _report._dmarc authorization.`,
        })
      }
    }

    return { findings, results }
  },
}
