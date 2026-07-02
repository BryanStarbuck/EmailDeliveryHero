import { deriveTlsRptFindings } from "@module/reports/derive-findings"
import { resolve4, resolve6, resolveMx, resolveTxt } from "../dns-util"
import type { Checker, CheckOutcome, Finding } from "../types"

/**
 * TLS-RPT (SMTP TLS Reporting, RFC 8460). Inspects the TXT record at `_smtp._tls.<domain>` that tells
 * remote MTAs where to mail daily aggregate reports about STARTTLS / MTA-STS / DANE negotiation
 * failures. First round is pure DNS: presence, singleton state, `v=TLSRPTv1` syntax/version, `rua`
 * endpoint grammar + scheme, unknown-tag and stray-TXT hygiene, plus an advisory MX/A reachability
 * probe of each `rua` target. Actually ingesting and parsing the JSON reports (and TTL sanity, which
 * needs a full `dig` answer) are future capabilities that emit a single muted `info` each.
 *
 * The structured observation (spec §5 `tls_rpt_check_results` — today the `checks.tls_rpt` object
 * embedded in the audit JSON) is returned as this checker's `results` payload and lands at
 * `AuditResult.results["infra.tls_rpt"]`, one per (run, domain). The scheduler's regression diff
 * (spec §6) compares each run's findings against the previous snapshot to flag record
 * disappearance, new duplicates, and rua breakage as new problems.
 */

const CHECK_ID = "infra.tls_rpt"
const KNOWN_TAGS = new Set(["v", "rua"])

interface RuaEndpoint {
  uri: string
  scheme: "mailto" | "https"
  domain: string
  host: string
  sizeLimit: string | null
  external: boolean
  /** Advisory MX/A reachability: true/false once probed, null when the probe was transient. */
  reachable: boolean | null
}

/**
 * One parsed rua endpoint as persisted in the results payload (spec §5 `rua_endpoints` JSONB —
 * `[{ "uri", "scheme", "domain", "size_limit", "reachable", "external" }]`, camelCase here per the
 * file-store mapping).
 */
export interface TlsRptRuaEndpoint {
  uri: string
  scheme: "mailto" | "https"
  domain: string
  sizeLimit: string | null
  reachable: boolean | null
  external: boolean
}

/**
 * The structured, parsed TLS-RPT observation for one domain in one audit run — the JSON-file
 * projection of the spec §5 `tls_rpt_check_results` row (`checks.tls_rpt`, camelCase exactly as
 * the spec's file-store mapping). When storage graduates to Postgres this object becomes one row
 * keyed by (audit_run_id, domain_id) — a store-only change, no checker changes.
 */
export interface TlsRptResults {
  /** A TLSRPTv1 record exists at `_smtp._tls.<domain>`. */
  present: boolean
  /** Number of TLSRPTv1 TXT strings found (singleton check). */
  recordCount: number
  /** Reassembled TXT string as published (the single record when present). */
  rawRecord: string | null
  /** Record starts with exactly `v=TLSRPTv1`. */
  versionOk: boolean
  /** Parsed rua reporting endpoints with scheme/domain/size-limit/reachability/externality. */
  ruaEndpoints: TlsRptRuaEndpoint[]
  /** Syntactically valid AND has ≥1 well-formed rua (spec §5). */
  valid: boolean
  /** Tags outside {v, rua} observed on the record (e.g. a typo'd `ruf`). */
  unknownTags: string[]
  /** Non-TLSRPT TXT strings observed at `_smtp._tls.<domain>` (spec §12 raw+parsed pane). */
  strayTxt: string[]
  checkedAt: string
}

/** A TXT string that is (or is trying to be) a TLS-RPT record — caught loosely so broken ones surface. */
function isTlsRptCandidate(rec: string): boolean {
  const lower = rec.toLowerCase()
  return (
    lower.includes("tlsrptv1") || /^\s*v\s*=\s*tlsrpt/.test(lower) || /(^|;)\s*rua\s*=/.test(lower)
  )
}

function parseTag(raw: string): { key: string; value: string } {
  const eq = raw.indexOf("=")
  if (eq < 0) return { key: raw.trim(), value: "" }
  return { key: raw.slice(0, eq).trim(), value: raw.slice(eq + 1).trim() }
}

/** RFC 8460 permits an optional `!<size>` suffix on a rua URI, e.g. `mailto:a@b!10m`. */
function splitSizeLimit(uri: string): { base: string; sizeLimit: string | null } {
  const bang = uri.lastIndexOf("!")
  if (bang > 0 && /^\d+[kmgt]?$/i.test(uri.slice(bang + 1))) {
    return { base: uri.slice(0, bang), sizeLimit: uri.slice(bang + 1) }
  }
  return { base: uri, sizeLimit: null }
}

function schemeOf(base: string): string | null {
  const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(base)
  return m ? m[1].toLowerCase() : null
}

function isEmailAddress(addr: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(addr)
}

function isExternal(target: string, audited: string): boolean {
  const t = target.replace(/\.$/, "").toLowerCase()
  const a = audited.replace(/\.$/, "").toLowerCase()
  return t !== a && !t.endsWith(`.${a}`)
}

/**
 * The TTL sub-check stays a registered non-scoring future stub; report ingestion is now REAL —
 * `infra.tls_rpt_reports_ingested` is fed from the ingested TLS-RPT reports (pm/emails.mdx §5) by
 * deriveTlsRptFindings, appended alongside this stub in run().
 */
function futureFindings(domain: string): Finding[] {
  return [
    {
      id: "infra.tls_rpt_ttl_sane",
      checkId: CHECK_ID,
      title: "Record TTL sanity (future)",
      severity: "info",
      detail: `The TTL of _smtp._tls.${domain} is not inspected in the first round — node:dns omits it and dig +short does not return it.`,
      remediation: `Keep the TTL of the _smtp._tls.${domain} TXT record between 3600 and 86400 seconds (too low causes excess lookups, too high slows fixes).`,
    },
  ]
}

async function checkEndpoints(endpoints: RuaEndpoint[], domain: string): Promise<Finding[]> {
  const findings: Finding[] = []
  for (const [i, ep] of endpoints.entries()) {
    if (ep.external) {
      findings.push({
        id: `infra.tls_rpt_rua_external_authorized.${i}`,
        checkId: CHECK_ID,
        title: "Reports sent to an external organization",
        severity: "info",
        detail: `rua endpoint ${ep.uri} points at ${ep.domain}, outside ${domain}. RFC 8460 allows external rua without any authorization record.`,
        remediation: `Confirm ${ep.domain} is your intended third-party TLS-RPT processor; no DNS authorization record is required for external rua.`,
        evidence: ep.uri,
      })
    }

    if (ep.scheme === "mailto") {
      const mx = await resolveMx(ep.domain)
      if (mx.error) {
        ep.reachable = null
        findings.push({
          id: `infra.tls_rpt_endpoint_reachable.${i}`,
          checkId: CHECK_ID,
          title: "Could not verify rua mailbox domain",
          severity: "info",
          detail: `MX lookup for the rua domain ${ep.domain} failed transiently (${mx.error}); reachability is unknown, not confirmed broken.`,
          remediation:
            "Retry the audit shortly; if it persists, check the reporting mailbox domain's nameservers.",
          evidence: ep.uri,
        })
      } else if (mx.records.length === 0) {
        ep.reachable = false
        findings.push({
          id: `infra.tls_rpt_endpoint_reachable.${i}`,
          checkId: CHECK_ID,
          title: "rua mailbox domain has no MX",
          severity: "warning",
          detail: `The rua mailto domain ${ep.domain} has no MX record, so the daily TLS reports emailed there will bounce.`,
          remediation: `Point rua at a domain with valid MX, or add an MX record for ${ep.domain} (e.g. rua=mailto:tls-reports@${domain}).`,
          evidence: ep.uri,
        })
      } else {
        ep.reachable = true
        findings.push({
          id: `infra.tls_rpt_endpoint_reachable.${i}`,
          checkId: CHECK_ID,
          title: "rua mailbox domain reachable",
          severity: "ok",
          detail: `${ep.domain} has ${mx.records.length} MX record(s) — reports can be delivered.`,
          evidence: ep.uri,
        })
      }
    } else {
      const [a, aaaa] = [await resolve4(ep.host), await resolve6(ep.host)]
      const resolved = a.records.length > 0 || aaaa.records.length > 0
      if (resolved) {
        ep.reachable = true
        findings.push({
          id: `infra.tls_rpt_endpoint_reachable.${i}`,
          checkId: CHECK_ID,
          title: "rua HTTPS host reachable",
          severity: "ok",
          detail: `${ep.host} resolves (${a.records.length} A / ${aaaa.records.length} AAAA record(s)).`,
          evidence: ep.uri,
        })
      } else if (a.error || aaaa.error) {
        ep.reachable = null
        findings.push({
          id: `infra.tls_rpt_endpoint_reachable.${i}`,
          checkId: CHECK_ID,
          title: "Could not verify rua HTTPS host",
          severity: "info",
          detail: `Address lookup for the rua host ${ep.host} failed transiently (${a.error ?? aaaa.error}); reachability is unknown, not confirmed broken.`,
          remediation:
            "Retry the audit shortly; if it persists, check the reporting host's nameservers.",
          evidence: ep.uri,
        })
      } else {
        ep.reachable = false
        findings.push({
          id: `infra.tls_rpt_endpoint_reachable.${i}`,
          checkId: CHECK_ID,
          title: "rua HTTPS host does not resolve",
          severity: "warning",
          detail: `The rua host ${ep.host} has no A/AAAA record (NXDOMAIN), so the HTTPS report collector is unreachable.`,
          remediation: `Ensure ${ep.host} resolves and serves the HTTPS TLS-RPT collector, or switch to rua=mailto:tls-reports@${domain}.`,
          evidence: ep.uri,
        })
      }
    }
  }
  return findings
}

/** Project the internal parsed endpoints into the persisted results shape (spec §5). */
function toPersistedEndpoints(endpoints: RuaEndpoint[]): TlsRptRuaEndpoint[] {
  return endpoints.map((ep) => ({
    uri: ep.uri,
    scheme: ep.scheme,
    domain: ep.domain,
    sizeLimit: ep.sizeLimit,
    reachable: ep.reachable,
    external: ep.external,
  }))
}

export const tlsRptCheck: Checker = {
  id: "infra.tls_rpt",
  label: "TLS-RPT",
  async run(ctx): Promise<CheckOutcome> {
    const domain = ctx.domain
    const name = `_smtp._tls.${domain}`
    // The structured §5/§12 snapshot persisted at AuditResult.results["infra.tls_rpt"] — powers
    // the explainer's raw+parsed breakdown and the §11 trended fields. Filled in as we learn each
    // field; every early-exit path returns it alongside the findings.
    const results: TlsRptResults = {
      present: false,
      recordCount: 0,
      rawRecord: null,
      versionOk: false,
      ruaEndpoints: [],
      valid: false,
      unknownTags: [],
      strayTxt: [],
      checkedAt: new Date().toISOString(),
    }
    // The TTL future stub + the REAL report-fed sub-check (pm/emails.mdx §5): ingested TLS-RPT
    // reports for this domain roll into infra.tls_rpt_reports_ingested (warning on failures,
    // info at zero / when nothing is ingested yet / when ingestion is disabled).
    const future = [...futureFindings(domain), ...deriveTlsRptFindings(ctx.domainId ?? "", domain)]

    const { records, error, empty } = await resolveTxt(name)
    if (error) {
      // Transient DNS failure: presence is UNKNOWN, not confirmed absent (spec §3 edge cases) —
      // leave results.present false but flag the finding as info, never warning.
      return {
        findings: [
          {
            id: "infra.tls_rpt_present",
            checkId: CHECK_ID,
            title: "Could not look up TLS-RPT",
            severity: "info",
            detail: `DNS lookup for TXT ${name} failed transiently (${error}); the record's presence is unknown, not confirmed absent.`,
            remediation: `Retry the audit shortly. If it persists, check the authoritative nameservers for ${domain} (SERVFAIL/timeout).`,
            evidence: name,
          },
          ...future,
        ],
        results,
      }
    }

    const txt = records.map((r) => r.trim()).filter(Boolean)
    const candidates = txt.filter(isTlsRptCandidate)
    const stray = txt.filter((r) => !isTlsRptCandidate(r))
    results.strayTxt = stray

    if (candidates.length === 0) {
      return {
        findings: [
          {
            id: "infra.tls_rpt_present",
            checkId: CHECK_ID,
            title: "No TLS-RPT record",
            severity: "warning",
            detail: `${name} has no v=TLSRPTv1 TXT record${empty ? " (NXDOMAIN / no data)" : ""}. You are blind to STARTTLS, MTA-STS, and DANE negotiation failures against this domain.`,
            remediation: `Publish a TXT record: _smtp._tls.${domain}. IN TXT "v=TLSRPTv1; rua=mailto:tls-reports@${domain}"`,
            evidence: name,
          },
          ...future,
        ],
        results,
      }
    }

    results.present = true
    results.recordCount = candidates.length

    const findings: Finding[] = []

    if (stray.length > 0) {
      findings.push({
        id: "infra.tls_rpt_no_extra_txt",
        checkId: CHECK_ID,
        title: "Stray TXT at the reporting name",
        severity: "info",
        detail: `Non-TLS-RPT TXT record(s) exist at ${name}. They do not break TLS-RPT but clutter the reporting label.`,
        remediation: `Remove unrelated TXT records from _smtp._tls.${domain}; only the single v=TLSRPTv1 record belongs there.`,
        evidence: stray.join(" | "),
      })
    } else {
      findings.push({
        id: "infra.tls_rpt_no_extra_txt",
        checkId: CHECK_ID,
        title: "No stray TXT at the reporting name",
        severity: "ok",
        detail: `Only the TLS-RPT record is present at ${name}.`,
      })
    }

    if (candidates.length > 1) {
      findings.push({
        id: "infra.tls_rpt_single",
        checkId: CHECK_ID,
        title: "Multiple TLS-RPT records",
        severity: "critical",
        detail: `${name} publishes ${candidates.length} TLSRPTv1 TXT records. Per RFC 8460 §3.1 receivers treat more than one record as if no policy is published, so TLS reporting is effectively off.`,
        remediation: `Delete the duplicate TXT record(s) at _smtp._tls.${domain}; keep exactly one v=TLSRPTv1 record.`,
        evidence: candidates.join(" | "),
      })
      return { findings: [...findings, ...future], results }
    }

    findings.push({
      id: "infra.tls_rpt_single",
      checkId: CHECK_ID,
      title: "TLS-RPT record is a singleton",
      severity: "ok",
      detail: "Exactly one TLSRPTv1 record is published.",
      evidence: candidates[0],
    })

    const record = candidates[0]
    results.rawRecord = record
    const tags = record
      .split(";")
      .map((t) => t.trim())
      .filter(Boolean)
      .map(parseTag)
    const first = tags[0]

    if (first?.key.toLowerCase() !== "v") {
      findings.push({
        id: "infra.tls_rpt_syntax",
        checkId: CHECK_ID,
        title: "Malformed TLS-RPT record (v= not first)",
        severity: "critical",
        detail:
          "The record does not begin with the v=TLSRPTv1 version tag. RFC 8460 requires v= be the first tag, so receivers ignore the whole record.",
        remediation: `Rewrite the record so it begins exactly: v=TLSRPTv1; rua=mailto:tls-reports@${domain}`,
        evidence: record,
      })
      return { findings: [...findings, ...future], results }
    }

    if (first.value !== "TLSRPTv1") {
      findings.push({
        id: "infra.tls_rpt_version",
        checkId: CHECK_ID,
        title: "Wrong TLS-RPT version",
        severity: "critical",
        detail: `The version tag is "v=${first.value}", not the required "v=TLSRPTv1" (the value is case-sensitive). Receivers treat the record as invalid.`,
        remediation: `Set the version tag to exactly v=TLSRPTv1 (e.g. v=TLSRPTv1; rua=mailto:tls-reports@${domain}).`,
        evidence: record,
      })
      return { findings: [...findings, ...future], results }
    }

    results.versionOk = true
    findings.push({
      id: "infra.tls_rpt_syntax",
      checkId: CHECK_ID,
      title: "TLS-RPT record is well-formed",
      severity: "ok",
      detail:
        "The record begins with v=TLSRPTv1 and parses as valid semicolon-separated tag=value pairs.",
      evidence: record,
    })
    findings.push({
      id: "infra.tls_rpt_version",
      checkId: CHECK_ID,
      title: "TLS-RPT version is TLSRPTv1",
      severity: "ok",
      detail: "The version token is exactly TLSRPTv1.",
    })

    const unknown = tags.filter((t) => !KNOWN_TAGS.has(t.key.toLowerCase())).map((t) => t.key)
    results.unknownTags = unknown
    if (unknown.length > 0) {
      findings.push({
        id: "infra.tls_rpt_unknown_tags",
        checkId: CHECK_ID,
        title: "Unknown TLS-RPT tag(s)",
        severity: "info",
        detail: `Unknown tag(s) ${unknown.join(", ")} present — RFC 8460 defines only v and rua for TLS-RPT (ruf/pct/sp belong to DMARC and are silently ignored here).`,
        remediation: `Remove the non-standard tag(s) ${unknown.join(", ")} from the record; TLS-RPT supports only v= and rua=.`,
        evidence: record,
      })
    }

    const ruaValues = tags
      .filter((t) => t.key.toLowerCase() === "rua")
      .map((t) => t.value)
      .filter(Boolean)
    if (ruaValues.length === 0) {
      findings.push({
        id: "infra.tls_rpt_rua_present",
        checkId: CHECK_ID,
        title: "TLS-RPT record has no rua endpoint",
        severity: "critical",
        detail:
          "The record has no rua= tag, so receivers have nowhere to send TLS failure reports — it is present but operationally useless.",
        remediation: `Add a reporting endpoint so the final record reads: v=TLSRPTv1; rua=mailto:tls-reports@${domain}`,
        evidence: record,
      })
      return { findings: [...findings, ...future], results }
    }

    findings.push({
      id: "infra.tls_rpt_rua_present",
      checkId: CHECK_ID,
      title: "TLS-RPT rua endpoint declared",
      severity: "ok",
      detail: "At least one rua reporting endpoint is present.",
    })

    const uris = ruaValues
      .flatMap((v) => v.split(","))
      .map((u) => u.trim())
      .filter(Boolean)
    const endpoints: RuaEndpoint[] = []
    let malformed = 0

    uris.forEach((uri, i) => {
      const { base, sizeLimit } = splitSizeLimit(uri)
      const scheme = schemeOf(base)
      if (scheme === "mailto") {
        const addr = base.slice("mailto:".length)
        if (!isEmailAddress(addr)) {
          malformed++
          findings.push({
            id: `infra.tls_rpt_rua.${i}`,
            checkId: CHECK_ID,
            title: "Malformed rua mailto URI",
            severity: "warning",
            detail: `The rua entry "${uri}" is not a valid mailto: address (expected local@domain).`,
            remediation: `Use a full mailbox, e.g. rua=mailto:tls-reports@${domain}.`,
            evidence: uri,
          })
          return
        }
        const d = addr.slice(addr.indexOf("@") + 1).toLowerCase()
        endpoints.push({
          uri,
          scheme: "mailto",
          domain: d,
          host: d,
          sizeLimit,
          external: isExternal(d, domain),
          reachable: null,
        })
      } else if (scheme === "https") {
        let host = ""
        try {
          host = new URL(base).hostname
        } catch {
          host = ""
        }
        if (!host) {
          malformed++
          findings.push({
            id: `infra.tls_rpt_rua.${i}`,
            checkId: CHECK_ID,
            title: "Malformed rua HTTPS URI",
            severity: "warning",
            detail: `The rua entry "${uri}" is not a parseable https:// URL with a host.`,
            remediation: `Use a full HTTPS URL, e.g. rua=https://reports.${domain}/tlsrpt.`,
            evidence: uri,
          })
          return
        }
        endpoints.push({
          uri,
          scheme: "https",
          domain: host.toLowerCase(),
          host,
          sizeLimit,
          external: isExternal(host, domain),
          reachable: null,
        })
      } else if (scheme) {
        malformed++
        findings.push({
          id: `infra.tls_rpt_rua_scheme.${i}`,
          checkId: CHECK_ID,
          title: "Unsupported rua scheme",
          severity: "warning",
          detail: `The rua URI "${uri}" uses the "${scheme}:" scheme; RFC 8460 allows only mailto: and https:, so receivers skip it${scheme === "http" ? " (plain HTTP is never accepted, use HTTPS)" : ""}.`,
          remediation: `Replace with rua=mailto:tls-reports@${domain} or rua=https://reports.${domain}/tlsrpt (HTTPS, not ${scheme}).`,
          evidence: uri,
        })
      } else {
        malformed++
        findings.push({
          id: `infra.tls_rpt_rua.${i}`,
          checkId: CHECK_ID,
          title: "Malformed rua URI",
          severity: "warning",
          detail: `The rua entry "${uri}" has no mailto:/https: scheme${uri.includes("@") ? " — a bare email address needs the mailto: prefix" : ""}.`,
          remediation: `Prefix the address with mailto:, e.g. rua=mailto:tls-reports@${domain}, or use an https:// URL.`,
          evidence: uri,
        })
      }
    })

    if (malformed === 0) {
      findings.push({
        id: "infra.tls_rpt_rua",
        checkId: CHECK_ID,
        title: "All rua endpoints well-formed",
        severity: "ok",
        detail: `${uris.length} reporting URI(s) parse as valid mailto:/https: endpoints.`,
        evidence: uris.join(", "),
      })
    }

    findings.push(...(await checkEndpoints(endpoints, domain)))

    // checkEndpoints has now filled each endpoint's reachability, so the persisted snapshot
    // (spec §5) reflects the advisory MX/A probe. Valid = version ok AND ≥1 well-formed rua.
    results.ruaEndpoints = toPersistedEndpoints(endpoints)
    results.valid = results.versionOk && endpoints.length > 0

    return { findings: [...findings, ...future], results }
  },
}
