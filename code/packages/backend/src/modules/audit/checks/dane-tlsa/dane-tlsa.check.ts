import { type DigAnswer, dig, digAnswer, resolveCname, resolveMx } from "../dns-util"
import type { MxRoutingResults } from "../mx-routing/mx-routing.check"
import type { Checker, CheckOutcome, Finding } from "../types"

/**
 * DANE / TLSA for SMTP (RFC 7672, on RFC 6698/7671). For each inbound MX host of a domain this checker
 * looks up the TLSA record at `_25._tcp.<mx-host>` that pins the MX's TLS certificate/key, and audits
 * the record's parameters, digest shape, TTL, rollover staging, name alignment, DNSSEC prerequisite
 * and full-MX coverage. DANE has a HARD dependency on DNSSEC: a TLSA record on an unsigned zone is a
 * no-op that gives false confidence, so that combination is the sharpest finding here.
 *
 * First-round is pure DNS + parsing (node:dns helpers + shelling to Brew `dig` for the TLSA/DS/DNSKEY
 * RRtypes node cannot query natively; the full-answer `digAnswer` variant supplies the RR TTL and
 * distinguishes SERVFAIL from "no record" — spec §3 edge case (b) / AC10). The live :25 STARTTLS
 * cert-match probe — and authoritative DNSSEC validation via a validating resolver — are FUTURE and
 * only ever emit a single `info` (their structured columns stay null, spec AC9).
 */

// The recommended SMTP DANE profile: usage 3 (DANE-EE) + selector 1 (SPKI) + matching-type 1 (SHA-256).
const REC_USAGE = 3
const REC_SELECTOR = 1
const REC_MTYPE = 1

/** TLSA TTL guidance (spec §2 `infra.dane_ttl_sane`): ≤ ~1h recommended, "very long" is a rollover risk. */
const TTL_RECOMMENDED_MAX = 3600
const TTL_VERY_LONG = 86400

export interface Tlsa {
  usage: number
  selector: number
  mtype: number
  data: string
  /** RR TTL in seconds; null when the answer did not expose one. */
  ttl: number | null
  raw: string
}

/** One TLSA RR as persisted in the structured results (spec §5 `tlsa_records` JSONB shape). */
export interface DaneTlsaRecord {
  usage: number
  selector: number
  mtype: number
  data: string
  ttl: number | null
}

/**
 * One row per MX host per audit run — the JSON-file projection of the spec §5 `dane_check_results`
 * table (camelCase keys exactly as the spec's `checkResults.dane[]` example). Persisted as an array
 * at `AuditResult.results["infra.dane_tlsa"]`; when the store migrates to Postgres each element
 * becomes one `dane_check_results` row.
 */
export interface DaneHostResult {
  /** Canonical MX hostname (post-CNAME). */
  mxHost: string
  /** MX priority, for coverage reporting. */
  mxPreference: number | null
  /** MX host's zone DNSSEC-signed (DS/DNSKEY observed first-round; AD-bit trust is FUTURE). */
  dnssecSigned: boolean
  /** Any TLSA at `_25._tcp.<mx>`. */
  tlsaPresent: boolean
  tlsaRecords: DaneTlsaRecord[]
  /** At least one record is SMTP-usable (usage 2/3); null when no TLSA / lookup failed. */
  paramsOk: boolean | null
  /** A `3 1 1` record is present; null when no TLSA / lookup failed. */
  recommended311: boolean | null
  /** NULL until the :25 STARTTLS probe runs (FUTURE, spec AC9). */
  certMatch: boolean | null
  /** >=2 staged TLSA records. */
  rolloverReady: boolean
  /** NULL until the probe runs (FUTURE). */
  starttlsOffered: boolean | null
  /** Last lookup/probe error, if any — e.g. SERVFAIL on a signed zone (spec AC10). */
  probeError: string | null
  checkedAt: string
}

export type DaneTlsaResults = DaneHostResult[]

interface HostSummary {
  host: string
  canonical: string
  lookupError: boolean
  usableDane: boolean
}

/** Parse full-answer TLSA RRs into structured records. RDATA is "usage selector mtype hex…". */
export function parseTlsa(answers: DigAnswer[]): Tlsa[] {
  const out: Tlsa[] = []
  for (const rr of answers) {
    const tok = rr.rdata.trim().split(/\s+/)
    if (tok.length < 3) continue
    const usage = Number(tok[0])
    const selector = Number(tok[1])
    const mtype = Number(tok[2])
    if (!Number.isInteger(usage) || !Number.isInteger(selector) || !Number.isInteger(mtype))
      continue
    const data = tok.slice(3).join("").replace(/\s+/g, "").toLowerCase()
    out.push({ usage, selector, mtype, data, ttl: rr.ttl, raw: rr.rdata.trim() })
  }
  return out
}

/** Follow the CNAME chain for an MX host to its final canonical name (RFC 7672 TLSA base name). */
async function canonicalName(host: string): Promise<{ canonical: string; cnamed: boolean }> {
  let current = host.replace(/\.$/, "")
  let cnamed = false
  for (let i = 0; i < 8; i++) {
    const c = await resolveCname(current)
    if (c.records.length === 0) break
    cnamed = true
    current = c.records[0].replace(/\.$/, "")
  }
  return { canonical: current, cnamed }
}

/** The last two labels of a hostname — a first-round heuristic for the zone apex to probe for DNSSEC. */
function parentZone(host: string): string {
  const labels = host.replace(/\.$/, "").split(".")
  return labels.length <= 2 ? host : labels.slice(-2).join(".")
}

/**
 * Observe (not authoritatively validate) whether the MX host's zone is DNSSEC-signed by looking for a
 * DS record at the parent delegation or a DNSKEY at the apex. Trusting the AD bit needs a validating
 * resolver and is FUTURE; presence of DS/DNSKEY is a sound first-round signal.
 */
async function observeDnssec(host: string): Promise<{ signed: boolean; error: boolean }> {
  const zone = parentZone(host)
  // DS (at the parent) and DNSKEY (at the apex) are independent — query them concurrently.
  const [ds, dnskey] = await Promise.all([dig(zone, "DS"), dig(zone, "DNSKEY")])
  if (ds.records.length > 0 || dnskey.records.length > 0) return { signed: true, error: false }
  return { signed: false, error: Boolean(ds.error && dnskey.error) }
}

const REM_UNSIGNED =
  "Either sign the MX host's zone (publish DNSKEY, add a DS record at the parent registrar) — preferred — or remove the TLSA record so it is not mistaken for protection. A sending MTA MUST ignore an unsigned TLSA."
const REM_PARAMS =
  "Republish the record as `3 1 1` (DANE-EE, SPKI, SHA-256): `_25._tcp.<mx>. 3600 IN TLSA 3 1 1 <sha256-of-SPKI>`. Remove any usage-0/1 (PKIX) records — they are unusable for SMTP per RFC 7672."
const REM_DIGEST =
  "Regenerate the digest with the correct hash and republish: a `3 1 1` record's association data must be exactly 64 hex characters (SHA-256); a matching-type-2 record must be 128 hex characters (SHA-512)."
const REM_ROLLOVER =
  "Publish the NEXT cert's `3 1 1` digest alongside the current one BEFORE renewing (>=2 TLSA records), and remove the old record only after the new cert is live, so a renewal never breaks DANE."
const REM_ALIGN =
  "Publish the TLSA record at the fully-qualified canonical MX name (post-CNAME), and ensure every name in the CNAME chain is DNSSEC-signed; otherwise DANE-aware senders cannot validate the pin."
const REM_ALL_MX_PARTIAL =
  "Publish a `3 1 1` TLSA for EVERY MX host including backups/secondaries — partial DANE lets an attacker steer delivery to the unprotected MX, so it is no better than no DANE."
const REM_ALL_MX_NONE =
  "Publish `_25._tcp.<mx>. 3600 IN TLSA 3 1 1 <sha256-of-SPKI>` for every MX host (on DNSSEC-signed zones) to enable authenticated, downgrade-resistant inbound TLS."
const REM_TTL =
  "Set the TLSA TTL to 3600s (or lower during a planned rollover) so pins propagate quickly; avoid absurdly long or zero TTLs."

/** Inputs `analyzeHost` needs for one MX host — separated from the DNS calls so it is pure/testable. */
export interface HostObservation {
  host: string
  priority: number
  canonical: string
  cnamed: boolean
  tlsa: { records: DigAnswer[]; error?: string }
  dnssec: { signed: boolean; error: boolean }
  checkedAt?: string
}

/**
 * All per-host DANE analysis (spec §2 sub-checks except the coverage rollup): findings + the
 * structured `dane_check_results` row + the summary the `infra.dane_all_mx` rollup consumes.
 */
export function analyzeHost(obs: HostObservation): {
  findings: Finding[]
  summary: HostSummary
  row: DaneHostResult
} {
  const findings: Finding[] = []
  const { host, canonical, cnamed, tlsa, dnssec } = obs
  const tag = canonical.replace(/[^a-z0-9]/gi, "_")
  const label = `${host} (prio ${obs.priority})`
  const tlsaName = `_25._tcp.${canonical}`
  const checkedAt = obs.checkedAt ?? new Date().toISOString()

  const baseRow = {
    mxHost: canonical,
    mxPreference: obs.priority,
    dnssecSigned: dnssec.signed,
    certMatch: null,
    starttlsOffered: null,
    checkedAt,
  }

  if (tlsa.error) {
    // Spec AC10: SERVFAIL on a signed zone is a DNSSEC validation failure, never "no DANE".
    const validationFailure = tlsa.error === "SERVFAIL" && dnssec.signed
    findings.push({
      id: `infra.dane_tlsa_present.${tag}`,
      checkId: "infra",
      title: validationFailure
        ? `TLSA lookup SERVFAIL on signed zone: ${host}`
        : `TLSA lookup failed for ${host}`,
      severity: validationFailure ? "critical" : "info",
      detail: validationFailure
        ? `Querying TLSA at ${tlsaName} returned SERVFAIL while the zone shows a DNSSEC chain — that signals a DNSSEC validation failure (bogus signatures / broken chain), not an absent record. Validating resolvers are refusing this zone's answers.`
        : `Querying TLSA at ${tlsaName} failed (${tlsa.error}). On a DNSSEC-signed zone a SERVFAIL can indicate a validation failure rather than an absent record — retry before concluding DANE is absent.`,
      remediation: validationFailure
        ? "Repair the zone's DNSSEC chain (re-sign, fix the DS at the parent) — until then validating resolvers SERVFAIL every lookup, which breaks DANE and much more."
        : "Retry the audit later; if SERVFAIL persists on a signed zone, investigate the zone's DNSSEC chain.",
      evidence: tlsaName,
    })
    return {
      findings,
      summary: { host, canonical, lookupError: true, usableDane: false },
      row: {
        ...baseRow,
        tlsaPresent: false,
        tlsaRecords: [],
        paramsOk: null,
        recommended311: null,
        rolloverReady: false,
        probeError: tlsa.error,
      },
    }
  }

  const records = parseTlsa(tlsa.records)
  const usable = records.some((r) => r.usage === 2 || r.usage === 3)
  const summary: HostSummary = {
    host,
    canonical,
    lookupError: false,
    usableDane: records.length > 0 && usable,
  }
  const row: DaneHostResult = {
    ...baseRow,
    tlsaPresent: records.length > 0,
    tlsaRecords: records.map((r) => ({
      usage: r.usage,
      selector: r.selector,
      mtype: r.mtype,
      data: r.data,
      ttl: r.ttl,
    })),
    paramsOk: records.length === 0 ? null : usable,
    recommended311:
      records.length === 0
        ? null
        : records.some(
            (r) => r.usage === REC_USAGE && r.selector === REC_SELECTOR && r.mtype === REC_MTYPE,
          ),
    rolloverReady: records.length >= 2,
    probeError: null,
  }

  // --- infra.dane_tlsa_present ------------------------------------------------------------
  if (records.length === 0) {
    // Absence is rolled up by infra.dane_all_mx; note DNSSEC readiness per host when transient.
    if (dnssec.error) {
      findings.push({
        id: `infra.dane_dnssec_prereq.${tag}`,
        checkId: "infra",
        title: `DNSSEC status unknown for ${host}`,
        severity: "info",
        detail: `Could not observe DS/DNSKEY for ${host}'s zone; DANE readiness is unknown.`,
        remediation: "Retry the audit later to re-check the DNSSEC chain for this MX host.",
      })
    } else if (!dnssec.signed) {
      findings.push({
        id: `infra.dane_dnssec_prereq.${tag}`,
        checkId: "infra",
        title: `No DANE and zone unsigned: ${host}`,
        severity: "warning",
        detail: `${host} has no TLSA record and its zone shows no DNSSEC chain (no DS/DNSKEY observed). DANE is impossible until the zone is signed.`,
        remediation: REM_UNSIGNED,
        evidence: tlsaName,
      })
    }
    return { findings, summary, row }
  }

  findings.push({
    id: `infra.dane_tlsa_present.${tag}`,
    checkId: "infra",
    title: `TLSA present for ${label}`,
    severity: "ok",
    detail: `Found ${records.length} TLSA record(s) at ${tlsaName}.`,
    evidence: records.map((r) => r.raw).join(" | "),
  })

  // --- infra.dane_without_dnssec / infra.dane_dnssec_prereq -------------------------------
  if (dnssec.error) {
    findings.push({
      id: `infra.dane_dnssec_prereq.${tag}`,
      checkId: "infra",
      title: `DNSSEC status unknown for ${host}`,
      severity: "info",
      detail: `A TLSA record exists at ${tlsaName} but DS/DNSKEY could not be observed for the zone; the DNSSEC prerequisite is unverified.`,
      remediation: "Retry the audit later to confirm the MX host's zone is DNSSEC-signed.",
    })
  } else if (!dnssec.signed) {
    findings.push({
      id: `infra.dane_without_dnssec.${tag}`,
      checkId: "infra",
      title: `TLSA on an unsigned zone: ${host}`,
      severity: "critical",
      detail: `${host} publishes a TLSA record but its zone shows no DNSSEC chain (no DS/DNSKEY observed). Sending MTAs MUST ignore an unsigned TLSA, so this record gives false confidence and provides no protection.`,
      remediation: REM_UNSIGNED,
      evidence: records.map((r) => r.raw).join(" | "),
    })
  } else {
    findings.push({
      id: `infra.dane_dnssec_prereq.${tag}`,
      checkId: "infra",
      title: `DNSSEC prerequisite met for ${host}`,
      severity: "ok",
      detail: `${host}'s zone shows a DNSSEC chain (DS/DNSKEY observed); the TLSA record can be trusted by DANE-aware senders.`,
    })
  }

  // --- infra.dane_name_alignment ---------------------------------------------------------
  if (cnamed) {
    if (!dnssec.signed && !dnssec.error) {
      findings.push({
        id: `infra.dane_name_alignment.${tag}`,
        checkId: "infra",
        title: `MX is a CNAME to an unsigned target: ${host}`,
        severity: "critical",
        detail: `${host} is a CNAME resolving to ${canonical}, whose zone is not DNSSEC-signed. Senders cannot validate a TLSA reached through an unsigned CNAME hop.`,
        remediation: REM_ALIGN,
        evidence: `${host} -> ${canonical}`,
      })
    } else {
      findings.push({
        id: `infra.dane_name_alignment.${tag}`,
        checkId: "infra",
        title: `TLSA reached via CNAME for ${host}`,
        severity: "info",
        detail: `${host} is a CNAME to canonical name ${canonical}; the TLSA record was read at the canonical name. Confirm every hop in the chain is DNSSEC-signed.`,
        remediation: REM_ALIGN,
        evidence: `${host} -> ${canonical}`,
      })
    }
  }

  // --- infra.dane_tlsa_params + infra.dane_digest_length (per record) --------------------
  records.forEach((r, i) => {
    const rid = `${tag}.${i}`
    const shown = `${r.usage} ${r.selector} ${r.mtype}`
    if (r.usage === 0 || r.usage === 1) {
      findings.push({
        id: `infra.dane_tlsa_params.${rid}`,
        checkId: "infra",
        title: `Unusable TLSA usage (${r.usage}) on ${host}`,
        severity: "critical",
        detail: `Record "${shown} …" uses PKIX usage ${r.usage}, which is not usable for SMTP per RFC 7672 — senders ignore it entirely.`,
        remediation: REM_PARAMS,
        evidence: r.raw,
      })
    } else if (r.usage === REC_USAGE && r.selector === REC_SELECTOR && r.mtype === REC_MTYPE) {
      findings.push({
        id: `infra.dane_tlsa_params.${rid}`,
        checkId: "infra",
        title: `Recommended 3 1 1 profile on ${host}`,
        severity: "ok",
        detail: `Record is the recommended SMTP DANE profile (DANE-EE / SPKI / SHA-256).`,
        evidence: r.raw,
      })
    } else {
      findings.push({
        id: `infra.dane_tlsa_params.${rid}`,
        checkId: "infra",
        title: `Usable but non-recommended TLSA params on ${host}`,
        severity: "info",
        detail: `Record "${shown} …" is SMTP-usable (usage ${r.usage}) but not the recommended \`3 1 1\` (DANE-TA usage 2, selector-0 full-cert, or matching-type-2 SHA-512).`,
        remediation: REM_PARAMS,
        evidence: r.raw,
      })
    }

    // Digest shape: SHA-256 => 64 hex, SHA-512 => 128 hex; empty only allowed for usage 2.
    const hexOk = /^[0-9a-f]*$/.test(r.data)
    const emptyAllowed = r.usage === 2
    let badDigest = false
    if (r.data.length === 0) {
      badDigest = !emptyAllowed
    } else if (!hexOk) {
      badDigest = true
    } else if (r.mtype === 1 && r.data.length !== 64) {
      badDigest = true
    } else if (r.mtype === 2 && r.data.length !== 128) {
      badDigest = true
    }
    if (badDigest) {
      findings.push({
        id: `infra.dane_digest_length.${rid}`,
        checkId: "infra",
        title: `Malformed TLSA digest on ${host}`,
        severity: "critical",
        detail: `Record "${shown}" has association data of ${r.data.length} hex chars, which is invalid for matching-type ${r.mtype} — senders treat the record as unusable.`,
        remediation: REM_DIGEST,
        evidence: r.raw,
      })
    }
  })

  // --- infra.dane_ttl_sane (spec §2/§7: first-round, read the RR TTL from the answer) -----
  const ttls = records.map((r) => r.ttl).filter((t): t is number => t !== null)
  if (ttls.length > 0) {
    const maxTtl = Math.max(...ttls)
    const zero = ttls.some((t) => t === 0)
    if (zero) {
      findings.push({
        id: `infra.dane_ttl_sane.${tag}`,
        checkId: "infra",
        title: `Zero TLSA TTL on ${host}`,
        severity: "warning",
        detail: `A TLSA record at ${tlsaName} has a TTL of 0 — every DANE-aware sender re-queries on every delivery, hammering the resolvers and defeating caching.`,
        remediation: REM_TTL,
        evidence: records.map((r) => `${r.raw} (ttl ${r.ttl ?? "?"})`).join(" | "),
      })
    } else if (maxTtl > TTL_VERY_LONG) {
      findings.push({
        id: `infra.dane_ttl_sane.${tag}`,
        checkId: "infra",
        title: `Very long TLSA TTL on ${host}`,
        severity: "warning",
        detail: `The TLSA at ${tlsaName} carries a TTL of ${maxTtl}s (> 24h). A pin that long lingers in caches through a cert rollover, so an emergency re-pin cannot propagate — DANE-aware senders keep failing against the stale digest.`,
        remediation: REM_TTL,
        evidence: records.map((r) => `${r.raw} (ttl ${r.ttl ?? "?"})`).join(" | "),
      })
    } else if (maxTtl > TTL_RECOMMENDED_MAX) {
      findings.push({
        id: `infra.dane_ttl_sane.${tag}`,
        checkId: "infra",
        title: `TLSA TTL above the recommended 1h on ${host}`,
        severity: "info",
        detail: `The TLSA at ${tlsaName} has a TTL of ${maxTtl}s; ≤3600s is recommended so a re-pin propagates quickly during a rollover.`,
        remediation: REM_TTL,
        evidence: records.map((r) => `${r.raw} (ttl ${r.ttl ?? "?"})`).join(" | "),
      })
    } else {
      findings.push({
        id: `infra.dane_ttl_sane.${tag}`,
        checkId: "infra",
        title: `Sane TLSA TTL on ${host}`,
        severity: "ok",
        detail: `TLSA TTL at ${tlsaName} is ${maxTtl}s (≤ the recommended 3600s), so pin changes propagate quickly.`,
      })
    }
  }

  // --- infra.dane_rollover ---------------------------------------------------------------
  if (records.length < 2) {
    findings.push({
      id: `infra.dane_rollover.${tag}`,
      checkId: "infra",
      title: `Single TLSA record on ${host} (rollover risk)`,
      severity: "warning",
      detail: `${host} has exactly one TLSA record. When the certificate is renewed with a new key, the pinned digest stops matching and every DANE-aware sender hard-fails delivery.`,
      remediation: REM_ROLLOVER,
      evidence: records.map((r) => r.raw).join(" | "),
    })
  } else {
    findings.push({
      id: `infra.dane_rollover.${tag}`,
      checkId: "infra",
      title: `Rollover staged on ${host}`,
      severity: "ok",
      detail: `${host} has ${records.length} TLSA records staged (current + next), so a cert renewal will not break DANE.`,
    })
  }

  return { findings, summary, row }
}

export const daneTlsaCheck: Checker = {
  id: "infra.dane_tlsa",
  label: "DANE / TLSA",
  async run(ctx): Promise<CheckOutcome> {
    const findings: Finding[] = []

    // Spec §3 step 1: reuse the MX list resolved by infra.mx_routing when the run published it
    // upstream (pm/run_checks.mdx Stage 1); otherwise resolve it here (deduped by the per-run memo).
    let hosts: { exchange: string; priority: number }[] | null = null
    const upstreamMx = ctx.upstream?.["infra.mx_routing"] as MxRoutingResults | undefined
    if (upstreamMx) {
      hosts = upstreamMx.hosts.map((h) => ({ exchange: h.host, priority: h.priority }))
    } else {
      const mx = await resolveMx(ctx.domain)
      if (mx.error) {
        return {
          findings: [
            {
              id: "infra.dane_mx_lookup",
              checkId: "infra",
              title: "Could not look up MX for DANE",
              severity: "info",
              detail: `DNS lookup for MX ${ctx.domain} failed (${mx.error}); DANE could not be evaluated. This is usually transient.`,
              remediation:
                "Retry the audit later. If it persists, check the domain's authoritative nameservers.",
            },
          ],
          results: [] satisfies DaneTlsaResults,
        }
      }
      hosts = mx.records
    }

    if (hosts.length === 0) {
      return {
        findings: [
          {
            id: "infra.dane_no_mx",
            checkId: "infra",
            title: "No MX hosts — DANE not applicable",
            severity: "info",
            detail: `${ctx.domain} publishes no MX records, so there is no inbound mail host to protect with DANE.`,
            remediation:
              "If this domain receives mail, publish MX records first, then add a `3 1 1` TLSA at `_25._tcp.<mx>` on the (DNSSEC-signed) MX zone.",
          },
        ],
        results: [] satisfies DaneTlsaResults,
      }
    }

    const sorted = [...hosts].sort((a, b) => a.priority - b.priority)

    // Process MX hosts concurrently — each host runs several `dig` lookups (TLSA + DS/DNSKEY), so a
    // sequential loop over 5+ hosts easily exceeds a sane audit budget. Each host builds its own
    // finding list; they are flattened back in priority order after all hosts resolve.
    const perHost = await Promise.all(
      sorted.map(async (record) => {
        const host = record.exchange.replace(/\.$/, "")
        const { canonical, cnamed } = await canonicalName(host)
        const tlsaName = `_25._tcp.${canonical}`
        // TLSA lookup and the DNSSEC observation are independent — run them concurrently per host.
        const [tlsa, dnssec] = await Promise.all([
          digAnswer(tlsaName, "TLSA"),
          observeDnssec(canonical),
        ])
        return analyzeHost({
          host,
          priority: record.priority,
          canonical,
          cnamed,
          tlsa: { records: tlsa.records, error: tlsa.error },
          dnssec,
        })
      }),
    )

    // Flatten per-host findings back in MX priority order.
    for (const p of perHost) findings.push(...p.findings)
    const summaries = perHost.map((p) => p.summary)
    const rows: DaneTlsaResults = perHost.map((p) => p.row)

    // --- infra.dane_all_mx (coverage rollup) --------------------------------------------------
    const known = summaries.filter((s) => !s.lookupError)
    const withDane = known.filter((s) => s.usableDane)
    if (known.length > 0) {
      if (withDane.length === 0) {
        findings.push({
          id: "infra.dane_all_mx",
          checkId: "infra",
          title: "No MX host publishes DANE",
          severity: "warning",
          detail: `None of the ${known.length} MX host(s) for ${ctx.domain} publish a usable TLSA record, so inbound mail is not DANE-protected.`,
          remediation: REM_ALL_MX_NONE,
          evidence: known.map((s) => s.canonical).join(", "),
        })
      } else if (withDane.length < known.length) {
        const missing = known.filter((s) => !s.usableDane).map((s) => s.canonical)
        findings.push({
          id: "infra.dane_all_mx",
          checkId: "infra",
          title: "Partial DANE coverage across MX hosts",
          severity: "critical",
          detail: `${withDane.length} of ${known.length} MX host(s) publish DANE but ${missing.join(", ")} do not. An attacker can steer delivery to an unprotected MX, so partial DANE is effectively no DANE.`,
          remediation: REM_ALL_MX_PARTIAL,
          evidence: missing.join(", "),
        })
      } else {
        findings.push({
          id: "infra.dane_all_mx",
          checkId: "infra",
          title: "All MX hosts publish DANE",
          severity: "ok",
          detail: `All ${known.length} MX host(s) for ${ctx.domain} publish a usable TLSA record.`,
          evidence: known.map((s) => s.canonical).join(", "),
        })
      }
    }

    // --- FUTURE probe sub-checks (cert-match / dangling / STARTTLS) — single info, never fail --
    // Spec AC9: with the probe disabled the certMatch/starttlsOffered columns stay null and no
    // false criticals are emitted.
    findings.push({
      id: "infra.dane_tlsa_cert_match",
      checkId: "infra",
      title: "Certificate-match probe pending",
      severity: "info",
      detail:
        "The live :25 STARTTLS cert-match probe is not run in the first round. When enabled it will connect to each MX on port 25, complete STARTTLS, and verify the pinned digest matches the presented certificate/key (infra.dane_tlsa_cert_match), flag dangling records that match no live/staged cert (infra.dane_tlsa_dangling), and confirm STARTTLS is offered (infra.dane_starttls_offered).",
      remediation:
        "Enable the :25 STARTTLS cert-match probe in admin settings to verify the pinned digest matches the live certificate and that STARTTLS is offered.",
    })

    return { findings, results: rows }
  },
}
