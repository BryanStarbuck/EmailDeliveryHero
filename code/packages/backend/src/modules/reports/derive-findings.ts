import type { Finding } from "@module/audit/checks/types"
import { readAppConfig } from "@shared/config-store"
import type { DmarcReportRow, ParsedDmarcReport, ParsedTlsRptReport } from "./report.types"
import { listDmarcReports, listTlsRptReports } from "./report-store"

/**
 * Report → Finding derivation (pm/emails.mdx §3/§5). Aggregates the stored, parsed reports over a
 * rolling window (default 7 days, anchored on the NEWEST report window so a historical corpus
 * still analyzes) and scores them against the problem catalog. Every finding carries
 * `source: "report"` and rolls into the EXISTING categories: `dmarc.*` (DMARC column) and
 * `infra.*` (DNS & Infrastructure column) — no seventh category (§6).
 */

// ─── Aggregation shapes (also served raw to the Reports UI, §7.1) ────────────────────────────────

/** One merged per-source row of the expandable details table (§7.1 "Open the details"). */
export interface DmarcSourceRow {
  sourceIp: string
  count: number
  /** Worst disposition seen for the source (reject > quarantine > none). */
  disposition: string
  spfEvaluated: string
  dkimEvaluated: string
  spfAligned: boolean
  dkimAligned: boolean
  dmarcPass: boolean
  headerFrom: string
  envelopeSpfDomain: string
  dkimSigningDomains: string[]
  reporters: string[]
}

export interface DmarcAggregate {
  reportCount: number
  reporters: string[]
  window: { begin: string; end: string }
  totalMessages: number
  /**
   * FULLY-aligned volume — both SPF and DKIM align (§12's "DMARC-aligned pass" figure: 1,157 of
   * 1,195 for the corpus). A single-mechanism pass still passes DMARC (dmarcPassMessages) but
   * counts as "failing alignment" here — it is the fragile slice the pass-rate finding flags.
   */
  alignedPassMessages: number
  /** Volume passing DMARC at all (either mechanism aligned) — what receivers actually deliver. */
  dmarcPassMessages: number
  /** Dual-aligned percentage 0–100 (100 when no volume) — §12's 96.8%. */
  passRatePct: number
  policyPublished: ParsedDmarcReport["policyPublished"] | null
  rows: DmarcSourceRow[]
}

export interface TlsRptReporterDay {
  reporterOrg: string
  reportDate: string
  policyType: string
  successCount: number
  failureCount: number
  failureDetails: { resultType: string; count: number }[]
}

export interface TlsRptAggregate {
  reportCount: number
  reporters: string[]
  window: { begin: string; end: string }
  totalSuccess: number
  totalFailure: number
  policyTypes: string[]
  rows: TlsRptReporterDay[]
}

const DISPOSITION_RANK: Record<string, number> = { none: 0, quarantine: 1, reject: 2 }

/** True when `child` equals `parent` or is a subdomain of it. */
export function underDomain(child: string, parent: string): boolean {
  const c = child.replace(/\.$/, "").toLowerCase()
  const p = parent.replace(/\.$/, "").toLowerCase()
  return c === p || c.endsWith(`.${p}`)
}

/** "Known sender" heuristic (§3.1): the row's envelope or a DKIM d= traces to the org domain. */
export function isKnownSender(row: DmarcReportRow, domain: string): boolean {
  if (row.envelopeSpfDomain && underDomain(row.envelopeSpfDomain, domain)) return true
  return row.dkimSigningDomains.some((d) => underDomain(d, domain))
}

/**
 * Volume breakdown of a DMARC aggregate (pm/emails.mdx §13.3/§16.3 snapshot fields): how many
 * messages passed on one mechanism only (the fragile slices), failed both, or were actively
 * quarantined/rejected by receivers.
 */
export function dmarcVolumeBreakdown(agg: DmarcAggregate): {
  dkimOnly: number
  spfOnly: number
  bothFail: number
  quarantined: number
  rejected: number
} {
  let dkimOnly = 0
  let spfOnly = 0
  let bothFail = 0
  let quarantined = 0
  let rejected = 0
  for (const row of agg.rows) {
    if (row.dkimAligned && !row.spfAligned) dkimOnly += row.count
    else if (row.spfAligned && !row.dkimAligned) spfOnly += row.count
    else if (!row.spfAligned && !row.dkimAligned) bothFail += row.count
    if (row.disposition === "quarantine") quarantined += row.count
    else if (row.disposition === "reject") rejected += row.count
  }
  return { dkimOnly, spfOnly, bothFail, quarantined, rejected }
}

/**
 * The §7.1 fragile-stream detection, shared by the per-source dmarc.report_alignment_fragility
 * enumeration (§5) and the aggregate content.report_fragility verdict (§13.2): OWN streams that
 * pass DMARC on only one mechanism. DKIM-only rows count only when the envelope traces to the org
 * domain (an ESP subdomain under aspf=s); a DKIM-only row with an unrelated envelope is forwarded
 * mail — benign when DKIM aligns (§3.1). SPF-only rows count when the stream is otherwise ours.
 */
export function fragileStreams(
  agg: DmarcAggregate,
  domain: string,
): Map<string, { count: number; ips: Set<string>; dkimOnly: boolean }> {
  const fragile = new Map<string, { count: number; ips: Set<string>; dkimOnly: boolean }>()
  for (const row of agg.rows) {
    if (!row.dmarcPass || row.spfAligned === row.dkimAligned) continue
    const dkimOnly = row.dkimAligned && !row.spfAligned
    if (dkimOnly && !(row.envelopeSpfDomain && underDomain(row.envelopeSpfDomain, domain))) continue
    if (!dkimOnly && !isKnownSender(row, domain)) continue
    const streamKey = `${row.envelopeSpfDomain || row.sourceIp}|${dkimOnly ? "dkim" : "spf"}`
    const entry = fragile.get(streamKey) ?? { count: 0, ips: new Set<string>(), dkimOnly }
    entry.count += row.count
    entry.ips.add(row.sourceIp)
    fragile.set(streamKey, entry)
  }
  return fragile
}

/** Reports whose window overlaps [start, end]. */
function inWindow(begin: string, end: string, start: string, stop: string): boolean {
  return begin <= stop && end >= start
}

/** The rolling window, anchored on the newest report so old corpora still aggregate (§4.6). */
function windowFor(newestEnd: string, windowDays: number): { begin: string; end: string } {
  const endMs = Date.parse(newestEnd)
  const anchor = Number.isFinite(endMs) ? endMs : Date.now()
  return {
    begin: new Date(anchor - windowDays * 24 * 60 * 60 * 1000).toISOString(),
    end: new Date(anchor).toISOString(),
  }
}

export function aggregateDmarc(reports: ParsedDmarcReport[], windowDays: number): DmarcAggregate {
  const newestEnd =
    reports
      .map((r) => r.window.end)
      .sort()
      .at(-1) ?? new Date().toISOString()
  const window = windowFor(newestEnd, windowDays)
  const current = reports.filter((r) =>
    inWindow(r.window.begin, r.window.end, window.begin, window.end),
  )

  const bySource = new Map<string, DmarcSourceRow>()
  let total = 0
  let dualAligned = 0
  let dmarcPass = 0
  for (const report of current) {
    for (const row of report.rows) {
      total += row.count
      if (row.spfAligned && row.dkimAligned) dualAligned += row.count
      if (row.dmarcPass) dmarcPass += row.count
      const key = `${row.sourceIp}|${row.envelopeSpfDomain}|${row.spfAligned}|${row.dkimAligned}`
      const merged = bySource.get(key)
      if (merged) {
        merged.count += row.count
        if (
          (DISPOSITION_RANK[row.disposition] ?? 0) > (DISPOSITION_RANK[merged.disposition] ?? 0)
        ) {
          merged.disposition = row.disposition
        }
        for (const d of row.dkimSigningDomains) {
          if (!merged.dkimSigningDomains.includes(d)) merged.dkimSigningDomains.push(d)
        }
        if (!merged.reporters.includes(report.reporterOrg))
          merged.reporters.push(report.reporterOrg)
      } else {
        bySource.set(key, {
          ...row,
          dkimSigningDomains: [...row.dkimSigningDomains],
          reporters: [report.reporterOrg],
        })
      }
    }
  }

  return {
    reportCount: current.length,
    reporters: [...new Set(current.map((r) => r.reporterOrg))].sort(),
    window,
    totalMessages: total,
    alignedPassMessages: dualAligned,
    dmarcPassMessages: dmarcPass,
    passRatePct: total === 0 ? 100 : Math.round((dualAligned / total) * 1000) / 10,
    policyPublished: current[0]?.policyPublished ?? null,
    rows: [...bySource.values()].sort((a, b) => b.count - a.count),
  }
}

export function aggregateTlsRpt(
  reports: ParsedTlsRptReport[],
  windowDays: number,
): TlsRptAggregate {
  const newestEnd =
    reports
      .map((r) => r.window.end || r.reportDate)
      .sort()
      .at(-1) ?? new Date().toISOString()
  const window = windowFor(newestEnd, windowDays)
  const current = reports.filter((r) =>
    inWindow(
      r.window.begin || r.reportDate,
      r.window.end || r.reportDate,
      window.begin,
      window.end,
    ),
  )

  const rows: TlsRptReporterDay[] = []
  let success = 0
  let failure = 0
  for (const report of current) {
    for (const policy of report.policies) {
      success += policy.successCount
      failure += policy.failureCount
      rows.push({
        reporterOrg: report.reporterOrg,
        reportDate: report.reportDate,
        policyType: policy.policyType,
        successCount: policy.successCount,
        failureCount: policy.failureCount,
        failureDetails: policy.failureDetails,
      })
    }
  }
  rows.sort((a, b) => b.reportDate.localeCompare(a.reportDate))

  return {
    reportCount: current.length,
    reporters: [...new Set(current.map((r) => r.reporterOrg))].sort(),
    window,
    totalSuccess: success,
    totalFailure: failure,
    policyTypes: [...new Set(rows.map((r) => r.policyType))].sort(),
    rows,
  }
}

// ─── Findings (§5 table) ─────────────────────────────────────────────────────────────────────────

const DMARC_CHECK_ID = "dmarc.reports"
const TLS_CHECK_ID = "infra.tls_rpt"

function fmtWindow(w: { begin: string; end: string }): string {
  return `${w.begin.slice(0, 10)}→${w.end.slice(0, 10)}`
}

/** The single muted finding when the admin master switch is off (pm/emails.mdx §8). */
export function ingestionDisabledFinding(id: string, checkId: string): Finding {
  return {
    id,
    checkId,
    title: "Report ingestion disabled",
    severity: "info",
    detail:
      "Report-email ingestion is switched off in Settings → Admin, so this check contributes nothing to the score.",
    remediation:
      "Enable report ingestion under Settings → Admin to feed this check with real receiver data.",
    source: "report",
  }
}

/** DMARC-aggregate findings for one domain (dmarc.* — the DMARC dashboard column, §5/§6). */
export function deriveDmarcReportFindings(domainId: string, domain: string): Finding[] {
  const config = readAppConfig().reports
  if (!config.enabled) {
    return [ingestionDisabledFinding("dmarc.real_pass_rate", DMARC_CHECK_ID)]
  }
  const reports = listDmarcReports(domainId)
  if (reports.length === 0) {
    return [
      {
        id: "dmarc.real_pass_rate",
        checkId: DMARC_CHECK_ID,
        title: "No DMARC aggregate reports ingested yet",
        severity: "info",
        detail: `No rua aggregate reports have been ingested for ${domain}; the real-world DMARC pass rate is unknown until receivers' reports arrive (typically 24–72h after publishing rua=).`,
        remediation: `Publish rua=mailto:dmarc@${domain} on _dmarc.${domain} and point the report mailbox or drop folder here (Settings → Admin), then Ingest now on the Reports page.`,
        source: "report",
      },
    ]
  }

  const agg = aggregateDmarc(reports, config.windowDays)
  const findings: Finding[] = []
  const enforced = (agg.policyPublished?.p ?? "none") === "reject"

  // dmarc.real_pass_rate — the dual-aligned percentage over the window (§5 row 1, §12: 96.8%).
  const failVolume = agg.totalMessages - agg.alignedPassMessages
  const failSources = new Set(
    agg.rows.filter((r) => !(r.spfAligned && r.dkimAligned)).map((r) => r.sourceIp),
  ).size
  findings.push({
    id: "dmarc.real_pass_rate",
    checkId: DMARC_CHECK_ID,
    title: `DMARC-aligned pass rate ${agg.passRatePct}%`,
    severity: failVolume > 0 && agg.passRatePct < 99.5 ? "warning" : "info",
    detail: `${agg.passRatePct}% of mail is DMARC-aligned (${agg.alignedPassMessages} / ${agg.totalMessages} msgs, ${fmtWindow(agg.window)}); ${failVolume} msgs from ${failSources} source(s) fail alignment on at least one mechanism. Reporters: ${agg.reporters.join(", ")}.`,
    remediation:
      failVolume > 0
        ? `Fix or authorize the failing sources (SPF include: / DKIM selector / alignment) ${enforced ? "— they are being evaluated under p=reject right now" : "before raising the policy"}.`
        : undefined,
    source: "report",
  })

  // dmarc.report_unaligned_source — rows failing BOTH alignments (§5 row 2).
  const bothFail = agg.rows.filter((r) => !r.spfAligned && !r.dkimAligned && r.count > 0)
  if (bothFail.length === 0) {
    findings.push({
      id: "dmarc.report_unaligned_source",
      checkId: DMARC_CHECK_ID,
      title: "No unauthorized senders",
      severity: "ok",
      detail: `0 rows fail both SPF and DKIM alignment across ${agg.totalMessages} msgs — no spoofing or forgotten sender is visible in the reports.`,
      source: "report",
    })
  } else {
    for (const row of bothFail) {
      const known = row.envelopeSpfDomain !== "" && underDomain(row.envelopeSpfDomain, domain)
      findings.push({
        id: `dmarc.report_unaligned_source.${row.sourceIp}`,
        checkId: DMARC_CHECK_ID,
        title: known
          ? `Own stream failing all authentication (${row.sourceIp})`
          : `Unauthorized sender ${row.sourceIp}`,
        severity: known ? "warning" : "critical",
        detail: `Source ${row.sourceIp} sent ${row.count} msg(s) as ${row.headerFrom || domain} — SPF ${row.spfEvaluated}/aligned ${row.spfAligned}, DKIM ${row.dkimEvaluated}/aligned ${row.dkimAligned} (disposition: ${row.disposition}).`,
        remediation: known
          ? `Authorize this sender: add it to SPF (include:) and enable DKIM signing with a selector under ${domain}.`
          : `If this is your sender, add it to SPF (include:) and enable DKIM for it; if not, it is spoofing — it is already being rejected under p=reject, monitor it and report high-volume abuse.`,
        evidence: `${row.sourceIp} envelope=${row.envelopeSpfDomain || "-"} dkim_d=${row.dkimSigningDomains.join(",") || "-"}`,
        source: "report",
      })
    }
  }

  // dmarc.report_alignment_fragility — own streams passing via ONE mechanism only (§5 row 3);
  // detection shared with the aggregate content.report_fragility verdict (fragileStreams above).
  const fragile = fragileStreams(agg, domain)
  if (fragile.size === 0) {
    findings.push({
      id: "dmarc.report_alignment_fragility",
      checkId: DMARC_CHECK_ID,
      title: "All passing streams are dual-aligned",
      severity: "ok",
      detail:
        "Every known stream that passes DMARC aligns on both SPF and DKIM — no single point of failure.",
      source: "report",
    })
  } else {
    const aspf = agg.policyPublished?.aspf ?? "r"
    const adkim = agg.policyPublished?.adkim ?? "r"
    for (const [key, s] of fragile) {
      const envelope = key.split("|")[0]
      findings.push({
        id: `dmarc.report_alignment_fragility.${envelope}`,
        checkId: DMARC_CHECK_ID,
        title: s.dkimOnly
          ? `Stream is DKIM-only (${envelope})`
          : `Stream is SPF-only (${envelope})`,
        severity: "warning",
        detail: s.dkimOnly
          ? `${s.count} msg(s) from ${[...s.ips].slice(0, 4).join(", ")} (envelope ${envelope}) pass DMARC via DKIM only — SPF alignment fails under aspf=${aspf}. One DKIM key rotation/breakage and the whole stream fails DMARC${(agg.policyPublished?.p ?? "") === "reject" ? " and is rejected under p=reject" : ""}.`
          : `${s.count} msg(s) from ${[...s.ips].slice(0, 4).join(", ")} (envelope ${envelope}) pass DMARC via SPF only — DKIM fails or does not align under adkim=${adkim}. A Return-Path change or a forward breaks the stream.`,
        remediation: s.dkimOnly
          ? `Set aspf=r on _dmarc.${domain}, or brand the Return-Path (e.g. bounces.${domain} CNAME'd at the ESP) so the envelope aligns and the stream has dual-auth resilience.`
          : `Enable DKIM signing with a selector under ${domain} (selector._domainkey.${domain}) at this sender, and/or set adkim=r.`,
        evidence: s.dkimOnly
          ? `v=DMARC1; p=${agg.policyPublished?.p ?? "reject"}; aspf=r`
          : `selector._domainkey.${domain}`,
        source: "report",
      })
    }
  }

  // dmarc.report_enforcement — own mail actively quarantined/rejected (§5 row 4).
  const enforcedRows = agg.rows.filter(
    (r) => r.disposition === "quarantine" || r.disposition === "reject",
  )
  if (enforcedRows.length === 0) {
    findings.push({
      id: "dmarc.report_enforcement",
      checkId: DMARC_CHECK_ID,
      title: "No mail quarantined or rejected",
      severity: "info",
      detail: `Every reported row carries disposition=none — receivers are not dropping mail sent as ${domain}.`,
      source: "report",
    })
  } else {
    for (const row of enforcedRows) {
      findings.push({
        id: `dmarc.report_enforcement.${row.sourceIp}`,
        checkId: DMARC_CHECK_ID,
        title: `Mail ${row.disposition} by receivers (${row.sourceIp})`,
        severity: "critical",
        detail: `${row.count} msg(s) from ${row.sourceIp} were ${row.disposition} by ${row.reporters.join(", ")}.`,
        remediation: `Identify the failing source ${row.sourceIp}, authorize it (SPF include: / DKIM selector under ${domain}), and confirm alignment before it recurs.`,
        source: "report",
      })
    }
  }

  // dmarc.report_new_source — sources unseen in prior windows (§5 row 5). Needs a prior baseline.
  const prior = reports.filter((r) => r.window.end < agg.window.begin)
  if (prior.length > 0) {
    const priorIps = new Set(prior.flatMap((r) => r.rows.map((row) => row.sourceIp)))
    const fresh = agg.rows.filter((r) => !priorIps.has(r.sourceIp))
    if (fresh.length > 0) {
      const totalNew = fresh.reduce((n, r) => n + r.count, 0)
      findings.push({
        id: "dmarc.report_new_source",
        checkId: DMARC_CHECK_ID,
        title: `${fresh.length} new sending source(s) appeared this window`,
        severity: "info",
        detail: `New sending source(s) ${fresh
          .slice(0, 5)
          .map((r) => r.sourceIp)
          .join(
            ", ",
          )}${fresh.length > 5 ? ", …" : ""} (${totalNew} msg(s)) appeared this window and were absent from prior windows.`,
        remediation: `Reconcile against your known senders; add to SPF/DKIM if yours, else monitor for spoofing.`,
        source: "report",
      })
    }
  }

  return findings
}

/** TLS-RPT findings for one domain (infra.tls_rpt_reports_ingested — DNS & Infra column, §5). */
export function deriveTlsRptFindings(domainId: string, domain: string): Finding[] {
  const config = readAppConfig().reports
  if (!config.enabled) {
    return [ingestionDisabledFinding("infra.tls_rpt_reports_ingested", TLS_CHECK_ID)]
  }
  const reports = listTlsRptReports(domainId)
  if (reports.length === 0) {
    return [
      {
        id: "infra.tls_rpt_reports_ingested",
        checkId: TLS_CHECK_ID,
        title: "No TLS reports ingested yet",
        severity: "info",
        detail:
          "No RFC 8460 TLS-RPT reports have been ingested; failure volume and trend (starttls-not-supported, certificate-host-mismatch, validation-failure) are unknown until reports arrive.",
        remediation: `Publish rua=mailto:tls-reports@${domain} on _smtp._tls.${domain} and point the report mailbox or drop folder here (Settings → Admin), then Ingest now on the Reports page.`,
        source: "report",
      },
    ]
  }

  const agg = aggregateTlsRpt(reports, config.windowDays)
  const findings: Finding[] = []

  if (agg.totalFailure > 0) {
    const types = [...new Set(agg.rows.flatMap((r) => r.failureDetails.map((d) => d.resultType)))]
    const fixes: Record<string, string> = {
      "starttls-not-supported": "ensure every MX offers STARTTLS",
      "certificate-host-mismatch": "replace the MX certificate so its name matches the MX host",
      "certificate-expired": "renew the expired MX certificate",
      "validation-failure": "install a certificate from a trusted CA on the MX",
      "tlsa-invalid": "repair the TLSA record after the key roll",
      "dnssec-invalid": "fix the DNSSEC chain for the TLSA record",
      "sts-policy-fetch-error": `make https://mta-sts.${domain}/.well-known/mta-sts.txt reachable`,
      "sts-policy-invalid": "correct the MTA-STS policy file syntax",
      "sts-webpki-invalid": "fix the certificate on the mta-sts policy host",
    }
    const layerFixes = types.map((t) => fixes[t] ?? `investigate ${t}`).join("; ")
    findings.push({
      id: "infra.tls_rpt_reports_ingested",
      checkId: TLS_CHECK_ID,
      title: `Inbound TLS failures reported (${agg.totalFailure} session(s))`,
      severity: "warning",
      detail: `${agg.reporters.join(", ")}: ${agg.totalSuccess} ok / ${agg.totalFailure} failed TLS sessions over ${fmtWindow(agg.window)} (${types.join(", ") || "no failure-details given"}). Senders enforcing MTA-STS/DANE bounce or downgrade mail on these failures.`,
      remediation: `Fix the reported layer: ${layerFixes || `check the MX certificates and MTA-STS/TLSA records for ${domain}`}.`,
      evidence: types.join(", "),
      source: "report",
    })
  } else {
    findings.push({
      id: "infra.tls_rpt_reports_ingested",
      checkId: TLS_CHECK_ID,
      title: "Inbound TLS healthy",
      severity: "info",
      detail: `${agg.reporters.join(", ")}: ${agg.totalSuccess} ok / 0 failed TLS sessions over ${fmtWindow(agg.window)} (policy: ${agg.policyTypes.join(", ") || "n/a"}). Healthy baseline recorded so a later regression is detectable.`,
      source: "report",
    })
  }

  // no-policy-found where a policy is expected (§3.2 row 3) — another reporter saw sts/tlsa.
  const sawPolicy = agg.rows.some((r) => r.policyType === "sts" || r.policyType === "tlsa")
  const noPolicy = agg.rows.filter((r) => r.policyType === "no-policy-found")
  if (sawPolicy && noPolicy.length > 0) {
    findings.push({
      id: "infra.tls_rpt_no_policy_found",
      checkId: TLS_CHECK_ID,
      title: "A reporter saw no TLS policy",
      severity: "warning",
      detail: `${noPolicy.map((r) => r.reporterOrg).join(", ")} reported policy-type no-policy-found while other reporters saw your MTA-STS/DANE policy — the policy is not consistently visible.`,
      remediation: `Verify the _mta-sts.${domain} TXT record and the HTTPS policy file (or the TLSA record) resolve from everywhere.`,
      source: "report",
    })
  }

  return findings
}
