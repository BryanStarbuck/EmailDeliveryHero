import { resolveTxt } from "../dns-util"
import type { Checker, Finding } from "../types"

/**
 * MTA-STS (SMTP MTA Strict Transport Security, RFC 8461). MTA-STS has two moving parts on different
 * transports, and per the spec we split them:
 *
 *  1. A DNS TXT record at `_mta-sts.<domain>` (`v=STSv1; id=<version>`) — pure DNS, FIRST-ROUND here.
 *  2. An HTTPS policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt` — needs an HTTPS
 *     client + TLS/cert validation, so every sub-check that reads the served policy body is FUTURE.
 *
 * First-round sub-checks (implemented): infra.mta_sts_txt, infra.mta_sts_version,
 * infra.mta_sts_txt_single, infra.mta_sts_id_format, infra.mta_sts_vs_tlsrpt.
 *
 * Future sub-checks (the served-policy family: infra.mta_sts_policy / _https_cert / _policy_version /
 * _mode / _mx_present / _mx_match / _max_age / _id_freshness / _txt_policy_consistency /
 * _https_redirect / _content_type) are collapsed into a single `info` "pending" finding — never a
 * warning/critical — until the HTTPS probe ships behind the `mtaSts.httpsProbe.enabled` flag.
 */

const CHECK_ID = "infra.mta_sts"

/** id token: 1–32 printable ASCII, alphanumeric (RFC 8461 §3.1 style, monotonic-friendly). */
const ID_RE = /^[A-Za-z0-9]{1,32}$/

interface ParsedTxt {
  raw: string
  tags: string[]
  map: Record<string, string>
  firstKey: string
  versionOk: boolean
  id: string | undefined
}

/** Parse a `;`-separated MTA-STS tag list into a first-tag-aware map. */
function parseStsTxt(raw: string): ParsedTxt {
  const tags = raw
    .split(";")
    .map((t) => t.trim())
    .filter(Boolean)
  const map: Record<string, string> = {}
  for (const tag of tags) {
    const eq = tag.indexOf("=")
    if (eq === -1) continue
    const key = tag.slice(0, eq).trim().toLowerCase()
    const value = tag.slice(eq + 1).trim()
    if (!(key in map)) map[key] = value
  }
  const firstEq = tags.length > 0 ? tags[0].indexOf("=") : -1
  const firstKey = firstEq > -1 ? tags[0].slice(0, firstEq).trim().toLowerCase() : ""
  const versionOk = firstKey === "v" && (map.v ?? "").toLowerCase() === "stsv1"
  return { raw, tags, map, firstKey, versionOk, id: map.id }
}

export const mtaStsCheck: Checker = {
  id: CHECK_ID,
  label: "MTA-STS",
  async run(ctx): Promise<Finding[]> {
    const txtName = `_mta-sts.${ctx.domain}`
    // resolveTxt concatenates each record's 255-byte character-string chunks into one string.
    const txt = await resolveTxt(txtName)

    // Transient DNS failure (SERVFAIL / timeout) — retry later, never a false problem.
    if (txt.error) {
      return [
        {
          id: "infra.mta_sts_txt",
          checkId: CHECK_ID,
          title: "Could not look up MTA-STS TXT",
          severity: "info",
          detail: `DNS lookup for TXT ${txtName} failed transiently (${txt.error}). MTA-STS status is unknown this run.`,
          remediation: `Retry the audit. If it persists, verify the authoritative nameservers for ${ctx.domain} are responding.`,
        },
      ]
    }

    // Candidate MTA-STS records: anything that looks like a v=STS* tag set (catches STSv1 and typos).
    const candidates = txt.records.filter((r) => /v=sts/i.test(r))
    if (candidates.length === 0) {
      // Feature absent — info only. Per the roll-up rule this must NOT turn the DNS & Infra cell amber.
      return [
        {
          id: "infra.mta_sts_txt",
          checkId: CHECK_ID,
          title: "No MTA-STS policy published",
          severity: "info",
          detail: `${ctx.domain} has no _mta-sts TXT record. MTA-STS is optional but recommended: it tells sending servers to always use TLS to your MX hosts and forbids downgrade attacks.`,
          remediation: `Publish a TXT record at ${txtName}: "v=STSv1; id=20260701000000" and serve the matching policy at https://mta-sts.${ctx.domain}/.well-known/mta-sts.txt`,
        },
      ]
    }

    const findings: Finding[] = []
    const parsed = candidates.map(parseStsTxt)
    const stsv1 = parsed.filter((p) => p.versionOk)
    // Inspect a primary record: prefer a correctly-versioned one, else the first candidate.
    const primary = stsv1[0] ?? parsed[0]

    // --- infra.mta_sts_txt_single: duplicate detection ---
    if (stsv1.length > 1) {
      findings.push({
        id: "infra.mta_sts_txt_single",
        checkId: CHECK_ID,
        title: "Multiple MTA-STS TXT records",
        severity: "warning",
        detail: `${txtName} publishes ${stsv1.length} STSv1 TXT records; it is undefined which one a sender uses.`,
        remediation: `Remove the extra _mta-sts TXT record so exactly one "v=STSv1; id=..." remains.`,
        evidence: candidates.join(" | "),
      })
    } else {
      findings.push({
        id: "infra.mta_sts_txt_single",
        checkId: CHECK_ID,
        title: "Single MTA-STS TXT record",
        severity: "ok",
        detail: "Exactly one _mta-sts STSv1 TXT record is published.",
        evidence: primary.raw,
      })
    }

    // --- infra.mta_sts_version: first tag must be exactly v=STSv1 ---
    if (primary.versionOk) {
      findings.push({
        id: "infra.mta_sts_version",
        checkId: CHECK_ID,
        title: "MTA-STS version tag valid",
        severity: "ok",
        detail: 'The record begins with "v=STSv1".',
        evidence: primary.raw,
      })
    } else {
      findings.push({
        id: "infra.mta_sts_version",
        checkId: CHECK_ID,
        title: "MTA-STS version tag invalid",
        severity: "warning",
        detail: `The _mta-sts TXT must begin with the exact token "v=STSv1" as its first tag. Observed first tag: "${primary.tags[0] ?? "(empty)"}".`,
        remediation: `Correct the record to begin with "v=STSv1;", e.g. "v=STSv1; id=20260701000000".`,
        evidence: primary.raw,
      })
    }

    // --- infra.mta_sts_id_format: id present and 1–32 alphanumeric ---
    const id = primary.id
    if (id && ID_RE.test(id)) {
      findings.push({
        id: "infra.mta_sts_id_format",
        checkId: CHECK_ID,
        title: "MTA-STS id is valid",
        severity: "ok",
        detail: `Policy id "${id}" is a valid 1–32 char alphanumeric token.`,
        evidence: primary.raw,
      })
    } else {
      findings.push({
        id: "infra.mta_sts_id_format",
        checkId: CHECK_ID,
        title: id ? "MTA-STS id is malformed" : "MTA-STS id is missing",
        severity: "warning",
        detail: id
          ? `Policy id "${id}" must match ^[A-Za-z0-9]{1,32}$ (1–32 alphanumeric chars); senders may ignore the policy.`
          : "The _mta-sts TXT record has no id= tag, so senders cannot detect when the policy changes.",
        remediation: `Set id to a short alphanumeric version stamp, e.g. "v=STSv1; id=20260701120000".`,
        evidence: primary.raw,
      })
    }

    // --- infra.mta_sts_txt: overall roll-up of the TXT record ---
    const txtValid = primary.versionOk && !!id && ID_RE.test(id)
    if (txtValid) {
      findings.push({
        id: "infra.mta_sts_txt",
        checkId: CHECK_ID,
        title: "MTA-STS TXT record present",
        severity: "ok",
        detail: `Found a valid _mta-sts TXT record (id="${id}").`,
        evidence: primary.raw,
      })
    } else {
      findings.push({
        id: "infra.mta_sts_txt",
        checkId: CHECK_ID,
        title: "MTA-STS TXT record is malformed",
        severity: "warning",
        detail: `${txtName} has a record but it does not parse as a valid "v=STSv1; id=<token>".`,
        remediation: `Publish exactly: "v=STSv1; id=20260701000000" at ${txtName}.`,
        evidence: primary.raw,
      })
    }

    // --- infra.mta_sts_vs_tlsrpt: cross-check that a TLS-RPT endpoint exists to receive failures ---
    const tlsrptName = `_smtp._tls.${ctx.domain}`
    const tlsrpt = await resolveTxt(tlsrptName)
    if (tlsrpt.error) {
      findings.push({
        id: "infra.mta_sts_vs_tlsrpt",
        checkId: CHECK_ID,
        title: "Could not check TLS-RPT",
        severity: "info",
        detail: `DNS lookup for TXT ${tlsrptName} failed transiently (${tlsrpt.error}), so TLS-RPT presence is unknown this run.`,
        remediation: `Retry the audit to confirm a TLS-RPT record exists alongside MTA-STS.`,
      })
    } else if (tlsrpt.records.some((r) => /v=tlsrptv1/i.test(r))) {
      findings.push({
        id: "infra.mta_sts_vs_tlsrpt",
        checkId: CHECK_ID,
        title: "TLS-RPT reporting present",
        severity: "ok",
        detail: "A TLS-RPT record exists to receive MTA-STS/TLS failure reports.",
        evidence: tlsrptName,
      })
    } else {
      findings.push({
        id: "infra.mta_sts_vs_tlsrpt",
        checkId: CHECK_ID,
        title: "MTA-STS present but no TLS-RPT",
        severity: "info",
        detail: `${ctx.domain} publishes MTA-STS but has no _smtp._tls TLS-RPT record, so enforcement/TLS failures are reported to no one.`,
        remediation: `Publish ${tlsrptName} TXT "v=TLSRPTv1; rua=mailto:tlsrpt@${ctx.domain}".`,
      })
    }

    // --- FUTURE (served-policy) family: one pending info, never warning/critical. ---
    // Gated on the HTTPS probe (mtaSts.httpsProbe.enabled). Only surfaced when a TXT is present,
    // since a sender would never fetch a policy the TXT does not advertise.
    findings.push({
      id: "infra.mta_sts_policy",
      checkId: CHECK_ID,
      title: "MTA-STS policy-file checks pending",
      severity: "info",
      detail: `A TXT record is published; the HTTPS policy at https://mta-sts.${ctx.domain}/.well-known/mta-sts.txt is not yet fetched by this app. Once the HTTPS probe ships it will verify the policy is served (HTTP 200, text/plain, no redirect), the certificate is valid for mta-sts.${ctx.domain}, that mode/max_age are sane, that every live MX matches an mx: pattern, and that the id is bumped whenever the policy body changes.`,
      remediation: `Serve the policy at https://mta-sts.${ctx.domain}/.well-known/mta-sts.txt with a valid CA cert and "Content-Type: text/plain", e.g.:\nversion: STSv1\nmode: enforce\nmx: mail.${ctx.domain}\nmax_age: 604800`,
    })

    return findings
  },
}
