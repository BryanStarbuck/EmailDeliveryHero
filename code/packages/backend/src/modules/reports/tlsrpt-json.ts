import type { ParsedTlsRptReport, TlsRptPolicyResult } from "./report.types"

/**
 * TLS-RPT (RFC 8460) JSON → ParsedTlsRptReport (pm/emails.mdx §4.3/§4.4): organization-name,
 * date-range, and each policies[] entry's policy-type/policy-domain, success/failure session
 * counts, and failure-details. Returns null when the JSON is not a TLS-RPT document.
 */

interface RawTlsRpt {
  "organization-name"?: string
  "date-range"?: { "start-datetime"?: string; "end-datetime"?: string }
  "report-id"?: string
  policies?: {
    policy?: { "policy-type"?: string; "policy-domain"?: string }
    summary?: {
      "total-successful-session-count"?: number
      "total-failure-session-count"?: number
    }
    "failure-details"?: { "result-type"?: string; "failed-session-count"?: number }[]
  }[]
}

export function parseTlsRptJson(json: string): ParsedTlsRptReport | null {
  let raw: RawTlsRpt
  try {
    raw = JSON.parse(json) as RawTlsRpt
  } catch {
    return null
  }
  if (typeof raw !== "object" || raw === null) return null
  if (!raw["organization-name"] && !Array.isArray(raw.policies)) return null

  const begin = raw["date-range"]?.["start-datetime"] ?? ""
  const end = raw["date-range"]?.["end-datetime"] ?? ""
  const policies: TlsRptPolicyResult[] = (raw.policies ?? []).map((p) => ({
    policyType: (p.policy?.["policy-type"] ?? "no-policy-found").toLowerCase(),
    policyDomain: (p.policy?.["policy-domain"] ?? "").toLowerCase(),
    successCount: p.summary?.["total-successful-session-count"] ?? 0,
    failureCount: p.summary?.["total-failure-session-count"] ?? 0,
    failureDetails: (p["failure-details"] ?? []).map((d) => ({
      resultType: (d["result-type"] ?? "unknown").toLowerCase(),
      count: d["failed-session-count"] ?? 0,
    })),
  }))

  return {
    kind: "tlsrpt",
    reporterOrg: raw["organization-name"] ?? "unknown",
    reportDate: begin ? begin.slice(0, 10) : "unknown",
    window: { begin, end },
    policies,
  }
}
