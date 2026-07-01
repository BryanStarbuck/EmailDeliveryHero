/**
 * The audit engine's shared vocabulary. Each deliverability check is a small pluggable `Checker`
 * that inspects one aspect of a domain's email setup (SPF, DKIM, DMARC, MX, blacklist) and returns
 * zero or more `Finding`s. A finding always carries a severity and, when something is wrong, a
 * concrete `remediation` string telling the user exactly how to fix it.
 */

export type Severity = "ok" | "info" | "warning" | "critical"

export interface Finding {
  /** Stable id for the finding kind, e.g. "spf.missing". */
  id: string
  /** Which checker produced it, e.g. "spf". */
  checkId: string
  title: string
  severity: Severity
  /** Human explanation of what was observed. */
  detail: string
  /** How to fix it (present when severity is warning/critical; omitted when ok). */
  remediation?: string
  /** Raw evidence (the DNS record found, the blocklist that matched, etc.). */
  evidence?: string
}

/** Everything a checker needs to inspect one domain. */
export interface CheckContext {
  domain: string
  /** DKIM selectors to probe, e.g. ["google", "default"]. */
  dkimSelectors: string[]
  /** Sending IPs to test against DNS blacklists (optional; MX IPs are used when empty). */
  sendingIps: string[]
}

export interface Checker {
  id: string
  label: string
  run(ctx: CheckContext): Promise<Finding[]>
}

/** The result of auditing one domain — the full finding list plus a rolled-up score/status. */
export interface AuditResult {
  domainId: string
  domain: string
  ranAt: string
  /** 0–100, derived from finding severities. */
  score: number
  status: Severity
  findings: Finding[]
  counts: Record<Severity, number>
}

/** Roll a flat finding list into a 0–100 score, an overall status, and per-severity counts. */
export function summarize(findings: Finding[]): {
  score: number
  status: Severity
  counts: Record<Severity, number>
} {
  const counts: Record<Severity, number> = { ok: 0, info: 0, warning: 0, critical: 0 }
  for (const f of findings) counts[f.severity]++

  // Each warning costs 12 points, each critical 30; floor at 0.
  const penalty = counts.warning * 12 + counts.critical * 30
  const score = Math.max(0, 100 - penalty)

  const status: Severity =
    counts.critical > 0 ? "critical" : counts.warning > 0 ? "warning" : counts.info > 0 ? "info" : "ok"

  return { score, status, counts }
}
