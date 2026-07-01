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

/** A DKIM public-key hash observed on another monitored domain (latest audit). */
export interface PeerDkimKey {
  domain: string
  selector: string
  keySha256: string
}

/** Everything a checker needs to inspect one domain. */
export interface CheckContext {
  domain: string
  /** DKIM selectors to probe, e.g. ["google", "default"]. */
  dkimSelectors: string[]
  /** Sending IPs to test against DNS blacklists (optional; MX IPs are used when empty). */
  sendingIps: string[]
  /** sha256(decoded p=) per selector across the OTHER monitored domains — powers dkim.duplicate_key. */
  peerDkimKeys?: PeerDkimKey[]
  /** The previous audit's structured results for this domain — powers dkim.rotation first-seen carry-forward. */
  previousResults?: Record<string, unknown>
}

/**
 * A checker may return a bare finding list, or findings plus a structured machine-readable payload
 * (pm/checks/*.mdx §5 "Information schema" — e.g. the parsed DMARC tag map). The payload lands in
 * `AuditResult.results[checker.id]` and powers the per-technology detail pages.
 */
export interface CheckOutcome {
  findings: Finding[]
  results?: unknown
}

export interface Checker {
  id: string
  label: string
  run(ctx: CheckContext): Promise<Finding[] | CheckOutcome>
}

/**
 * The result of auditing one domain — the full finding list plus a rolled-up score/status.
 * Vocabulary (pm/dashboard.mdx §1): this is one RUN — per domain, with start/stop date-times.
 * Inside it, the six categories are TESTS and each finding belongs to a SUB-TEST.
 */
export interface AuditResult {
  /** Unique id for this run (pm/dashboard.mdx §1). Absent only on pre-history persisted data. */
  runId: string
  domainId: string
  domain: string
  /** ISO date-time the run started. */
  startedAt: string
  /** ISO date-time the run stopped. */
  finishedAt: string
  /** Kept for older readers; always equals finishedAt. */
  ranAt: string
  /** 0–100, derived from finding severities. */
  score: number
  status: Severity
  findings: Finding[]
  counts: Record<Severity, number>
  /** Structured per-check payloads keyed by checker id (e.g. results.dmarc — the parsed record). */
  results?: Record<string, unknown>
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
    counts.critical > 0
      ? "critical"
      : counts.warning > 0
        ? "warning"
        : counts.info > 0
          ? "info"
          : "ok"

  return { score, status, counts }
}
