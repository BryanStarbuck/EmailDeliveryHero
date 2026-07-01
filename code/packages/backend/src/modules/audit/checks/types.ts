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
  /**
   * Regression flag (pm/engineering.mdx §8): true when this problem newly appeared — or worsened in
   * severity — versus the domain's previous run. Only set on warning/critical findings, and only
   * when a previous run exists to diff against.
   */
  isNew?: boolean
}

/** A DKIM public-key hash observed on another monitored domain (latest audit). */
export interface PeerDkimKey {
  domain: string
  selector: string
  keySha256: string
}

/**
 * One forwarder / mailing list a domain declares it sends through (pm/checks/arc.mdx §4/§5 — the
 * `arc_forwarders` reference table, stored per-domain as `arc.forwarders` in domains.yaml today).
 */
export interface ArcForwarderConfig {
  /** Human label, e.g. "acme-users Google Group". */
  label: string
  /** The probe target that forwards to us. */
  forwardAddress: string
  /** Expected ARC signing domain (d=); nullable until configured or observed from a sample. */
  signerDomain?: string
  /** Expected ARC signing selector (s=). */
  signerSelector?: string
  /** Where the forwarded copy lands for capture (drives the future swaks probe). */
  probeMailbox?: string
}

/** Per-domain ARC / forwarding configuration (pm/checks/arc.mdx §4 per-domain config inputs). */
export interface ArcConfig {
  /** Operator-declared "this domain sends through forwarders/lists" flag. */
  usesForwarding: boolean
  /** The declared forwarders / mailing lists. */
  forwarders: ArcForwarderConfig[]
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
  /** Per-domain ARC / forwarding config — powers arc.applicable / arc.forwarding_risk / arc.selector_dns. */
  arc?: ArcConfig
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
  /**
   * How many findings in this run are NEW problems versus the previous run (pm/engineering.mdx §8
   * regression detection) — i.e. how many findings carry `isNew: true`. 0 on a domain's first run.
   */
  newProblemCount?: number
  /** Structured per-check payloads keyed by checker id (e.g. results.dmarc — the parsed record). */
  results?: Record<string, unknown>
}

/** Severity ordering used by the regression diff — higher rank = worse. */
const SEVERITY_RANK: Record<Severity, number> = { ok: 0, info: 1, warning: 2, critical: 3 }

/**
 * Regression detection (pm/engineering.mdx §8): diff a run's findings against the domain's
 * previous run. A warning/critical finding is flagged `isNew` when its `id` did not exist in the
 * previous run, or when it existed at a lower severity (it worsened). Mutates the passed findings
 * in place and returns how many were flagged. With no previous run there is no baseline to
 * regress from, so nothing is flagged.
 */
export function flagNewProblems(
  previous: Finding[] | undefined,
  current: Finding[],
): number {
  if (!previous) return 0
  const previousRank = new Map<string, number>()
  for (const f of previous) {
    const rank = SEVERITY_RANK[f.severity]
    const seen = previousRank.get(f.id)
    if (seen === undefined || rank > seen) previousRank.set(f.id, rank)
  }
  let flagged = 0
  for (const f of current) {
    if (f.severity !== "warning" && f.severity !== "critical") continue
    const before = previousRank.get(f.id)
    if (before === undefined || SEVERITY_RANK[f.severity] > before) {
      f.isNew = true
      flagged++
    }
  }
  return flagged
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
