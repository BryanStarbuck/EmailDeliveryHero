import { resolve4, resolveMx, resolveTxt } from "../dns-util"
import type { Checker, Finding } from "../types"

/**
 * Sender Reputation Metrics (Spam & Content family, `content` checkId prefix).
 *
 * Reputation is behavioral telemetry owned by the receivers and your ESP — it is NOT a DNS fact this
 * app can read directly. So per pm/checks/reputation_metrics.mdx §7, almost every sub-check is FUTURE,
 * gated behind a `reputation_integrations` row (Google Postmaster Tools API, provider FBLs, ESP
 * metrics). The FIRST round ships only what needs no external feed:
 *
 *   - content.reputation_data_available  (info: no integration connected → metrics unknown)
 *   - content.postmaster_verified        (DNS: is a Google verification TXT published?)
 *   - content.fbl_enrollment             (advisory: enroll the sending IPs' networks in provider FBLs)
 *   - content.blocklist_history          (trend of stored ./blacklists results — needs the cross-run
 *                                         store, which is not reachable from a stateless Checker, so it
 *                                         degrades to an info until the store is wired in)
 *
 * Every FUTURE metric sub-check emits exactly ONE `info` "not connected" finding — never a
 * warning/critical — so an un-integrated domain never produces a false positive (spec §8.1).
 */

const CHECK_ID = "content"

/** Provider feedback-loop programs to enroll in, with the exact signup URL for each. */
const FBL_PROGRAMS = [
  "Yahoo Complaint Feedback Loop (CFL): https://senders.yahooinc.com/complaint-feedback-loop/",
  "Microsoft SNDS + JMRP: https://sendersupport.olc.protection.outlook.com/snds/ and https://sendersupport.olc.protection.outlook.com/pm/",
  "Comcast FBL: https://postmaster.comcast.net/",
].join("; ")

/**
 * One FUTURE metric sub-check that is gated behind a third-party integration. First round it emits a
 * single `info` "not connected" finding naming what it will verify and which integration to connect.
 */
interface PendingSubcheck {
  id: string
  title: string
  /** What the sub-check will verify once its integration is live. */
  verifies: string
  /** The integration that unlocks it. */
  integration: string
  /** The concrete operational lever the finding will prescribe (from the spec's remediation column). */
  fix: string
}

const PENDING: PendingSubcheck[] = [
  {
    id: "content.complaint_rate",
    title: "Spam-complaint rate (< 0.3%, ideally < 0.1%)",
    verifies:
      "the Gmail/Yahoo bulk-sender rule that the spam-complaint rate stays below 0.3% (hard limit) and ideally below 0.1%",
    integration: "Google Postmaster Tools",
    fix: "Pause the offending campaign/segment, suppress recent FBL complainers, add RFC 8058 one-click unsubscribe, and re-permission or drop cold segments until the rate is below 0.1%.",
  },
  {
    id: "content.gpt_spam_rate",
    title: "GPT user-reported spam-rate trend",
    verifies:
      "that Google Postmaster Tools spamRate stays flat/low (< 0.1%) and is not climbing week over week",
    integration: "Google Postmaster Tools",
    fix: "Identify the campaign/day the spike started (join to send logs), suppress that segment, and slow volume until the GPT rate recovers below 0.1%.",
  },
  {
    id: "content.gpt_domain_reputation",
    title: "GPT domain reputation band",
    verifies:
      "that the Google Postmaster Tools domain reputation band is High (or at least Medium)",
    integration: "Google Postmaster Tools",
    fix: "Cut volume to your most-engaged recipients only, fix the complaint/bounce drivers, and hold steady 2–4 weeks — reputation is earned back slowly, not with a config change.",
  },
  {
    id: "content.gpt_ip_reputation",
    title: "GPT per-IP reputation band",
    verifies:
      "that the Google Postmaster Tools reputation band for each sending IP is High or Medium",
    integration: "Google Postmaster Tools",
    fix: "For a shared-IP pool, ask the ESP to move you or investigate co-tenants; for a dedicated IP, re-warm gradually and reduce complaint sources.",
  },
  {
    id: "content.gpt_auth_rate",
    title: "GPT SPF/DKIM/DMARC pass rates",
    verifies:
      "that Google Postmaster Tools SPF/DKIM/DMARC success ratios are ~100% (all streams aligned)",
    integration: "Google Postmaster Tools",
    fix: "Trace the unaligned stream (forwarder, sub-mailer) and fix its SPF/DKIM alignment; cross-check the spf and dkim checks.",
  },
  {
    id: "content.delivery_errors",
    title: "GPT delivery-error categories",
    verifies:
      "that Google Postmaster Tools delivery-error categories (RATE_LIMITED, SUSPECTED_SPAM, REJECTED_DUE_TO_...) are low",
    integration: "Google Postmaster Tools",
    fix: "Address the specific error class Gmail reports — slow down for rate-limits; fix content/auth for spam rejects.",
  },
  {
    id: "content.fbl_processing",
    title: "FBL complaints ingested and suppressed",
    verifies:
      "that received FBL/ARF complaints are actually parsed and the complainers added to the suppression list (not just received)",
    integration: "FBL mailbox connector (IMAP + ARF parsing)",
    fix: "Automate: parse each FBL/ARF report and add the recipient to the global suppression list within 24h — never mail them again.",
  },
  {
    id: "content.bounce_rate",
    title: "Hard-bounce rate (< 2%, alarm ≥ 5%)",
    verifies: "that the hard-bounce rate stays low — target below 2%, alarm at or above 5%",
    integration: "ESP metrics API",
    fix: "Remove all hard-bounced addresses immediately, run list validation (verify MX/SMTP) before the next send, and stop importing unverified lists.",
  },
  {
    id: "content.engagement",
    title: "Positive engagement dominates",
    verifies:
      "that opens/clicks/replies and 'not spam' recoveries dominate over deletes-unread and spam-marks",
    integration: "ESP metrics API",
    fix: "Segment by engagement, suppress 90-day+ non-openers, send wanted content/cadence, and sunset dormant subscribers.",
  },
  {
    id: "content.warmup",
    title: "New IP/domain ramps gradually",
    verifies:
      "that a newly first-seen IP/domain ramps volume gradually with no cold-start day-one blast",
    integration: "ESP metrics API",
    fix: "Follow a warmup ramp (day 1: ~50 per mailbox provider, roughly double the daily cap, prioritize most-engaged recipients) over 4–8 weeks; hold at each step if complaints rise.",
  },
  {
    id: "content.volume_consistency",
    title: "Day-to-day volume is steady",
    verifies:
      "that day-over-day send volume is steady with no > 5x swings or long gaps followed by a blast",
    integration: "ESP metrics API",
    fix: "Smooth sends across days; avoid the 'big Monday blast, silent all week' pattern; spread large campaigns over a ramp.",
  },
]

/** Derive candidate sending IPs the same way blacklist.check does: configured first, else MX A records. */
async function candidateIps(domain: string, configured: string[]): Promise<string[]> {
  if (configured.length > 0) return configured
  const mx = await resolveMx(domain)
  const ips: string[] = []
  for (const record of mx.records) {
    const a = await resolve4(record.exchange)
    ips.push(...a.records)
  }
  return [...new Set(ips)]
}

/** content.postmaster_verified — is a Google verification TXT (the GPT/Search Console token) published? */
async function postmasterVerified(domain: string): Promise<Finding> {
  const { records, error } = await resolveTxt(domain)
  if (error) {
    return {
      id: "content.postmaster_verified.lookup_failed",
      checkId: CHECK_ID,
      title: "Could not check Google Postmaster verification",
      severity: "info",
      detail: `DNS lookup for TXT ${domain} failed (${error}); cannot confirm the Google verification record. Retry later.`,
      remediation:
        "Retry the audit. If it persists, check the domain's authoritative nameservers, then verify the domain at postmaster.google.com.",
    }
  }
  const token = records.find((r) => r.toLowerCase().startsWith("google-site-verification="))
  if (token) {
    return {
      id: "content.postmaster_verified.ok",
      checkId: CHECK_ID,
      title: "Google verification record present",
      severity: "ok",
      detail: `${domain} publishes a google-site-verification TXT record, the prerequisite for Google Postmaster Tools (and Search Console) data.`,
      evidence: token,
    }
  }
  return {
    id: "content.postmaster_verified.missing",
    checkId: CHECK_ID,
    title: "Domain not verified in Google Postmaster Tools",
    severity: "warning",
    detail: `${domain} has no google-site-verification TXT record, so it is not verified in Google Postmaster Tools and Gmail reputation (spamRate, domain/IP reputation) is invisible.`,
    remediation:
      "Add the domain in postmaster.google.com and publish the Google Postmaster Tools TXT verification record (or reuse existing Search Console verification).",
  }
}

/** content.fbl_enrollment — advisory: enroll the sending IPs' networks in provider FBLs. Config-only. */
async function fblEnrollment(domain: string, configured: string[]): Promise<Finding> {
  const ips = await candidateIps(domain, configured)
  if (ips.length === 0) {
    return {
      id: "content.fbl_enrollment.no_ips",
      checkId: CHECK_ID,
      title: "No sending IPs to advise FBL enrollment for",
      severity: "info",
      detail:
        "No sending IPs were configured and none could be derived from MX records, so feedback-loop (FBL) enrollment could not be advised.",
      remediation:
        "Add the IP addresses your mail actually sends from to this domain, then enroll each network in its provider FBL.",
    }
  }
  return {
    id: "content.fbl_enrollment.advisory",
    checkId: CHECK_ID,
    title: "Enroll sending IPs in provider feedback loops (FBLs)",
    severity: "warning",
    detail: `Confirm every sending IP (${ips.join(", ")}) is enrolled in the relevant provider feedback loops. Without enrollment, spam complaints happen invisibly and the same recipients complain repeatedly, quietly eroding reputation.`,
    remediation: `Enroll each sending network's FBL and wire the FBL mailbox into your suppression pipeline: ${FBL_PROGRAMS}.`,
    evidence: ips.join(", "),
  }
}

export const reputationMetricsCheck: Checker = {
  id: "content.reputation",
  label: "Sender Reputation Metrics",
  async run(ctx): Promise<Finding[]> {
    const findings: Finding[] = []

    // content.reputation_data_available — first round has no integration wired, so reputation metrics
    // are "unknown". This is `info`, never amber, per spec §8.1.
    findings.push({
      id: "content.reputation_data_available",
      checkId: CHECK_ID,
      title: "No reputation source connected",
      severity: "info",
      detail: `No reputation integration (Google Postmaster Tools, ESP metrics, or FBL) is connected for ${ctx.domain}, so complaint/bounce/reputation metrics are unknown. This does not mean a problem — only that receiver-side telemetry is not yet visible.`,
      remediation:
        "Connect Google Postmaster Tools (verify the domain in GPT, add the API credential) and/or your ESP metrics API in Settings → Integrations.",
    })

    // content.postmaster_verified — pure DNS.
    findings.push(await postmasterVerified(ctx.domain))

    // content.fbl_enrollment — config advisory, derived from the sending IPs.
    findings.push(await fblEnrollment(ctx.domain, ctx.sendingIps))

    // content.blocklist_history — a pure TREND over the app's own stored ./blacklists results across
    // audit runs. That cross-run history is not reachable from a stateless Checker (CheckContext only
    // exposes domain/dkimSelectors/sendingIps), so it degrades to an `info` rather than fabricating a
    // recurrence verdict. Once the store is wired in, this becomes a `warning` when the same DNSBL has
    // listed the domain/IP >= 2 times in the trailing window.
    findings.push({
      id: "content.blocklist_history",
      checkId: CHECK_ID,
      title: "DNSBL recurrence trend pending stored history",
      severity: "info",
      detail:
        "Recurring DNSBL listings over time are a reputation signal, but this trend reads the app's own stored blacklist results across prior audit runs, which are not available from a single stateless run. It will flag the domain/IP being listed on the same DNSBL >= 2 times in the trailing window once the audit-history store is wired in.",
      remediation:
        "When a listing recurs, fix the root cause (complaint source, compromised account, or open relay) rather than only requesting delisting; cross-reference the current listing in the blacklists check.",
    })

    // FUTURE metric sub-checks — one `info` "not connected" each; never warning/critical.
    for (const p of PENDING) {
      findings.push({
        id: p.id,
        checkId: CHECK_ID,
        title: `${p.title} — not connected`,
        severity: "info",
        detail: `Pending the ${p.integration} integration. Once connected this will verify ${p.verifies}. Until then reputation for this signal is unknown, not failing.`,
        remediation: `Connect ${p.integration} in Settings → Integrations to enable this check. Once data is flowing: ${p.fix}`,
      })
    }

    return findings
  },
}
