import type { Checker, Finding } from "../types"

/**
 * Inbox Placement Testing (seed-list / deliverability testing) — the empirical "did our mail actually
 * reach the inbox?" measurement that complements the DNS-side predictors (SPF/DKIM/DMARC). It sends a
 * tokenized probe to a curated seed list spanning Gmail, Outlook/Microsoft 365, Yahoo/AOL, and Apple
 * iCloud, waits a settle window, reads each seed mailbox back (folder + the receiver's own
 * `Authentication-Results`), and rolls the verdicts into a per-provider and overall inbox-placement
 * rate — attributing every miss to its auth/content/reputation cause.
 *
 * Per the spec (pm/checks/inbox_placement.mdx §7 "First round vs future"), EVERY sub-check in this
 * family is FUTURE-round: all of them require (a) sending a real probe message and (b) reading remote
 * mailboxes over a seed-service API or IMAP/Graph/JMAP. NONE are doable with pure `node:dns/promises`,
 * so nothing here can run in the first (DNS-only) round.
 *
 * Consequently this checker performs no DNS work and NEVER fabricates a placement verdict. Per spec
 * §6 ("until then every content.placement_* sub-check reports not configured") and acceptance
 * criterion #1 ("never a false ok or critical"), it emits one family-level gate finding plus one
 * `info` "not configured" finding per sub-check — using the exact sub-check ids from §2 so that, when
 * the seed integration + send-probe capability ship, each id lights up in place and the regression
 * diff (spec §6, pm/engineering.mdx §8) has a stable baseline. This mirrors the sibling FUTURE-gated
 * pattern in reputation-metrics.check.ts and link-url-reputation.check.ts.
 */

const CHECK_ID = "content"

/**
 * One FUTURE placement sub-check gated behind the seed-list integration (spec §2 / §7). First round
 * it emits a single `info` "not configured" finding naming what it will verify and the concrete
 * remediation lever from the spec's table — never a generic "improve deliverability" (criterion #8).
 */
interface PendingSubcheck {
  /** The exact sub-check id from spec §2 — the finding id it will keep once live. */
  id: string
  title: string
  /** What the sub-check will verify once the seed integration is live (spec §2 "What it verifies"). */
  verifies: string
  /** The concrete remediation lever from the spec §2 table, prefaced once data flows. */
  fix: string
}

/** Spec §2 — the placement sub-family, in table order. Every row is FUTURE (spec §7). */
const PENDING: PendingSubcheck[] = [
  {
    id: "content.seedlist_overall",
    title: "Overall inbox-placement rate",
    verifies:
      "the aggregate inbox-placement rate across all providers (inbox seeds ÷ delivered seeds, and ÷ total seeds): ≥ 80% is ok, 50–79% warning, < 50% critical",
    fix: "Fix the lowest-scoring provider first (see the per-provider placement rows); each maps to an auth/content/reputation cause.",
  },
  {
    id: "content.placement_gmail",
    title: "Gmail / Google Workspace placement",
    verifies:
      "Inbox vs Spam vs tab vs Missing at Gmail / Google Workspace seeds (majority Spam/Missing → critical; majority Promotions/Updates instead of Primary → warning)",
    fix: "Raise Gmail Postmaster reputation (see the reputation-metrics check), ensure DMARC pass plus one-click List-Unsubscribe (see the list-unsubscribe check), and reduce promotional markup for Primary placement.",
  },
  {
    id: "content.placement_outlook",
    title: "Outlook.com / Hotmail / Microsoft 365 placement",
    verifies:
      "Inbox vs Junk vs Missing at Outlook.com / Hotmail / Microsoft 365 seeds (majority Junk or Missing → critical: SmartScreen filtering / SNDS reputation)",
    fix: "Enrol the sending IP in Microsoft SNDS + JMRP, keep the complaint rate low, verify DKIM/DMARC pass; if Missing, check for a Microsoft block and request delisting via the Sender Support form.",
  },
  {
    id: "content.placement_yahoo",
    title: "Yahoo / AOL placement",
    verifies:
      "Inbox vs Bulk/Spam vs Missing at Yahoo / AOL seeds (majority Bulk or Missing → critical: engagement-driven filtering)",
    fix: "Meet the 2024 Yahoo bulk-sender rules (aligned DMARC, one-click unsubscribe, complaint rate < 0.3%); improve engagement/list hygiene; use Yahoo's Sender Hub for feedback.",
  },
  {
    id: "content.placement_apple",
    title: "Apple iCloud / me.com / mac.com placement",
    verifies:
      "Inbox vs Junk vs Missing at Apple iCloud / me.com / mac.com seeds (majority Junk or Missing → critical)",
    fix: "Ensure valid SPF+DKIM+DMARC and clean IP/domain reputation; Apple weights authentication and prior recipient interaction heavily.",
  },
  {
    id: "content.seed_auth_pass",
    title: "SPF+DKIM+DMARC pass at the receivers",
    verifies:
      "that SPF and DKIM and DMARC all reported pass in the receivers' own Authentication-Results at the seeds — a DMARC fail (or SPF+DKIM both fail) observed at the receiver despite green DNS is critical (usually a DKIM body-hash break or Return-Path misalignment)",
    fix: "If DKIM fails at the receiver: stop the ESP/relay rewriting the signed body/headers, or re-sign after modification. If SPF fails: align the Return-Path to the From: org-domain. Re-test.",
  },
  {
    id: "content.seed_tab_placement",
    title: "Gmail tab placement (Primary vs Promotions)",
    verifies:
      "the Gmail tab the message is filed under — Primary vs Promotions vs Social vs Updates vs Forums (relationship/transactional mail landing in Promotions → warning; it is delivered, not spam)",
    fix: "Reduce promotional signals (fewer images/CTAs/tracking links, plainer HTML) and send from a consistent Primary-associated stream.",
  },
  {
    id: "content.seed_missing",
    title: "Messages that never arrived (silent drop / hard block)",
    verifies:
      "seeds where the tokenized message never appeared after the max settle window + retries — not Inbox, not Spam — i.e. a silent drop or hard block (≥ 1 provider majority-Missing → critical)",
    fix: "Treat as a block: check the blacklists check for a fresh DNSBL listing, check provider block pages (Microsoft/Google/Yahoo), request delisting, and pause sending to that provider until cleared.",
  },
  {
    id: "content.seed_trend",
    title: "Inbox-placement rate trend (advisory)",
    verifies:
      "the inbox-placement rate over time (per provider and overall) across repeated scheduled tests — a downward trend (e.g. Gmail inbox 95%→70% over two weeks) signals reputation decay",
    fix: "Investigate the reputation trend early (see the reputation-metrics check), tighten list hygiene, and slow send volume before the slide becomes Spam/Missing.",
  },
  {
    id: "content.placement_longtail",
    title: "Long-tail provider placement (Zoho, GMX, Mail.ru, corporate)",
    verifies:
      "Inbox vs Spam vs Missing at secondary providers when present in the seed list (systemic Spam/Missing across the long tail → warning: often a blacklist or PTR/HELO issue)",
    fix: "Cross-check the blacklists check, the reverse-dns check (PTR), and the HELO/EHLO identity; fix the shared infrastructure fault the long tail exposes.",
  },
  {
    id: "content.seed_delivery_latency",
    title: "Send-to-arrival delivery latency",
    verifies:
      "the time from send to arrival at each provider — a proxy for greylisting / throttling / tempfail (delivery > 15 min or repeated tempfails → warning)",
    fix: "Expect and honor 4xx tempfails with correct retry backoff; warm the IP/domain more gradually; verify you are not being rate-limited for volume spikes.",
  },
  {
    id: "content.seed_coverage",
    title: "Seed-list coverage per provider",
    verifies:
      "that the seed list itself is healthy — enough live, reachable seeds per major provider to make the rate meaningful (a provider with 0 live seeds is 'unknown', not 'ok')",
    fix: "Add/repair seed mailboxes for the uncovered provider (or enable it in the seed service) so its column produces a real verdict.",
  },
  {
    id: "content.seed_spf_receiver",
    title: "SPF pass at the receiver (attribution slice)",
    verifies:
      "that SPF specifically reported pass in the seeds' Authentication-Results (spf=fail/softfail observed at seeds → critical)",
    fix: "Align the Return-Path and confirm the sending IP is in the SPF pass-set — see the spf check (spf.ip_coverage).",
  },
  {
    id: "content.seed_dkim_receiver",
    title: "DKIM pass at the receiver (attribution slice)",
    verifies:
      "that DKIM specifically reported pass in the seeds' Authentication-Results (dkim=fail/none observed despite a valid published key → critical)",
    fix: "Body-hash break: stop post-signing modification, and verify the selector the receiver used matches a published key — see the dkim check.",
  },
  {
    id: "content.seed_dmarc_receiver",
    title: "DMARC pass at the receiver (attribution slice)",
    verifies:
      "that DMARC specifically reported pass in the seeds' Authentication-Results (dmarc=fail → critical: neither aligned SPF nor aligned DKIM passed)",
    fix: "Achieve at least one aligned authenticated identifier (From: org-domain) — see the dmarc check.",
  },
]

export const inboxPlacementCheck: Checker = {
  id: "content.inbox_placement",
  label: "Inbox Placement Testing",
  async run(_ctx): Promise<Finding[]> {
    // The whole family is feature-gated behind a seed-list integration + a "send a probe" capability
    // (spec §6). Until that exists there is nothing to measure with pure DNS, so we surface a
    // family-level "not configured" gate plus one `info` per sub-check — never a warning/critical,
    // never a fabricated ok (acceptance criterion #1).
    const findings: Finding[] = [
      {
        id: "content.inbox_placement.pending",
        checkId: CHECK_ID,
        title: "Inbox placement testing not configured",
        severity: "info",
        detail:
          "Seed-list inbox-placement testing is a future capability: it sends a tokenized probe to " +
          "a curated seed list across Gmail, Outlook/Microsoft 365, Yahoo/AOL, and Apple iCloud, then " +
          "reads each mailbox back to record which folder the copy landed in (Inbox / Spam / Gmail " +
          "Promotions tab / Missing) and what the receiver's own Authentication-Results reported for " +
          "SPF/DKIM/DMARC. None of this can run in the pure-DNS first round, so no placement verdict " +
          "is asserted here — the sub-checks below report 'not configured', not ok and not failing.",
        remediation:
          'Configure a seed-list integration to enable inbox placement testing. Add a "seedList:" ' +
          "block to ~/.email_delivery_hero/config.yaml with either a seed-service API key " +
          "(GlockApps / Mailtrap / Everest / MailReach style) or self-hosted seed mailbox credentials " +
          "(IMAP for Gmail/Yahoo/iCloud, Microsoft Graph for Outlook/M365, or JMAP), then use " +
          '"Send seed test now" to send one tokenized probe. Because each run spends a credit and ' +
          "sends real email, it runs on a slow dedicated cadence (daily/weekly), not the 6h DNS cadence.",
      },
    ]

    // One `info` "not configured" per sub-check (spec §2/§6): the exact §2 ids, so each lights up in
    // place — and the regression diff has a stable per-sub-check baseline — once the integration ships.
    for (const p of PENDING) {
      findings.push({
        id: p.id,
        checkId: CHECK_ID,
        title: `${p.title} — not configured`,
        severity: "info",
        detail: `Pending the seed-list integration (seed-service API key or self-hosted seed mailboxes). Once configured this will verify ${p.verifies}. Until then placement for this signal is unknown, not failing.`,
        remediation: `Configure the seed-list integration (config.yaml "seedList:" block) to enable this check. Once data is flowing: ${p.fix}`,
      })
    }

    return findings
  },
}
