import type { Checker, Finding } from "./types"

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
 * Consequently this checker performs no DNS work and NEVER fabricates a placement verdict. It emits a
 * single `info` finding announcing the family is pending until a seed-list integration is configured
 * (acceptance criterion #1: "report not configured, never a false ok or critical"). When the seed
 * integration + send-probe capability ship, the sub-checks in §2 (`content.seedlist_overall`,
 * `content.placement_gmail|outlook|yahoo|apple|longtail`, `content.seed_auth_pass`,
 * `content.seed_{spf,dkim,dmarc}_receiver`, `content.seed_tab_placement`, `content.seed_missing`,
 * `content.seed_delivery_latency`, `content.seed_coverage`, `content.seed_trend`) light up here.
 */
export const inboxPlacementCheck: Checker = {
  id: "content.inbox_placement",
  label: "Inbox Placement Testing",
  async run(_ctx): Promise<Finding[]> {
    // The whole family is feature-gated behind a seed-list integration + a "send a probe" capability
    // (spec §6). Until that exists there is nothing to measure with pure DNS, so we surface a single
    // non-alarming "not configured" notice — never a warning/critical, never a fabricated ok.
    return [
      {
        id: "content.inbox_placement.pending",
        checkId: "content",
        title: "Inbox placement testing not configured",
        severity: "info",
        detail:
          "Seed-list inbox-placement testing is a future capability: it sends a tokenized probe to " +
          "a curated seed list across Gmail, Outlook/Microsoft 365, Yahoo/AOL, and Apple iCloud, then " +
          "reads each mailbox back to record which folder the copy landed in (Inbox / Spam / Gmail " +
          "Promotions tab / Missing) and what the receiver's own Authentication-Results reported for " +
          "SPF/DKIM/DMARC. Once a seed integration is configured it will report the overall and " +
          "per-provider inbox-placement rate (content.seedlist_overall, content.placement_gmail/" +
          "outlook/yahoo/apple/longtail), the receiver-observed auth verdict (content.seed_auth_pass " +
          "and the content.seed_spf/dkim/dmarc_receiver slices), Gmail tab placement " +
          "(content.seed_tab_placement), Missing/hard-block detection (content.seed_missing), delivery " +
          "latency (content.seed_delivery_latency), seed coverage (content.seed_coverage), and the " +
          "inbox-rate trend over repeated tests (content.seed_trend). None of this can run in the " +
          "pure-DNS first round, so no placement verdict is asserted here.",
        remediation:
          'Configure a seed-list integration to enable inbox placement testing. Add a "seedList:" ' +
          "block to ~/.email_delivery_hero/config.yaml with either a seed-service API key " +
          "(GlockApps / Mailtrap / Everest / MailReach style) or self-hosted seed mailbox credentials " +
          "(IMAP for Gmail/Yahoo/iCloud, Microsoft Graph for Outlook/M365, or JMAP), then use " +
          '"Send seed test now" to send one tokenized probe. Because each run spends a credit and ' +
          "sends real email, it runs on a slow dedicated cadence (daily/weekly), not the 6h DNS cadence.",
      },
    ]
  },
}
