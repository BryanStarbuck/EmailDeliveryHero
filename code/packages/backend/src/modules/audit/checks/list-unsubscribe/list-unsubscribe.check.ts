import type { Checker, Finding } from "./types"

/**
 * List-Unsubscribe (RFC 2369) & one-click unsubscribe (RFC 8058).
 *
 * Since Feb 2024 Gmail and Yahoo require every bulk sender (> 5,000 msgs/day) to ship a working
 * `List-Unsubscribe-Post: List-Unsubscribe=One-Click` header alongside an https unsubscribe URI, offer
 * a body unsubscribe link, and honor requests within 2 days. This checker audits a captured bulk
 * message's headers for all of that plus From-alignment, precedence, and priority hygiene.
 *
 * Per the spec (pm/checks/list_unsubscribe.mdx §2, §7 "First round vs future"), EVERY sub-check here is
 * a FUTURE-round check: it needs a captured sample message from the `content_sample_messages` store
 * (owned by content_scoring), and the endpoint sub-checks additionally need an opt-in HTTPS probe.
 * None can run from DNS alone. The `CheckContext` in the first round carries no message sample and no
 * store handle, so — following Acceptance Criterion #1 ("with no sample message for a domain, the
 * checker emits exactly one info finding and no false criticals") — we emit a single, honest `info`
 * finding that names exactly what will be verified once a sample (and, optionally, the endpoint probe)
 * are available. We deliberately do NOT fabricate any warning/critical result without a sample.
 */

/** The sample-backed sub-checks this checker will run once a captured message exists. */
const PENDING_SUBCHECKS = [
  "content.list_unsubscribe (RFC 2369 header present)",
  "content.list_unsub_oneclick (List-Unsubscribe-Post: List-Unsubscribe=One-Click)",
  "content.list_unsub_https / content.list_unsub_mailto (an https and a mailto method)",
  "content.list_unsub_syntax (angle-bracketed, comma-separated, no unrendered merge tags)",
  "content.from_alignment (From: aligns with SPF and/or DKIM)",
  "content.precedence / content.no_priority_abuse (Precedence: bulk; no forced high priority)",
  "content.list_id / content.list_headers_consistent / content.list_unsub_per_recipient",
  "content.list_unsub_reachable / _https_get_safe / _tls (opt-in HTTPS one-click POST probe)",
].join("; ")

export const listUnsubscribeCheck: Checker = {
  id: "content.list_unsubscribe",
  label: "List-Unsubscribe & One-Click",
  async run(_ctx): Promise<Finding[]> {
    // First round: no captured sample message is available (the content_sample_messages store is
    // owned by content_scoring and is not wired yet), so every sub-check is pending. Emit exactly one
    // info finding — never a false critical.
    return [
      {
        id: "content.list_unsubscribe.no_sample",
        checkId: "content",
        title: "List-management headers not yet audited — no sample message",
        severity: "info",
        detail:
          "The List-Unsubscribe / one-click audit inspects a captured bulk message's headers, but no sample message has been captured for this domain yet, so it is pending. Once a sample is available it will verify: " +
          `${PENDING_SUBCHECKS}. Gmail/Yahoo require bulk senders (> 5,000 msgs/day) to ship a working one-click unsubscribe since Feb 2024, so this is a hard bulk-deliverability gate.`,
        remediation:
          'Upload a sample of a real bulk campaign (a .eml file) for this domain via the domain detail page\'s "Upload sample message" control (stored under ~/.email_delivery_hero/samples/<domainId>/). Set the isBulkSender toggle if you send > 5,000 msgs/day so missing one-click is escalated to critical, and enable the probeUnsubEndpoint toggle (default off) to also test that the https endpoint answers the one-click POST with a 2xx. Publish the headers now regardless: List-Unsubscribe: <https://unsub.example.com/u/{token}>, <mailto:unsubscribe@example.com?subject=unsub-{token}> and List-Unsubscribe-Post: List-Unsubscribe=One-Click.',
      },
    ]
  },
}
