import { deriveDmarcReportFindings } from "@module/reports/derive-findings"
import type { Checker, Finding } from "../types"

/**
 * DMARC aggregate-report findings (pm/emails.mdx §5) — the field-data companion to the DNS-based
 * `dmarc` checker. Reads the parsed rua reports ingested for this domain
 * (`<state>/reports/<domainId>/dmarc/`, pm/emails.mdx §9) and emits:
 *
 *   dmarc.real_pass_rate              — aligned-pass % over the rolling window
 *   dmarc.report_unaligned_source.*   — sources failing BOTH SPF+DKIM alignment (spoofing/unknown)
 *   dmarc.report_alignment_fragility.* — own streams passing on only one mechanism
 *   dmarc.report_enforcement[.*]      — own mail actively quarantined/rejected
 *   dmarc.report_new_source           — sources unseen in prior windows
 *
 * All findings carry checkId "dmarc.reports" so they roll into the EXISTING DMARC dashboard
 * column (categoryOf keys on the "dmarc" prefix — pm/emails.mdx §6, no seventh category), and
 * `source: "report"` so the run detail shows the "from reports" chip (§7.2). Pure local file
 * reads — no network, so it can never flake a run.
 */
export const dmarcReportsCheck: Checker = {
  id: "dmarc.reports",
  label: "DMARC reports",
  async run(ctx): Promise<Finding[]> {
    return deriveDmarcReportFindings(ctx.domainId ?? "", ctx.domain)
  },
}
