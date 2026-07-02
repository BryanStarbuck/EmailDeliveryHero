import {
	aggregateDmarc,
	deriveDmarcReportFindings,
	dmarcVolumeBreakdown,
} from "@module/reports/derive-findings";
import { listDmarcReports } from "@module/reports/report-store";
import { readAppConfig } from "@shared/config-store";
import type { Checker, CheckOutcome } from "../types";

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
 *
 * SNAPSHOT RULE (pm/emails.mdx §16.3): alongside the findings, the checker serializes the
 * `DmarcAggregate` it already computes into the run file (results["dmarc.reports"] → the run
 * YAML's `dmarc.reports` key, snake_case), so the explainer page's aggregate-breakdown and
 * per-source tables are RUN-SCOPED — an older run stays a snapshot, never silently showing newer
 * report data — and the §16.4 history strip can plot real pass-rate history.
 */
export const dmarcReportsCheck: Checker = {
	id: "dmarc.reports",
	label: "DMARC reports",
	async run(ctx): Promise<CheckOutcome> {
		const domainId = ctx.domainId ?? "";
		const findings = deriveDmarcReportFindings(domainId, ctx.domain);
		const config = readAppConfig().reports;
		if (!config.enabled) return { findings };
		const reports = listDmarcReports(domainId);
		if (reports.length === 0) return { findings };
		const agg = aggregateDmarc(reports, config.windowDays);
		const breakdown = dmarcVolumeBreakdown(agg);
		return {
			findings,
			results: {
				report_count: agg.reportCount,
				reporters: agg.reporters,
				window: { begin: agg.window.begin, end: agg.window.end },
				window_days: config.windowDays,
				total_messages: agg.totalMessages,
				aligned_pass_messages: agg.alignedPassMessages,
				dmarc_pass_messages: agg.dmarcPassMessages,
				pass_rate_pct: agg.passRatePct,
				dkim_only: breakdown.dkimOnly,
				spf_only: breakdown.spfOnly,
				both_fail: breakdown.bothFail,
				quarantined: breakdown.quarantined,
				rejected: breakdown.rejected,
				policy_published: agg.policyPublished
					? {
							p: agg.policyPublished.p,
							sp: agg.policyPublished.sp,
							adkim: agg.policyPublished.adkim,
							aspf: agg.policyPublished.aspf,
							pct: agg.policyPublished.pct,
							np: agg.policyPublished.np,
						}
					: null,
				// The §7.1 per-source columns, count-desc — the explainer's expandable table.
				rows: agg.rows.map((r) => ({
					source_ip: r.sourceIp,
					count: r.count,
					disposition: r.disposition,
					spf_evaluated: r.spfEvaluated,
					spf_aligned: r.spfAligned,
					dkim_evaluated: r.dkimEvaluated,
					dkim_aligned: r.dkimAligned,
					dmarc_pass: r.dmarcPass,
					header_from: r.headerFrom,
					envelope: r.envelopeSpfDomain,
					dkim_signing_domains: r.dkimSigningDomains,
					reporters: r.reporters,
				})),
			},
		};
	},
};
