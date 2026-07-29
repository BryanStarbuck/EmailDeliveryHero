import type { DmarcReportRow } from "../report.types";
import type { ComplaintCode } from "./complaint.types";

/**
 * Row → complaint classification (pm/Email_Complaints.mdx §7).
 *
 * Two invariants make the Complaints board trustworthy:
 *  1. EVERY row lands in exactly one code — including healthy rows (C00) — so the per-code volumes
 *     always reconcile to 100% of reported mail and nothing is silently dropped.
 *  2. The order below is normative (§7.2). Predicates overlap, so the classifier walks the order and
 *     stops at the first match; the specific codes come before the general ones.
 *
 * C11–C15 are report-level, not row-level, and are evaluated in board.ts.
 */

/**
 * ESP default signing domains (pm/Email_Complaints.mdx §7 C02). Mail signed with one of these
 * carries a valid DKIM signature that can NEVER align with the customer's From domain, because the
 * `d=` belongs to the provider. It is the single most common invisible deliverability defect: the
 * mail passes DMARC today only if SPF happens to align, and it is silently one Return-Path change
 * away from being rejected outright.
 */
const ESP_DEFAULT_DKIM = [
	/\.gappssmtp\.com$/, // Google Workspace, before custom DKIM is switched on
	/\.onmicrosoft\.com$/, // Microsoft 365
	/^sendgrid\.net$/,
	/\.sendgrid\.net$/,
	/^sendgrid\.info$/,
	/\.mcsv\.net$/, // Mailchimp
	/\.mcdlv\.net$/,
	/^amazonses\.com$/,
	/\.amazonses\.com$/,
	/\.hubspotemail\.net$/,
	/\.zoho\.com$/,
	/\.mailgun\.org$/,
	/\.pphosted\.com$/,
];

/** True when `child` equals `parent` or is a subdomain of it. */
export function underDomain(child: string, parent: string): boolean {
	const c = (child ?? "").replace(/\.$/, "").toLowerCase();
	const p = (parent ?? "").replace(/\.$/, "").toLowerCase();
	if (!c || !p) return false;
	return c === p || c.endsWith(`.${p}`);
}

export function isEspDefaultDomain(domain: string): boolean {
	const d = (domain ?? "").replace(/\.$/, "").toLowerCase();
	return ESP_DEFAULT_DKIM.some((re) => re.test(d));
}

/** Context the classifier needs beyond the row itself. */
export interface ClassifyContext {
	/** The monitored org domain, e.g. "act3ai.com". */
	domain: string;
	/**
	 * Source IPs resolved from the domain's own published SPF record (pm/Email_Complaints.mdx §7.1
	 * rule 1). Optional: without it the known-sender test falls back to identity matching, which is
	 * enough for every row in the reference corpus but under-counts large provider ranges.
	 */
	spfAuthorizedIps?: ReadonlySet<string>;
}

/**
 * The "known sender" test (pm/Email_Complaints.mdx §7.1, normative).
 *
 * CRITICAL: an identity is only evidence when the mechanism that carried it PASSED. A spoofer forges
 * `envelope_from` and `d=` as the victim's domain — that is the whole attack — so matching on the
 * claimed domain alone would file every spoofing attempt as "our own mail being blocked" and hand
 * the user a fix-it list for an attacker's mail. Every real spoofing row in the reference corpus
 * claims `act3ai.com` in both the envelope and the DKIM `d=`; only the *results* separate them.
 *
 * A source is known when a PASSING SPF identity or a PASSING DKIM `d=` traces to our org domain,
 * when a passing signature is one of our ESPs using its own default key, or when the IP is
 * authorized by our own published SPF record (which no forger can influence).
 */
export function isKnownSender(
	row: DmarcReportRow,
	ctx: ClassifyContext,
): boolean {
	// The IP is the one claim a spoofer cannot forge — check it first and unconditionally.
	if (ctx.spfAuthorizedIps?.has(row.sourceIp)) return true;

	const spfResults = row.spfResults ?? [];
	const dkimResults = row.dkimResults ?? [];

	for (const r of spfResults) {
		if (r.result === "pass" && underDomain(r.domain, ctx.domain)) return true;
	}
	for (const d of dkimResults) {
		if (d.result !== "pass") continue;
		if (underDomain(d.domain, ctx.domain)) return true;
		if (isEspDefaultDomain(d.domain)) return true;
	}

	// Fallback for reports stored before per-result detail was parsed: fall back to the identity
	// lists, but only when the corresponding aligned verdict passed.
	if (spfResults.length === 0 && dkimResults.length === 0) {
		if (row.spfAligned && underDomain(row.envelopeSpfDomain, ctx.domain))
			return true;
		if (
			row.dkimAligned &&
			row.dkimSigningDomains.some(
				(d) => underDomain(d, ctx.domain) || isEspDefaultDomain(d),
			)
		)
			return true;
	}
	return false;
}

/**
 * True when the receiver overrode its own DMARC verdict because the message arrived through a
 * forwarder whose ARC chain it trusted (pm/Email_Complaints.mdx §7 C07). Google writes this as
 * `<reason><type>local_policy</type><comment>arc=pass</comment>`; the RFC also defines dedicated
 * forwarding reason types.
 */
export function isArcRescued(row: DmarcReportRow): boolean {
	for (const reason of row.reasons ?? []) {
		if (
			reason.type === "forwarded" ||
			reason.type === "trusted_forwarder" ||
			reason.type === "mailing_list"
		)
			return true;
		if (reason.type === "local_policy" && /arc\s*=\s*pass/i.test(reason.comment ?? ""))
			return true;
	}
	return false;
}

/** True when the message was excluded from enforcement by the policy's `pct=` sampling. */
export function isSampledOut(row: DmarcReportRow): boolean {
	return (row.reasons ?? []).some((r) => r.type === "sampled_out");
}

const ENFORCED = new Set(["quarantine", "reject"]);
/** SPF results that mean "this identity is not authorized, but not hard-failed either". */
const SOFT_SPF = new Set(["softfail", "neutral", "none", "permerror", "temperror"]);

/**
 * Classify one row (pm/Email_Complaints.mdx §7.2). Returns exactly one code, always.
 *
 * Order: C00 → C07 → C01/C10 → C03 → C12 → C04 → C08 → C09 → C02 → C06 → C05, with C09 as the
 * terminal fallback so the function is total.
 */
export function classifyRow(
	row: DmarcReportRow,
	ctx: ClassifyContext,
): ComplaintCode {
	const known = isKnownSender(row, ctx);

	// C00 — both mechanisms aligned. The healthy majority; listed so volumes reconcile.
	if (row.dkimAligned && row.spfAligned) return "C00";

	// C07 — a forward broke authentication and the receiver's ARC trust rescued it. Not a defect.
	if (isArcRescued(row)) return "C07";

	// C01 / C10 — the receiver actually acted. Whether this is an attack being stopped (C01) or our
	// own mail being blocked (C10) is decided purely by whether we recognize the sender.
	if (ENFORCED.has(row.disposition)) return known ? "C10" : "C01";

	// C03 — nothing aligned and the receiver delivered anyway. Either a forgotten sender of ours or
	// a spoofer that got through because the policy is not enforcing.
	if (!row.dkimAligned && !row.spfAligned) return "C03";

	// C12 — the policy was not applied because `pct=` sampled the message out.
	if (isSampledOut(row)) return "C12";

	// Exactly one mechanism aligns from here. Diagnose WHY the other one didn't.

	// C04 — a signature cites a selector we do not publish, from a sender we recognize.
	const ourDkim = (row.dkimResults ?? []).filter((d) =>
		underDomain(d.domain, ctx.domain),
	);
	if (known && ourDkim.some((d) => d.result === "permerror" || d.result === "temperror"))
		return "C04";

	// C08 — we signed as ourselves and the signature did not verify: something rewrote the message.
	if (ourDkim.some((d) => d.result === "fail")) return "C08";

	// C09 — a third-party identity we have not authorized (soft SPF result from a foreign domain).
	const foreignSoftSpf = (row.spfResults ?? []).some(
		(s) =>
			SOFT_SPF.has(s.result) &&
			!underDomain(s.domain, ctx.domain) &&
			!isEspDefaultDomain(s.domain),
	);
	if (foreignSoftSpf) return "C09";

	// C02 — signed with the provider's OWN domain, so the signature can never align.
	if (
		!row.dkimAligned &&
		(row.dkimResults ?? []).some(
			(d) => d.result === "pass" && isEspDefaultDomain(d.domain),
		)
	)
		return "C02";

	// C06 — passes on DKIM alone: the Return-Path does not align. Survives forwarding, breaks on a
	// Return-Path change.
	if (row.dkimAligned && !row.spfAligned) return "C06";

	// C05 — passes on SPF alone: DKIM does not align. Breaks on every forward.
	if (row.spfAligned && !row.dkimAligned) return known ? "C05" : "C09";

	return "C09";
}
