import { aggregateDmarc } from "@module/reports/derive-findings";
import { listDmarcReports } from "@module/reports/report-store";
import { readAppConfig } from "@shared/config-store";
import { readBlacklistRuns } from "../blacklist/store";
import { resolve4, resolveMx, resolveTxt } from "../dns-util";
import type { Checker, Finding } from "../types";

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
 *   - content.fbl_enrollment             (info-only reference: which networks to enroll in provider FBLs —
 *                                         only when the sending IPs are actually KNOWN, i.e. configured
 *                                         or observed passing DMARC in the ingested aggregate reports.
 *                                         Never amber: enrollment is not observable without the FUTURE
 *                                         FBL connector, so it can never be a detected fault here)
 *   - content.blocklist_history          (trend of stored ./blacklists results across audit runs —
 *                                         warns when the same DNSBL listed the domain/IP >= 2 times in
 *                                         the trailing window; reads the blacklist store, no integration)
 *
 * Every FUTURE metric sub-check emits exactly ONE `info` "not connected" finding — never a
 * warning/critical — so an un-integrated domain never produces a false positive (spec §8.1).
 */

const CHECK_ID = "content";

/**
 * Trailing window (days) over which `content.blocklist_history` counts recurring DNSBL listings —
 * matches the "last 30 days" reputation sparkline in the spec's UI section (§4).
 */
const BLOCKLIST_HISTORY_WINDOW_DAYS = 30;

/** A listing on the same DNSBL zone this many times in the window is a recurrence (spec §8 AC #7). */
const BLOCKLIST_RECURRENCE_THRESHOLD = 2;

/**
 * Provider feedback-loop programs, split by what they key on. The IP-keyed ones authorize through the
 * netblock's WHOIS/abuse contact, so they are only enrollable by whoever OWNS the sending IPs — on a
 * shared pool (Google Workspace, or any ESP) that is the provider, not the domain owner.
 */
const FBL_PROGRAMS_IP = [
	"Microsoft SNDS + JMRP: https://sendersupport.olc.protection.outlook.com/snds/ and https://sendersupport.olc.protection.outlook.com/pm/",
	"Comcast FBL: https://postmaster.comcast.net/",
].join("; ");

/** Keyed on the DKIM d= domain / the domain itself, so these stay enrollable on a shared pool. */
const FBL_PROGRAMS_DOMAIN = [
	"Yahoo Complaint Feedback Loop (CFL — enrolls your DKIM d= domain, not an IP): https://senders.yahooinc.com/complaint-feedback-loop/",
	"Google Postmaster Tools (Gmail spam rate + domain reputation): https://postmaster.google.com/",
].join("; ");

/**
 * One FUTURE metric sub-check that is gated behind a third-party integration. First round it emits a
 * single `info` "not connected" finding naming what it will verify and which integration to connect.
 */
interface PendingSubcheck {
	id: string;
	title: string;
	/** What the sub-check will verify once its integration is live. */
	verifies: string;
	/** The integration that unlocks it. */
	integration: string;
	/** The concrete operational lever the finding will prescribe (from the spec's remediation column). */
	fix: string;
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
		verifies:
			"that the hard-bounce rate stays low — target below 2%, alarm at or above 5%",
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
];

/** Where the IPs an advisory reasons about came from. `mx` is the INBOUND path — never outbound. */
export type SendingIpSource = "configured" | "dmarc_reports" | "mx";

export interface CandidateIps {
	ips: string[];
	source: SendingIpSource;
}

/**
 * How many observed IPs the advisory prints. A cloud sender's DMARC reports name dozens of ephemeral
 * addresses (Google alone rotates a wide IPv6 range), and FBL enrollment is per sending NETWORK, not
 * per address — so the full list is noise. The finding always states the true total alongside.
 */
const MAX_ADVISED_IPS = 10;

/**
 * IPs observed sending AS this domain, from the ingested DMARC aggregate reports, heaviest first.
 * Only rows that PASSED DMARC are taken: the same reports also list spoofing sources, and those must
 * never be advised on as if they were ours.
 */
function observedSendingIps(domainId: string, windowDays: number): string[] {
	const reports = listDmarcReports(domainId);
	if (reports.length === 0) return [];
	const agg = aggregateDmarc(reports, windowDays);

	// One IP can appear on several rows (different envelope/alignment keys), so sum before ranking.
	const volume = new Map<string, number>();
	for (const row of agg.rows) {
		if (!row.dmarcPass) continue;
		volume.set(row.sourceIp, (volume.get(row.sourceIp) ?? 0) + row.count);
	}
	return [...volume.entries()]
		.sort((a, b) => b[1] - a[1])
		.map(([ip]) => ip);
}

/**
 * Candidate sending IPs, best provenance first: configured, else observed in DMARC reports, else the
 * MX hosts' A records.
 *
 * The MX tier is a LAST resort and is tagged `mx` so callers can tell it apart, because MX addresses
 * are where mail ARRIVES, not where it leaves from — on Google Workspace they resolve to the
 * `*-in-f*.1e100.net` inbound frontends while the real outbound is `mail-*.google.com` plus whatever
 * ESP is in play. Any finding that speaks about *sending* must reject this tier rather than print it.
 */
async function candidateIps(
	domain: string,
	domainId: string,
	configured: string[],
): Promise<CandidateIps> {
	if (configured.length > 0) return { ips: configured, source: "configured" };

	const reports = readAppConfig().reports;
	if (domainId && reports.enabled) {
		const observed = observedSendingIps(domainId, reports.windowDays);
		if (observed.length > 0)
			return { ips: observed, source: "dmarc_reports" };
	}

	const mx = await resolveMx(domain);
	const ips: string[] = [];
	for (const record of mx.records) {
		const a = await resolve4(record.exchange);
		ips.push(...a.records);
	}
	return { ips: [...new Set(ips)], source: "mx" };
}

/** content.postmaster_verified — is a Google verification TXT (the GPT/Search Console token) published? */
async function postmasterVerified(domain: string): Promise<Finding> {
	const { records, error } = await resolveTxt(domain);
	if (error) {
		return {
			id: "content.postmaster_verified.lookup_failed",
			checkId: CHECK_ID,
			title: "Could not check Google Postmaster verification",
			severity: "info",
			detail: `DNS lookup for TXT ${domain} failed (${error}); cannot confirm the Google verification record. Retry later.`,
			remediation:
				"Retry the audit. If it persists, check the domain's authoritative nameservers, then verify the domain at postmaster.google.com.",
		};
	}
	const token = records.find((r) =>
		r.toLowerCase().startsWith("google-site-verification="),
	);
	if (token) {
		return {
			id: "content.postmaster_verified.ok",
			checkId: CHECK_ID,
			title: "Google verification record present",
			severity: "ok",
			detail: `${domain} publishes a google-site-verification TXT record, the prerequisite for Google Postmaster Tools (and Search Console) data.`,
			evidence: token,
		};
	}
	return {
		id: "content.postmaster_verified.missing",
		checkId: CHECK_ID,
		title: "Domain not verified in Google Postmaster Tools",
		severity: "warning",
		detail: `${domain} has no google-site-verification TXT record, so it is not verified in Google Postmaster Tools and Gmail reputation (spamRate, domain/IP reputation) is invisible.`,
		remediation:
			"Add the domain in postmaster.google.com and publish the Google Postmaster Tools TXT verification record (or reuse existing Search Console verification).",
	};
}

/**
 * content.fbl_enrollment — advisory: enroll the sending IPs' networks in provider FBLs.
 *
 * Advises ONLY on IPs whose provenance is real (configured, or observed passing DMARC). When the
 * only thing available is the MX fallback there is no evidence about outbound at all, so it says so
 * instead — naming inbound MX addresses as "every sending IP" would be a false positive on every
 * domain that has not recorded its sending IPs.
 *
 * ALWAYS `info`, never amber. Enrollment is not observable from here: it lives in the provider
 * portals, behind the `reputation_integrations` connector that is still FUTURE (spec §7). Emitting a
 * warning would assert non-enrollment we cannot see, and — because nothing the operator does could
 * clear it — would pin the domain amber forever. Spec §4: `info` "unknown" (no integration) never
 * turns a category amber; it shows as a "not connected" dot. Weight is 0, so the score is untouched.
 * When the FBL connector lands, THAT is what may legitimately warn on a confirmed non-enrollment.
 */
export async function fblEnrollment(
	domain: string,
	domainId: string,
	configured: string[],
): Promise<Finding> {
	const { ips, source } = await candidateIps(domain, domainId, configured);

	if (source === "mx" || ips.length === 0) {
		return {
			id: "content.fbl_enrollment.no_ips",
			checkId: CHECK_ID,
			title: "No sending IPs to advise FBL enrollment for",
			severity: "info",
			detail: `No sending IPs are recorded for ${domain} and none could be observed in its DMARC aggregate reports, so feedback-loop (FBL) enrollment cannot be advised. MX records are deliberately not used as a substitute: they are the inbound path — the addresses mail ARRIVES on — and say nothing about what this domain sends from.`,
			remediation: `Record the IPs your mail actually sends from, or ingest DMARC aggregate reports so they can be observed from the field. If you send through a shared pool (Google Workspace, or an ESP) you will not own those IPs and cannot enroll them anywhere — use the domain-keyed programs instead: ${FBL_PROGRAMS_DOMAIN}.`,
		};
	}

	const provenance =
		source === "configured"
			? "recorded for this domain"
			: "observed passing DMARC alignment in this domain's aggregate reports";
	const shown = ips.slice(0, MAX_ADVISED_IPS);
	const listed =
		ips.length > shown.length
			? `${shown.join(", ")} — ${ips.length} sources in total, the ${shown.length} heaviest shown`
			: shown.join(", ");
	return {
		id: "content.fbl_enrollment.advisory",
		checkId: CHECK_ID,
		title: "Feedback-loop (FBL) enrollment for your sending networks",
		severity: "info",
		detail: `Reference — this is not a detected fault, and it does not affect this domain's health score. Enrollment lives in the provider portals and cannot be read from here, so treat it as a checklist. The networks behind every sending IP (${listed}), ${provenance}, should be enrolled in the feedback loops that apply to them. Where a network is not enrolled, spam complaints arrive invisibly and the same recipients can complain repeatedly.`,
		remediation: `Enroll per sending NETWORK — not per address; a cloud pool rotates addresses — and wire the resulting complaint feed into your suppression pipeline. For a network whose IPs you own: ${FBL_PROGRAMS_IP}. For a shared/ESP pool those two are not enrollable by you, since the pool owner holds the netblock's abuse contact — use ${FBL_PROGRAMS_DOMAIN}, and take complaints from the ESP's own feed (its spam-report webhook / suppression list) instead.`,
		evidence: `${shown.join(", ")}${ips.length > shown.length ? ` (+${ips.length - shown.length} more)` : ""} (source: ${source})`,
	};
}

/**
 * content.blocklist_history — a pure TREND over the app's own stored ./blacklists results across
 * audit runs (spec §2/§7, AC #7). Reads the blacklist store (keyed by domain NAME, same key this
 * checker receives as ctx.domain) and flags any DNSBL zone that has listed the domain/IP
 * >= BLOCKLIST_RECURRENCE_THRESHOLD times within the trailing window. Needs NO external integration.
 * A (zone, target) counts at most once per run, so recurrence means "listed on distinct runs",
 * not "many targets in one run".
 */
export function blocklistHistory(domain: string): Finding {
	const runs = readBlacklistRuns(domain);
	const cutoff =
		Date.now() - BLOCKLIST_HISTORY_WINDOW_DAYS * 24 * 60 * 60 * 1000;
	const windowed = runs.filter((r) => {
		const t = Date.parse(r.ran_at);
		return Number.isNaN(t) || t >= cutoff;
	});

	if (windowed.length === 0) {
		return {
			id: "content.blocklist_history",
			checkId: CHECK_ID,
			title: "No stored blacklist history yet",
			severity: "info",
			detail: `Recurring DNSBL listings over time are a reputation signal, but ${domain} has no stored blacklist results in the trailing ${BLOCKLIST_HISTORY_WINDOW_DAYS} days to trend yet. Once the Blacklists check has run across several audits, this flags any DNSBL that lists the domain/IP repeatedly.`,
			remediation:
				"Run the Blacklists check across a few audits to build history; then this will surface any recurring listings.",
		};
	}

	// Count distinct runs (within the window) that listed each (zone, target) pair.
	const counts = new Map<
		string,
		{ zone: string; name: string; target: string; runs: number }
	>();
	for (const run of windowed) {
		const seenThisRun = new Set<string>();
		for (const zr of run.results) {
			if (!zr.listed) continue;
			const key = `${zr.zone} ${zr.target}`;
			if (seenThisRun.has(key)) continue;
			seenThisRun.add(key);
			const entry = counts.get(key) ?? {
				zone: zr.zone,
				name: zr.name,
				target: zr.target,
				runs: 0,
			};
			entry.runs++;
			counts.set(key, entry);
		}
	}

	const recurring = [...counts.values()]
		.filter((c) => c.runs >= BLOCKLIST_RECURRENCE_THRESHOLD)
		.sort((a, b) => b.runs - a.runs);

	if (recurring.length === 0) {
		return {
			id: "content.blocklist_history",
			checkId: CHECK_ID,
			title: "No recurring DNSBL listings",
			severity: "ok",
			detail: `Across ${windowed.length} stored blacklist run(s) in the trailing ${BLOCKLIST_HISTORY_WINDOW_DAYS} days, no DNSBL has listed ${domain} or its IPs ${BLOCKLIST_RECURRENCE_THRESHOLD} or more times — no recurring-listing reputation pattern.`,
		};
	}

	const listSummary = recurring
		.slice(0, 6)
		.map((c) => `${c.name} (${c.zone}) → ${c.target}: ${c.runs}×`)
		.join("; ");
	return {
		id: "content.blocklist_history",
		checkId: CHECK_ID,
		title: "Recurring DNSBL listings over time",
		severity: "warning",
		detail: `Across ${windowed.length} stored blacklist run(s) in the trailing ${BLOCKLIST_HISTORY_WINDOW_DAYS} days, the same DNSBL(s) listed ${domain} or its IPs ${BLOCKLIST_RECURRENCE_THRESHOLD}+ times — a recurrence pattern, not a one-off: ${listSummary}. Repeated listings mean the underlying cause was never fixed, only delisted.`,
		remediation:
			"Fix the root cause (complaint source, compromised account, or open relay), not just the delisting request; cross-reference the current listing in the blacklists check.",
		evidence: recurring
			.map((c) => `${c.zone}|${c.target}=${c.runs}`)
			.join(", "),
	};
}

export const reputationMetricsCheck: Checker = {
	id: "content.reputation",
	label: "Sender Reputation Metrics",
	async run(ctx): Promise<Finding[]> {
		const findings: Finding[] = [];

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
		});

		// content.postmaster_verified — pure DNS.
		findings.push(await postmasterVerified(ctx.domain));

		// content.fbl_enrollment — advisory over the sending IPs, when their provenance is real.
		findings.push(
			await fblEnrollment(ctx.domain, ctx.domainId ?? "", ctx.sendingIps),
		);

		// content.blocklist_history — a pure TREND over the app's own stored ./blacklists results across
		// audit runs (needs NO external integration, spec §7). Reads the blacklist store (keyed by the
		// same domain NAME this checker receives) and warns when the same DNSBL has listed the domain/IP
		// >= 2 times in the trailing window.
		findings.push(blocklistHistory(ctx.domain));

		// FUTURE metric sub-checks — one `info` "not connected" each; never warning/critical.
		for (const p of PENDING) {
			findings.push({
				id: p.id,
				checkId: CHECK_ID,
				title: `${p.title} — not connected`,
				severity: "info",
				detail: `Pending the ${p.integration} integration. Once connected this will verify ${p.verifies}. Until then reputation for this signal is unknown, not failing.`,
				remediation: `Connect ${p.integration} in Settings → Integrations to enable this check. Once data is flowing: ${p.fix}`,
			});
		}

		return findings;
	},
};
