import type { Finding } from "../types";

/**
 * Inbox-placement scoring (pm/checks/inbox_placement.mdx §2/§3): the pure aggregate-and-attribute
 * engine that turns one recorded seed test (the `inbox_placement_tests` envelope plus its
 * `inbox_placement_results` children, spec §5) into the placement sub-family findings — the
 * per-provider matrix rows, the receiver-observed auth slices, the missing/latency/coverage
 * verdicts, and the trend diff against prior tests. No I/O here: everything is a pure function of
 * the recorded test data so re-scoring a stored test is idempotent (spec §3 "re-reading a mailbox
 * is idempotent on the test token") and unit-testable.
 */

const CHECK_ID = "content";

/** Normalized folder verdict per seed (spec §3 "Read the folder"). */
export type PlacementFolder = "inbox" | "spam" | "promotions" | "missing";

/** The Gmail category tab a delivered copy was filed under (spec §3, `CATEGORY_*` labels). */
export type GmailTab =
	| "primary"
	| "promotions"
	| "social"
	| "updates"
	| "forums";

/**
 * One `inbox_placement_results` row (spec §5): which folder one seed's copy landed in, plus the
 * receiver's OWN `Authentication-Results` verdict (null when not delivered / not parseable).
 */
export interface SeedPlacementResult {
	/** Provider key, e.g. "gmail" | "outlook" | "yahoo" | "apple" | a long-tail name ("zoho"). */
	provider: string;
	folder: PlacementFolder;
	gmailTab: GmailTab | null;
	spfPass: boolean | null;
	dkimPass: boolean | null;
	dmarcPass: boolean | null;
	/** Send → arrival in seconds (null when missing). */
	latencySecs: number | null;
	/** The seed mailbox (or a hash of it, for privacy). */
	seedAddress?: string | null;
	/**
	 * Why a `missing` seed never produced a copy (spec §3 edge cases / criterion #9): a hard 5xx
	 * bounce is distinguished from accepted-then-filtered-or-dropped.
	 */
	missingReason?: "bounced" | "dropped" | null;
}

/** One `inbox_placement_tests` envelope + its per-seed children (spec §5). */
export interface InboxPlacementTest {
	id: string;
	/** 'glockapps' | 'mailtrap' | 'everest' | 'mailreach' | 'self_hosted' | … */
	seedService: string;
	/** null = the neutral default template was sent (spec §3 "Sample selection"). */
	sampleId: string | null;
	/** The unique per-test tag (plus-address / X-EDH-Test-Id / subject suffix) used to find the send. */
	testToken: string;
	sentAt: string;
	/** When read-back completed (null while the settle window is still polling). */
	settledAt: string | null;
	seedCount: number;
	deliveredCount: number;
	/** Overall inbox rate % computed at scoring time (recomputed here — idempotent). */
	overallInbox: number | null;
	results: SeedPlacementResult[];
}

/** The admin-tunable overall-rate bands (spec §4 "Admin-only settings", defaults 80 / 50). */
export interface PlacementThresholds {
	warnBelowPct: number;
	criticalBelowPct: number;
}

export const DEFAULT_PLACEMENT_THRESHOLDS: PlacementThresholds = {
	warnBelowPct: 80,
	criticalBelowPct: 50,
};

/** Provider aliases → the four major provider keys (spec §1 seed-list coverage). */
const PROVIDER_ALIASES: Record<string, string> = {
	gmail: "gmail",
	googlemail: "gmail",
	google: "gmail",
	"google workspace": "gmail",
	workspace: "gmail",
	outlook: "outlook",
	hotmail: "outlook",
	live: "outlook",
	msn: "outlook",
	microsoft: "outlook",
	"microsoft 365": "outlook",
	m365: "outlook",
	office365: "outlook",
	yahoo: "yahoo",
	ymail: "yahoo",
	aol: "yahoo",
	apple: "apple",
	icloud: "apple",
	"me.com": "apple",
	"mac.com": "apple",
	me: "apple",
	mac: "apple",
};

/** Collapse provider spellings (hotmail → outlook, icloud → apple, …) onto stable keys. */
export function normalizeProvider(provider: string): string {
	const key = provider.trim().toLowerCase();
	return PROVIDER_ALIASES[key] ?? key;
}

/** The four major mailbox providers, in spec §2 table order, with their per-row identity. */
const MAJOR_PROVIDERS: {
	key: string;
	findingId: string;
	label: string;
	junkName: string;
	fix: string;
}[] = [
	{
		key: "gmail",
		findingId: "content.placement_gmail",
		label: "Gmail / Google Workspace",
		junkName: "Spam",
		fix: "Raise Gmail Postmaster reputation (see the reputation-metrics check), ensure DMARC pass plus one-click List-Unsubscribe (see the list-unsubscribe check), and reduce promotional markup for Primary placement.",
	},
	{
		key: "outlook",
		findingId: "content.placement_outlook",
		label: "Outlook.com / Hotmail / Microsoft 365",
		junkName: "Junk",
		fix: "Enrol the sending IP in Microsoft SNDS + JMRP, keep the complaint rate low, verify DKIM/DMARC pass; if Missing, check for a Microsoft block and request delisting via the Sender Support form. See the reputation-metrics and blacklists checks.",
	},
	{
		key: "yahoo",
		findingId: "content.placement_yahoo",
		label: "Yahoo / AOL",
		junkName: "Bulk",
		fix: "Meet the 2024 Yahoo bulk-sender rules (aligned DMARC, one-click unsubscribe, complaint rate < 0.3%); improve engagement/list hygiene; use Yahoo's Sender Hub for feedback. See the reputation-metrics check.",
	},
	{
		key: "apple",
		findingId: "content.placement_apple",
		label: "Apple iCloud / me.com / mac.com",
		junkName: "Junk",
		fix: "Ensure valid SPF+DKIM+DMARC (see the spf/dkim/dmarc checks) and a clean IP/domain reputation (see the reputation-metrics check); Apple weights authentication and prior recipient interaction heavily.",
	},
];

const MAJOR_KEYS = new Set(MAJOR_PROVIDERS.map((m) => m.key));

/** The Gmail tabs that count as "Promotions exile" (delivered but not Primary — spec §1/§2). */
const PROMO_TABS: ReadonlySet<string> = new Set([
	"promotions",
	"social",
	"updates",
	"forums",
]);

/** Per-provider roll-up (spec §3 "Aggregate + score"). */
export interface ProviderAggregate {
	provider: string;
	total: number;
	inbox: number;
	spam: number;
	promotions: number;
	missing: number;
	/** Missing seeds that hard-bounced 5xx (criterion #9 — distinguished from silent drops). */
	bounced: number;
	/** Seeds that produced any verdict: total − missing. */
	delivered: number;
	/** inbox ÷ delivered × 100 (null when nothing was delivered). */
	inboxRatePct: number | null;
	spfFails: number;
	dkimFails: number;
	dmarcFails: number;
	/** Delivered seeds where at least one auth verdict was parsed. */
	authParsed: number;
	maxLatencySecs: number | null;
}

/** Group and aggregate a test's seed results per normalized provider. */
export function aggregateByProvider(
	results: SeedPlacementResult[],
): Map<string, ProviderAggregate> {
	const map = new Map<string, ProviderAggregate>();
	for (const r of results) {
		const key = normalizeProvider(r.provider);
		let agg = map.get(key);
		if (!agg) {
			agg = {
				provider: key,
				total: 0,
				inbox: 0,
				spam: 0,
				promotions: 0,
				missing: 0,
				bounced: 0,
				delivered: 0,
				inboxRatePct: null,
				spfFails: 0,
				dkimFails: 0,
				dmarcFails: 0,
				authParsed: 0,
				maxLatencySecs: null,
			};
			map.set(key, agg);
		}
		agg.total++;
		agg[r.folder]++;
		if (r.folder === "missing" && r.missingReason === "bounced") agg.bounced++;
		if (r.folder !== "missing") {
			if (r.spfPass === false) agg.spfFails++;
			if (r.dkimPass === false) agg.dkimFails++;
			if (r.dmarcPass === false) agg.dmarcFails++;
			if (r.spfPass !== null || r.dkimPass !== null || r.dmarcPass !== null)
				agg.authParsed++;
		}
		if (r.latencySecs !== null && r.latencySecs !== undefined) {
			agg.maxLatencySecs = Math.max(agg.maxLatencySecs ?? 0, r.latencySecs);
		}
	}
	for (const agg of map.values()) {
		agg.delivered = agg.total - agg.missing;
		agg.inboxRatePct =
			agg.delivered > 0 ? (agg.inbox / agg.delivered) * 100 : null;
	}
	return map;
}

/** Overall roll-up: inbox ÷ delivered (the scored rate) and inbox ÷ total (spec §2 row 1). */
export interface OverallAggregate {
	seedCount: number;
	delivered: number;
	inbox: number;
	spam: number;
	promotions: number;
	missing: number;
	inboxOfDeliveredPct: number | null;
	inboxOfTotalPct: number;
}

export function aggregateOverall(
	results: SeedPlacementResult[],
): OverallAggregate {
	const counts = { inbox: 0, spam: 0, promotions: 0, missing: 0 };
	for (const r of results) counts[r.folder]++;
	const seedCount = results.length;
	const delivered = seedCount - counts.missing;
	return {
		seedCount,
		delivered,
		inbox: counts.inbox,
		spam: counts.spam,
		promotions: counts.promotions,
		missing: counts.missing,
		inboxOfDeliveredPct:
			delivered > 0 ? (counts.inbox / delivered) * 100 : null,
		inboxOfTotalPct: seedCount > 0 ? (counts.inbox / seedCount) * 100 : 0,
	};
}

/** "82.5%" — one decimal, trailing .0 trimmed. */
function pct(value: number): string {
	const rounded = Math.round(value * 10) / 10;
	return `${Number.isInteger(rounded) ? rounded.toFixed(0) : rounded.toFixed(1)}%`;
}

/** Overall-rate → severity band (spec §3: ≥ 80 ok, 50–79 warning, < 50 critical). */
function bandOf(
	ratePct: number,
	t: PlacementThresholds,
): "ok" | "warning" | "critical" {
	if (ratePct >= t.warnBelowPct) return "ok";
	if (ratePct >= t.criticalBelowPct) return "warning";
	return "critical";
}

/** One point of the trend sparkline (spec §4) — overall + per-provider inbox rate of one test. */
export interface TrendPoint {
	sentAt: string;
	overallPct: number | null;
	byProvider: Record<string, number | null>;
}

/** Oldest → newest series across the stored tests, for the §4 Trend sparkline. */
export function trendSeries(tests: InboxPlacementTest[]): TrendPoint[] {
	return [...tests]
		.sort((a, b) => a.sentAt.localeCompare(b.sentAt))
		.map((t) => {
			const overall = aggregateOverall(t.results);
			const byProvider: Record<string, number | null> = {};
			for (const [key, agg] of aggregateByProvider(t.results))
				byProvider[key] = agg.inboxRatePct;
			return {
				sentAt: t.sentAt,
				overallPct: overall.inboxOfDeliveredPct,
				byProvider,
			};
		});
}

export interface ScoreOptions {
	domain: string;
	/** Providers the operator selected to test (spec §4 config inputs) — drives seed_coverage. */
	providers?: string[];
	thresholds?: PlacementThresholds;
}

/** Short receiver-auth summary for a provider row detail, e.g. "SPF/DKIM/DMARC: pass/pass/FAIL(2)". */
function authSummary(agg: ProviderAggregate): string {
	if (agg.authParsed === 0) return "receiver auth verdict not parsed";
	const part = (fails: number): string =>
		fails > 0 ? `FAIL(${fails})` : "pass";
	return `receiver SPF/DKIM/DMARC: ${part(agg.spfFails)}/${part(agg.dkimFails)}/${part(agg.dmarcFails)}`;
}

/**
 * Score one recorded seed test into the full placement finding set (spec §2 table, §3 severity
 * mapping, acceptance criteria #3–#9). `previousTests` (newest first, NOT including `test`)
 * powers `content.seed_trend`.
 */
export function scorePlacementTest(
	test: InboxPlacementTest,
	previousTests: InboxPlacementTest[],
	opts: ScoreOptions,
): Finding[] {
	const t = opts.thresholds ?? DEFAULT_PLACEMENT_THRESHOLDS;
	const findings: Finding[] = [];
	const byProvider = aggregateByProvider(test.results);
	const overall = aggregateOverall(test.results);
	const delivered = test.results.filter((r) => r.folder !== "missing");

	// ── content.seedlist_overall ────────────────────────────────────────────────────────────────
	if (overall.seedCount === 0) {
		findings.push({
			id: "content.seedlist_overall",
			checkId: CHECK_ID,
			title: "Seed test recorded no per-seed results",
			severity: "info",
			detail: `The seed test sent ${test.sentAt} (token ${test.testToken}) targeted ${test.seedCount} seed(s) but recorded no per-seed verdicts, so no inbox-placement rate can be computed.`,
			remediation:
				"Re-run the seed test. If it persists, check the seed-service results API / self-hosted mailbox read-back (IMAP/Graph/JMAP) credentials.",
		});
	} else {
		const rate = overall.inboxOfDeliveredPct ?? 0;
		const severity = overall.delivered === 0 ? "critical" : bandOf(rate, t);
		const worst = [...byProvider.values()]
			.filter((a) => a.delivered > 0 || a.missing > 0)
			.sort((a, b) => (a.inboxRatePct ?? -1) - (b.inboxRatePct ?? -1))[0];
		findings.push({
			id: "content.seedlist_overall",
			checkId: CHECK_ID,
			title:
				severity === "ok"
					? `Overall inbox placement ${pct(rate)}`
					: `Overall inbox placement ${pct(rate)} — below the ${severity === "critical" ? `${t.criticalBelowPct}% critical` : `${t.warnBelowPct}% healthy`} bar`,
			severity,
			detail: `Overall inbox rate ${pct(rate)}: ${overall.inbox} of ${overall.delivered} delivered seed(s) landed in the Inbox (${pct(overall.inboxOfTotalPct)} of all ${overall.seedCount} seeds; ${overall.spam} spam, ${overall.promotions} promotions, ${overall.missing} missing). Industry "good" is ≥ ${t.warnBelowPct}%.`,
			evidence: `test ${test.testToken} sent ${test.sentAt}`,
			...(severity !== "ok" && {
				remediation: `Fix the lowest-scoring provider first${worst ? ` — ${worst.provider} at ${worst.inboxRatePct === null ? "0% (nothing delivered)" : pct(worst.inboxRatePct)} inbox` : ""}: each provider row below maps the miss to its auth (spf/dkim/dmarc checks), content (content-scoring check), or reputation (reputation-metrics + blacklists checks) cause.`,
			}),
		});
	}

	// ── content.placement_gmail / _outlook / _yahoo / _apple ───────────────────────────────────
	for (const major of MAJOR_PROVIDERS) {
		const agg = byProvider.get(major.key);
		if (!agg || agg.total === 0) {
			findings.push({
				id: major.findingId,
				checkId: CHECK_ID,
				title: `${major.label} placement unknown — no live seeds`,
				severity: "info",
				detail: `The seed test had no live ${major.label} seeds, so this provider's placement row is unknown, not ok (see content.seed_coverage).`,
				remediation: `Add/repair ${major.label} seed mailboxes (or enable the provider in the seed service) so this column produces a real verdict.`,
			});
			continue;
		}
		const junkShare = agg.spam + agg.missing;
		const majorityJunk = junkShare * 2 > agg.total;
		const majorityPromo =
			major.key === "gmail" && agg.promotions * 2 > agg.total;
		const breakdown = `Inbox ${agg.inbox}/${agg.total}${agg.inboxRatePct !== null ? ` (${pct(agg.inboxRatePct)} of delivered)` : ""}, ${major.junkName} ${agg.spam}, Promotions ${agg.promotions}, Missing ${agg.missing}${agg.bounced > 0 ? ` (${agg.bounced} hard-bounced 5xx)` : ""}; ${authSummary(agg)}.`;
		if (majorityJunk) {
			findings.push({
				id: major.findingId,
				checkId: CHECK_ID,
				title: `Majority ${agg.missing > agg.spam ? "Missing" : major.junkName} at ${major.label}`,
				severity: "critical",
				detail: `${junkShare} of ${agg.total} ${major.label} seed(s) went to ${major.junkName} or never arrived. ${breakdown}`,
				remediation: major.fix,
			});
		} else if (majorityPromo) {
			findings.push({
				id: major.findingId,
				checkId: CHECK_ID,
				title: `Majority of Gmail seeds delivered to Promotions/Updates, not Primary`,
				severity: "warning",
				detail: `${agg.promotions} of ${agg.total} Gmail seed(s) were filed under a category tab instead of Primary (delivered, not spam — see content.seed_tab_placement). ${breakdown}`,
				remediation: major.fix,
			});
		} else {
			findings.push({
				id: major.findingId,
				checkId: CHECK_ID,
				title: `${major.label}: ${agg.inboxRatePct !== null ? pct(agg.inboxRatePct) : "0%"} inbox`,
				severity: "ok",
				detail: breakdown,
			});
		}
	}

	// ── content.seed_auth_pass (+ the three attribution slices) ────────────────────────────────
	const authParsed = delivered.filter(
		(r) => r.spfPass !== null || r.dkimPass !== null || r.dmarcPass !== null,
	);
	const dmarcFails = delivered.filter((r) => r.dmarcPass === false);
	const bothFails = delivered.filter(
		(r) => r.spfPass === false && r.dkimPass === false,
	);
	const anyMechFails = delivered.filter(
		(r) => r.spfPass === false || r.dkimPass === false || r.dmarcPass === false,
	);
	if (authParsed.length === 0) {
		findings.push({
			id: "content.seed_auth_pass",
			checkId: CHECK_ID,
			title: "Receiver auth verdicts not observed",
			severity: "info",
			detail: `No Authentication-Results header could be parsed from the ${delivered.length} delivered seed(s), so the receivers' own SPF/DKIM/DMARC verdict is unknown for this test.`,
			remediation:
				"Ensure the seed read-back captures full message headers (Authentication-Results / ARC-Authentication-Results) so receiver-observed auth can be verified.",
		});
	} else if (dmarcFails.length > 0 || bothFails.length > 0) {
		const mechanisms: string[] = [];
		const spfFailCount = delivered.filter((r) => r.spfPass === false).length;
		const dkimFailCount = delivered.filter((r) => r.dkimPass === false).length;
		if (spfFailCount > 0)
			mechanisms.push(
				`spf (${spfFailCount} seed(s) — see content.seed_spf_receiver)`,
			);
		if (dkimFailCount > 0)
			mechanisms.push(
				`dkim (${dkimFailCount} seed(s) — see content.seed_dkim_receiver)`,
			);
		if (dmarcFails.length > 0)
			mechanisms.push(
				`dmarc (${dmarcFails.length} seed(s) — see content.seed_dmarc_receiver)`,
			);
		const providers = [
			...new Set(
				[...dmarcFails, ...bothFails].map((r) => normalizeProvider(r.provider)),
			),
		];
		findings.push({
			id: "content.seed_auth_pass",
			checkId: CHECK_ID,
			title: "Authentication FAILED at the receivers despite the send",
			severity: "critical",
			detail: `The receivers' own Authentication-Results reported ${dmarcFails.length > 0 ? `DMARC fail at ${dmarcFails.length} delivered seed(s)` : `SPF and DKIM both fail at ${bothFails.length} delivered seed(s)`} (providers: ${providers.join(", ")}) — even if the DNS-side SPF/DKIM/DMARC checks are green. Failing mechanism(s): ${mechanisms.join("; ")}. This is usually a DKIM body-hash break (a relay rewriting the signed body) or a Return-Path not aligned with the From: org-domain.`,
			remediation:
				"If DKIM fails at the receiver: stop the ESP/relay rewriting the signed body/headers, or re-sign after modification (see the dkim check). If SPF fails: align the Return-Path to the From: org-domain (see the spf check). Then re-test. See also the dmarc check for alignment.",
		});
	} else if (anyMechFails.length > 0) {
		const mechs = [
			...(delivered.some((r) => r.spfPass === false) ? ["spf"] : []),
			...(delivered.some((r) => r.dkimPass === false) ? ["dkim"] : []),
		];
		findings.push({
			id: "content.seed_auth_pass",
			checkId: CHECK_ID,
			title: "One authentication mechanism failed at some receivers",
			severity: "warning",
			detail: `${anyMechFails.length} delivered seed(s) reported a receiver-observed ${mechs.join("+")} failure while DMARC still passed via the other aligned identifier. A single remaining aligned mechanism is fragile — one forwarder or relay change away from DMARC fail. Failing mechanism(s): ${mechs.map((m) => `${m} (see content.seed_${m}_receiver)`).join("; ")}.`,
			remediation:
				"Fix the failing mechanism now while DMARC still passes: align the Return-Path for SPF (spf check) or stop post-signing body modification for DKIM (dkim check).",
		});
	} else {
		findings.push({
			id: "content.seed_auth_pass",
			checkId: CHECK_ID,
			title: "SPF, DKIM and DMARC all passed at the receivers",
			severity: "ok",
			detail: `All ${authParsed.length} delivered seed(s) with a parsed Authentication-Results header reported spf=pass, dkim=pass and dmarc=pass — the receivers' own verdict matches the DNS-side predictions.`,
		});
	}

	// ── content.seed_tab_placement (Gmail Primary vs Promotions) ───────────────────────────────
	const gmail = byProvider.get("gmail");
	const gmailDelivered = test.results.filter(
		(r) => normalizeProvider(r.provider) === "gmail" && r.folder !== "missing",
	);
	if (!gmail || gmail.total === 0 || gmailDelivered.length === 0) {
		findings.push({
			id: "content.seed_tab_placement",
			checkId: CHECK_ID,
			title: "Gmail tab placement unknown",
			severity: "info",
			detail:
				gmail && gmail.total > 0
					? "No Gmail seed received the probe, so the Primary-vs-Promotions tab verdict is unknown for this test."
					: "The seed test had no Gmail seeds, so tab placement (Primary vs Promotions) could not be measured.",
			remediation:
				"Add Gmail seeds (see content.seed_coverage) so tab placement produces a verdict.",
		});
	} else {
		const promo = gmailDelivered.filter(
			(r) =>
				r.folder === "promotions" ||
				(r.gmailTab !== null && PROMO_TABS.has(r.gmailTab)),
		);
		if (promo.length > 0) {
			const tabs = [
				...new Set(promo.map((r) => r.gmailTab ?? "promotions")),
			].join("/");
			findings.push({
				id: "content.seed_tab_placement",
				checkId: CHECK_ID,
				title: `${pct((promo.length / gmailDelivered.length) * 100)} of delivered Gmail seeds filed under ${tabs}`,
				severity: "warning",
				detail: `${promo.length} of ${gmailDelivered.length} delivered Gmail seed(s) landed in a category tab (${tabs}) instead of Primary. Promotions is delivered — not spam — but it tanks open rates for relationship/transactional mail that belongs in Primary.`,
				remediation:
					"Reduce promotional signals: fewer images/CTAs/tracking links, plainer HTML, and send from a consistent Primary-associated stream (see the content-scoring check for the content levers).",
			});
		} else {
			findings.push({
				id: "content.seed_tab_placement",
				checkId: CHECK_ID,
				title: "All delivered Gmail seeds in the Primary tab",
				severity: "ok",
				detail: `All ${gmailDelivered.length} delivered Gmail seed(s) were filed under Primary — no Promotions/Updates exile.`,
			});
		}
	}

	// ── content.seed_missing (silent drop / hard block) ────────────────────────────────────────
	const missingSeeds = test.results.filter((r) => r.folder === "missing");
	const majorityMissing = [...byProvider.values()].filter(
		(a) => a.total > 0 && a.missing * 2 > a.total,
	);
	if (missingSeeds.length === 0) {
		findings.push({
			id: "content.seed_missing",
			checkId: CHECK_ID,
			title: "Every seed received the probe",
			severity: "ok",
			detail: `All ${overall.seedCount} seed(s) produced a folder verdict after the settle window — no silent drops or hard blocks.`,
		});
	} else {
		const bounced = missingSeeds.filter(
			(r) => r.missingReason === "bounced",
		).length;
		const dropped = missingSeeds.length - bounced;
		const bounceNote = `${bounced} hard-bounced (5xx reject at SMTP time) and ${dropped} were accepted then silently dropped/filtered`;
		if (majorityMissing.length > 0) {
			findings.push({
				id: "content.seed_missing",
				checkId: CHECK_ID,
				title: `Probe never arrived at ${majorityMissing.map((a) => a.provider).join(", ")} — hard block / silent drop`,
				severity: "critical",
				detail: `${majorityMissing.map((a) => `${a.provider}: ${a.missing}/${a.total} seeds missing`).join("; ")} after the full settle window + retry polls. Of all ${missingSeeds.length} missing seed(s), ${bounceNote}. Provider-wide Missing is a block, not a filtering nuance.`,
				remediation:
					"Treat as a block: check the blacklists check for a fresh DNSBL listing, check the provider block pages (Microsoft Sender Support, Google Postmaster, Yahoo Sender Hub), request delisting, and pause sending to that provider until cleared. See also the reputation-metrics check.",
			});
		} else {
			findings.push({
				id: "content.seed_missing",
				checkId: CHECK_ID,
				title: `${missingSeeds.length} seed(s) never received the probe`,
				severity: "warning",
				detail: `${missingSeeds.length} of ${overall.seedCount} seed(s) had no copy after the full settle window + retries (${bounceNote}), but no provider is majority-missing.`,
				remediation:
					"Watch the affected providers for escalation; cross-check the blacklists check for a fresh listing and verify the missing seeds' addresses are still live (content.seed_coverage).",
			});
		}
	}

	// ── content.seed_trend (advisory — history diff) ───────────────────────────────────────────
	const previous = previousTests[0];
	if (!previous) {
		findings.push({
			id: "content.seed_trend",
			checkId: CHECK_ID,
			title: "First seed test — trend starts with the next run",
			severity: "info",
			detail: `This is the first recorded seed test for ${opts.domain}; the inbox-placement trend (overall and per provider) begins once a second scheduled test exists to diff against.`,
			remediation:
				"Keep the scheduled seed-test cadence (daily/weekly) running so placement decay is caught as a trend before it becomes Spam/Missing.",
		});
	} else {
		const prevOverall = aggregateOverall(previous.results);
		const curRate = overall.inboxOfDeliveredPct ?? 0;
		const prevRate = prevOverall.inboxOfDeliveredPct ?? 0;
		const drop = prevRate - curRate;
		const prevByProvider = aggregateByProvider(previous.results);
		const providerDrops: string[] = [];
		let worstProviderDrop = 0;
		for (const [key, agg] of byProvider) {
			const before = prevByProvider.get(key);
			if (!before || before.inboxRatePct === null || agg.inboxRatePct === null)
				continue;
			const d = before.inboxRatePct - agg.inboxRatePct;
			if (d > 0.5) {
				providerDrops.push(
					`${key} ${pct(before.inboxRatePct)}→${pct(agg.inboxRatePct)}`,
				);
				worstProviderDrop = Math.max(worstProviderDrop, d);
			}
		}
		const bandWorsened =
			bandOf(curRate, t) !== "ok" && bandOf(prevRate, t) === "ok";
		if (drop >= 10 || worstProviderDrop >= 15 || bandWorsened) {
			findings.push({
				id: "content.seed_trend",
				checkId: CHECK_ID,
				title: `Inbox placement trending DOWN: ${pct(prevRate)} → ${pct(curRate)} overall`,
				severity: "warning",
				detail: `Versus the previous test (${previous.sentAt}), the overall inbox rate moved ${pct(prevRate)} → ${pct(curRate)}${providerDrops.length > 0 ? `; per provider: ${providerDrops.join(", ")}` : ""}. A downward slide across repeated tests signals reputation decay before it becomes Spam/Missing.`,
				remediation:
					"Investigate the reputation trend early (see the reputation-metrics check), tighten list hygiene, and slow send volume before the slide becomes Spam/Missing.",
			});
		} else {
			findings.push({
				id: "content.seed_trend",
				checkId: CHECK_ID,
				title: `Inbox placement trend: ${pct(prevRate)} → ${pct(curRate)} overall`,
				severity: "info",
				detail: `Versus the previous test (${previous.sentAt}), the overall inbox rate is ${drop > 0.5 ? "slightly down" : drop < -0.5 ? "up" : "stable"} (${pct(prevRate)} → ${pct(curRate)})${providerDrops.length > 0 ? `; per provider: ${providerDrops.join(", ")}` : ""}. ${previousTests.length + 1} test(s) recorded for the sparkline.`,
				remediation:
					"No action needed — keep the scheduled cadence running so decay is caught as a trend.",
			});
		}
	}

	// ── content.placement_longtail (only when long-tail seeds are present — spec §2) ───────────
	const longtail = [...byProvider.values()].filter(
		(a) => !MAJOR_KEYS.has(a.provider),
	);
	if (longtail.length > 0) {
		const total = longtail.reduce((n, a) => n + a.total, 0);
		const junk = longtail.reduce((n, a) => n + a.spam + a.missing, 0);
		const names = longtail.map((a) => a.provider).join(", ");
		if (junk * 2 > total) {
			findings.push({
				id: "content.placement_longtail",
				checkId: CHECK_ID,
				title: `Systemic Spam/Missing across long-tail providers (${names})`,
				severity: "warning",
				detail: `${junk} of ${total} long-tail seed(s) (${names}) went to Spam or never arrived. Smaller providers lean harder on shared infrastructure signals, so a systemic long-tail miss usually exposes a blacklist, PTR, or HELO/EHLO fault the majors tolerate.`,
				remediation:
					"Cross-check the blacklists check, the reverse-dns check (PTR), and the HELO/EHLO identity of the sending MTA; fix the shared infrastructure fault the long tail exposes.",
			});
		} else {
			findings.push({
				id: "content.placement_longtail",
				checkId: CHECK_ID,
				title: `Long-tail providers (${names}): ${junk} of ${total} seed(s) non-inbox`,
				severity: "ok",
				detail: longtail
					.map(
						(a) =>
							`${a.provider}: inbox ${a.inbox}/${a.total}, spam ${a.spam}, missing ${a.missing}`,
					)
					.join("; "),
			});
		}
	}

	// ── content.seed_delivery_latency (greylisting / throttling proxy) ─────────────────────────
	const withLatency = delivered.filter(
		(r) => r.latencySecs !== null && r.latencySecs !== undefined,
	);
	if (withLatency.length === 0) {
		findings.push({
			id: "content.seed_delivery_latency",
			checkId: CHECK_ID,
			title: "Delivery latency not measured",
			severity: "info",
			detail:
				"No seed recorded a send→arrival timestamp pair, so delivery latency (the greylisting/throttling proxy) is unknown for this test.",
			remediation:
				"Ensure the seed read-back records each copy's arrival time so latency can be measured.",
		});
	} else {
		const slow = [...byProvider.values()].filter(
			(a) => a.maxLatencySecs !== null && a.maxLatencySecs > 15 * 60,
		);
		if (slow.length > 0) {
			findings.push({
				id: "content.seed_delivery_latency",
				checkId: CHECK_ID,
				title: `Slow delivery (> 15 min) at ${slow.map((a) => a.provider).join(", ")}`,
				severity: "warning",
				detail: `${slow.map((a) => `${a.provider}: slowest arrival ${Math.round((a.maxLatencySecs ?? 0) / 60)} min`).join("; ")}. Delivery this slow usually means greylisting, rate-limiting, or repeated 4xx tempfails at the provider edge.`,
				remediation:
					"Expect and honor 4xx tempfails with correct retry backoff; warm the IP/domain more gradually; verify you are not being rate-limited for volume spikes (see the reputation-metrics check).",
			});
		} else {
			const max = Math.max(...withLatency.map((r) => r.latencySecs ?? 0));
			findings.push({
				id: "content.seed_delivery_latency",
				checkId: CHECK_ID,
				title: `All seeds arrived promptly (slowest ${max}s)`,
				severity: "ok",
				detail: `Every delivered seed arrived within the 15-minute window (slowest ${max}s across ${withLatency.length} timed seed(s)) — no greylisting/throttling signal.`,
			});
		}
	}

	// ── content.seed_coverage (the seed list itself is healthy) ────────────────────────────────
	const expected = (opts.providers ?? MAJOR_PROVIDERS.map((m) => m.key)).map(
		normalizeProvider,
	);
	const uncovered = expected.filter(
		(p) => (byProvider.get(p)?.total ?? 0) === 0,
	);
	if (uncovered.length > 0) {
		findings.push({
			id: "content.seed_coverage",
			checkId: CHECK_ID,
			title: `No live seeds for ${uncovered.join(", ")}`,
			severity: "warning",
			detail: `${uncovered.length} selected provider(s) (${uncovered.join(", ")}) had 0 live seeds in this test, so their placement rows are "unknown", not "ok" — the overall rate under-represents real inbox share.`,
			remediation: `Add/repair seed mailboxes for ${uncovered.join(", ")} (or enable the provider(s) in the seed service) so each column produces a real verdict.`,
		});
	} else {
		const minSeeds = Math.min(
			...expected.map((p) => byProvider.get(p)?.total ?? 0),
		);
		findings.push({
			id: "content.seed_coverage",
			checkId: CHECK_ID,
			title: `Seed list covers all ${expected.length} selected providers`,
			severity: "ok",
			detail: `Every selected provider (${expected.join(", ")}) had live seeds in this test (minimum ${minSeeds} per provider).`,
		});
	}

	// ── content.seed_spf_receiver / seed_dkim_receiver / seed_dmarc_receiver ───────────────────
	const slices: {
		id: string;
		mech: string;
		field: keyof Pick<
			SeedPlacementResult,
			"spfPass" | "dkimPass" | "dmarcPass"
		>;
		failWord: string;
		fix: string;
	}[] = [
		{
			id: "content.seed_spf_receiver",
			mech: "SPF",
			field: "spfPass",
			failWord: "spf=fail/softfail",
			fix: "Align the Return-Path (MAIL FROM) to the From: org-domain and confirm the sending IP is inside the SPF pass-set — see the spf check (spf.ip_coverage).",
		},
		{
			id: "content.seed_dkim_receiver",
			mech: "DKIM",
			field: "dkimPass",
			failWord: "dkim=fail/none",
			fix: "Body-hash break: stop post-signing modification by the ESP/relay (or re-sign after it), and verify the selector the receiver used matches a published key — see the dkim check.",
		},
		{
			id: "content.seed_dmarc_receiver",
			mech: "DMARC",
			field: "dmarcPass",
			failWord: "dmarc=fail",
			fix: "Achieve at least one ALIGNED authenticated identifier (SPF or DKIM domain matching the From: org-domain) — see the dmarc check.",
		},
	];
	for (const slice of slices) {
		const observed = delivered.filter((r) => r[slice.field] !== null);
		const fails = observed.filter((r) => r[slice.field] === false);
		if (observed.length === 0) {
			findings.push({
				id: slice.id,
				checkId: CHECK_ID,
				title: `Receiver-observed ${slice.mech} verdict not available`,
				severity: "info",
				detail: `No delivered seed exposed a parsed ${slice.mech.toLowerCase()}= result in its Authentication-Results header for this test.`,
				remediation:
					"Ensure the seed read-back captures the receivers' Authentication-Results headers so this attribution slice can be verified.",
			});
		} else if (fails.length > 0) {
			const providers = [
				...new Set(fails.map((r) => normalizeProvider(r.provider))),
			];
			findings.push({
				id: slice.id,
				checkId: CHECK_ID,
				title: `${slice.failWord} observed at ${fails.length} seed(s)`,
				severity: "critical",
				detail: `The receivers' own Authentication-Results reported ${slice.failWord} at ${fails.length} of ${observed.length} delivered seed(s) (providers: ${providers.join(", ")}) — the receiver's verdict, not a DNS prediction.`,
				remediation: slice.fix,
			});
		} else {
			findings.push({
				id: slice.id,
				checkId: CHECK_ID,
				title: `${slice.mech} passed at all observed receivers`,
				severity: "ok",
				detail: `All ${observed.length} delivered seed(s) with a parsed verdict reported ${slice.mech.toLowerCase()}=pass in the receivers' Authentication-Results.`,
			});
		}
	}

	return findings;
}

/**
 * The structured `results.inbox_placement` payload (spec §5 — the `inbox_placement_tests` envelope
 * + `inbox_placement_results` children mapped onto today's audit JSON, promoting cleanly to the
 * future tables in a single-module change). `allTests` (newest first, INCLUDING `test`) feeds the
 * trend series the §4 sparkline renders.
 */
export function placementPayload(
	test: InboxPlacementTest,
	allTests: InboxPlacementTest[],
): Record<string, unknown> {
	const overall = aggregateOverall(test.results);
	return {
		configured: true,
		seedService: test.seedService,
		sampleId: test.sampleId,
		testToken: test.testToken,
		sentAt: test.sentAt,
		settledAt: test.settledAt,
		seedCount: overall.seedCount,
		deliveredCount: overall.delivered,
		overallInbox:
			overall.inboxOfDeliveredPct === null
				? null
				: Math.round(overall.inboxOfDeliveredPct * 100) / 100,
		results: test.results.map((r) => ({
			provider: normalizeProvider(r.provider),
			folder: r.folder,
			gmailTab: r.gmailTab,
			spfPass: r.spfPass,
			dkimPass: r.dkimPass,
			dmarcPass: r.dmarcPass,
			latencySecs: r.latencySecs,
			...(r.missingReason ? { missingReason: r.missingReason } : {}),
		})),
		providers: [...aggregateByProvider(test.results).values()],
		trend: trendSeries(allTests),
	};
}
