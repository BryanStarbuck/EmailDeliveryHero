import type { Finding } from "../types";
import {
	aggregateByProvider,
	aggregateOverall,
	type InboxPlacementTest,
	normalizeProvider,
	type SeedPlacementResult,
	scorePlacementTest,
	trendSeries,
} from "./placement";

/**
 * The pure inbox-placement scoring engine (pm/checks/inbox_placement.mdx §2/§3 severity mapping,
 * acceptance criteria #3–#9): folder aggregation, the overall-rate bands, per-provider majority
 * rules, receiver-auth attribution slices, missing/bounce distinction, latency, coverage, trend.
 */

const seed = (
	provider: string,
	folder: SeedPlacementResult["folder"],
	extra: Partial<SeedPlacementResult> = {},
): SeedPlacementResult => ({
	provider,
	folder,
	gmailTab: null,
	spfPass: folder === "missing" ? null : true,
	dkimPass: folder === "missing" ? null : true,
	dmarcPass: folder === "missing" ? null : true,
	latencySecs: folder === "missing" ? null : 45,
	...extra,
});

const makeTest = (
	results: SeedPlacementResult[],
	overrides: Partial<InboxPlacementTest> = {},
): InboxPlacementTest => ({
	id: "t1",
	seedService: "glockapps",
	sampleId: null,
	testToken: "edh-abc",
	sentAt: "2026-06-01T10:00:00.000Z",
	settledAt: "2026-06-01T10:12:00.000Z",
	seedCount: results.length,
	deliveredCount: results.filter((r) => r.folder !== "missing").length,
	overallInbox: null,
	results,
	...overrides,
});

const score = (
	test: InboxPlacementTest,
	previous: InboxPlacementTest[] = [],
): Map<string, Finding> =>
	new Map(
		scorePlacementTest(test, previous, { domain: "example.com" }).map((f) => [
			f.id,
			f,
		]),
	);

describe("normalizeProvider", () => {
	it("collapses provider spellings onto the four major keys", () => {
		expect(normalizeProvider("Hotmail")).toBe("outlook");
		expect(normalizeProvider("iCloud")).toBe("apple");
		expect(normalizeProvider("AOL")).toBe("yahoo");
		expect(normalizeProvider("Google Workspace")).toBe("gmail");
		expect(normalizeProvider("zoho")).toBe("zoho");
	});
});

describe("aggregation", () => {
	it("computes per-provider and overall rates over delivered seeds", () => {
		const results = [
			seed("gmail", "inbox"),
			seed("gmail", "spam"),
			seed("gmail", "missing"),
			seed("outlook", "inbox"),
		];
		const byProvider = aggregateByProvider(results);
		const gmail = byProvider.get("gmail");
		expect(gmail).toMatchObject({
			total: 3,
			inbox: 1,
			spam: 1,
			missing: 1,
			delivered: 2,
		});
		expect(gmail?.inboxRatePct).toBe(50);
		const overall = aggregateOverall(results);
		expect(overall).toMatchObject({
			seedCount: 4,
			delivered: 3,
			inbox: 2,
			missing: 1,
		});
		expect(overall.inboxOfDeliveredPct).toBeCloseTo((2 / 3) * 100);
		expect(overall.inboxOfTotalPct).toBe(50);
	});
});

describe("scorePlacementTest — severity bands and majority rules", () => {
	it("maps the overall rate to ok / warning / critical (criterion #4)", () => {
		// 8/10 delivered inbox = 80% → ok.
		const ok = score(
			makeTest([
				...Array.from({ length: 8 }, () => seed("gmail", "inbox")),
				seed("outlook", "spam"),
				seed("yahoo", "spam"),
			]),
		);
		expect(ok.get("content.seedlist_overall")?.severity).toBe("ok");

		// 6/10 = 60% → warning band, exact percentage in the detail.
		const warn = score(
			makeTest([
				...Array.from({ length: 6 }, () => seed("gmail", "inbox")),
				...Array.from({ length: 4 }, () => seed("outlook", "spam")),
			]),
		);
		const warnFinding = warn.get("content.seedlist_overall");
		expect(warnFinding?.severity).toBe("warning");
		expect(warnFinding?.detail).toContain("60%");
		expect(warnFinding?.remediation).toBeTruthy();

		// 4/10 = 40% → critical.
		const crit = score(
			makeTest([
				...Array.from({ length: 4 }, () => seed("gmail", "inbox")),
				...Array.from({ length: 6 }, () => seed("outlook", "spam")),
			]),
		);
		expect(crit.get("content.seedlist_overall")?.severity).toBe("critical");
	});

	it("marks a majority-Junk provider critical and majority-Promotions Gmail warning (criterion #5)", () => {
		const findings = score(
			makeTest([
				seed("gmail", "promotions", { gmailTab: "promotions" }),
				seed("gmail", "promotions", { gmailTab: "promotions" }),
				seed("gmail", "inbox", { gmailTab: "primary" }),
				seed("outlook", "spam"),
				seed("outlook", "spam"),
				seed("outlook", "inbox"),
				seed("yahoo", "inbox"),
				seed("apple", "inbox"),
			]),
		);
		expect(findings.get("content.placement_outlook")?.severity).toBe(
			"critical",
		);
		// Promotions is delivered, not spam: the Gmail row warns, never critical.
		expect(findings.get("content.placement_gmail")?.severity).toBe("warning");
		expect(findings.get("content.seed_tab_placement")?.severity).toBe(
			"warning",
		);
		expect(findings.get("content.placement_yahoo")?.severity).toBe("ok");
		expect(findings.get("content.placement_apple")?.severity).toBe("ok");
	});

	it("reports an uncovered provider as unknown info + a coverage warning, never ok (seed_coverage)", () => {
		const findings = score(
			makeTest([
				seed("gmail", "inbox"),
				seed("outlook", "inbox"),
				seed("yahoo", "inbox"),
			]),
		);
		const apple = findings.get("content.placement_apple");
		expect(apple?.severity).toBe("info");
		expect(apple?.title).toMatch(/unknown/i);
		const coverage = findings.get("content.seed_coverage");
		expect(coverage?.severity).toBe("warning");
		expect(coverage?.detail).toContain("apple");
	});
});

describe("scorePlacementTest — receiver auth attribution (criterion #7)", () => {
	it("marks receiver-observed DMARC fail critical and names the failing mechanism", () => {
		const findings = score(
			makeTest([
				seed("gmail", "inbox", { dkimPass: false, dmarcPass: false }),
				seed("outlook", "inbox"),
				seed("yahoo", "inbox"),
				seed("apple", "inbox"),
			]),
		);
		const auth = findings.get("content.seed_auth_pass");
		expect(auth?.severity).toBe("critical");
		expect(auth?.detail).toContain("content.seed_dkim_receiver");
		expect(findings.get("content.seed_dkim_receiver")?.severity).toBe(
			"critical",
		);
		expect(findings.get("content.seed_dmarc_receiver")?.severity).toBe(
			"critical",
		);
		expect(findings.get("content.seed_spf_receiver")?.severity).toBe("ok");
	});

	it("warns when one mechanism fails while DMARC still passes (fragile single alignment)", () => {
		const findings = score(
			makeTest([
				seed("gmail", "inbox", { spfPass: false }),
				seed("outlook", "inbox"),
				seed("yahoo", "inbox"),
				seed("apple", "inbox"),
			]),
		);
		expect(findings.get("content.seed_auth_pass")?.severity).toBe("warning");
		expect(findings.get("content.seed_spf_receiver")?.severity).toBe(
			"critical",
		);
		expect(findings.get("content.seed_dmarc_receiver")?.severity).toBe("ok");
	});
});

describe("scorePlacementTest — missing, latency, longtail", () => {
	it("flags a majority-missing provider critical and distinguishes hard bounces (criteria #6/#9)", () => {
		const findings = score(
			makeTest([
				seed("gmail", "inbox"),
				seed("outlook", "missing", { missingReason: "bounced" }),
				seed("outlook", "missing", { missingReason: "dropped" }),
				seed("yahoo", "inbox"),
				seed("apple", "inbox"),
			]),
		);
		const missing = findings.get("content.seed_missing");
		expect(missing?.severity).toBe("critical");
		expect(missing?.detail).toMatch(/1 hard-bounced/);
		expect(missing?.remediation).toMatch(/blacklists/i);
		expect(findings.get("content.placement_outlook")?.severity).toBe(
			"critical",
		);
	});

	it("warns on > 15 min delivery latency (greylisting/throttling proxy)", () => {
		const findings = score(
			makeTest([
				seed("gmail", "inbox", { latencySecs: 20 * 60 }),
				seed("outlook", "inbox"),
				seed("yahoo", "inbox"),
				seed("apple", "inbox"),
			]),
		);
		const latency = findings.get("content.seed_delivery_latency");
		expect(latency?.severity).toBe("warning");
		expect(latency?.detail).toContain("gmail");
	});

	it("flags systemic long-tail Spam/Missing as a shared-infrastructure warning", () => {
		const findings = score(
			makeTest([
				seed("gmail", "inbox"),
				seed("outlook", "inbox"),
				seed("yahoo", "inbox"),
				seed("apple", "inbox"),
				seed("zoho", "spam"),
				seed("gmx", "missing"),
			]),
		);
		const longtail = findings.get("content.placement_longtail");
		expect(longtail?.severity).toBe("warning");
		expect(longtail?.remediation).toMatch(/reverse-dns|PTR/i);
	});
});

describe("scorePlacementTest — trend (criterion #12/#13)", () => {
	const healthy = makeTest(
		[
			...Array.from({ length: 9 }, () => seed("gmail", "inbox")),
			seed("outlook", "inbox"),
			seed("yahoo", "inbox"),
			seed("apple", "inbox"),
		],
		{ id: "t0", testToken: "edh-prev", sentAt: "2026-05-25T10:00:00.000Z" },
	);

	it("is info on the first test (no baseline)", () => {
		const findings = score(makeTest([seed("gmail", "inbox")]));
		expect(findings.get("content.seed_trend")?.severity).toBe("info");
	});

	it("warns on a ≥ 10-point overall drop against the previous test", () => {
		const slid = makeTest(
			[
				...Array.from({ length: 6 }, () => seed("gmail", "inbox")),
				...Array.from({ length: 4 }, () => seed("gmail", "spam")),
				seed("outlook", "inbox"),
				seed("yahoo", "inbox"),
				seed("apple", "inbox"),
			],
			{ sentAt: "2026-06-01T10:00:00.000Z" },
		);
		const findings = score(slid, [healthy]);
		const trend = findings.get("content.seed_trend");
		expect(trend?.severity).toBe("warning");
		expect(trend?.title).toMatch(/DOWN/i);
	});

	it("builds the oldest→newest sparkline series across stored tests", () => {
		const series = trendSeries([makeTest([seed("gmail", "inbox")]), healthy]);
		expect(series).toHaveLength(2);
		expect(series[0].sentAt).toBe("2026-05-25T10:00:00.000Z");
		expect(series[1].overallPct).toBe(100);
		expect(series[0].byProvider.gmail).toBe(100);
	});
});
