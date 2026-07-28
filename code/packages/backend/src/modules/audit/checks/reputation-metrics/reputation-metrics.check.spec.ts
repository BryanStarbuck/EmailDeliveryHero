import * as derive from "@module/reports/derive-findings";
import * as reportStore from "@module/reports/report-store";
import * as configStore from "@shared/config-store";
import type {
	BlacklistRunResults,
	ZoneResult,
} from "../blacklist/blacklist-types";
import * as store from "../blacklist/store";
import * as dns from "../dns-util";
import { summarize } from "../types";
import { blocklistHistory, fblEnrollment } from "./reputation-metrics.check";

/**
 * content.blocklist_history — the first-round DNSBL-recurrence trend (pm/checks/reputation_metrics.mdx
 * §2/§7, AC #7). Warns when the same DNSBL listed the domain/IP >= 2 times in the trailing window.
 */

const listing = (
	zone: string,
	name: string,
	target: string,
	listed = true,
): ZoneResult =>
	({
		zone,
		name,
		tier: "high",
		kind: "ip",
		target,
		listed,
		return_code: listed ? "127.0.0.2" : null,
		sub_list: null,
		reason_txt: null,
		lookup_url: "",
		delist_url: "",
		severity: listed ? "critical" : null,
		inconclusive: false,
		refusal_code: null,
		query_ms: 1,
		problem_state: null,
		paid_delist_offered: false,
		auto_expires: null,
	}) as ZoneResult;

const run = (ranAt: string, results: ZoneResult[]): BlacklistRunResults =>
	({
		schema_version: 1,
		technology: "blacklists",
		domain: "example.com",
		audit_id: ranAt,
		ran_at: ranAt,
		results,
	}) as unknown as BlacklistRunResults;

function mockRuns(runs: BlacklistRunResults[]): void {
	jest.spyOn(store, "readBlacklistRuns").mockReturnValue(runs);
}

afterEach(() => jest.restoreAllMocks());

describe("blocklistHistory", () => {
	const recent = () => new Date().toISOString();

	it("is info when there is no stored blacklist history", () => {
		mockRuns([]);
		const f = blocklistHistory("example.com");
		expect(f.id).toBe("content.blocklist_history");
		expect(f.severity).toBe("info");
	});

	it("is ok when no zone recurs (one-off listing only)", () => {
		mockRuns([
			run(recent(), [
				listing("zen.spamhaus.org", "Spamhaus ZEN", "203.0.113.10"),
			]),
			run(recent(), [
				listing("zen.spamhaus.org", "Spamhaus ZEN", "203.0.113.10", false),
			]),
		]);
		const f = blocklistHistory("example.com");
		expect(f.severity).toBe("ok");
	});

	it("warns when the same DNSBL lists the same target across >= 2 runs", () => {
		mockRuns([
			run(recent(), [
				listing("zen.spamhaus.org", "Spamhaus ZEN", "203.0.113.10"),
			]),
			run(recent(), [
				listing("zen.spamhaus.org", "Spamhaus ZEN", "203.0.113.10"),
			]),
		]);
		const f = blocklistHistory("example.com");
		expect(f.severity).toBe("warning");
		expect(f.remediation).toContain("root cause");
		expect(f.evidence).toContain("zen.spamhaus.org|203.0.113.10=2");
	});

	it("counts a (zone,target) at most once per run (dedupes within a run)", () => {
		// Same run lists the pair twice — must NOT count as a recurrence on its own.
		mockRuns([
			run(recent(), [
				listing("zen.spamhaus.org", "Spamhaus ZEN", "203.0.113.10"),
				listing("zen.spamhaus.org", "Spamhaus ZEN", "203.0.113.10"),
			]),
		]);
		expect(blocklistHistory("example.com").severity).toBe("ok");
	});

	it("ignores runs older than the trailing window", () => {
		const old = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
		mockRuns([
			run(old, [listing("zen.spamhaus.org", "Spamhaus ZEN", "203.0.113.10")]),
			run(old, [listing("zen.spamhaus.org", "Spamhaus ZEN", "203.0.113.10")]),
		]);
		// Both recurrences are outside the 30-day window → no windowed runs → info.
		expect(blocklistHistory("example.com").severity).toBe("info");
	});
});

/**
 * content.fbl_enrollment — the advisory may only speak about IPs whose provenance is real. MX A
 * records are the INBOUND path, so they must never be printed as "every sending IP" (which turned
 * Google Workspace's `*-in-f*.1e100.net` frontends into a standing amber warning on every domain
 * that had not recorded its sending IPs).
 */
describe("fblEnrollment", () => {
	const GOOGLE_MX_IPS = ["192.178.158.26", "173.194.43.27"];

	/** MX resolving to Google's inbound frontends — the shape that produced the false positive. */
	function mockMx(): void {
		jest.spyOn(dns, "resolveMx").mockResolvedValue({
			records: [
				{ exchange: "aspmx.l.google.com", priority: 1 },
				{ exchange: "alt3.aspmx.l.google.com", priority: 10 },
			],
			empty: false,
		} as Awaited<ReturnType<typeof dns.resolveMx>>);
		jest
			.spyOn(dns, "resolve4")
			.mockImplementation(async (name: string) => ({
				records: [
					name.startsWith("alt3") ? GOOGLE_MX_IPS[1] : GOOGLE_MX_IPS[0],
				],
				empty: false,
			}));
	}

	function mockReports(enabled: boolean, rows: Partial<derive.DmarcSourceRow>[]): void {
		jest
			.spyOn(configStore, "readAppConfig")
			.mockReturnValue({
				reports: { enabled, windowDays: 7 },
			} as ReturnType<typeof configStore.readAppConfig>);
		jest
			.spyOn(reportStore, "listDmarcReports")
			.mockReturnValue(
				rows.length
					? ([{}] as ReturnType<typeof reportStore.listDmarcReports>)
					: [],
			);
		jest.spyOn(derive, "aggregateDmarc").mockReturnValue({
			rows,
		} as derive.DmarcAggregate);
	}

	it("does NOT present MX addresses as sending IPs — info, not a warning", async () => {
		mockMx();
		mockReports(false, []);
		const f = await fblEnrollment("act3ai.com", "dom-1", []);

		expect(f.id).toBe("content.fbl_enrollment.no_ips");
		expect(f.severity).toBe("info");
		for (const ip of GOOGLE_MX_IPS) {
			expect(JSON.stringify(f)).not.toContain(ip);
		}
	});

	it("points a shared-pool sender at the domain-keyed programs, not the IP-keyed ones", async () => {
		mockMx();
		mockReports(false, []);
		const f = await fblEnrollment("act3ai.com", "dom-1", []);

		expect(f.remediation).toContain("postmaster.google.com");
		expect(f.remediation).toContain("complaint-feedback-loop");
		// SNDS/JMRP need the netblock's abuse contact — unenrollable without owning the IPs.
		expect(f.remediation).not.toContain("snds");
	});

	it("advises on configured sending IPs", async () => {
		mockMx();
		mockReports(false, []);
		const f = await fblEnrollment("act3ai.com", "dom-1", ["203.0.113.10"]);

		expect(f.id).toBe("content.fbl_enrollment.advisory");
		expect(f.detail).toContain("203.0.113.10");
		expect(f.evidence).toContain("source: configured");
	});

	// Enrollment is only visible in the provider portals, behind the FUTURE FBL connector. A warning
	// would assert a fault we cannot observe AND could never be cleared, pinning the domain amber.
	it("is never amber, whatever the provenance — it carries no health penalty", async () => {
		mockMx();

		mockReports(false, []);
		expect((await fblEnrollment("a.com", "d", [])).severity).toBe("info");
		expect((await fblEnrollment("a.com", "d", ["203.0.113.10"])).severity).toBe(
			"info",
		);

		mockReports(true, [{ sourceIp: "209.85.220.41", dmarcPass: true }]);
		expect((await fblEnrollment("a.com", "d", [])).severity).toBe("info");
	});

	it("says plainly that it is not a fault and does not affect the score", async () => {
		mockMx();
		mockReports(false, []);
		const f = await fblEnrollment("act3ai.com", "dom-1", ["203.0.113.10"]);

		expect(f.detail).toContain("not a detected fault");
		expect(f.detail).toContain("health score");
	});

	it("observes sending IPs from DMARC reports, keeping only DMARC-passing sources", async () => {
		mockMx();
		mockReports(true, [
			{ sourceIp: "209.85.220.41", dmarcPass: true },
			{ sourceIp: "149.72.120.130", dmarcPass: true },
			{ sourceIp: "198.51.100.7", dmarcPass: false }, // spoofer in the same reports
		]);
		const f = await fblEnrollment("act3ai.com", "dom-1", []);

		expect(f.id).toBe("content.fbl_enrollment.advisory");
		expect(f.detail).toContain("209.85.220.41");
		expect(f.detail).toContain("149.72.120.130");
		expect(f.detail).not.toContain("198.51.100.7");
		expect(f.evidence).toContain("source: dmarc_reports");
	});

	it("ranks observed IPs by volume and caps the printed list, stating the true total", async () => {
		mockMx();
		// 12 passing sources — more than the print cap — with a deliberately unsorted volume order.
		mockReports(
			true,
			Array.from({ length: 12 }, (_, i) => ({
				sourceIp: `203.0.113.${i + 1}`,
				dmarcPass: true,
				count: i + 1,
			})),
		);
		const f = await fblEnrollment("act3ai.com", "dom-1", []);

		expect(f.detail).toContain("12 sources in total");
		expect(f.detail).toContain("203.0.113.12"); // heaviest, ranked first
		expect(f.detail).not.toContain("203.0.113.1,"); // lightest, cut by the cap
		expect(f.evidence).toContain("+2 more");
	});

	it("sums an IP appearing on several rows before ranking", async () => {
		mockMx();
		mockReports(true, [
			{ sourceIp: "203.0.113.9", dmarcPass: true, count: 5 },
			{ sourceIp: "203.0.113.9", dmarcPass: true, count: 5 },
			{ sourceIp: "203.0.113.8", dmarcPass: true, count: 8 },
		]);
		const f = await fblEnrollment("act3ai.com", "dom-1", []);

		// 10 combined beats 8, so .9 leads despite each single row being smaller.
		expect(f.detail).toContain("203.0.113.9, 203.0.113.8");
	});

	it("falls back to the info finding when every report source failed DMARC", async () => {
		mockMx();
		mockReports(true, [{ sourceIp: "198.51.100.7", dmarcPass: false }]);
		const f = await fblEnrollment("act3ai.com", "dom-1", []);

		expect(f.id).toBe("content.fbl_enrollment.no_ips");
		expect(f.severity).toBe("info");
	});

	it("leaves the rolled-up score and status untouched", async () => {
		mockMx();
		mockReports(true, [{ sourceIp: "209.85.220.41", dmarcPass: true }]);
		const f = await fblEnrollment("act3ai.com", "dom-1", []);

		// Alone: score stays 100, and the domain reads "info" (not-connected dot), never amber.
		expect(summarize([f])).toMatchObject({ score: 100, status: "info" });

		// Alongside a real finding: contributes nothing to the deduction.
		const ok = { ...f, id: "x", severity: "ok" as const };
		expect(summarize([ok]).score).toBe(summarize([ok, f]).score);
	});
});
