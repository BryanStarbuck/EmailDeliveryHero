import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.EDH_STATE_DIR = mkdtempSync(join(tmpdir(), "edh-verdict-spec-"));

import type { Complaint, ComplaintBoard } from "./complaint.types";
import {
	listComplaintSnapshots,
	readComplaintSnapshot,
	saveComplaintSnapshot,
} from "./snapshot-store";
import { boardVerdict, trendOf } from "./verdict";

/**
 * The verdict model and the per-run snapshot store (pm/Email_Complaints.mdx §8, §12).
 *
 * These are the two pieces the board's honesty rests on: §8.2 decides what the user is told at the
 * top of the page, and §12 decides whether a historical run tells the truth about itself.
 */

function complaint(over: Partial<Complaint>): Complaint {
	return {
		code: "C02",
		key: "esp_default_dkim_key",
		title: "Mail signed with your provider's own key",
		verdict: "problem",
		severity: "warning",
		messages: 100,
		sharePct: 10,
		trend: "steady",
		previousMessages: 100,
		explanation: "",
		evidenceSummary: "",
		fixIds: [],
		sources: [],
		...over,
	};
}

const HEALTHY = { messages: 1000, authenticatedPct: 99.5 };

describe("trendOf (pm/Email_Complaints.mdx §8.4)", () => {
	it("calls a complaint that was absent before 'new'", () => {
		expect(trendOf(50, 0)).toBe("new");
	});

	it("calls a complaint that has stopped firing 'resolved'", () => {
		// The whole point of §8.4: a fix must read back as feedback, not silence.
		expect(trendOf(0, 500)).toBe("resolved");
	});

	it("treats ±20% as steady and anything beyond it as a real move", () => {
		expect(trendOf(110, 100)).toBe("steady");
		expect(trendOf(90, 100)).toBe("steady");
		expect(trendOf(121, 100)).toBe("worse");
		expect(trendOf(79, 100)).toBe("better");
	});

	it("is steady, not 'new', when nothing fired in either window", () => {
		expect(trendOf(0, 0)).toBe("steady");
	});
});

describe("boardVerdict (pm/Email_Complaints.mdx §8.2)", () => {
	it("reports insufficient data rather than health when reports are thin", () => {
		// Silence must never render as health — the single most important rule on the page.
		expect(boardVerdict([], HEALTHY, 2)).toBe("insufficient_data");
		expect(boardVerdict([], { messages: 0, authenticatedPct: 0 }, 10)).toBe(
			"insufficient_data",
		);
	});

	it("escalates to action on any critical complaint", () => {
		expect(
			boardVerdict([complaint({ severity: "critical" })], HEALTHY, 10),
		).toBe("action");
	});

	it("escalates to action when our OWN mail is being blocked (C10)", () => {
		// C10 outranks its own severity: mail we recognize being rejected is the worst thing here.
		expect(
			boardVerdict(
				[complaint({ code: "C10", severity: "info", verdict: "problem" })],
				HEALTHY,
				10,
			),
		).toBe("action");
	});

	it("escalates to action when unauthorized mail is being delivered at ≥1% (C03)", () => {
		expect(
			boardVerdict(
				[complaint({ code: "C03", severity: "warning", sharePct: 1 })],
				HEALTHY,
				10,
			),
		).toBe("action");
		expect(
			boardVerdict(
				[complaint({ code: "C03", severity: "info", sharePct: 0.4 })],
				HEALTHY,
				10,
			),
		).not.toBe("action");
	});

	it("falls to attention on a warning, or on an authenticated rate under 95%", () => {
		expect(boardVerdict([complaint({ severity: "warning" })], HEALTHY, 10)).toBe(
			"attention",
		);
		expect(
			boardVerdict([], { messages: 1000, authenticatedPct: 94.9 }, 10),
		).toBe("attention");
	});

	it("distinguishes 'watch' from 'all clear'", () => {
		expect(
			boardVerdict(
				[complaint({ severity: "info", verdict: "watch" })],
				HEALTHY,
				10,
			),
		).toBe("watch");
		expect(
			boardVerdict([complaint({ severity: "ok", verdict: "ok" })], HEALTHY, 10),
		).toBe("ok");
	});

	it("stays 'all clear' when the only complaint is a spoofer being rejected", () => {
		// C01 is the system WORKING. Rendering it red is the classic DMARC-dashboard failure.
		expect(
			boardVerdict(
				[complaint({ code: "C01", severity: "info", verdict: "ok" })],
				HEALTHY,
				10,
			),
		).toBe("ok");
	});
});

describe("the per-run snapshot store (pm/Email_Complaints.mdx §12)", () => {
	const board = (over: Partial<ComplaintBoard> = {}) =>
		({
			domainId: "d1",
			domain: "act3ai.com",
			verdict: "action",
			headline: "",
			ingestionEnabled: true,
			window: { begin: "2026-05-01T00:00:00Z", end: "2026-07-01T00:00:00Z", days: 60 },
			previousWindow: { begin: "", end: "" },
			totals: {
				messages: 10,
				authenticated: 10,
				dmarcPassing: 10,
				notAligned: 0,
				blocked: 0,
				spoof: 0,
				authenticatedPct: 100,
			},
			deltas: { authenticatedPct: 0, messages: 0 },
			reporters: [],
			reports: [],
			series: [],
			policyObserved: [],
			complaints: [],
			fixes: [],
			ingest: { lastIngestAt: null, reportsStored: 0, undecodable: [] },
			...over,
		}) as ComplaintBoard;

	it("round-trips one run's board", () => {
		saveComplaintSnapshot("act3ai.com", "run-1", board());
		expect(readComplaintSnapshot("act3ai.com", "run-1")?.domain).toBe(
			"act3ai.com",
		);
	});

	it("returns null for a run that has no snapshot", () => {
		// The run-scoped route depends on this: a missing snapshot must 404, never silently fall
		// back to the live board, which would show today's evidence under a historical heading.
		expect(readComplaintSnapshot("act3ai.com", "never-ran")).toBeNull();
	});

	it("never rewrites an existing snapshot — run history is immutable", () => {
		saveComplaintSnapshot("immutable.com", "run-x", board({ verdict: "action" }));
		saveComplaintSnapshot("immutable.com", "run-x", board({ verdict: "ok" }));
		expect(readComplaintSnapshot("immutable.com", "run-x")?.verdict).toBe(
			"action",
		);
	});

	it("lists a domain's snapshots newest window-end first", () => {
		saveComplaintSnapshot(
			"listing.com",
			"r-old",
			board({
				window: { begin: "2026-01-01T00:00:00Z", end: "2026-03-01T00:00:00Z", days: 60 },
			}),
		);
		saveComplaintSnapshot(
			"listing.com",
			"r-new",
			board({
				window: { begin: "2026-05-01T00:00:00Z", end: "2026-07-01T00:00:00Z", days: 60 },
			}),
		);
		const listed = listComplaintSnapshots("listing.com");
		expect(listed).toHaveLength(2);
		expect(listed[0]?.window.end).toBe("2026-07-01T00:00:00Z");
	});

	it("returns an empty list for a domain that has never been snapshotted", () => {
		expect(listComplaintSnapshots("unknown-domain.example")).toEqual([]);
	});
});
