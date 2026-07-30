import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * The "findings describe the PRESENT" contract for report-derived findings:
 *
 *   1. the aggregation window is anchored on the clock, so a corpus that stopped arriving reports
 *      "no current data" instead of freezing its last verdict on every rescan, and
 *   2. a row that failed BOTH alignments is only OUR sender on independent evidence — never on its
 *      envelope or its d=, both of which a spoofer forges for free. Forged mail the published policy
 *      already stopped is the policy WORKING and must never be scored as our fault.
 */

// state-dir reads EDH_STATE_DIR at call time, so set it before any store call.
process.env.EDH_STATE_DIR = mkdtempSync(join(tmpdir(), "edh-derive-spec-"));

import {
	aggregateDmarc,
	authenticatedSourceIps,
	deriveDmarcReportFindings,
	isOwnUnalignedSender,
	wasForwardedByReceiver,
} from "./derive-findings";
import type { DmarcReportRow, ParsedDmarcReport } from "./report.types";
import { saveDmarcReport } from "./report-store";

const DOMAIN = "example.com";

function daysAgo(n: number): Date {
	return new Date(Date.now() - n * 24 * 60 * 60 * 1000);
}

function row(over: Partial<DmarcReportRow> & { sourceIp: string }): DmarcReportRow {
	return {
		count: 1,
		disposition: "none",
		spfEvaluated: "pass",
		dkimEvaluated: "pass",
		spfAligned: true,
		dkimAligned: true,
		dmarcPass: true,
		headerFrom: DOMAIN,
		envelopeSpfDomain: DOMAIN,
		dkimSigningDomains: [DOMAIN],
		...over,
	};
}

/** A row that fails both mechanisms while forging our envelope AND our d= — the spoofer shape. */
function forged(sourceIp: string, disposition: string): DmarcReportRow {
	return row({
		sourceIp,
		disposition,
		spfEvaluated: "fail",
		dkimEvaluated: "permerror",
		spfAligned: false,
		dkimAligned: false,
		dmarcPass: false,
	});
}

let reportSeq = 0;
function report(
	domainId: string,
	dayOffset: number,
	rows: DmarcReportRow[],
): ParsedDmarcReport {
	const day = daysAgo(dayOffset);
	const r: ParsedDmarcReport = {
		kind: "dmarc",
		reporterOrg: "google.com",
		reportId: `spec-${++reportSeq}`,
		window: {
			begin: new Date(day.getTime() - 12 * 60 * 60 * 1000).toISOString(),
			end: day.toISOString(),
		},
		policyPublished: {
			domain: DOMAIN,
			p: "reject",
			sp: null,
			adkim: "r",
			aspf: "r",
			pct: "100",
			np: null,
		},
		rows,
	};
	saveDmarcReport(domainId, r);
	return r;
}

describe("aggregateDmarc — the window is anchored on now, not on the newest report", () => {
	it("excludes reports older than the window and counts them as stale", () => {
		const reports = [
			report("agg-stale", 40, [row({ sourceIp: "203.0.113.1" })]),
			report("agg-stale", 30, [row({ sourceIp: "203.0.113.2" })]),
		];
		const agg = aggregateDmarc(reports, 7);
		expect(agg.reportCount).toBe(0);
		expect(agg.staleReportCount).toBe(2);
		expect(agg.totalMessages).toBe(0);
		// The window ends now — an old corpus can never hold it open.
		expect(Date.parse(agg.window.end)).toBeGreaterThan(
			daysAgo(1).getTime(),
		);
		expect(agg.newestReportEnd).not.toBeNull();
	});

	it("reports the real DMARC pass rate separately from the dual-aligned rate", () => {
		const reports = [
			report("agg-rates", 1, [
				// 9 msgs pass DMARC on SPF alone — deliverable, but single-mechanism.
				row({
					sourceIp: "203.0.113.10",
					count: 9,
					dkimEvaluated: "fail",
					dkimAligned: false,
				}),
				// 1 msg fails outright.
				forged("198.51.100.1", "reject"),
			]),
		];
		const agg = aggregateDmarc(reports, 7);
		expect(agg.totalMessages).toBe(10);
		expect(agg.dmarcPassMessages).toBe(9);
		expect(agg.dmarcPassRatePct).toBe(90);
		// Dual alignment is far lower, and must not be presented as the DMARC pass rate.
		expect(agg.alignedPassMessages).toBe(0);
		expect(agg.passRatePct).toBe(0);
	});

	// Severity keys on disposition, so disposition is part of a row's identity. Merging across it and
	// keeping the strongest label reported a source that Gmail rejected and Yahoo DELIVERED as wholly
	// rejected — burying the delivered volume, the one slice that is an unanswered threat, under the
	// label of the slice that is the policy working.
	it("keeps rows that differ only on disposition apart", () => {
		const reports = [
			report("agg-mixed", 1, [
				forged("198.51.100.9", "reject"),
				{ ...forged("198.51.100.9", "none"), count: 5000 },
			]),
		];
		const agg = aggregateDmarc(reports, 7);
		const rows = agg.rows.filter((r) => r.sourceIp === "198.51.100.9");
		expect(rows).toHaveLength(2);
		expect(rows.map((r) => r.disposition).sort()).toEqual(["none", "reject"]);
		expect(rows.find((r) => r.disposition === "none")?.count).toBe(5000);
		expect(rows.find((r) => r.disposition === "reject")?.count).toBe(1);
	});
});

describe("partly-blocked spoofing is scored on the delivered slice", () => {
	it("raises a critical for the delivered volume instead of calling it all blocked", () => {
		report("mixed-disp", 1, [
			forged("198.51.100.9", "reject"),
			{ ...forged("198.51.100.9", "none"), count: 5000 },
		]);
		const findings = deriveDmarcReportFindings("mixed-disp", DOMAIN);
		const unaligned = findings.filter((f) =>
			f.id.startsWith("dmarc.report_unaligned_source.198.51.100.9"),
		);
		// Two outcomes for one IP: distinct ids, so neither can shadow the other in the run diff.
		expect(new Set(unaligned.map((f) => f.id)).size).toBe(2);
		const delivered = unaligned.find((f) => f.severity === "critical");
		expect(delivered).toBeDefined();
		expect(delivered?.title).toContain("Unauthorized sender");
		expect(delivered?.detail).toContain("5000 msg(s)");
		expect(
			unaligned.some(
				(f) => f.severity === "info" && f.title.includes("Spoofed mail"),
			),
		).toBe(true);
		// The aggregate row must not read clean while 5000 forged msgs are landing.
		const passRate = findings.find((f) => f.id === "dmarc.real_pass_rate");
		expect(passRate?.severity).toBe("warning");
	});
});

describe("isOwnUnalignedSender — ownership needs independent evidence", () => {
	const forgedRow = forged("198.51.100.7", "reject");

	it("does not trust a forged envelope or a forged d=", () => {
		expect(forgedRow.envelopeSpfDomain).toBe(DOMAIN);
		expect(forgedRow.dkimSigningDomains).toContain(DOMAIN);
		expect(isOwnUnalignedSender(forgedRow, new Set())).toBe(false);
	});

	it("accepts an IP that has authenticated for us before", () => {
		const ips = authenticatedSourceIps([
			report("own-evidence", 20, [row({ sourceIp: "198.51.100.7" })]),
		]);
		expect(isOwnUnalignedSender(forgedRow, ips)).toBe(true);
	});

	it("accepts a configured sending IP", () => {
		expect(isOwnUnalignedSender(forgedRow, new Set(["198.51.100.7"]))).toBe(
			true,
		);
	});
});

describe("wasForwardedByReceiver — the receiver's own explanation for the override", () => {
	it("recognises the RFC 7489 forwarding override types", () => {
		for (const type of ["forwarded", "trusted_forwarder", "mailing_list"]) {
			expect(wasForwardedByReceiver({ reasons: [{ type, comment: null }] })).toBe(
				true,
			);
		}
	});

	it("recognises Google's local_policy/arc=pass rescue", () => {
		expect(
			wasForwardedByReceiver({
				reasons: [{ type: "local_policy", comment: "arc=pass" }],
			}),
		).toBe(true);
	});

	it("does not treat a bare local_policy or sampled_out override as forwarding", () => {
		expect(
			wasForwardedByReceiver({
				reasons: [{ type: "local_policy", comment: "internal allowlist" }],
			}),
		).toBe(false);
		expect(
			wasForwardedByReceiver({ reasons: [{ type: "sampled_out", comment: null }] }),
		).toBe(false);
		expect(wasForwardedByReceiver({})).toBe(false);
	});
});

describe("deriveDmarcReportFindings", () => {
	it("reports 'no current data' rather than re-firing a fault nobody is reporting any more", () => {
		const id = "stale-corpus";
		// A month-old window in which everything was broken and rejected.
		report(id, 30, [forged("198.51.100.20", "reject")]);
		const findings = deriveDmarcReportFindings(id, DOMAIN);

		expect(findings.every((f) => f.severity === "info")).toBe(true);
		const passRate = findings.find((f) => f.id === "dmarc.real_pass_rate");
		expect(passRate?.title).toContain("No DMARC report data in the last");
		expect(passRate?.detail).toContain("deliberately not scored");
		// The stale per-IP rows must be gone entirely, not merely downgraded.
		expect(findings.some((f) => f.id.includes("198.51.100.20"))).toBe(false);
	});

	it("scores forged mail the policy stopped as info, and never advises adding it to SPF", () => {
		const id = "spoof-blocked";
		report(id, 1, [
			row({ sourceIp: "203.0.113.30", count: 500 }),
			forged("198.51.100.31", "reject"),
		]);
		const findings = deriveDmarcReportFindings(id, DOMAIN);

		const unaligned = findings.find(
			(f) => f.id.startsWith("dmarc.report_unaligned_source.198.51.100.31."),
		);
		expect(unaligned?.severity).toBe("info");
		expect(unaligned?.title).toContain("Spoofed mail");
		expect(unaligned?.remediation).toContain("do NOT add this IP to SPF");
		expect(unaligned?.detail).toContain("forged claims");

		// The enforcement row for the same IP is the policy working — never critical.
		const enforcement = findings.find(
			(f) => f.id.startsWith("dmarc.report_enforcement.198.51.100.31."),
		);
		expect(enforcement?.severity).toBe("info");
		expect(enforcement?.title).toContain("Spoofed mail");

		// Nothing in this window is a critical: 500 of 501 msgs are delivering fine.
		expect(findings.some((f) => f.severity === "critical")).toBe(false);
	});

	it("still flags forged mail receivers are DELIVERING as critical", () => {
		const id = "spoof-delivered";
		report(id, 1, [forged("198.51.100.41", "none")]);
		const findings = deriveDmarcReportFindings(id, DOMAIN);

		const unaligned = findings.find(
			(f) => f.id.startsWith("dmarc.report_unaligned_source.198.51.100.41."),
		);
		expect(unaligned?.severity).toBe("critical");
		expect(unaligned?.title).toContain("Unauthorized sender");
	});

	it("does not call receiver-declared forwarded mail spoofing, even when delivered", () => {
		const id = "forwarded-relay";
		// The relay authenticated for ANOTHER domain and the reporter says it rescued the message via
		// ARC. Unaligned by design — the one shape that must not become a critical.
		report(id, 1, [
			{
				...row({
					sourceIp: "2001:db8::1",
					disposition: "none",
					spfAligned: false,
					dkimAligned: false,
					dmarcPass: false,
					envelopeSpfDomain: "relay.example.net",
					dkimSigningDomains: ["relay.example.net"],
				}),
				reasons: [{ type: "local_policy", comment: "arc=pass" }],
			},
		]);
		const findings = deriveDmarcReportFindings(id, DOMAIN);

		const unaligned = findings.find(
			(f) => f.id.startsWith("dmarc.report_unaligned_source.2001:db8::1."),
		);
		expect(unaligned?.severity).toBe("info");
		expect(unaligned?.title).toContain("Forwarded mail arriving unaligned");
		expect(unaligned?.evidence).toContain("classified=forwarded");
		expect(findings.some((f) => f.severity === "critical")).toBe(false);
	});

	it("flags our OWN broken sender as a warning, and its rejection as critical", () => {
		const id = "own-broken";
		// Evidence of ownership: the IP authenticated for us three weeks ago.
		report(id, 21, [row({ sourceIp: "203.0.113.50", count: 100 })]);
		// Today it fails both mechanisms and receivers are rejecting it.
		report(id, 1, [
			row({ sourceIp: "203.0.113.51", count: 200 }),
			{ ...forged("203.0.113.50", "reject"), count: 40 },
		]);
		const findings = deriveDmarcReportFindings(id, DOMAIN);

		const unaligned = findings.find(
			(f) => f.id.startsWith("dmarc.report_unaligned_source.203.0.113.50."),
		);
		expect(unaligned?.severity).toBe("warning");
		expect(unaligned?.title).toContain("Own stream failing all authentication");
		expect(unaligned?.remediation).toContain("Authorize this sender");

		const enforcement = findings.find(
			(f) => f.id.startsWith("dmarc.report_enforcement.203.0.113.50."),
		);
		expect(enforcement?.severity).toBe("critical");
		expect(enforcement?.title).toContain("Our mail");
	});

	it("keys dmarc.real_pass_rate on the DMARC pass rate, not on dual alignment", () => {
		const id = "spf-only-stream";
		// Every message passes DMARC via SPF only: deliverable, fragile, 0% dual-aligned.
		report(id, 1, [
			row({
				sourceIp: "203.0.113.60",
				count: 1000,
				dkimEvaluated: "fail",
				dkimAligned: false,
			}),
		]);
		const findings = deriveDmarcReportFindings(id, DOMAIN);

		const passRate = findings.find((f) => f.id === "dmarc.real_pass_rate");
		expect(passRate?.title).toBe("DMARC pass rate 100%");
		expect(passRate?.severity).toBe("info");
		// The fragility is not lost — it moves to the row that actually means it.
		const fragility = findings.find((f) =>
			f.id.startsWith("dmarc.report_alignment_fragility."),
		);
		expect(fragility?.severity).toBe("warning");
		expect(fragility?.title).toContain("SPF-only");
	});
});
