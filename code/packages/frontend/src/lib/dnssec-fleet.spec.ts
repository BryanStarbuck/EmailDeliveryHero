import { describe, expect, it } from "vitest";
import type { AuditResult, DnssecResults } from "@/api/types";
import {
	compareFleetRows,
	daysUntil,
	type DnssecFleetRow,
	isDeprecatedAlgo,
	toDnssecFleetRow,
} from "./dnssec-fleet";

const NOW = Date.parse("2026-07-01T00:00:00Z");

function run(over: Partial<AuditResult>, dnssec?: Partial<DnssecResults>): AuditResult {
	return {
		domainId: over.domainId ?? "d1",
		domain: over.domain ?? "example.com",
		ranAt: "2026-07-01T00:00:00Z",
		score: 100,
		status: "ok",
		findings: over.findings ?? [],
		counts: { ok: 0, info: 0, warning: 0, critical: 0 },
		results: dnssec
			? { "infra.dnssec": { signed: false, ds_present: null, ds_digest_types: [], algorithms: [], ds_matches_dnskey: null, dane_ready: false, ...dnssec } }
			: undefined,
		...over,
	} as AuditResult;
}

describe("daysUntil", () => {
	it("floors toward the past so a 12h-out expiry reads 0 days", () => {
		expect(daysUntil("2026-07-01T12:00:00Z", NOW)).toBe(0);
	});
	it("is negative for an already-expired signature", () => {
		expect(daysUntil("2026-06-28T00:00:00Z", NOW)).toBe(-3);
	});
	it("returns null for null/invalid input", () => {
		expect(daysUntil(null, NOW)).toBeNull();
		expect(daysUntil("not-a-date", NOW)).toBeNull();
	});
});

describe("toDnssecFleetRow", () => {
	it("marks a run with no snapshot as unknown, not unsigned", () => {
		const row = toDnssecFleetRow(run({}), NOW);
		expect(row.unknown).toBe(true);
		expect(row.signed).toBe(false);
	});
	it("prefers camelCase dsPresent then falls back to snake_case", () => {
		expect(toDnssecFleetRow(run({}, { dsPresent: true }), NOW).dsPresent).toBe(true);
		expect(toDnssecFleetRow(run({}, { ds_present: true }), NOW).dsPresent).toBe(true);
	});
	it("folds the worst infra.dnssec finding severity", () => {
		const row = toDnssecFleetRow(
			run({
				findings: [
					{ id: "1", checkId: "infra.dnssec_signed", title: "", severity: "ok", detail: "" },
					{ id: "2", checkId: "infra.dnssec_validates", title: "", severity: "critical", detail: "" },
					{ id: "3", checkId: "infra.spf_all", title: "", severity: "warning", detail: "" },
				],
			}, { signed: true }),
			NOW,
		);
		expect(row.severity).toBe("critical");
	});
	it("computes daysToExpiry from the earliest RRSIG expiry", () => {
		const row = toDnssecFleetRow(run({}, { signed: true, rrsigEarliestExpiry: "2026-07-11T00:00:00Z" }), NOW);
		expect(row.daysToExpiry).toBe(10);
	});
});

describe("compareFleetRows", () => {
	it("orders broken before healthy, then sooner expiry first", () => {
		const mk = (over: Partial<DnssecFleetRow>): DnssecFleetRow => ({
			domainId: "x", domain: "x.com", severity: "ok", signed: true, dsPresent: true,
			validates: true, bogus: false, algorithms: [13], rrsigEarliestExpiry: null,
			daysToExpiry: null, unknown: false, ...over,
		});
		const broken = mk({ domain: "broken.com", severity: "critical" });
		const soon = mk({ domain: "soon.com", daysToExpiry: 2 });
		const later = mk({ domain: "later.com", daysToExpiry: 40 });
		const sorted = [later, soon, broken].sort(compareFleetRows);
		expect(sorted.map((r) => r.domain)).toEqual(["broken.com", "soon.com", "later.com"]);
	});
});

describe("isDeprecatedAlgo", () => {
	it("flags RSASHA1 (5) and RSASHA1-NSEC3 (7); passes 13/8", () => {
		expect(isDeprecatedAlgo(5)).toBe(true);
		expect(isDeprecatedAlgo(7)).toBe(true);
		expect(isDeprecatedAlgo(13)).toBe(false);
		expect(isDeprecatedAlgo(8)).toBe(false);
	});
});
