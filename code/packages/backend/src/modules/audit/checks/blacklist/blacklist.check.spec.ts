import type { IpTarget, TargetSource, ZoneResult } from "./blacklist-types";
import { reclassifySharedNetblockListings } from "./blacklist.check";

/**
 * An IP we merely OBSERVED carrying the mail (an ESP relay, a provider's outbound pool) sits in a
 * netblock whose abuse contact belongs to the provider — the operator cannot request the delisting,
 * so the delisting instruction is wrong and `critical` reads as an emergency they cannot end. It is
 * capped at `warning`, NOT flattened to `info`: the pool carries this domain's authenticated mail,
 * so the listing still costs delivery and the check must not report green.
 *
 * And "observed" is decided by evidence, not by the source tag alone — FCrDNS under the org domain
 * or a declared ASN makes the address the operator's, whatever put it in the sweep.
 */

const target = (
	ip: string,
	source: TargetSource,
	org: string | null = "GOOGLE - Google LLC, US",
	over: Partial<IpTarget> = {},
): IpTarget => ({
	ip,
	source,
	ptr: null,
	fcrdns_ok: null,
	asn: org === null ? null : { number: 15169, org },
	...over,
});

const listing = (target: string, over: Partial<ZoneResult> = {}): ZoneResult =>
	({
		zone: "bl.0spam.org",
		name: "0spam",
		tier: "medium",
		kind: "ip",
		target,
		listed: true,
		return_code: "127.0.0.2",
		sub_list: null,
		reason_txt: null,
		lookup_url: "",
		delist_url: "",
		severity: "warning",
		inconclusive: false,
		refusal_code: null,
		query_ms: 1,
		problem_state: null,
		paid_delist_offered: false,
		auto_expires: null,
		...over,
	}) as ZoneResult;

const DOMAIN = "example.com";

describe("reclassifySharedNetblockListings", () => {
	it("caps a listing on an observed ESP/provider relay at warning and names the owning network", () => {
		const results = [listing("209.85.208.69", { severity: "critical" })];
		reclassifySharedNetblockListings(
			results,
			[target("209.85.208.69", "email_report")],
			DOMAIN,
		);
		expect(results[0].severity).toBe("warning");
		expect(results[0].shared_netblock).toBe("GOOGLE - Google LLC, US");
	});

	it("never drops a listed mail-carrying IP to info — the check must not read green", () => {
		const results = [listing("209.85.208.69", { severity: "warning" })];
		reclassifySharedNetblockListings(
			results,
			[target("209.85.208.69", "email_report")],
			DOMAIN,
		);
		expect(results[0].severity).toBe("warning");
	});

	it("keeps full severity on an IP the operator declared as theirs", () => {
		for (const source of ["sending_ips", "spf_authorized"] as const) {
			const results = [listing("203.0.113.10", { severity: "critical" })];
			reclassifySharedNetblockListings(
				results,
				[target("203.0.113.10", source, "ACME - Acme Corp")],
				DOMAIN,
			);
			expect(results[0].severity).toBe("critical");
			expect(results[0].shared_netblock).toBeUndefined();
		}
	});

	// The regression that mattered: `mx_resolved` is only populated when NO sending IPs were declared,
	// and `v=spf1 mx -all` emits no ip4 literal — so a self-hoster matched neither declared source and
	// their own listed server was written off as a provider's pool.
	it("keeps full severity on a self-hosted MX whose FCrDNS resolves under the org domain", () => {
		const results = [listing("203.0.113.25", { severity: "critical" })];
		reclassifySharedNetblockListings(
			results,
			[
				target("203.0.113.25", "mx_resolved", "ACME - Acme Corp", {
					ptr: "mail.example.com",
					fcrdns_ok: true,
				}),
			],
			DOMAIN,
		);
		expect(results[0].severity).toBe("critical");
		expect(results[0].shared_netblock).toBeUndefined();
	});

	it("does not treat an unverified or foreign PTR as ownership", () => {
		const unverified = listing("203.0.113.26", { severity: "critical" });
		const foreign = listing("203.0.113.27", { severity: "critical" });
		reclassifySharedNetblockListings(
			[unverified, foreign],
			[
				// Reverse DNS claims the name but the forward lookup does not agree — anyone can publish
				// a PTR; only a matching round trip is evidence.
				target("203.0.113.26", "mx_resolved", "ACME - Acme Corp", {
					ptr: "mail.example.com",
					fcrdns_ok: false,
				}),
				target("203.0.113.27", "mx_resolved", "GOOGLE - Google LLC, US", {
					ptr: "mail-sor-f69.google.com",
					fcrdns_ok: true,
				}),
			],
			DOMAIN,
		);
		expect(unverified.severity).toBe("warning");
		expect(foreign.severity).toBe("warning");
		expect(foreign.shared_netblock).toBe("GOOGLE - Google LLC, US");
	});

	it("keeps full severity on an observed IP sharing an ASN the operator declared", () => {
		const results = [listing("203.0.113.40", { severity: "critical" })];
		reclassifySharedNetblockListings(
			results,
			[
				target("203.0.113.9", "sending_ips", "ACME - Acme Corp"),
				target("203.0.113.40", "email_report", "ACME - Acme Corp"),
			],
			DOMAIN,
		);
		expect(results[0].severity).toBe("critical");
		expect(results[0].shared_netblock).toBeUndefined();
	});

	it("still caps when the ASN lookup produced nothing, rather than claiming ownership", () => {
		const results = [listing("198.51.100.4", { severity: "critical" })];
		reclassifySharedNetblockListings(
			results,
			[target("198.51.100.4", "email_report", null)],
			DOMAIN,
		);
		expect(results[0].severity).toBe("warning");
		expect(results[0].shared_netblock).toBe(
			"an unidentified third-party network",
		);
	});

	it("leaves clean rows, domain rows and unknown targets untouched", () => {
		const clean = listing("209.85.208.69", {
			listed: false,
			severity: null,
			return_code: null,
		});
		const domainRow = listing("em2598.example.com", {
			kind: "domain",
			zone: "dbl.spamhaus.org",
			severity: "critical",
		});
		const orphan = listing("203.0.113.99", { severity: "critical" });
		reclassifySharedNetblockListings(
			[clean, domainRow, orphan],
			[target("209.85.208.69", "email_report")],
			DOMAIN,
		);
		expect(clean.severity).toBeNull();
		// A domain listing has no netblock owner to defer to, and an IP with no target record is not
		// evidence of anything — neither may be silently downgraded.
		expect(domainRow.severity).toBe("critical");
		expect(orphan.severity).toBe("critical");
	});
});
