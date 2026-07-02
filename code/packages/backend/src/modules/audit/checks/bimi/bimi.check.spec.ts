import type { CheckContext, CheckOutcome, Finding } from "../types";
import {
	type BimiResults,
	bimiCheck,
	parseBimiSelectorHeader,
} from "./bimi.check";

/**
 * BIMI checker spec (pm/checks/bimi.mdx §8 acceptance criteria). All DNS goes through the mocked
 * dns-util, so these tests exercise the first-round (pure-DNS) logic deterministically: presence,
 * syntax, single-record, the DMARC-at-enforcement prerequisite (read from the sibling dmarc
 * result), l=/a= URL shape, selector handling, and the structured per-selector results payload.
 */

jest.mock("../dns-util", () => ({
	resolveTxt: jest.fn(),
	resolve4: jest.fn(),
	resolve6: jest.fn(),
	resolveCname: jest.fn(),
}));

const dns = require("../dns-util") as Record<string, jest.Mock>;

const found = (records: string[]) => ({ records, empty: records.length === 0 });

/** Route TXT lookups by name; default: no record anywhere. */
function mockTxt(byName: Record<string, string[]>): void {
	dns.resolveTxt.mockImplementation(async (name: string) =>
		found(byName[name] ?? []),
	);
}

function mockHostsResolve(): void {
	dns.resolve4.mockResolvedValue(found(["203.0.113.10"]));
	dns.resolve6.mockResolvedValue(found([]));
	dns.resolveCname.mockResolvedValue(found([]));
}

async function run(ctx: Partial<CheckContext>): Promise<CheckOutcome> {
	const outcome = await bimiCheck.run({
		domain: "example.com",
		dkimSelectors: [],
		sendingIps: [],
		...ctx,
	});
	// The BIMI checker always returns a CheckOutcome (findings + structured results).
	expect(Array.isArray(outcome)).toBe(false);
	return outcome as CheckOutcome;
}

const byId = (findings: Finding[], id: string) =>
	findings.find((f) => f.id === id);

/** A sibling dmarc result as the run graph publishes it into ctx.upstream (pm/checks/bimi.mdx §3). */
const dmarcUpstream = (policy: string) => ({
	dmarc: {
		policy,
		is_enforcing: policy === "quarantine" || policy === "reject",
		raw_record: `v=DMARC1; p=${policy}`,
	},
});

const GOOD =
	"v=BIMI1; l=https://example.com/bimi/logo.svg; a=https://example.com/bimi/vmc.pem";

beforeEach(() => {
	jest.resetAllMocks();
	mockHostsResolve();
});

describe("parseBimiSelectorHeader", () => {
	it("reads the s= selector from a BIMI-Selector header", () => {
		expect(
			parseBimiSelectorHeader(
				"From: a@b.com\nBIMI-Selector: v=BIMI1; s=Marketing\nTo: c@d.com",
			),
		).toBe("marketing");
	});

	it("unfolds folded headers and handles missing header/s=", () => {
		expect(parseBimiSelectorHeader("BIMI-Selector: v=BIMI1;\r\n s=news")).toBe(
			"news",
		);
		expect(parseBimiSelectorHeader("Subject: hi")).toBeNull();
		expect(parseBimiSelectorHeader("BIMI-Selector: v=BIMI1")).toBeNull();
		expect(parseBimiSelectorHeader(undefined)).toBeNull();
	});
});

describe("bimiCheck", () => {
	it("no _bimi record → bimi_present warning, never critical (§8.1), with a results row", async () => {
		mockTxt({});
		const { findings, results } = await run({
			upstream: dmarcUpstream("reject"),
		});
		expect(byId(findings, "content.bimi_present")?.severity).toBe("warning");
		expect(findings.every((f) => f.severity !== "critical")).toBe(true);
		const r = results as BimiResults;
		expect(r.selector).toBe("default");
		expect(r.present).toBe(false);
		expect(r.rawRecord).toBeNull();
		expect(r.dmarcEnforcing).toBe(true);
		expect(r.svgValid).toBeNull();
		expect(r.vmcValid).toBeNull();
		expect(r.vmcNotAfter).toBeNull();
		expect(r.vmcIssuer).toBeNull();
		expect(r.checkedAt).toBeTruthy();
	});

	it("valid record + sibling DMARC p=none → bimi_dmarc_prereq critical (§8.2), no _dmarc re-query", async () => {
		mockTxt({ "default._bimi.example.com": [GOOD] });
		const { findings } = await run({ upstream: dmarcUpstream("none") });
		const prereq = byId(findings, "content.bimi_dmarc_prereq");
		expect(prereq?.severity).toBe("critical");
		expect(prereq?.remediation).toContain("p=quarantine");
		// The sibling result was used — _dmarc was NOT re-queried (pm/checks/bimi.mdx §3).
		const queried = dns.resolveTxt.mock.calls.map((c: string[]) => c[0]);
		expect(queried).not.toContain("_dmarc.example.com");
	});

	it("valid record + sibling DMARC p=quarantine → bimi_dmarc_prereq ok (§8.3) and dmarcEnforcing persisted (§8.9)", async () => {
		mockTxt({ "default._bimi.example.com": [GOOD] });
		const { findings, results } = await run({
			upstream: dmarcUpstream("quarantine"),
		});
		expect(byId(findings, "content.bimi_dmarc_prereq")?.severity).toBe("ok");
		const r = results as BimiResults;
		expect(r.present).toBe(true);
		expect(r.rawRecord).toBe(GOOD);
		expect(r.svgUrl).toBe("https://example.com/bimi/logo.svg");
		expect(r.vmcUrl).toBe("https://example.com/bimi/vmc.pem");
		expect(r.dmarcEnforcing).toBe(true);
	});

	it("falls back to a direct _dmarc lookup when no sibling dmarc result is published", async () => {
		mockTxt({
			"default._bimi.example.com": [GOOD],
			"_dmarc.example.com": ["v=DMARC1; p=reject"],
		});
		const { findings } = await run({});
		expect(byId(findings, "content.bimi_dmarc_prereq")?.severity).toBe("ok");
	});

	it("http:// l= is critical; missing a= is a warning (§8.4/§8.5)", async () => {
		mockTxt({
			"default._bimi.example.com": ["v=BIMI1; l=http://example.com/logo.svg"],
		});
		const { findings } = await run({ upstream: dmarcUpstream("reject") });
		expect(byId(findings, "content.bimi_svg_url")?.severity).toBe("critical");
		expect(byId(findings, "content.bimi_vmc")?.severity).toBe("warning");
		expect(byId(findings, "content.bimi_vmc")?.remediation).toContain(
			"Mark Verifying Authority",
		);
	});

	it("unresolvable a= host is critical (§8.4)", async () => {
		mockTxt({ "default._bimi.example.com": [GOOD] });
		dns.resolve4.mockResolvedValue(found([]));
		dns.resolve6.mockResolvedValue(found([]));
		const { findings } = await run({ upstream: dmarcUpstream("reject") });
		expect(byId(findings, "content.bimi_vmc_url")?.severity).toBe("critical");
	});

	it("two v=BIMI1 records → bimi_single warning (§8.6)", async () => {
		mockTxt({
			"default._bimi.example.com": [
				GOOD,
				"v=BIMI1; l=https://example.com/other.svg",
			],
		});
		const { findings } = await run({ upstream: dmarcUpstream("reject") });
		expect(byId(findings, "content.bimi_single")?.severity).toBe("warning");
	});

	it("malformed record (v not first / stray tokens) → bimi_syntax critical", async () => {
		mockTxt({
			"default._bimi.example.com": [
				"l=https://example.com/logo.svg; v=BIMI1; junk",
			],
		});
		const { findings } = await run({ upstream: dmarcUpstream("reject") });
		expect(byId(findings, "content.bimi_syntax")?.severity).toBe("critical");
	});

	it("declined record (empty l=/a=) is info, not a failure (§3)", async () => {
		mockTxt({ "default._bimi.example.com": ["v=BIMI1; l=; a=;"] });
		const { findings } = await run({ upstream: dmarcUpstream("none") });
		expect(byId(findings, "content.bimi_l_present")?.severity).toBe("info");
		expect(
			findings.every(
				(f) => f.severity !== "warning" && f.severity !== "critical",
			),
		).toBe(true);
	});

	it("BIMI-Selector header naming a selector with no record → bimi_selector warning; with a record → ok (§8.7)", async () => {
		mockTxt({ "default._bimi.example.com": [GOOD] });
		const missing = await run({
			upstream: dmarcUpstream("reject"),
			bimi: {
				selectors: [],
				sampleMessage: "BIMI-Selector: v=BIMI1; s=marketing",
			},
		});
		const miss = byId(missing.findings, "content.bimi_selector.marketing");
		expect(miss?.severity).toBe("warning");
		expect(miss?.remediation).toContain("marketing._bimi.example.com");

		mockTxt({
			"default._bimi.example.com": [GOOD],
			"marketing._bimi.example.com": ["v=BIMI1; l=https://example.com/mk.svg"],
		});
		const present = await run({
			upstream: dmarcUpstream("reject"),
			bimi: {
				selectors: [],
				sampleMessage: "BIMI-Selector: v=BIMI1; s=marketing",
			},
		});
		expect(
			byId(present.findings, "content.bimi_selector.marketing")?.severity,
		).toBe("ok");
		const r = present.results as BimiResults;
		const row = r.selectors.find((s) => s.selector === "marketing");
		expect(row?.present).toBe(true);
		expect(row?.svgUrl).toBe("https://example.com/mk.svg");
	});

	it("configured extra selectors are audited even when the default record is absent", async () => {
		mockTxt({
			"v1._bimi.example.com": ["v=BIMI1; l=https://example.com/v1.svg"],
		});
		const { findings, results } = await run({
			upstream: dmarcUpstream("reject"),
			bimi: { selectors: ["v1", "v2"] },
		});
		expect(byId(findings, "content.bimi_selector.v1")?.severity).toBe("ok");
		expect(byId(findings, "content.bimi_selector.v2")?.severity).toBe(
			"warning",
		);
		expect((results as BimiResults).selectors.map((s) => s.selector)).toEqual([
			"default",
			"v1",
			"v2",
		]);
	});

	it("every non-ok finding carries a concrete remediation (§8.8) and the future round is info-only (§8.10)", async () => {
		mockTxt({
			"default._bimi.example.com": ["v=BIMI1; l=http://example.com/logo.svg"],
		});
		const { findings } = await run({ upstream: dmarcUpstream("none") });
		for (const f of findings) {
			if (f.severity === "warning" || f.severity === "critical") {
				expect(f.remediation).toBeTruthy();
			}
		}
		expect(byId(findings, "content.bimi_future_validation")?.severity).toBe(
			"info",
		);
	});

	it("transient _bimi lookup failure degrades to info with no structured results", async () => {
		dns.resolveTxt.mockResolvedValue({
			records: [],
			empty: false,
			error: "ETIMEOUT",
		});
		const { findings, results } = await run({
			upstream: dmarcUpstream("reject"),
		});
		expect(byId(findings, "content.bimi_present")?.severity).toBe("info");
		expect(results).toBeUndefined();
	});

	it("flags a dangling CNAME on the _bimi name (bimi_dns_health)", async () => {
		mockTxt({ "default._bimi.example.com": [GOOD] });
		dns.resolveCname.mockImplementation(async (name: string) =>
			name === "default._bimi.example.com"
				? found(["dead.host.example.net"])
				: found([]),
		);
		dns.resolve4.mockImplementation(async (host: string) =>
			host === "dead.host.example.net" ? found([]) : found(["203.0.113.10"]),
		);
		dns.resolve6.mockResolvedValue(found([]));
		const { findings } = await run({ upstream: dmarcUpstream("reject") });
		expect(byId(findings, "content.bimi_dns_health")?.severity).toBe("warning");
	});

	it("flags a dangling CNAME even when the dead target makes the TXT lookup come back empty (§2/§3)", async () => {
		// The classic silent-disappearance case: `_bimi` is a CNAME to an unclaimed host, so the TXT
		// lookup finds nothing — bimi_present warns AND bimi_dns_health names the dangling CNAME.
		mockTxt({});
		dns.resolveCname.mockImplementation(async (name: string) =>
			name === "default._bimi.example.com"
				? found(["unclaimed.example.net"])
				: found([]),
		);
		dns.resolve4.mockResolvedValue(found([]));
		dns.resolve6.mockResolvedValue(found([]));
		const { findings } = await run({ upstream: dmarcUpstream("reject") });
		expect(byId(findings, "content.bimi_present")?.severity).toBe("warning");
		const health = byId(findings, "content.bimi_dns_health");
		expect(health?.severity).toBe("warning");
		expect(health?.remediation).toContain("unclaimed.example.net");
	});

	it("a CNAME target that serves TXT (no A/AAAA) is alive, not dangling", async () => {
		// A BIMI CNAME target hosts the TXT record — it need not have any A/AAAA of its own.
		mockTxt({
			"default._bimi.example.com": [GOOD],
			"bimi.provider.example.net": [GOOD],
		});
		dns.resolveCname.mockImplementation(async (name: string) =>
			name === "default._bimi.example.com"
				? found(["bimi.provider.example.net"])
				: found([]),
		);
		dns.resolve4.mockImplementation(async (host: string) =>
			host === "example.com" ? found(["203.0.113.10"]) : found([]),
		);
		dns.resolve6.mockResolvedValue(found([]));
		const { findings } = await run({ upstream: dmarcUpstream("reject") });
		expect(byId(findings, "content.bimi_dns_health")?.severity).toBe("ok");
	});
});
