import type { Dkim2Results } from "./dkim2.check";

jest.mock("../dns-util", () => ({ resolveTxt: jest.fn() }));

import { resolveTxt } from "../dns-util";
import type { CheckContext, CheckOutcome, Finding } from "../types";
import { dkim2Check } from "./dkim2.check";

const mockResolveTxt = resolveTxt as jest.MockedFunction<typeof resolveTxt>;

/** A base64 p= long enough to estimate as a ~2048-bit RSA modulus (readiness ok). */
const GOOD_RSA_P = "A".repeat(400);
/** A short base64 p= that estimates well under 1024 bits (weak → readiness warning). */
const WEAK_RSA_P = "A".repeat(120);
/** A raw-32-byte ed25519 public key, base64. */
const ED25519_P = Buffer.alloc(32, 7).toString("base64");

function ctx(overrides: Partial<CheckContext> = {}): CheckContext {
	return {
		domain: "example.com",
		dkimSelectors: [],
		sendingIps: [],
		...overrides,
	};
}

/** Route mocked TXT answers by query name (unmocked names → empty, like an NXDOMAIN). */
function dnsAnswers(
	map: Record<string, { records?: string[]; empty?: boolean; error?: string }>,
) {
	mockResolveTxt.mockImplementation(async (name: string) => {
		const a = map[name];
		if (!a) return { records: [], empty: true };
		return { records: a.records ?? [], empty: a.empty ?? false, error: a.error };
	});
}

async function run(
	c: CheckContext,
): Promise<{ findings: Finding[]; results: Dkim2Results }> {
	const outcome = (await dkim2Check.run(c)) as CheckOutcome;
	return {
		findings: outcome.findings,
		results: outcome.results as Dkim2Results,
	};
}

const byId = (findings: Finding[], id: string) =>
	findings.find((f) => f.id === id);

/** The DKIM cell goes red only on a critical dkim2.* finding (advisory info/warning never do). */
const hasCritical = (findings: Finding[]) =>
	findings.some((f) => f.severity === "critical");

beforeEach(() => mockResolveTxt.mockReset());

describe("dkim2Check (pm/checks/dkim2.mdx)", () => {
	it("registers under id 'dkim2' so findings roll into the DKIM cell via the dkim2. prefix", () => {
		expect(dkim2Check.id).toBe("dkim2");
		expect(dkim2Check.label).toContain("DKIM2");
	});

	it("not-applicable path (p=none, no forwarding): single info dkim2.applicability, cell not critical", async () => {
		const c: CheckContext = {
			...ctx(),
			upstream: { dmarc: { record: { policy: "none", is_enforcing: false } } },
		};
		dnsAnswers({});
		const { findings, results } = await run(c);

		const applicability = byId(findings, "dkim2.applicability");
		expect(applicability?.severity).toBe("info");
		expect(applicability?.title).toContain("not applicable");
		expect(results.applicable).toBe(false);
		expect(results.draftVersion).toBe("draft-04");
		// Advisory-only: nothing turns the DKIM cell red.
		expect(hasCritical(findings)).toBe(false);
		// No chain stub in the quiet not-applicable case; sample-derived fields stay null.
		expect(byId(findings, "dkim2.chain_present")).toBeUndefined();
		expect(results.chainPresent).toBeNull();
		expect(results.chainValid).toBeNull();
		// Every non-ok finding still carries a concrete remediation.
		for (const f of findings)
			if (f.severity !== "ok") expect(f.remediation).toBeTruthy();
	});

	it("applicable (enforcing DMARC) + resolving ed25519 selector: readiness ok, selector_dns ok, chain stub present", async () => {
		dnsAnswers({
			"d2._domainkey.example.com": {
				records: [`v=DKIM1; k=ed25519; p=${ED25519_P}`],
			},
		});
		const c: CheckContext = {
			...ctx({ dkimSelectors: ["d2"] }),
			upstream: { dmarc: { record: { policy: "reject", is_enforcing: true } } },
		};
		const { findings, results } = await run(c);

		expect(results.applicable).toBe(true);
		expect(results.policySource).toBe("sibling");
		expect(results.dmarcPolicy).toBe("reject");
		expect(byId(findings, "dkim2.selector_dns.d2")?.severity).toBe("ok");
		expect(byId(findings, "dkim2.key_readiness.d2")?.severity).toBe("ok");
		// FUTURE sample sub-checks stubbed as a single info — never a fabricated verdict.
		expect(byId(findings, "dkim2.chain_present")?.severity).toBe("info");
		expect(hasCritical(findings)).toBe(false);
		// Signer readiness fields populated from the resolving ed25519 selector.
		expect(results.signerDomain).toBe("example.com");
		expect(results.signerSelector).toBe("d2");
		expect(results.selectorResolves).toBe(true);
		expect(results.keyType).toBe("ed25519");
		expect(results.keyBits).toBeNull();
		expect(results.selectors).toEqual([
			{
				selector: "d2",
				resolves: true,
				rawKeyRecord: `v=DKIM1; k=ed25519; p=${ED25519_P}`,
				keyType: "ed25519",
				keyBits: null,
			},
		]);
		// ed25519 present → no "add an ed25519 selector" RSA-only nudge.
		expect(byId(findings, "dkim2.key_readiness")).toBeUndefined();
	});

	it("weak RSA readiness key → dkim2.key_readiness warning (never critical)", async () => {
		dnsAnswers({
			"d2._domainkey.example.com": {
				records: [`v=DKIM1; k=rsa; p=${WEAK_RSA_P}`],
			},
		});
		const c: CheckContext = {
			...ctx({ dkimSelectors: ["d2"], arc: { usesForwarding: true, forwarders: [] } }),
		};
		const { findings, results } = await run(c);

		expect(results.applicable).toBe(true); // forwarding declared
		expect(byId(findings, "dkim2.key_readiness.d2")?.severity).toBe("warning");
		expect(byId(findings, "dkim2.key_readiness.d2")?.remediation).toBeTruthy();
		expect(hasCritical(findings)).toBe(false);
		// RSA-only across resolving selectors → the ed25519 nudge fires.
		expect(byId(findings, "dkim2.key_readiness")?.severity).toBe("info");
		expect(results.keyType).toBe("rsa");
		expect(typeof results.keyBits).toBe("number");
	});

	it("healthy RSA-2048 readiness key → dkim2.key_readiness ok + ed25519 nudge, cell not critical", async () => {
		dnsAnswers({
			"d2._domainkey.example.com": {
				records: [`v=DKIM1; k=rsa; p=${GOOD_RSA_P}`],
			},
		});
		const c: CheckContext = {
			...ctx({ dkimSelectors: ["d2"] }),
			upstream: { dmarc: { record: { policy: "quarantine", is_enforcing: true } } },
		};
		const { findings } = await run(c);
		expect(byId(findings, "dkim2.selector_dns.d2")?.severity).toBe("ok");
		expect(byId(findings, "dkim2.key_readiness.d2")?.severity).toBe("ok");
		expect(byId(findings, "dkim2.key_readiness")?.severity).toBe("info");
		expect(hasCritical(findings)).toBe(false);
	});

	it("no selector resolves → single advisory info dkim2.selector_dns (NOT critical)", async () => {
		dnsAnswers({}); // every lookup empty
		const c: CheckContext = {
			...ctx({ dkimSelectors: ["d2"] }),
			upstream: { dmarc: { record: { policy: "reject", is_enforcing: true } } },
		};
		const { findings, results } = await run(c);

		const selectorDns = byId(findings, "dkim2.selector_dns");
		expect(selectorDns?.severity).toBe("info");
		expect(selectorDns?.remediation).toBeTruthy();
		expect(hasCritical(findings)).toBe(false);
		expect(results.selectorResolves).toBe(false);
		// No per-selector ok row, since it never resolved.
		expect(byId(findings, "dkim2.selector_dns.d2")).toBeUndefined();
	});

	it("falls back to the 'default' selector when none are configured", async () => {
		dnsAnswers({});
		const c: CheckContext = {
			...ctx(),
			upstream: { dmarc: { record: { policy: "reject", is_enforcing: true } } },
		};
		const { results } = await run(c);
		expect(results.selectors.map((s) => s.selector)).toEqual(["default"]);
		expect(mockResolveTxt).toHaveBeenCalledWith("default._domainkey.example.com");
	});

	it("degrades to info (never critical) when a selector lookup fails transiently", async () => {
		dnsAnswers({ "d2._domainkey.example.com": { error: "ETIMEOUT" } });
		const c: CheckContext = {
			...ctx({ dkimSelectors: ["d2"] }),
			upstream: { dmarc: { record: { policy: "reject", is_enforcing: true } } },
		};
		const { findings, results } = await run(c);
		expect(byId(findings, "dkim2.selector_dns.d2")?.severity).toBe("info");
		expect(hasCritical(findings)).toBe(false);
		// A transient error leaves resolves unknown (null) rather than fabricating false.
		expect(results.selectors[0].resolves).toBeNull();
	});

	it("every non-ok finding carries a concrete remediation (acceptance §8.1)", async () => {
		dnsAnswers({
			"d2._domainkey.example.com": {
				records: [`v=DKIM1; k=rsa; p=${WEAK_RSA_P}`],
			},
		});
		const c: CheckContext = {
			...ctx({ dkimSelectors: ["d2"], arc: { usesForwarding: true, forwarders: [] } }),
		};
		const { findings } = await run(c);
		for (const f of findings)
			if (f.severity !== "ok") expect(f.remediation).toBeTruthy();
	});
});
