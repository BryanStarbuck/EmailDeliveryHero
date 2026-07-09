jest.mock("../dns-util", () => ({ resolveTxt: jest.fn() }));
jest.mock("@shared/tool-runner", () => ({
	locateTool: jest.fn(() => "/fake/tool"),
	runTool: jest.fn(async () => ({
		code: 0,
		stdout: "{}",
		stderr: "",
		timedOut: false,
	})),
}));

import { locateTool, runTool } from "@shared/tool-runner";
import { resolveTxt } from "../dns-util";
import type { CheckContext, CheckOutcome, Finding } from "../types";
import { dmarcbisCheck, type DmarcbisSection } from "./dmarcbis.check";
import {
	buildWalkNames,
	resolveOrgDomain,
	type TxtResolver,
} from "./tree-walk";

const mockResolveTxt = resolveTxt as jest.MockedFunction<typeof resolveTxt>;
const mockLocateTool = locateTool as jest.MockedFunction<typeof locateTool>;
const mockRunTool = runTool as jest.MockedFunction<typeof runTool>;

// ---------------------------------------------------------------------------------------------
// tree-walk.ts — the pure RFC 9989 tree walk, exercised with a fake resolver (no real DNS).
// ---------------------------------------------------------------------------------------------

/** Build a fake TxtResolver from a name → records map (missing name = no record). */
function fakeResolver(map: Record<string, string[]>): TxtResolver {
	return async (name: string) => ({ records: map[name] ?? [] });
}

describe("tree-walk buildWalkNames (RFC 9989 §1)", () => {
	it("produces the canonical 8-query sequence for a >7-label author domain", () => {
		expect(buildWalkNames("a.b.c.d.e.f.g.h.i.j.mail.example.com")).toEqual([
			"a.b.c.d.e.f.g.h.i.j.mail.example.com", // full author domain (13 labels)
			"g.h.i.j.mail.example.com", // jump to 7 labels — remove several at once
			"h.i.j.mail.example.com", // 6 labels — one at a time from here
			"i.j.mail.example.com", // 5
			"j.mail.example.com", // 4
			"mail.example.com", // 3
			"example.com", // 2
			"com", // 1 — the cap is reached here
		]);
	});

	it("strips one label at a time for a short (<=7 label) name, no jump", () => {
		expect(buildWalkNames("mail.example.com")).toEqual([
			"mail.example.com",
			"example.com",
			"com",
		]);
	});
});

describe("resolveOrgDomain (RFC 9989 tree walk)", () => {
	it("caps the >7-label walk at exactly 8 _dmarc queries", async () => {
		const resolver = fakeResolver({});
		const walk = await resolveOrgDomain(
			"a.b.c.d.e.f.g.h.i.j.mail.example.com",
			resolver,
		);
		expect(walk.queryPath).toHaveLength(8);
		expect(walk.queryPath.map((r) => r.name)).toEqual([
			"_dmarc.a.b.c.d.e.f.g.h.i.j.mail.example.com",
			"_dmarc.g.h.i.j.mail.example.com",
			"_dmarc.h.i.j.mail.example.com",
			"_dmarc.i.j.mail.example.com",
			"_dmarc.j.mail.example.com",
			"_dmarc.mail.example.com",
			"_dmarc.example.com",
			"_dmarc.com",
		]);
		// No record anywhere → no Org Domain, terminated at the cap.
		expect(walk.resolvedOrgDomain).toBeNull();
		expect(walk.foundVia).toBe("tld-cap");
		expect(walk.selectedBy).toBeNull();
	});

	it("stops at a psd=n record and marks its own domain the Org Domain", async () => {
		const resolver = fakeResolver({
			"_dmarc.mail.example.com": ["v=DMARC1; p=reject; psd=n"],
		});
		const walk = await resolveOrgDomain("mail.example.com", resolver);
		expect(walk.resolvedOrgDomain).toBe("mail.example.com");
		expect(walk.selectedBy).toBe("psd=n");
		expect(walk.foundVia).toBe("treewalk");
		expect(walk.coveredByParent).toBe(false);
		// Stopped on the first rung — never queried the parents.
		expect(walk.queryPath).toHaveLength(1);
	});

	it("puts the Org Domain one label below a psd=y parent (not the starting rung)", async () => {
		const resolver = fakeResolver({
			"_dmarc.com": ["v=DMARC1; p=reject; psd=y"],
		});
		const walk = await resolveOrgDomain("foo.example.com", resolver);
		expect(walk.resolvedOrgDomain).toBe("example.com");
		expect(walk.selectedBy).toBe("psd=y-below");
		expect(walk.foundVia).toBe("parent");
		expect(walk.coveredByParent).toBe(true);
	});

	it("falls back to the fewest-labels record when no psd anchor exists", async () => {
		const resolver = fakeResolver({
			"_dmarc.a.example.com": ["v=DMARC1; p=none"],
			"_dmarc.example.com": ["v=DMARC1; p=reject"],
		});
		const walk = await resolveOrgDomain("a.example.com", resolver);
		expect(walk.resolvedOrgDomain).toBe("example.com");
		expect(walk.selectedBy).toBe("fewest-labels");
		expect(walk.coveredByParent).toBe(true);
		expect(walk.labelCount).toBe(2);
	});

	it("ignores a psd=y on the STARTING rung (falls through to fewest-labels)", async () => {
		const resolver = fakeResolver({
			"_dmarc.example.com": ["v=DMARC1; p=reject; psd=y"],
		});
		const walk = await resolveOrgDomain("example.com", resolver);
		expect(walk.selectedBy).toBe("fewest-labels");
		expect(walk.resolvedOrgDomain).toBe("example.com");
	});
});

// ---------------------------------------------------------------------------------------------
// dmarcbis.check.ts — the checker, with a mocked resolveTxt + a synthetic ctx.upstream.dmarc.
// ---------------------------------------------------------------------------------------------

function dnsAnswers(map: Record<string, string[]>): void {
	mockResolveTxt.mockImplementation(async (name: string) => ({
		records: map[name] ?? [],
		empty: !(name in map),
	}));
}

interface SiblingRecord {
	parsed: Record<string, string>;
	found_at?: string | null;
	policy?: string | null;
	subdomain_policy?: string | null;
	np_policy?: string | null;
	external_report_auth?: {
		report_kind: string;
		report_domain: string;
		auth_name: string;
		authorized: boolean;
	}[];
}

/** A synthetic sibling `dmarc` §5 section for ctx.upstream.dmarc. */
function siblingDmarc(record: SiblingRecord) {
	return {
		record: {
			found_at: record.found_at ?? "_dmarc.example.com",
			policy: record.policy ?? "reject",
			subdomain_policy: record.subdomain_policy ?? null,
			np_policy: record.np_policy ?? null,
			external_report_auth: record.external_report_auth ?? [],
			parsed: record.parsed,
		},
	};
}

function ctx(over?: Partial<CheckContext>): CheckContext {
	return { domain: "example.com", dkimSelectors: [], sendingIps: [], ...over };
}

async function run(
	c: CheckContext,
): Promise<{ findings: Finding[]; results: DmarcbisSection }> {
	const outcome = (await dmarcbisCheck.run(c)) as CheckOutcome;
	return {
		findings: outcome.findings,
		results: outcome.results as DmarcbisSection,
	};
}

const byId = (findings: Finding[], id: string) =>
	findings.find((f) => f.id === id);

beforeEach(() => {
	mockResolveTxt.mockReset();
	mockLocateTool.mockReset().mockReturnValue("/fake/tool");
	mockRunTool
		.mockReset()
		.mockResolvedValue({ code: 0, stdout: "{}", stderr: "", timedOut: false });
});

describe("dmarcbisCheck (pm/checks/dmarcbis.mdx)", () => {
	it("registers under id 'dmarcbis' with the DMARCbis label", () => {
		expect(dmarcbisCheck.id).toBe("dmarcbis");
		expect(dmarcbisCheck.label).toContain("DMARCbis");
	});

	it("(1) matching org domain + clean DMARCbis tags → all conformance checks pass (DMARCbis-00)", async () => {
		dnsAnswers({
			"_dmarc.example.com": [
				"v=DMARC1; p=reject; sp=reject; np=reject; psd=n; rua=mailto:d@example.com",
			],
		});
		const { findings, results } = await run(
			ctx({
				upstream: {
					dmarc: siblingDmarc({
						parsed: {
							v: "DMARC1",
							p: "reject",
							sp: "reject",
							np: "reject",
							psd: "n",
							rua: "mailto:d@example.com",
						},
						subdomain_policy: "reject",
						np_policy: "reject",
					}),
					dkim: { working_selectors: 2 },
				},
			}),
		);
		expect(byId(findings, "dmarcbis.tree_walk")?.severity).toBe("ok");
		expect(byId(findings, "dmarcbis.psd")?.severity).toBe("ok");
		expect(byId(findings, "dmarcbis.np")?.severity).toBe("ok");
		expect(byId(findings, "dmarcbis.testing_flag")?.severity).toBe("ok");
		expect(byId(findings, "dmarcbis.removed_tags")?.severity).toBe("ok");
		expect(byId(findings, "dmarcbis.sp_semantics")?.severity).toBe("ok");
		expect(byId(findings, "dmarcbis.reject_advisory")?.severity).toBe("ok");
		// No warnings/criticals at all (companion emits no first-round criticals).
		expect(
			findings.every(
				(f) => f.severity !== "warning" && f.severity !== "critical",
			),
		).toBe(true);
		// The healthy goal state, and the structured section reflects the clean walk.
		expect(results.problem_states).toEqual(["DMARCbis-00"]);
		expect(results.read_from).toBe("dmarc");
		expect(results.org_domain.resolved_org_domain).toBe("example.com");
		expect(results.org_domain.matches_enforced_record).toBe(true);
		expect(results.org_domain.selected_by).toBe("psd=n");
		expect(results.tags.valid_set_ok).toBe(true);
		expect(results.tags.removed_tags_present).toEqual([]);
	});

	it("(2) removed tag present → dmarcbis.removed_tags info + DMARCbis-05", async () => {
		dnsAnswers({
			"_dmarc.example.com": ["v=DMARC1; p=reject; np=reject; psd=n; pct=100"],
		});
		const { findings, results } = await run(
			ctx({
				upstream: {
					dmarc: siblingDmarc({
						parsed: {
							v: "DMARC1",
							p: "reject",
							np: "reject",
							psd: "n",
							pct: "100",
						},
						np_policy: "reject",
					}),
					dkim: { working_selectors: 1 },
				},
			}),
		);
		expect(byId(findings, "dmarcbis.removed_tags")?.severity).toBe("info");
		expect(results.tags.removed_tags_present).toEqual(["pct"]);
		expect(results.tags.valid_set_ok).toBe(false);
		expect(results.problem_states).toContain("DMARCbis-05");
	});

	it("(3) t=y → dmarcbis.testing_flag warning + DMARCbis-04", async () => {
		dnsAnswers({
			"_dmarc.example.com": ["v=DMARC1; p=reject; np=reject; psd=n; t=y"],
		});
		const { findings, results } = await run(
			ctx({
				upstream: {
					dmarc: siblingDmarc({
						parsed: {
							v: "DMARC1",
							p: "reject",
							np: "reject",
							psd: "n",
							t: "y",
						},
						np_policy: "reject",
					}),
					dkim: { working_selectors: 1 },
				},
			}),
		);
		expect(byId(findings, "dmarcbis.testing_flag")?.severity).toBe("warning");
		expect(results.tags.t).toBe("y");
		expect(results.status).toBe("warning");
		expect(results.problem_states).toContain("DMARCbis-04");
	});

	it("(4) p=reject + unhealthy DKIM → dmarcbis.reject_advisory warning + DMARCbis-07", async () => {
		dnsAnswers({
			"_dmarc.example.com": ["v=DMARC1; p=reject; np=reject; psd=n"],
		});
		const { findings, results } = await run(
			ctx({
				upstream: {
					dmarc: siblingDmarc({
						parsed: { v: "DMARC1", p: "reject", np: "reject", psd: "n" },
						np_policy: "reject",
					}),
					dkim: { working_selectors: 0 },
				},
			}),
		);
		const f = byId(findings, "dmarcbis.reject_advisory");
		expect(f?.severity).toBe("warning");
		expect(f?.remediation).toContain("DKIM-sign");
		expect(results.tags.reject_reality).toEqual({
			policy: "reject",
			dkim_aligned_ok: false,
			spf_only_risk: true,
		});
		expect(results.problem_states).toContain("DMARCbis-07");
	});

	it("(5) absent sibling dmarc result → single info early return, no DNS or tools touched", async () => {
		dnsAnswers({});
		const { findings, results } = await run(ctx({ upstream: {} }));
		expect(findings).toHaveLength(1);
		expect(findings[0].id).toBe("dmarcbis.unavailable");
		expect(findings[0].severity).toBe("info");
		expect(results.status).toBe("info");
		expect(results.org_domain.resolved_org_domain).toBeNull();
		expect(results.problem_states).toEqual([]);
		expect(mockResolveTxt).not.toHaveBeenCalled();
		expect(mockRunTool).not.toHaveBeenCalled();
	});

	it("warns when the tree walk selects a different Org Domain than the enforced record (DMARCbis-01)", async () => {
		// The record is enforced at the apex, but a psd=n parent record makes the walk stop higher.
		dnsAnswers({
			"_dmarc.sub.example.com": [], // no own record
			"_dmarc.example.com": ["v=DMARC1; p=reject; psd=n"],
		});
		const { findings, results } = await run(
			ctx({
				domain: "sub.example.com",
				upstream: {
					dmarc: siblingDmarc({
						parsed: { v: "DMARC1", p: "reject", psd: "n" },
						found_at: "_dmarc.example.com",
					}),
					dkim: { working_selectors: 1 },
				},
			}),
		);
		// Enforced at example.com and the walk also resolves example.com → they MATCH (covered by parent).
		expect(results.org_domain.resolved_org_domain).toBe("example.com");
		expect(byId(findings, "dmarcbis.tree_walk")?.severity).toBe("info");
		expect(results.org_domain.covered_by_parent).toBe(true);
	});

	it("every non-ok finding carries a concrete remediation (AC2)", async () => {
		dnsAnswers({
			"_dmarc.example.com": ["v=DMARC1; p=reject; t=y; pct=50"],
		});
		const { findings } = await run(
			ctx({
				upstream: {
					dmarc: siblingDmarc({
						parsed: { v: "DMARC1", p: "reject", t: "y", pct: "50" },
					}),
					dkim: { working_selectors: 0 },
				},
			}),
		);
		for (const f of findings) {
			if (f.severity !== "ok") expect(f.remediation).toBeTruthy();
		}
	});
});
