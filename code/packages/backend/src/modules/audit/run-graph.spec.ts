import type { Checker } from "./checks/types";
import { CHECK_DEPENDENCIES, runCheckerGraph } from "./run-graph";

/**
 * pm/run_checks.mdx §2/§11.2 — the dependency-ordered promise-graph: all Stage-1 checks start
 * together; each Stage-2 check starts as soon as its named prerequisites finish (no barrier);
 * dmarc never before spf+dkim, bimi never before dmarc, dane_tlsa never before mx_routing+dnssec.
 */

const flush = () => new Promise(setImmediate);

function deferred(): { promise: Promise<void>; resolve: () => void } {
	let resolve!: () => void;
	const promise = new Promise<void>((r) => {
		resolve = r;
	});
	return { promise, resolve };
}

describe("runCheckerGraph", () => {
	const IDS = [
		"spf",
		"dkim",
		"dmarc",
		"content.bimi",
		"infra.mx_routing",
		"infra.dnssec",
		"infra.dane_tlsa",
		"infra.mta_sts",
	];

	function harness() {
		const checkers: Checker[] = IDS.map((id) => ({
			id,
			label: id,
			run: async () => [],
		}));
		const gates = Object.fromEntries(IDS.map((id) => [id, deferred()]));
		const started: string[] = [];
		const finished: string[] = [];
		const runOne = async (checker: Checker): Promise<void> => {
			started.push(checker.id);
			await gates[checker.id].promise;
			finished.push(checker.id);
		};
		return { checkers, gates, started, finished, runOne };
	}

	it("starts every foundation check together and gates dependents on their own prerequisites", async () => {
		const { checkers, gates, started, runOne } = harness();
		const graph = runCheckerGraph(checkers, runOne);
		await flush();

		// Stage 1: every check with no upstream dependency launched simultaneously.
		expect(started).toEqual(
			expect.arrayContaining([
				"spf",
				"dkim",
				"infra.mx_routing",
				"infra.dnssec",
			]),
		);
		// Stage 2: nothing dependency-gated has started yet.
		for (const id of [
			"dmarc",
			"content.bimi",
			"infra.dane_tlsa",
			"infra.mta_sts",
		]) {
			expect(started).not.toContain(id);
		}

		// mx_routing finishes → mta_sts starts WHILE spf/dkim are still in flight (no barrier)…
		gates["infra.mx_routing"].resolve();
		await flush();
		expect(started).toContain("infra.mta_sts");
		// …but dane_tlsa still waits on its second prerequisite, dnssec.
		expect(started).not.toContain("infra.dane_tlsa");

		gates["infra.dnssec"].resolve();
		await flush();
		expect(started).toContain("infra.dane_tlsa");

		// dmarc needs BOTH spf and dkim — one alone is not enough.
		gates.spf.resolve();
		await flush();
		expect(started).not.toContain("dmarc");
		gates.dkim.resolve();
		await flush();
		expect(started).toContain("dmarc");

		// bimi never starts before dmarc finishes.
		expect(started).not.toContain("content.bimi");
		gates.dmarc.resolve();
		await flush();
		expect(started).toContain("content.bimi");

		for (const id of IDS) gates[id].resolve();
		await graph;
	});

	it("runs a check whose prerequisite rejected — a failed dep never drops its subtree", async () => {
		const a: Checker = { id: "spf", label: "spf", run: async () => [] };
		const b: Checker = { id: "dkim", label: "dkim", run: async () => [] };
		const c: Checker = { id: "dmarc", label: "dmarc", run: async () => [] };
		const ran: string[] = [];
		await runCheckerGraph([a, b, c], async (checker) => {
			if (checker.id === "spf") throw new Error("boom");
			ran.push(checker.id);
		});
		expect(ran).toContain("dmarc");
		expect(ran).toContain("dkim");
	});

	it("declares the spec §2 dependency edges", () => {
		expect(CHECK_DEPENDENCIES.dmarc).toEqual(["spf", "dkim"]);
		expect(CHECK_DEPENDENCIES.arc).toEqual(["dmarc"]);
		expect(CHECK_DEPENDENCIES["content.bimi"]).toEqual(["dmarc"]);
		expect(CHECK_DEPENDENCIES["infra.mta_sts"]).toEqual(["infra.mx_routing"]);
		expect(CHECK_DEPENDENCIES["infra.dane_tlsa"]).toEqual([
			"infra.mx_routing",
			"infra.dnssec",
		]);
	});
});
