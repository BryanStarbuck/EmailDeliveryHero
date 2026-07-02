import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DomainsService } from "@module/domains/domains.service";
import { AuditService } from "./audit.service";
import { CHECKERS } from "./checks";
import type { Checker } from "./checks/types";

/**
 * pm/run_checks.mdx §1/§9/§10 — the trigger funnel and its guards: the trigger tag is recorded as
 * data on the audit record; concurrent runs of the same domain collapse into one; runForAll uses
 * settled semantics (a failed domain fails alone, never the batch) and honors the per-domain
 * scheduleEnabled flag only for scheduled triggers.
 */

// Replace the 21 real checkers (live DNS) with test doubles the specs below control.
jest.mock("./checks", () => ({ CHECKERS: [] as unknown[] }));

// Keep every persisted artifact (audits.json, runs/, config.yaml) in a throwaway dir.
process.env.EDH_STATE_DIR = mkdtempSync(join(tmpdir(), "edh-audit-spec-"));

interface FakeDomain {
	id: string;
	name: string;
	dkimSelectors: string[];
	sendingIps: string[];
	scheduleEnabled: boolean;
}

function fakeDomains(records: FakeDomain[]): DomainsService {
	return {
		onRemoved: jest.fn(),
		get: (id: string) => {
			const found = records.find((d) => d.id === id);
			if (!found) throw new Error(`No domain ${id}`);
			return found;
		},
		list: () => records,
	} as unknown as DomainsService;
}

function domain(id: string, scheduleEnabled = true): FakeDomain {
	return {
		id,
		name: `${id}.example.com`,
		dkimSelectors: [],
		sendingIps: [],
		scheduleEnabled,
	};
}

function setCheckers(...checkers: Checker[]): void {
	CHECKERS.length = 0;
	CHECKERS.push(...checkers);
}

describe("AuditService orchestration (pm/run_checks.mdx)", () => {
	it("records the trigger tag as data and collapses concurrent runs of the same domain", async () => {
		let release!: () => void;
		const gate = new Promise<void>((r) => {
			release = r;
		});
		let runs = 0;
		setCheckers({
			id: "spf",
			label: "SPF",
			run: async () => {
				runs++;
				await gate;
				return [];
			},
		});
		const service = new AuditService(fakeDomains([domain("d1")]));

		const first = service.runForDomain("d1");
		// §9: a duplicate concurrent run of the SAME domain joins the in-flight one.
		const second = service.runForDomain("d1", "api");
		expect(second).toBe(first);

		release();
		const result = await first;
		expect(runs).toBe(1);
		expect(result.trigger).toBe("manual");
		expect(result.domainId).toBe("d1");

		// The guard clears once the run finishes — a fresh run gets a fresh promise.
		const third = await service.runForDomain("d1", "scheduled-os");
		expect(third.trigger).toBe("scheduled-os");
		expect(runs).toBe(2);
	});

	it("runForAll settles — a failed domain fails alone and never rejects the batch", async () => {
		setCheckers({ id: "spf", label: "SPF", run: async () => [] });
		const records = [domain("ok1"), domain("boom"), domain("ok2")];
		const domains = fakeDomains(records);
		const realGet = domains.get.bind(domains);
		(domains as unknown as { get: (id: string) => FakeDomain }).get = (
			id: string,
		) => {
			if (id === "boom") throw new Error("domain store exploded");
			return realGet(id) as FakeDomain;
		};
		const service = new AuditService(domains);

		const results = await service.runForAll("api");
		expect(results.map((r) => r.domainId).sort()).toEqual(["ok1", "ok2"]);
		for (const r of results) expect(r.trigger).toBe("api");
	});

	it("scheduled triggers cover only scheduleEnabled domains; manual covers everything", async () => {
		setCheckers({ id: "spf", label: "SPF", run: async () => [] });
		const service = new AuditService(
			fakeDomains([domain("on", true), domain("off", false)]),
		);

		const scheduled = await service.runForAll("scheduled-inprocess");
		expect(scheduled.map((r) => r.domainId)).toEqual(["on"]);
		expect(scheduled[0].trigger).toBe("scheduled-inprocess");

		const manual = await service.runForAll("manual");
		expect(manual.map((r) => r.domainId).sort()).toEqual(["off", "on"]);
	});

	it("contains a throwing checker as a warning finding without aborting the domain", async () => {
		setCheckers(
			{
				id: "spf",
				label: "SPF",
				run: async () => {
					throw new Error("resolver melted");
				},
			},
			{
				id: "dkim",
				label: "DKIM",
				run: async () => ({ findings: [], results: { ok: true } }),
			},
		);
		const service = new AuditService(fakeDomains([domain("d1")]));
		const result = await service.runForDomain("d1");
		const errorFinding = result.findings.find((f) => f.id === "spf.error");
		expect(errorFinding?.severity).toBe("warning");
		// The sibling checker still ran and published its structured payload.
		expect(result.results?.dkim).toEqual({ ok: true });
	});
});
