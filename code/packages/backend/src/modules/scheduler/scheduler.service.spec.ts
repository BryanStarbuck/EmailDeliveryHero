import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { MonitoredDomain } from "@module/domains/domain.types";
import type { ScheduleConfig } from "./schedule.types";
import {
	defaultScheduleConfig,
	writeScheduleConfig,
} from "./schedule-config.store";
import { SchedulerService } from "./scheduler.service";

/**
 * POST /api/scheduler/run trigger semantics (pm/settings.mdx §3.3): scheduling defaults OFF and
 * the launchd agent is installed regardless, so a trigger while disabled must be a clean no-op;
 * force bypasses the switch (the tab's "Run a scheduled check now"); back-to-back scheduled
 * triggers dedupe (in-process timer + OS agent firing the same slot); and a scheduled run covers
 * only domains whose own scheduleEnabled is true (global AND per-domain switch, pm/domains.mdx §6).
 */

const domain = (id: string, scheduleEnabled: boolean): MonitoredDomain => ({
	id,
	name: `${id}.example.com`,
	label: id,
	dkimSelectors: [],
	sendingIps: [],
	scheduleEnabled,
	addedBy: "default",
	createdAt: "2026-01-01T00:00:00.000Z",
	updatedAt: "2026-01-01T00:00:00.000Z",
});

describe("SchedulerService.runNow", () => {
	let service: SchedulerService;
	let runForDomain: jest.Mock;

	const build = (
		config: Partial<ScheduleConfig>,
		domains: MonitoredDomain[],
	) => {
		// Fresh state dir per test: config.yaml and scheduler-state.json (lastRunAt) start empty, so
		// one test's dedupe window can never leak into the next.
		process.env.EDH_STATE_DIR = mkdtempSync(
			join(tmpdir(), "edh-scheduler-spec-"),
		);
		writeScheduleConfig({ ...defaultScheduleConfig(), ...config });
		runForDomain = jest.fn(async (id: string) => ({ domainId: id }));
		const audit = { runForDomain };
		const domainsService = { list: () => domains };
		// biome-ignore lint/suspicious/noExplicitAny: narrow fakes stand in for the real services
		service = new SchedulerService(audit as any, domainsService as any);
	};

	afterEach(() => {
		// Drop any timer runNow's re-arm left behind so jest exits cleanly.
		service.onModuleDestroy();
	});

	it("skips with reason 'disabled' when scheduling is off (the default)", async () => {
		build({}, [domain("a", true)]);
		const outcome = await service.runNow("os");
		expect(outcome).toEqual({ started: false, reason: "disabled" });
		expect(runForDomain).not.toHaveBeenCalled();
	});

	it("force runs even while the toggle is off, covering only schedule-enabled domains", async () => {
		build({}, [domain("a", true), domain("b", false)]);
		const outcome = await service.runNow("manual", true);
		expect(outcome).toEqual({ started: true, domains: 1 });
		expect(runForDomain).toHaveBeenCalledTimes(1);
		// The audit record is tagged with who asked (pm/run_checks.mdx §1): a hand trigger is "manual".
		expect(runForDomain).toHaveBeenCalledWith("a", "manual");
	});

	it("dedupes a second scheduled trigger inside the 5-minute window", async () => {
		build({ enabled: true }, [domain("a", true)]);
		expect((await service.runNow("os")).started).toBe(true);
		// The OS agent and the in-process timer firing the same slot: the second one skips…
		expect(await service.runNow("in-process")).toEqual({
			started: false,
			reason: "recently_ran",
		});
		// …but a forced run (the Settings tab button) always goes through.
		expect((await service.runNow("manual", true)).started).toBe(true);
	});

	it("honors an explicit domain-id scope ANDed with each domain's own switch", async () => {
		build({ enabled: true, domains: ["b"] }, [
			domain("a", true),
			domain("b", false),
		]);
		const outcome = await service.runNow("os");
		expect(outcome).toEqual({ started: true, domains: 0 });
		expect(runForDomain).not.toHaveBeenCalled();
	});

	it("reports coverage and the configured slots in status()", () => {
		build({ enabled: true, times: ["06:00", "18:00"] }, [
			domain("a", true),
			domain("b", false),
		]);
		const status = service.status();
		expect(status.enabled).toBe(true);
		expect(status.times).toEqual(["06:00", "18:00"]);
		expect(status.domainsCovered).toBe(1);
		expect(status.domainsTotal).toBe(2);
		expect(status.running).toBe(false);
	});
});
