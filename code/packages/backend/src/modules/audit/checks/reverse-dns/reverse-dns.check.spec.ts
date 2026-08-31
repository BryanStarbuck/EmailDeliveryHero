jest.mock("../dns-util", () => ({
	resolve4: jest.fn(),
	resolve6: jest.fn(),
	resolveCname: jest.fn(),
	resolveMx: jest.fn(),
	reverse: jest.fn(),
	reverseIpv4: jest.fn(),
}));

import {
	resolve4,
	resolve6,
	resolveCname,
	resolveMx,
	reverse,
	reverseIpv4,
} from "../dns-util";
import type { CheckContext, CheckOutcome, Finding } from "../types";
import {
	type ReverseDnsResults,
	reverseDnsCheck,
} from "./reverse-dns.check";

const mockResolve4 = resolve4 as jest.MockedFunction<typeof resolve4>;
const mockResolve6 = resolve6 as jest.MockedFunction<typeof resolve6>;
const mockResolveCname = resolveCname as jest.MockedFunction<
	typeof resolveCname
>;
const mockResolveMx = resolveMx as jest.MockedFunction<typeof resolveMx>;
const mockReverse = reverse as jest.MockedFunction<typeof reverse>;
const mockReverseIpv4 = reverseIpv4 as jest.MockedFunction<typeof reverseIpv4>;

const DOMAIN = "whitehatengineering.com";

/**
 * Recorded 2026-08-31: `whitehatengineering.com` has no configured sending IPs, so the checker
 * falls back to its Google Workspace MX. `alt1.aspmx.l.google.com` → 173.194.41.26, whose reverse
 * zone (Google's, not the operator's) carries two rotating front-end names — only the second of
 * which forward-confirms.
 */
const MX_IP = "173.194.41.26";
const MX_HOST = "alt1.aspmx.l.google.com";
const PTR_A = "mad01s14-in-f26.1e100.net";
const PTR_B = "yukulwh-in-f26.1e100.net";

const found = <T>(records: T[]) => ({ records, empty: records.length === 0 });
const none = <T>() => ({ records: [] as T[], empty: true });

const ctx = (over: Partial<CheckContext> = {}): CheckContext => ({
	domain: DOMAIN,
	dkimSelectors: [],
	sendingIps: [],
	...over,
});

const run = async (over: Partial<CheckContext> = {}) =>
	(await reverseDnsCheck.run(ctx(over))) as CheckOutcome;

const byId = (findings: Finding[], id: string): Finding | undefined =>
	findings.find((f) => f.id === id);

/** Point every forward lookup at the Google dual-PTR fixture above. */
function mockGoogleMx(ptrs: string[] = [PTR_A, PTR_B]) {
	mockResolveMx.mockResolvedValue(
		found([{ exchange: MX_HOST, priority: 5 }]),
	);
	mockReverse.mockResolvedValue(found(ptrs));
	mockResolve4.mockImplementation(async (name: string) => {
		if (name === MX_HOST) return found([MX_IP]);
		if (name === PTR_B) return found([MX_IP]);
		return none<string>();
	});
}

beforeEach(() => {
	jest.clearAllMocks();
	mockResolve4.mockResolvedValue(none<string>());
	mockResolve6.mockResolvedValue(none<string>());
	mockResolveCname.mockResolvedValue(none<string>());
	mockResolveMx.mockResolvedValue(none());
	mockReverse.mockResolvedValue(none<string>());
	mockReverseIpv4.mockReturnValue(null);
});

describe("reverse DNS on MX-sourced IPs", () => {
	it("reports a provider's multi-PTR front end as info, not a warning", async () => {
		mockGoogleMx();

		const { findings, results } = await run();
		const single = byId(findings, `infra.ptr_single.${MX_IP}`);

		expect(single?.severity).toBe("info");
		expect(single?.title).toBe(`${MX_IP} returns 2 PTR records`);
		// The old remediation told the operator to edit a reverse zone Google owns.
		expect(single?.remediation).not.toContain(`mail1.${DOMAIN}`);
		expect(single?.remediation).toContain("belongs to the mail provider");
		expect(findings.some((f) => f.severity === "warning")).toBe(false);
		expect((results as ReverseDnsResults).ips[0]).toMatchObject({
			ip: MX_IP,
			source: "mx",
			ptr_count: 2,
			forward_confirmed: true,
		});
	});

	it("downgrades a cloud-default PTR on an MX host to info", async () => {
		const generic = "ec2-203-0-113-24.compute-1.amazonaws.com";
		mockResolveMx.mockResolvedValue(
			found([{ exchange: "mx.example.net", priority: 10 }]),
		);
		mockReverse.mockResolvedValue(found([generic]));
		mockResolve4.mockImplementation(async (name: string) =>
			name === "mx.example.net" || name === generic
				? found(["203.0.113.24"])
				: none<string>(),
		);

		const { findings } = await run();

		expect(byId(findings, "infra.ptr_generic.203.0.113.24")?.severity).toBe(
			"info",
		);
		expect(
			byId(findings, "infra.ptr_no_ip_literal.203.0.113.24")?.severity,
		).toBe("info");
	});

	it("keeps the hard gates critical on an MX host", async () => {
		mockResolveMx.mockResolvedValue(
			found([{ exchange: MX_HOST, priority: 5 }]),
		);
		mockResolve4.mockImplementation(async (name: string) =>
			name === MX_HOST ? found([MX_IP]) : none<string>(),
		);
		mockReverse.mockResolvedValue(none<string>());

		const { findings } = await run();

		expect(byId(findings, `infra.ptr_present.${MX_IP}`)?.severity).toBe(
			"critical",
		);
	});

	it("still fails FCrDNS on an MX host whose PTR resolves elsewhere", async () => {
		mockGoogleMx([PTR_A]);
		mockResolve4.mockImplementation(async (name: string) =>
			name === MX_HOST
				? found([MX_IP])
				: name === PTR_A
					? found(["198.51.100.9"])
					: none<string>(),
		);

		const { findings } = await run();

		expect(byId(findings, `infra.fcrdns.${MX_IP}`)?.severity).toBe("critical");
	});
});

describe("reverse DNS on configured sending IPs", () => {
	it("keeps multi-PTR a warning with the reverse-zone remediation", async () => {
		mockReverse.mockResolvedValue(found([PTR_A, PTR_B]));
		mockResolve4.mockImplementation(async (name: string) =>
			name === PTR_B ? found([MX_IP]) : none<string>(),
		);

		const { findings, results } = await run({ sendingIps: [MX_IP] });
		const single = byId(findings, `infra.ptr_single.${MX_IP}`);

		expect(single?.severity).toBe("warning");
		expect(single?.remediation).toContain(`Reduce to a single PTR = mail1.${DOMAIN}`);
		expect((results as ReverseDnsResults).ips[0].source).toBe("sending_ip");
	});

	it("keeps a generic PTR a warning", async () => {
		const generic = "203-0-113-24.dsl.example-isp.net";
		mockReverse.mockResolvedValue(found([generic]));
		mockResolve4.mockImplementation(async (name: string) =>
			name === generic ? found(["203.0.113.24"]) : none<string>(),
		);

		const { findings } = await run({ sendingIps: ["203.0.113.24"] });

		expect(byId(findings, "infra.ptr_generic.203.0.113.24")?.severity).toBe(
			"warning",
		);
	});

	it("emits ptr_ok for a single confirming non-generic PTR", async () => {
		const host = `mail1.${DOMAIN}`;
		mockReverse.mockResolvedValue(found([host]));
		mockResolve4.mockImplementation(async (name: string) =>
			name === host ? found(["203.0.113.24"]) : none<string>(),
		);

		const { findings } = await run({ sendingIps: ["203.0.113.24"] });

		expect(byId(findings, "infra.ptr_ok.203.0.113.24")?.severity).toBe("ok");
	});
});
