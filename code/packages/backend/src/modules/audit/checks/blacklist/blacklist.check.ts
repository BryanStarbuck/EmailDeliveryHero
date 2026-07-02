import { Resolver } from "node:dns/promises";
import { mapLimit, withResource } from "@shared/concurrency";
import { logWarn } from "@shared/logging";
import { resolveMx, resolveTxt, resolve4 as utilResolve4 } from "../dns-util";
import type { Checker, CheckOutcome, Finding, Severity } from "../types";
import type {
	BlacklistRunResults,
	BlacklistTest,
	BlacklistTestResult,
	BlocklistZone,
	DomainTarget,
	IpTarget,
	PositiveReputation,
	ToolRun,
	ZoneHealth,
	ZoneResult,
} from "./blacklist-types";
import {
	collectEmailReportDomains,
	collectEmailReportIps,
} from "./email-targets";
import {
	buildQueryName,
	classifyAnswer,
	classifyZoneHealth,
	decodeDnswl,
	decodeMailspikeRep,
	decodeSenderScore,
	detectProblemStates,
	diffRuns,
	reverseIpv4,
	SEVERITY_RANK,
	spfLiteralIps,
	worstSeverity,
} from "./engine";
import {
	applyPortalStates,
	readLatestBlacklistRun,
	readPortalStates,
	saveBlacklistRun,
} from "./store";
import { loadZones, PROVIDER_PORTALS } from "./zones";

/**
 * DNS blacklist (DNSBL/RHSBL) membership — the full pm/checks/blacklists.mdx implementation:
 * target discovery (§11.1), RFC 5782 zone-health preflight (§11.2), refusal-code detection (§11.3),
 * IP + domain sweeps with return-code decoding (§11.4-5), positive-reputation probes (§11.6),
 * problem-state mapping (§16), diff vs the previous run (§11.9), and per-run persistence of the
 * test_results.yaml document (§12) that the /blacklists API and UI consume.
 */

const QUERY_CONCURRENCY = 8;
/** §10.4 etiquette: per-query timeout 5 s, concurrency cap 8 in-flight — locked by acceptance 19. */
const QUERY_TIMEOUT_MS = 5000;

/** Dedicated resolver so operators can point DNSBL traffic at a real recursive resolver
 *  (EDH_DNS_RESOLVER=ip[,ip]) — public resolvers get refused by Spamhaus/URIBL (§3, PS-9).
 *  Exported for the §21.3 live-recheck path (recheck.ts), which pins the same resolver. */
export function makeResolver(): {
	resolver: Resolver;
	mode: "system" | "custom";
	server: string | null;
} {
	const resolver = new Resolver({ timeout: QUERY_TIMEOUT_MS, tries: 1 });
	const custom = process.env.EDH_DNS_RESOLVER?.trim();
	if (custom) {
		const servers = custom
			.split(",")
			.map((s) => s.trim())
			.filter(Boolean);
		if (servers.length > 0) {
			resolver.setServers(servers);
			return { resolver, mode: "custom", server: servers.join(",") };
		}
	}
	return { resolver, mode: "system", server: null };
}

interface Lookup {
	records: string[];
	ms: number;
}

// ---- §10.4 tool_runs[] capture -----------------------------------------------------------------

/**
 * Build the replay command for a batch of in-process node:dns calls. The §12 field rule lets
 * in-process calls log their exact call expression; wrapping it in the Resolver construction makes
 * the whole string replayable verbatim in a terminal via `node -e '<command>'` with every input
 * argument (query names, resolver, timeout) visible — acceptance 19.
 */
function nodeDnsCommand(calls: string[], server: string | null): string {
	const setServers = server
		? ` r.setServers(${JSON.stringify(server.split(","))});`
		: "";
	return (
		`const {Resolver} = require("node:dns/promises"); ` +
		`const r = new Resolver({timeout:${QUERY_TIMEOUT_MS},tries:1});${setServers} ` +
		`Promise.all([${calls.join(", ")}].map(p => p.catch(e => e.code))).then(a => console.log(JSON.stringify(a)))`
	);
}

/**
 * Run one phase and append its ToolRun entry ({tool, command, started_at, duration_ms, exit_code,
 * output_format, parsed, error} — the locked §10.4 shape). exit_code 0 = resolved (NXDOMAIN counts
 * — "clean" is a successful answer), 1 = library error.
 */
async function loggedPhase<T>(
	log: ToolRun[],
	command: string,
	run: () => Promise<T>,
	parse: (value: T) => unknown,
): Promise<T> {
	const startedAt = new Date();
	const base = {
		tool: "node:dns/promises",
		command,
		started_at: startedAt.toISOString(),
		output_format: "json" as const,
	};
	try {
		const value = await run();
		log.push({
			...base,
			duration_ms: Date.now() - startedAt.getTime(),
			exit_code: 0,
			parsed: parse(value),
			error: null,
		});
		return value;
	} catch (err) {
		log.push({
			...base,
			duration_ms: Date.now() - startedAt.getTime(),
			exit_code: 1,
			parsed: null,
			error: err instanceof Error ? err.message : String(err),
		});
		throw err;
	}
}

/** resolve4 that treats NXDOMAIN/ENODATA (and any resolver failure) as an empty answer. */
async function query4(resolver: Resolver, name: string): Promise<Lookup> {
	const started = Date.now();
	try {
		const records = await resolver.resolve4(name);
		return { records, ms: Date.now() - started };
	} catch {
		return { records: [], ms: Date.now() - started };
	}
}

async function queryTxt(
	resolver: Resolver,
	name: string,
): Promise<string | null> {
	try {
		const records = await resolver.resolveTxt(name);
		const flat = records.map((chunks) => chunks.join("")).filter(Boolean);
		return flat.length > 0 ? flat.join(" | ") : null;
	} catch {
		return null;
	}
}

async function queryPtr(
	resolver: Resolver,
	ip: string,
): Promise<string | null> {
	try {
		const names = await resolver.reverse(ip);
		return names[0] ?? null;
	} catch {
		return null;
	}
}

/** Team Cymru DNS ASN lookup — origin.asn.cymru.com then AS<n>.asn.cymru.com for the org name. */
async function queryAsn(
	resolver: Resolver,
	ip: string,
): Promise<IpTarget["asn"]> {
	const reversed = reverseIpv4(ip);
	if (!reversed) return null;
	const origin = await queryTxt(resolver, `${reversed}.origin.asn.cymru.com`);
	if (!origin) return null;
	const asnField = origin.split("|")[0]?.trim().split(" ")[0];
	const asn = Number(asnField);
	if (!Number.isInteger(asn)) return null;
	const detail = await queryTxt(resolver, `AS${asn}.asn.cymru.com`);
	const org = detail ? (detail.split("|").pop()?.trim() ?? null) : null;
	return { number: asn, org };
}

/** §11.1 target discovery: configured sending IPs, else MX-derived, plus SPF ip4 literals, plus
 *  IPs mined from ingested DMARC report emails that authenticated as this domain (§19). */
async function discoverIpTargets(
	resolver: Resolver,
	domain: string,
	configured: string[],
): Promise<IpTarget[]> {
	const sources = new Map<string, IpTarget["source"]>();
	for (const ip of configured) {
		if (reverseIpv4(ip)) sources.set(ip, "sending_ips");
	}
	if (sources.size === 0) {
		const mx = await resolveMx(domain);
		for (const record of mx.records) {
			const a = await utilResolve4(record.exchange);
			for (const ip of a.records) {
				if (!sources.has(ip)) sources.set(ip, "mx_resolved");
			}
		}
	}
	const txt = await resolveTxt(domain);
	const spf = txt.records.find((r) => r.toLowerCase().startsWith("v=spf1"));
	if (spf) {
		for (const ip of spfLiteralIps(spf)) {
			if (!sources.has(ip)) sources.set(ip, "spf_authorized");
		}
	}
	// §19: IPs observed actually sending as this domain in DMARC rua reports (last 30 days),
	// capped at the top 20 by message volume. Dedupe keeps the stronger config-derived source tag.
	const emailIps = collectEmailReportIps(domain);
	for (const rep of emailIps.ips) {
		if (!sources.has(rep.ip)) sources.set(rep.ip, "email_report");
	}
	if (emailIps.truncated > 0) {
		// §19.1: the target cap is bounded but truncation is never silent.
		logWarn(
			`Blacklist sweep for ${domain}: ${emailIps.truncated} email-derived IP(s) beyond the top-20-by-volume cap were skipped`,
			"BlacklistCheck",
		);
	}

	return mapLimit(
		[...sources.entries()],
		QUERY_CONCURRENCY,
		async ([ip, source]) => {
			const ptr = await queryPtr(resolver, ip);
			let fcrdnsOk: boolean | null = null;
			if (ptr) {
				const forward = await query4(resolver, ptr);
				fcrdnsOk = forward.records.includes(ip);
			} else {
				fcrdnsOk = false;
			}
			const asn = await queryAsn(resolver, ip);
			return { ip, source, ptr, fcrdns_ok: fcrdnsOk, asn };
		},
	);
}

/** §11.2 RFC 5782 preflight: 127.0.0.2 must be listed, 127.0.0.1 must not. */
async function probeZoneHealth(
	resolver: Resolver,
	zone: BlocklistZone,
): Promise<ZoneHealth> {
	const started = Date.now();
	const positive = await query4(resolver, `2.0.0.127.${zone.zone}`);
	const negative = await query4(resolver, `1.0.0.127.${zone.zone}`);
	return classifyZoneHealth({
		zone: zone.zone,
		positiveAnswers: positive.records,
		negativeAnswers: negative.records,
		probeMs: Date.now() - started,
	});
}

function queryNameFor(r: ZoneResult): string {
	if (r.kind === "ip") {
		const reversed = reverseIpv4(r.target);
		return reversed ? `${reversed}.${r.zone}` : r.zone;
	}
	return `${r.target.toLowerCase()}.${r.zone}`;
}

/** One (zone × target) DNSBL query — exported for the §21.3 live-recheck path (recheck.ts). */
export async function queryPair(
	resolver: Resolver,
	zone: BlocklistZone,
	target: string,
): Promise<ZoneResult> {
	const base: ZoneResult = {
		zone: zone.zone,
		name: zone.name,
		tier: zone.tier,
		kind: zone.kind,
		target,
		listed: false,
		return_code: null,
		sub_list: null,
		reason_txt: null,
		lookup_url: zone.lookup_url,
		delist_url: zone.delist_url,
		severity: null,
		inconclusive: false,
		refusal_code: null,
		query_ms: 0,
		problem_state: null,
		paid_delist_offered: zone.paid_delist_offered ?? false,
		auto_expires: zone.auto_expires ?? null,
	};
	const name = buildQueryName(target, zone);
	if (!name) return { ...base, inconclusive: true }; // e.g. IPv6 target on an IPv4-only zone
	const answer = await query4(resolver, name);
	const decoded = classifyAnswer(zone, answer.records);
	const result: ZoneResult = {
		...base,
		listed: decoded.listed,
		return_code: decoded.return_code,
		sub_list: decoded.sub_list,
		severity: decoded.severity,
		refusal_code: decoded.refusal_code,
		inconclusive: decoded.refusal_code !== null,
		problem_state: decoded.problem_state,
		query_ms: answer.ms,
	};
	if (result.listed) {
		result.reason_txt = await queryTxt(resolver, name);
	}
	return result;
}

/** §11.6 positive-reputation probes: DNSWL, Sender Score, Mailspike reputation. */
async function probePositiveReputation(
	resolver: Resolver,
	ips: IpTarget[],
): Promise<PositiveReputation> {
	const out: PositiveReputation = {
		dnswl: { listed: false, category: null, trust: null },
		senderscore: { score: null, severity: "info" },
		mailspike_rep: { code: null, label: null },
	};
	const first = ips.find((t) => reverseIpv4(t.ip));
	if (!first) return out;
	const reversed = reverseIpv4(first.ip);
	// Positive/reputation lists are DNSBL-family zones too — same process-global cap (pm/run_checks.mdx §3.1).
	const [dnswl, score, rep] = await Promise.all([
		withResource("dnsbl", () => query4(resolver, `${reversed}.list.dnswl.org`)),
		withResource("dnsbl", () =>
			query4(resolver, `${reversed}.score.senderscore.com`),
		),
		withResource("dnsbl", () =>
			query4(resolver, `${reversed}.rep.mailspike.net`),
		),
	]);
	out.dnswl = decodeDnswl(dnswl.records);
	out.senderscore = decodeSenderScore(score.records);
	out.mailspike_rep = decodeMailspikeRep(rep.records);
	return out;
}

function delistRemediation(r: ZoneResult): string {
	const parts: string[] = [];
	parts.push(
		`Fix the root cause first — a delist request while the cause is live gets re-listed. ${causeHint(r)}`,
	);
	const url = r.reason_txt?.match(/https?:\/\/\S+/)?.[0] ?? r.delist_url;
	parts.push(
		`Then request removal at ${url} (reason code ${r.return_code ?? "n/a"}${r.sub_list ? ` = ${r.sub_list}` : ""}).`,
	);
	if (r.auto_expires)
		parts.push(
			`This list auto-expires (${r.auto_expires}) — waiting is a valid option.`,
		);
	if (r.paid_delist_offered) {
		parts.push(
			"NEVER pay for delisting: paid 'express' removal is unnecessary (listings auto-expire) and the industry considers pay-to-delist abusive (RFC 6471).",
		);
	}
	parts.push(
		"Re-run this check after the operator's processing window to confirm removal.",
	);
	return parts.join(" ");
}

function causeHint(r: ZoneResult): string {
	switch (r.problem_state) {
		case "PS-2":
			return "This zone flags compromised hosts: find and clean the infected machine, close open relays/proxies, rotate credentials.";
		case "PS-3":
			return "This is a policy listing (dynamic/consumer IP space): either send via your provider's smarthost, or get a proper static PTR and request policy exclusion.";
		case "PS-4":
			return "The domain itself is listed: if 'abused-legit', secure the hacked site/open redirect first; otherwise contest with evidence.";
		case "PS-5":
			return "Mail hit a spam trap: clean the recipient list (remove non-engaged/unverified addresses) and stop the offending stream.";
		case "PS-6":
			return "This is collateral from your network neighbors: verify you are clean on high-trust zones, then escalate to your provider's abuse desk.";
		case "PS-7":
			return "The trigger is reverse DNS: set a proper PTR (FCrDNS) for the IP before requesting removal.";
		default:
			return "Investigate the cause (compromise, complaints, open relay, list hygiene) using the reason text.";
	}
}

// ---- §12 tests[] — one row per sub-test, pass and fail alike -------------------------------------

/** Stable per-zone sub-test id (`dnsbl.` prefix locked by the spec; slug derived from the zone). */
function zoneTestId(zone: string): string {
	return `dnsbl.${zone.toLowerCase().replace(/[^a-z0-9]+/g, "_")}`;
}

function testFor(r: ZoneResult): BlacklistTest {
	let result: BlacklistTestResult;
	let title: string;
	if (r.inconclusive) {
		result = "info";
		title = `${r.name} — ${r.target} inconclusive${r.refusal_code ? " (query refused)" : " (zone unavailable)"}`;
	} else if (r.listed) {
		result =
			r.severity === "critical"
				? "fail"
				: r.severity === "warning"
					? "warn"
					: "info";
		title = `${r.name} — ${r.target} listed${r.sub_list ? ` (${r.sub_list})` : ""}`;
	} else {
		result = "pass";
		title = `${r.name} — ${r.target} clean`;
	}
	const answer = r.return_code ?? r.refusal_code ?? "NXDOMAIN";
	return {
		id: zoneTestId(r.zone),
		title,
		result,
		evidence: `${queryNameFor(r)} → ${answer}${r.reason_txt ? `; TXT: ${r.reason_txt}` : ""}`,
		...(r.listed ? { fix: delistRemediation(r) } : {}),
	};
}

/** The per-sub-test rows plus the dnsbl.aggregate roll-up (§2 / §12 example). */
function buildTests(
	results: ZoneResult[],
	status: Severity,
	counts: {
		listed: number;
		clean: number;
		inconclusive: number;
		zones: number;
		targets: number;
	},
): BlacklistTest[] {
	const tests = results.map(testFor);
	const worst = results
		.filter((r) => r.listed)
		.sort(
			(a, b) =>
				SEVERITY_RANK[b.severity ?? "info"] -
					SEVERITY_RANK[a.severity ?? "info"] || a.zone.localeCompare(b.zone),
		)[0];
	const aggregateResult: BlacklistTestResult =
		status === "critical"
			? "fail"
			: status === "warning"
				? "warn"
				: counts.listed > 0
					? "info"
					: "pass";
	tests.push({
		id: "dnsbl.aggregate",
		title:
			counts.listed > 0
				? `${counts.listed} listing(s) across ${counts.zones} zones × ${counts.targets} targets`
				: `No listings across ${counts.zones} zones × ${counts.targets} targets`,
		result: aggregateResult,
		evidence: `listed ${counts.listed} · clean ${counts.clean} · inconclusive ${counts.inconclusive}${worst ? ` — worst = ${worst.name} on ${worst.target}` : ""}`,
		...(worst
			? {
					fix: "Fix the highest-weight listing first (root cause before delisting), then re-run to confirm removal.",
				}
			: {}),
	});
	return tests;
}

export const blacklistCheck: Checker = {
	id: "blacklist",
	label: "DNS blacklists",
	async run(ctx): Promise<CheckOutcome> {
		const startedAt = Date.now();
		const ranAt = new Date(startedAt);
		// The deep-store id IS the envelope run id when the audit engine minted one (both are
		// timestamp-prefixed, so lexical order stays chronological) — the run-record snapshot and
		// the blacklists/<domain>/ copy of the same run join on it (pm/storage.mdx §7A, D8+D12).
		// The self-generated fallback covers direct invocations outside a persisted run.
		const auditId =
			ctx.runId ??
			`${ranAt.toISOString().replace(/[:.]/g, "-")}_${Math.random().toString(36).slice(2, 6)}`;
		const { resolver, mode, server } = makeResolver();

		const zones = loadZones().filter((z) => z.enabled);
		const sweepZones = zones.filter((z) => !z.positive);
		const toolRuns: ToolRun[] = [];

		// §11.1 target discovery (PTR/FCrDNS/ASN context probes attached — §11.7).
		const ipTargets = await loggedPhase(
			toolRuns,
			nodeDnsCommand(
				ctx.sendingIps.length > 0
					? ctx.sendingIps.map((ip) => `r.reverse(${JSON.stringify(ip)})`)
					: [
							`r.resolveMx(${JSON.stringify(ctx.domain)})`,
							`r.resolveTxt(${JSON.stringify(ctx.domain)})`,
						],
				server,
			),
			() => discoverIpTargets(resolver, ctx.domain, ctx.sendingIps),
			(targets) => targets,
		);
		// §3/§19.1 domain targets: the primary sending domain plus our own subdomains observed
		// authenticating (DKIM d= / SPF Return-Path) in ingested rua reports.
		const domainTargets: DomainTarget[] = [
			{ domain: ctx.domain, source: "primary", created: null },
		];
		for (const extra of collectEmailReportDomains(ctx.domain)) {
			domainTargets.push({
				domain: extra.domain,
				source: extra.source,
				created: null,
			});
		}

		// §11.2 preflight — dead/wildcarding zones are excluded from the sweep (PS-10).
		const zoneHealth = await loggedPhase(
			toolRuns,
			nodeDnsCommand(
				sweepZones.flatMap((z) => [
					`r.resolve4(${JSON.stringify(`2.0.0.127.${z.zone}`)})`,
					`r.resolve4(${JSON.stringify(`1.0.0.127.${z.zone}`)})`,
				]),
				server,
			),
			() =>
				mapLimit(sweepZones, QUERY_CONCURRENCY, (z) =>
					// The process-global `dnsbl` semaphore (pm/run_checks.mdx §3.1): with 4 domains in
					// flight a per-check cap alone would mean 32 concurrent hits on the same mirrors.
					withResource("dnsbl", () => probeZoneHealth(resolver, z)),
				),
			(health) => health,
		);
		const healthByZone = new Map(zoneHealth.map((h) => [h.zone, h]));
		const usableZones = sweepZones.filter((z) => {
			const h = healthByZone.get(z.zone);
			return h && h.status !== "dead" && h.status !== "wildcarding";
		});

		// §11.4-5 the sweep: every usable (zone × matching target).
		const pairs: Array<{ zone: BlocklistZone; target: string }> = [];
		for (const zone of usableZones) {
			if (zone.kind === "ip") {
				for (const t of ipTargets) pairs.push({ zone, target: t.ip });
			} else {
				for (const t of domainTargets) pairs.push({ zone, target: t.domain });
			}
		}
		const results = await loggedPhase(
			toolRuns,
			nodeDnsCommand(
				pairs
					.map((p) => buildQueryName(p.target, p.zone))
					.filter((n): n is string => n !== null)
					.map((n) => `r.resolve4(${JSON.stringify(n)})`),
				server,
			),
			() =>
				mapLimit(pairs, QUERY_CONCURRENCY, (p) =>
					// Process-global dnsbl cap shared across every in-flight domain (pm/run_checks.mdx §3.1).
					withResource("dnsbl", () => queryPair(resolver, p.zone, p.target)),
				),
			(rows) =>
				rows.map((r) => ({
					name: queryNameFor(r),
					answer:
						r.return_code ??
						r.refusal_code ??
						(r.inconclusive ? "inconclusive" : "NXDOMAIN"),
					listed: r.listed,
					...(r.reason_txt ? { txt: r.reason_txt } : {}),
				})),
		);

		const firstReversed = ipTargets
			.map((t) => reverseIpv4(t.ip))
			.find((r) => r !== null);
		const positive = await loggedPhase(
			toolRuns,
			nodeDnsCommand(
				firstReversed
					? [
							`r.resolve4(${JSON.stringify(`${firstReversed}.list.dnswl.org`)})`,
							`r.resolve4(${JSON.stringify(`${firstReversed}.score.senderscore.com`)})`,
							`r.resolve4(${JSON.stringify(`${firstReversed}.rep.mailspike.net`)})`,
						]
					: [],
				server,
			),
			() => probePositiveReputation(resolver, ipTargets),
			(rep) => rep,
		);

		const listedRows = results.filter((r) => r.listed);
		const inconclusiveRows = results.filter((r) => r.inconclusive);
		const refusalsDetected =
			results.some((r) => r.refusal_code !== null) ||
			zoneHealth.some((h) => h.status === "blocked");
		const deadZones = zoneHealth.filter(
			(h) => h.status === "dead" || h.status === "wildcarding",
		);

		const problemStates = detectProblemStates({
			results,
			zoneHealth,
			positive,
			zones: sweepZones,
			ipTargets,
		});
		const previous = readLatestBlacklistRun(ctx.domain);
		const diff = diffRuns(previous, results);

		// §12: status = worst post-weighting severity across the run's tests.
		const status = worstSeverity(listedRows.map((r) => r.severity));
		const tests = buildTests(results, status, {
			listed: listedRows.length,
			clean: results.length - listedRows.length - inconclusiveRows.length,
			inconclusive: inconclusiveRows.length,
			zones: sweepZones.length,
			targets: ipTargets.length + domainTargets.length,
		});

		const run: BlacklistRunResults = {
			schema_version: 1,
			technology: "blacklists",
			domain: ctx.domain,
			audit_id: auditId,
			ran_at: ranAt.toISOString(),
			duration_ms: Date.now() - startedAt,
			status,
			resolver: { mode, server, refusals_detected: refusalsDetected },
			targets: { ips: ipTargets, domains: domainTargets },
			zone_health: zoneHealth,
			results,
			tool_runs: toolRuns,
			tests,
			positive_reputation: positive,
			provider_portals: applyPortalStates(
				PROVIDER_PORTALS,
				readPortalStates(ctx.domain),
			),
			summary: {
				zones_enabled: sweepZones.length,
				pairs_queried: results.length,
				listed: listedRows.length,
				clean: results.length - listedRows.length - inconclusiveRows.length,
				inconclusive: inconclusiveRows.length,
				dead_zones_skipped: deadZones.length,
				worst_severity: status,
				problem_states: problemStates,
			},
			problem_states: problemStates,
			diff,
		};

		try {
			saveBlacklistRun(ctx.domain, run);
		} catch {
			// Persistence failure is already logged by the yaml store; the audit result still carries the run.
		}

		// ---- findings ---------------------------------------------------------------------------
		const findings: Finding[] = [];

		if (ipTargets.length === 0) {
			findings.push({
				id: "blacklist.no_ips",
				checkId: "blacklist",
				title: "No sending IPs to check",
				severity: "info",
				detail:
					"No sending IPs were configured and none could be derived from MX or SPF records; only domain blocklists were checked.",
				remediation:
					"Add the IP addresses your mail actually sends from to this domain so IP blacklist status can be verified.",
			});
		}

		for (const r of listedRows) {
			const severity: Severity = r.severity ?? "warning";
			findings.push({
				id: `blacklist.listed.${r.zone}.${r.target}`,
				checkId: "blacklist",
				title: `${r.target} is listed on ${r.name}`,
				severity,
				detail: `${r.kind === "ip" ? "Sending IP" : "Domain"} ${r.target} is on ${r.name} (${r.zone} answered ${r.return_code}${r.sub_list ? ` = ${r.sub_list}` : ""}).${r.reason_txt ? ` Reason: ${r.reason_txt}` : ""}`,
				remediation: delistRemediation(r),
				evidence: queryNameFor(r),
			});
		}

		if (refusalsDetected) {
			findings.push({
				id: "blacklist.refused",
				checkId: "blacklist",
				title: "Some blocklists refused our DNS queries",
				severity: "info",
				detail:
					"One or more zones returned in-band refusal codes (Spamhaus 127.255.255.x / URIBL_BLOCKED). Results for those zones are inconclusive — this says nothing bad about your domain.",
				remediation:
					"Point the checker at a real recursive resolver (set EDH_DNS_RESOLVER; avoid 8.8.8.8/1.1.1.1), or configure a free Spamhaus DQS key / Abusix key, then re-run.",
			});
		}

		if (deadZones.length > 0) {
			findings.push({
				id: "blacklist.zones_dead",
				checkId: "blacklist",
				title: `${deadZones.length} blocklist zone(s) dead or misbehaving — excluded`,
				severity: "info",
				detail: `RFC 5782 test probes failed for: ${deadZones.map((z) => `${z.zone} (${z.status})`).join(", ")}. Dead zones sometimes wildcard and "list the world", so they were excluded rather than reported.`,
				remediation:
					"No action needed for your domain. An operator can retire the zone in the Blocklist Zones config (blacklist_zones.yaml).",
			});
		}

		if (listedRows.length === 0) {
			findings.push({
				id: "blacklist.clean",
				checkId: "blacklist",
				title: "Not on any checked blacklist",
				severity: "ok",
				detail: `Checked ${ipTargets.length} IP(s) and ${domainTargets.length} domain(s) against ${usableZones.length} blocklist zones — none listed.`,
				evidence: ipTargets.map((t) => t.ip).join(", ") || ctx.domain,
			});
			if (problemStates.includes("PS-12")) {
				findings.push({
					id: "blacklist.positive_reputation",
					checkId: "blacklist",
					title: "No positive reputation established",
					severity: "info",
					detail: `Nothing is wrong, but nothing vouches for you either: not on DNSWL${positive.senderscore.score !== null ? `, Sender Score ${positive.senderscore.score}` : ", no Sender Score"}.`,
					remediation:
						"Register your MTA at dnswl.org (free tier) and keep sending volume steady so Sender Score materializes — positive signals buffer against gray-area filtering.",
				});
			}
		}

		return { findings, results: run };
	},
};
