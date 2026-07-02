import type { Severity } from "../types";
import type {
	BlacklistDiff,
	BlacklistRunResults,
	BlocklistZone,
	CodeMeaning,
	IpTarget,
	PositiveReputation,
	ProblemStateId,
	ZoneHealth,
	ZoneResult,
} from "./blacklist-types";

/**
 * Pure DNSBL decision logic (no I/O) — exported separately from the checker so it is unit-testable
 * the way dmarc.check.ts exports analyzeDmarcRecord. Implements pm/checks/blacklists.mdx §3
 * (query construction, refusal codes, severity mapping), §11 (tests), §16 (problem states).
 */

/** Reverse IPv4 octets for a DNSBL query. Returns null for anything that isn't dotted-quad IPv4. */
export function reverseIpv4(ip: string): string | null {
	const octets = ip.trim().split(".");
	if (octets.length !== 4) return null;
	for (const o of octets) {
		if (!/^\d{1,3}$/.test(o) || Number(o) > 255) return null;
	}
	return octets.slice().reverse().join(".");
}

/** Build the DNS query name for a (target, zone) pair; null when the target doesn't fit the zone. */
export function buildQueryName(
	target: string,
	zone: BlocklistZone,
): string | null {
	if (zone.kind === "ip") {
		const reversed = reverseIpv4(target);
		return reversed ? `${reversed}.${zone.zone}` : null;
	}
	// RHSBL: the domain is queried directly, lowercased, no reversal.
	return `${target.toLowerCase()}.${zone.zone}`;
}

export interface AnswerClassification {
	listed: boolean;
	return_code: string | null;
	sub_list: string | null;
	severity: Severity | null;
	problem_state: ProblemStateId | null;
	/** In-band "query refused" answer — inconclusive, never a listing. */
	refusal_code: string | null;
}

const NOT_LISTED: AnswerClassification = {
	listed: false,
	return_code: null,
	sub_list: null,
	severity: null,
	problem_state: null,
	refusal_code: null,
};

function refused(code: string): AnswerClassification {
	return { ...NOT_LISTED, refusal_code: code };
}

function lastOctet(address: string): number | null {
	const parts = address.split(".");
	if (parts.length !== 4) return null;
	const n = Number(parts[3]);
	return Number.isInteger(n) ? n : null;
}

/**
 * Decode a zone's A answers. Handles in-band refusals first (Spamhaus 127.255.255.x, URIBL bit 1 =
 * URIBL_BLOCKED), then exact code maps, then bitmasks, then the zone default. Answers outside
 * 127.0.0.0/8 (and the documented 127.0.1.x/127.0.2.x/127.0.4.x spaces) are treated as refusals —
 * a wildcarding middlebox, not a listing.
 */
export function classifyAnswer(
	zone: BlocklistZone,
	addresses: string[],
): AnswerClassification {
	if (addresses.length === 0) return NOT_LISTED;

	// Spamhaus in-band error codes: 127.255.255.252 bad query / .254 public resolver / .255 rate-limit.
	const spamhausError = addresses.find((a) => a.startsWith("127.255.255."));
	if (spamhausError) return refused(spamhausError);

	// Any non-loopback answer means a broken zone or interception — inconclusive, never a listing.
	const nonLoopback = addresses.find((a) => !a.startsWith("127."));
	if (nonLoopback) return refused(nonLoopback);

	// URIBL_BLOCKED: bit 1 (127.0.0.1) = query refused/over limit.
	if (zone.bitmask && addresses.includes("127.0.0.1"))
		return refused("127.0.0.1");

	const code = addresses[0];

	if (zone.codes) {
		const meaning = zone.codes[code];
		if (meaning) return classified(code, meaning);
	}

	if (zone.bitmask) {
		const octet = lastOctet(code);
		if (octet !== null) {
			const hits: CodeMeaning[] = [];
			const labels: string[] = [];
			for (const [bitStr, meaning] of Object.entries(zone.bitmask)) {
				const bit = Number(bitStr);
				if ((octet & bit) === bit) {
					hits.push(meaning);
					labels.push(meaning.label);
				}
			}
			if (hits.length > 0) {
				const worst = hits.reduce((a, b) =>
					SEVERITY_RANK[b.severity] > SEVERITY_RANK[a.severity] ? b : a,
				);
				return classified(code, { ...worst, label: labels.join(" + ") });
			}
		}
	}

	return classified(code, { label: zone.name, severity: zone.severity });
}

function classified(code: string, meaning: CodeMeaning): AnswerClassification {
	return {
		listed: meaning.severity !== "ok",
		return_code: code,
		sub_list: meaning.label,
		severity: meaning.severity,
		problem_state: meaning.problem_state ?? null,
		refusal_code: null,
	};
}

export const SEVERITY_RANK: Record<Severity, number> = {
	ok: 0,
	info: 1,
	warning: 2,
	critical: 3,
};

export function worstSeverity(
	severities: Array<Severity | null | undefined>,
): Severity {
	let worst: Severity = "ok";
	for (const s of severities) {
		if (s && SEVERITY_RANK[s] > SEVERITY_RANK[worst]) worst = s;
	}
	return worst;
}

/** Decode DNSWL 127.0.x.y — x = category, y = trust 0-3. */
export function decodeDnswl(addresses: string[]): {
	listed: boolean;
	category: string | null;
	trust: number | null;
} {
	const DNSWL_CATEGORIES: Record<number, string> = {
		2: "financial",
		3: "email service provider",
		4: "organization",
		5: "service/network provider",
		6: "personal/private server",
		7: "travel/leisure",
		8: "public sector/government",
		9: "media/tech",
		10: "education",
		11: "healthcare",
		12: "non-profit",
		13: "e-commerce",
		14: "special/other",
	};
	for (const a of addresses) {
		const parts = a.split(".").map(Number);
		if (parts.length === 4 && parts[0] === 127 && parts[1] === 0) {
			return {
				listed: true,
				category: DNSWL_CATEGORIES[parts[2]] ?? `category ${parts[2]}`,
				trust: parts[3],
			};
		}
	}
	return { listed: false, category: null, trust: null };
}

/** Decode Validity Sender Score 127.0.4.<score> (0-100; higher is better). */
export function decodeSenderScore(addresses: string[]): {
	score: number | null;
	severity: Severity;
} {
	for (const a of addresses) {
		const parts = a.split(".").map(Number);
		if (parts.length === 4 && parts[0] === 127) {
			const score = parts[3];
			if (score >= 0 && score <= 100) {
				return { score, severity: score < 70 ? "warning" : "info" };
			}
		}
	}
	return { score: null, severity: "info" };
}

/** Decode Mailspike rep.mailspike.net 127.0.0.10 (worst) … 127.0.0.20 (best). */
export function decodeMailspikeRep(addresses: string[]): {
	code: string | null;
	label: string | null;
} {
	const LABELS: Record<number, string> = {
		10: "worst reputation",
		11: "very bad",
		12: "bad",
		13: "suspicious",
		14: "neutral (probably spam)",
		15: "neutral",
		16: "neutral (probably legit)",
		17: "good",
		18: "very good",
		19: "excellent",
		20: "best reputation",
	};
	for (const a of addresses) {
		const octet = lastOctet(a);
		if (octet !== null && LABELS[octet])
			return { code: a, label: LABELS[octet] };
	}
	return { code: null, label: null };
}

/** RFC 5782 zone-health classification from the probe pair (§11 test 2). */
export function classifyZoneHealth(args: {
	zone: string;
	positiveAnswers: string[];
	negativeAnswers: string[];
	probeMs: number;
	slowThresholdMs?: number;
}): ZoneHealth {
	const { zone, positiveAnswers, negativeAnswers, probeMs } = args;
	const slowThreshold = args.slowThresholdMs ?? 2500;
	const positive = positiveAnswers[0] ?? "NXDOMAIN";
	const negative = negativeAnswers[0] ?? "NXDOMAIN";

	let status: ZoneHealth["status"];
	if (negativeAnswers.length > 0) {
		// 127.0.0.1 must never be listed — an answer means the zone wildcards (lists the world).
		status = "wildcarding";
	} else if (positiveAnswers.some((a) => a.startsWith("127.255.255."))) {
		status = "blocked";
	} else if (positiveAnswers.length === 0) {
		// Test point must answer for a live zone; silence = dead zone or blocked resolver.
		status = "dead";
	} else if (probeMs > slowThreshold) {
		status = "slow";
	} else {
		status = "ok";
	}
	return {
		zone,
		status,
		positive_probe: positive,
		negative_probe: negative,
		probe_ms: probeMs,
	};
}

/**
 * Map a finished run onto the named problem states of §16. PS-8 (provider-side block) cannot be
 * detected from DNS alone and is user/report driven, so it is never emitted here.
 */
export function detectProblemStates(args: {
	results: ZoneResult[];
	zoneHealth: ZoneHealth[];
	positive: PositiveReputation;
	zones: BlocklistZone[];
	/** IP target context (PTR/FCrDNS) — enables PS-7 detection when provided. */
	ipTargets?: IpTarget[];
}): ProblemStateId[] {
	const { results, zoneHealth, positive, ipTargets } = args;
	const states = new Set<ProblemStateId>();
	const listings = results.filter((r) => r.listed);

	for (const r of listings) {
		if (r.problem_state) {
			states.add(r.problem_state);
			continue;
		}
		// No explicit mapping from the code map — infer from zone traits.
		if (r.kind === "domain") states.add("PS-4");
		else if (
			r.tier === "low" &&
			(r.zone.includes("uceprotect") || r.zone.startsWith("netbl."))
		)
			states.add("PS-6");
		else if (r.auto_expires) states.add("PS-5");
		else if (r.tier === "high") states.add("PS-1");
		else states.add("PS-5");
	}

	// Collateral: allocation/ASN-wide zones.
	if (
		listings.some((r) =>
			/dnsbl-[23]\.uceprotect\.net|netbl\.spameatingmonkey\.net/.test(r.zone),
		)
	) {
		states.add("PS-6");
	}

	// PS-9: refusals anywhere, or a blocked zone in preflight.
	if (
		results.some((r) => r.refusal_code) ||
		zoneHealth.some((z) => z.status === "blocked")
	) {
		states.add("PS-9");
	}

	// PS-10: dead or wildcarding zone encountered this run.
	if (
		zoneHealth.some((z) => z.status === "dead" || z.status === "wildcarding")
	) {
		states.add("PS-10");
	}

	// PS-7: an rDNS/FCrDNS defect is driving listings — a listed IP whose PTR is missing or
	// fails forward-confirmation (SpamRATS NoPtr/Dyna and PBL-class listings follow from it).
	if (ipTargets) {
		const defective = new Set(
			ipTargets
				.filter((t) => t.ptr === null || t.fcrdns_ok === false)
				.map((t) => t.ip),
		);
		if (listings.some((r) => r.kind === "ip" && defective.has(r.target))) {
			states.add("PS-7");
		}
	}

	// PS-11: new-domain signals (ZRD 127.0.2.x hour codes / SEM-FRESH).
	if (
		listings.some((r) => r.zone.includes("zrd.") || r.zone.startsWith("fresh."))
	) {
		states.add("PS-11");
	}

	// PS-13: the ONLY open listings are on pay-to-delist operators (never-pay advisory).
	const realListings = listings.filter(
		(r) => r.severity === "warning" || r.severity === "critical",
	);
	if (
		realListings.length > 0 &&
		realListings.every((r) => r.paid_delist_offered)
	) {
		states.add("PS-13");
	}

	// PS-12: nothing vouches for the sender (only when otherwise clean — it's a prevention nudge).
	if (
		listings.length === 0 &&
		!positive.dnswl.listed &&
		(positive.senderscore.score === null || positive.senderscore.score < 70)
	) {
		states.add("PS-12");
	}

	if (states.size === 0 && listings.length === 0) states.add("PS-0");
	return [...states].sort((a, b) => Number(a.slice(3)) - Number(b.slice(3)));
}

/** Diff two runs (§11 test 9): clean→listed = new, listed→clean = resolved; refusals ignored. */
export function diffRuns(
	prev: BlacklistRunResults | null,
	curr: ZoneResult[],
): BlacklistDiff {
	if (!prev)
		return { new_listings: [], cleared: [], escalated: [], first_run: true };

	const key = (r: { zone: string; target: string }) => `${r.zone}|${r.target}`;
	const prevByKey = new Map(prev.results.map((r) => [key(r), r]));
	const currByKey = new Map(curr.map((r) => [key(r), r]));

	const diff: BlacklistDiff = {
		new_listings: [],
		cleared: [],
		escalated: [],
		first_run: false,
	};

	for (const r of curr) {
		if (r.inconclusive) continue;
		const before = prevByKey.get(key(r));
		if (before?.inconclusive) continue;
		if (r.listed && !before?.listed) {
			diff.new_listings.push({
				zone: r.zone,
				target: r.target,
				sub_list: r.sub_list,
			});
		} else if (r.listed && before?.listed && before.severity && r.severity) {
			if (SEVERITY_RANK[r.severity] > SEVERITY_RANK[before.severity]) {
				diff.escalated.push({
					zone: r.zone,
					target: r.target,
					from: before.severity,
					to: r.severity,
				});
			}
		}
	}
	for (const before of prev.results) {
		if (!before.listed || before.inconclusive) continue;
		const now = currByKey.get(key(before));
		if (now && !now.inconclusive && !now.listed) {
			diff.cleared.push({
				zone: before.zone,
				target: before.target,
				sub_list: before.sub_list,
			});
		}
	}
	return diff;
}

/** Extract literal ip4: addresses (single hosts only) from an SPF record for target discovery. */
export function spfLiteralIps(spfRecord: string): string[] {
	const ips: string[] = [];
	for (const term of spfRecord.split(/\s+/)) {
		const m = /^[+]?ip4:(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/i.exec(term);
		if (!m) continue;
		const prefix = m[2] === undefined ? 32 : Number(m[2]);
		if (prefix === 32 && reverseIpv4(m[1])) ips.push(m[1]);
	}
	return ips;
}
