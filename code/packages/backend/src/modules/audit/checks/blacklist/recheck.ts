import { mapLimit, withResource } from "@shared/concurrency";
import { makeResolver, queryPair } from "./blacklist.check";
import type { ZoneResult } from "./blacklist-types";
import { reverseIpv4 } from "./engine";
import { readLatestBlacklistRun } from "./store";
import { loadZones } from "./zones";

/**
 * The §21.3 live recheck (pm/checks/blacklists.mdx AC 27): an EPHEMERAL re-query of selected
 * zones/targets that obeys every §10.4 etiquette rule — pinned non-public resolver, 5 s per-query
 * timeout, 8-in-flight concurrency (the process-global `dnsbl` semaphore), refusal codes decoded
 * as inconclusive, never a listing — and NEVER writes a run file. The UI renders the returned
 * rows as a "live recheck HH:MM" overlay chip (▲ now listed / ▼ now clean / unchanged) beside the
 * stored run values; the viewed run's stored data is never overwritten.
 */

const RECHECK_CONCURRENCY = 8;

export interface RecheckOptions {
	/** Restrict to these zone hosts (default: every enabled sweep zone). */
	zones?: string[];
	/** Restrict to these targets — IPs and/or domains (default: the latest run's target set). */
	targets?: string[];
}

/** Overlay verdict vs the stored run: ▲ now listed / ▼ now clean / unchanged (§21.3). */
export type RecheckChange =
	| "now_listed"
	| "now_clean"
	| "unchanged"
	| "inconclusive"
	| "untracked";

export interface RecheckRow extends ZoneResult {
	/** listed-state of the same (zone × target) pair in the compared stored run; null = untracked. */
	stored_listed: boolean | null;
	change: RecheckChange;
}

export interface LiveRecheckResult {
	domain: string;
	/** ISO instant of the recheck — the UI's "live recheck HH:MM" chip. */
	checked_at: string;
	resolver: { mode: "system" | "custom"; server: string | null };
	/** audit_id of the stored run the overlay compares against (null = no stored run). */
	compared_run_id: string | null;
	results: RecheckRow[];
	summary: {
		listed: number;
		clean: number;
		inconclusive: number;
		pairs_queried: number;
	};
}

/** Raised for caller errors (unknown zone / nothing to check) — the controller maps it to 400. */
export class RecheckInputError extends Error {}

function classifyChange(
	row: ZoneResult,
	storedListed: boolean | null,
): RecheckChange {
	if (row.inconclusive) return "inconclusive";
	if (storedListed === null) return "untracked";
	if (row.listed && !storedListed) return "now_listed";
	if (!row.listed && storedListed) return "now_clean";
	return "unchanged";
}

/**
 * Re-query (zones × targets) live and diff against the domain's latest stored run. Ephemeral by
 * contract: this function performs zero writes.
 */
export async function liveRecheck(
	domain: string,
	opts: RecheckOptions = {},
): Promise<LiveRecheckResult> {
	const stored = readLatestBlacklistRun(domain);

	// ---- zones: every enabled sweep zone, optionally narrowed by the caller -------------------
	const catalog = loadZones().filter((z) => z.enabled && !z.positive);
	let zones = catalog;
	if (opts.zones && opts.zones.length > 0) {
		const wanted = new Set(
			opts.zones.map((z) => z.trim().toLowerCase()).filter(Boolean),
		);
		zones = catalog.filter((z) => wanted.has(z.zone.toLowerCase()));
		const known = new Set(zones.map((z) => z.zone.toLowerCase()));
		const unknown = [...wanted].filter((z) => !known.has(z));
		if (unknown.length > 0) {
			throw new RecheckInputError(
				`Unknown or disabled blocklist zone(s): ${unknown.join(", ")} — see GET /api/blacklists/zones for the effective catalog`,
			);
		}
	}

	// ---- targets: caller-scoped, else the latest run's target set -----------------------------
	let ipTargets: string[];
	let domainTargets: string[];
	if (opts.targets && opts.targets.length > 0) {
		const cleaned = [
			...new Set(opts.targets.map((t) => t.trim()).filter(Boolean)),
		];
		ipTargets = cleaned.filter((t) => reverseIpv4(t) !== null);
		domainTargets = cleaned
			.filter((t) => reverseIpv4(t) === null)
			.map((t) => t.toLowerCase());
	} else if (stored) {
		ipTargets = stored.targets.ips.map((t) => t.ip);
		domainTargets = stored.targets.domains.map((t) => t.domain);
	} else {
		// No stored run and no explicit targets: sweep at least the domain itself on RHSBL zones.
		ipTargets = [];
		domainTargets = [domain.toLowerCase()];
	}

	const pairs: Array<{ zone: (typeof zones)[number]; target: string }> = [];
	for (const zone of zones) {
		const targets = zone.kind === "ip" ? ipTargets : domainTargets;
		for (const target of targets) pairs.push({ zone, target });
	}
	if (pairs.length === 0) {
		throw new RecheckInputError(
			"Nothing to recheck — no (zone × target) pair matches the requested zones/targets",
		);
	}

	// ---- the sweep — §10.4 etiquette (pinned resolver, 5 s timeout, 8 in-flight) ---------------
	const { resolver, mode, server } = makeResolver();
	const rows = await mapLimit(pairs, RECHECK_CONCURRENCY, (p) =>
		// Process-global dnsbl cap shared with any audit in flight (pm/run_checks.mdx §3.1).
		withResource("dnsbl", () => queryPair(resolver, p.zone, p.target)),
	);

	const storedByPair = new Map<string, boolean>();
	if (stored) {
		for (const r of stored.results) {
			if (!r.inconclusive) storedByPair.set(`${r.zone}|${r.target}`, r.listed);
		}
	}
	const results: RecheckRow[] = rows.map((row) => {
		const storedListed = storedByPair.get(`${row.zone}|${row.target}`) ?? null;
		return {
			...row,
			stored_listed: storedListed,
			change: classifyChange(row, storedListed),
		};
	});

	const listed = results.filter((r) => r.listed).length;
	const inconclusive = results.filter((r) => r.inconclusive).length;
	return {
		domain,
		checked_at: new Date().toISOString(),
		resolver: { mode, server },
		compared_run_id: stored?.audit_id ?? null,
		results,
		summary: {
			listed,
			clean: results.length - listed - inconclusive,
			inconclusive,
			pairs_queried: results.length,
		},
	};
}
