import { Resolver } from "node:dns/promises";

/**
 * Reverse-DNS lookup for report source IPs (pm/Email_Complaints.mdx §10.2 evidence table).
 *
 * A PTR is what turns the evidence table from a list of numbers into something a person can read:
 * `mail-sor-f41.google.com` identifies a sender at a glance where `209.85.220.69` does not, and the
 * absence of a PTR is itself a signal — the four spoofing IPs in the reference corpus have none.
 *
 * Three constraints shape this module:
 *  - **Bounded.** The corpus has 135 distinct source IPs and a busy domain has more, so only the
 *    highest-volume IPs are resolved (`MAX_LOOKUPS`) and the rest render as "—". The board must not
 *    turn into a few hundred serial DNS round-trips.
 *  - **Never fatal.** A PTR is decoration on an evidence table. Every failure — NXDOMAIN, timeout,
 *    no resolver at all — resolves to null and the page renders exactly as before.
 *  - **Cached.** Boards are rebuilt on every page load and window change; the same handful of
 *    provider IPs dominate every one of them.
 */

/** Most IPs to resolve for one board — ordered by message volume, so the tail is what gets dropped. */
const MAX_LOOKUPS = 60;
/** Per-lookup ceiling. A slow PTR must not hold up the page. */
const TIMEOUT_MS = 2_000;
/** How long a resolved PTR stays good. Reverse DNS for sending infrastructure changes rarely. */
const TTL_MS = 60 * 60 * 1000;
/** Hard cap on the cache so a long-running server cannot grow it without bound. */
const MAX_CACHE_ENTRIES = 5_000;

const cache = new Map<string, { ptr: string | null; at: number }>();

function cached(ip: string): { ptr: string | null } | null {
	const hit = cache.get(ip);
	if (!hit) return null;
	if (Date.now() - hit.at > TTL_MS) {
		cache.delete(ip);
		return null;
	}
	return hit;
}

function remember(ip: string, ptr: string | null): void {
	if (cache.size >= MAX_CACHE_ENTRIES) {
		// Cheap eviction: drop the oldest inserted key. Map preserves insertion order.
		const oldest = cache.keys().next();
		if (!oldest.done) cache.delete(oldest.value);
	}
	cache.set(ip, { ptr, at: Date.now() });
}

async function lookupOne(ip: string): Promise<string | null> {
	const resolver = new Resolver({ timeout: TIMEOUT_MS, tries: 1 });
	try {
		const names = await resolver.reverse(ip);
		return names[0] ?? null;
	} catch {
		// No PTR, no resolver, or a timeout — all mean the same thing to the table: nothing to show.
		return null;
	}
}

/**
 * Resolve reverse DNS for the given IPs, highest-volume first.
 *
 * `ipsByVolume` must already be ordered by message count descending; only the first `MAX_LOOKUPS`
 * unresolved entries are looked up. Returns a map covering every IP passed in — IPs that were not
 * looked up, or that have no PTR, map to null — so callers never need to distinguish the two.
 */
export async function resolvePtrs(
	ipsByVolume: readonly string[],
): Promise<Map<string, string | null>> {
	const out = new Map<string, string | null>();
	const pending: string[] = [];

	for (const ip of ipsByVolume) {
		if (out.has(ip)) continue;
		const hit = cached(ip);
		if (hit) out.set(ip, hit.ptr);
		else if (pending.length < MAX_LOOKUPS) pending.push(ip);
		else out.set(ip, null);
	}

	const resolved = await Promise.all(
		pending.map(async (ip) => [ip, await lookupOne(ip)] as const),
	);
	for (const [ip, ptr] of resolved) {
		remember(ip, ptr);
		out.set(ip, ptr);
	}
	return out;
}

/** Test seam: drop the memo so a spec never depends on another spec's lookups. */
export function clearPtrCache(): void {
	cache.clear();
}
