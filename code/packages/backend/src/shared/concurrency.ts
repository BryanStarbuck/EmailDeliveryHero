/**
 * A tiny, dependency-free bounded-concurrency runner (a `p-limit`-style "task view"). The audit
 * runner uses it to scan domains in parallel with a small cap (pm/progress_ui.mdx §4.2–4.3). Because
 * DNS/SMTP checks are I/O-bound, bounded async concurrency — not OS worker threads — is the right,
 * lightweight tool. Runs `fn` over `items` with at most `limit` in flight and preserves input order.
 * Kept in sync with the frontend copy at `frontend/src/lib/concurrency.ts`.
 */
export async function mapLimit<T, R>(
	items: readonly T[],
	limit: number,
	fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
	const results = new Array<R>(items.length);
	const bound = Math.max(1, Math.min(limit, items.length));
	let next = 0;

	async function worker(): Promise<void> {
		while (true) {
			const i = next++;
			if (i >= items.length) return;
			results[i] = await fn(items[i], i);
		}
	}

	await Promise.all(Array.from({ length: bound }, () => worker()));
	return results;
}

/** Returned by `Semaphore.acquire()`; call it exactly once to hand the slot to the next waiter. */
export type Release = () => void;

/**
 * A tiny FIFO counting semaphore (pm/run_checks.mdx §3.2) — the second in-repo concurrency
 * primitive next to `mapLimit`. Used for the PROCESS-GLOBAL resource classes below: a per-domain
 * cap alone multiplies (4 domains × 8 DNSBL queries = 32 concurrent hits on the same mirrors), so
 * rate-sensitive resources are guarded by semaphores shared across all in-flight domains.
 */
export class Semaphore {
	private available: number;
	private readonly waiters: Array<(release: Release) => void> = [];

	constructor(readonly limit: number) {
		this.available = Math.max(1, limit);
	}

	acquire(): Promise<Release> {
		if (this.available > 0) {
			this.available--;
			return Promise.resolve(this.makeRelease());
		}
		return new Promise((resolve) => this.waiters.push(resolve));
	}

	/** Run `fn` inside one slot; the slot is released even when `fn` throws. */
	async with<T>(fn: () => Promise<T>): Promise<T> {
		const release = await this.acquire();
		try {
			return await fn();
		} finally {
			release();
		}
	}

	private makeRelease(): Release {
		let released = false;
		return () => {
			if (released) return;
			released = true;
			const next = this.waiters.shift();
			if (next) next(this.makeRelease());
			else this.available++;
		};
	}
}

/** The external resource classes a check can hold while it works (pm/run_checks.mdx §3.1). */
export type ResourceClass = "dnsbl" | "smtp25" | "http" | "cpu";

/**
 * The process-global resource semaphores (pm/run_checks.mdx §3.1). Shared by every in-flight
 * domain, whichever trigger started it:
 *  - dnsbl (8):  all DNSBL/RHSBL queries (blacklists + link_url_reputation)
 *  - smtp25 (4): all outbound SMTP connections (tls_transport, smtp_security, reachability, DANE)
 *  - http (4):   RDAP, MTA-STS/BIMI policy fetches, unsubscribe probes, integration APIs
 *  - cpu (2):    SpamAssassin child processes (the only CPU-bound work)
 * Plain DNS through the per-run memo is deliberately NOT guarded — cheap, cached, local resolver.
 */
export const RESOURCE_SEMAPHORES: Record<ResourceClass, Semaphore> = {
	dnsbl: new Semaphore(8),
	smtp25: new Semaphore(4),
	http: new Semaphore(4),
	cpu: new Semaphore(2),
};

/** Run `fn` while holding one slot of the named process-global resource semaphore. */
export function withResource<T>(
	resource: ResourceClass,
	fn: () => Promise<T>,
): Promise<T> {
	return RESOURCE_SEMAPHORES[resource].with(fn);
}
