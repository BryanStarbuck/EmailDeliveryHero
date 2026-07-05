import { SetMetadata } from "@nestjs/common";

/**
 * Per-route rate limiting metadata (pm/security.mdx §3.3). Read by the global {@link RateLimitGuard}.
 * A route WITHOUT this decorator is never rate-limited. Applied to unauthenticated or
 * resource-intensive endpoints (audit fan-out, the public client-error sink) so a single source
 * cannot flood the box even when the route is otherwise reachable.
 */
export const RATE_LIMIT_KEY = "rateLimit";

export interface RateLimitOptions {
	/** Max requests allowed from one source within the window. */
	limit: number;
	/** Sliding window length in milliseconds. */
	windowMs: number;
}

/** Limit a route to `limit` requests per `windowMs` per client source (IP + route). */
export const RateLimit = (limit: number, windowMs: number) =>
	SetMetadata(RATE_LIMIT_KEY, { limit, windowMs } satisfies RateLimitOptions);
