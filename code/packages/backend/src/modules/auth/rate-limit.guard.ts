import {
	type CanActivate,
	type ExecutionContext,
	HttpException,
	HttpStatus,
	Injectable,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { logWarn } from "@shared/logging";
import type { Request } from "express";
import {
	RATE_LIMIT_KEY,
	type RateLimitOptions,
} from "./rate-limit.decorator";

/**
 * Global fixed-window rate-limit guard (pm/security.mdx §3.3). Runs app-wide but is INERT unless a
 * route carries @RateLimit(...): only decorated routes are throttled, so ordinary reads are never
 * affected. State is a small in-process Map keyed by (route + client IP) — enough to stop a single
 * source from flooding the audit fan-out or the public client-error sink on this single-node app.
 * A distributed deploy would swap this for a shared store; the decorator contract stays the same.
 *
 * Fails OPEN on an internal error (never blocks a legitimate request because bookkeeping threw) but
 * fails CLOSED on quota (429 once the window is exceeded).
 */
@Injectable()
export class RateLimitGuard implements CanActivate {
	private readonly hits = new Map<string, { count: number; resetAt: number }>();
	private lastSweep = 0;

	constructor(private readonly reflector: Reflector) {}

	canActivate(context: ExecutionContext): boolean {
		let opts: RateLimitOptions | undefined;
		try {
			opts = this.reflector.getAllAndOverride<RateLimitOptions>(RATE_LIMIT_KEY, [
				context.getHandler(),
				context.getClass(),
			]);
		} catch {
			return true; // no metadata readable → not a rate-limited route
		}
		if (!opts || opts.limit <= 0 || opts.windowMs <= 0) return true;

		const req = context.switchToHttp().getRequest<Request>();
		const ip = this.clientIp(req);
		const routeKey = `${req.method} ${req.baseUrl ?? ""}${req.route?.path ?? req.path ?? ""}`;
		const key = `${routeKey}|${ip}`;
		const now = Date.now();
		this.sweep(now);

		const entry = this.hits.get(key);
		if (!entry || entry.resetAt <= now) {
			this.hits.set(key, { count: 1, resetAt: now + opts.windowMs });
			return true;
		}
		if (entry.count >= opts.limit) {
			const retryAfter = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
			logWarn(
				`Rate limit exceeded for ${routeKey} from ${ip} (${opts.limit}/${opts.windowMs}ms)`,
				"RateLimitGuard",
			);
			throw new HttpException(
				{
					statusCode: HttpStatus.TOO_MANY_REQUESTS,
					message: "Too many requests — slow down and retry shortly.",
					retryAfter,
				},
				HttpStatus.TOO_MANY_REQUESTS,
			);
		}
		entry.count += 1;
		return true;
	}

	/** Best-effort client IP; falls back to a constant so a missing IP still shares one bucket. */
	private clientIp(req: Request): string {
		const fwd = req.headers?.["x-forwarded-for"];
		if (typeof fwd === "string" && fwd.length > 0) return fwd.split(",")[0].trim();
		return req.ip ?? req.socket?.remoteAddress ?? "unknown";
	}

	/** Drop expired buckets occasionally so the Map cannot grow unbounded. */
	private sweep(now: number): void {
		if (now - this.lastSweep < 60_000) return;
		this.lastSweep = now;
		for (const [k, v] of this.hits) {
			if (v.resetAt <= now) this.hits.delete(k);
		}
	}
}
