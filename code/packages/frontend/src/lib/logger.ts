/* Front-end logging. The browser has no filesystem, so errors are (a) shown in the console for the
 * developer and (b) forwarded to the backend so they land in the ONE fault trail — error.err, tagged
 * [Frontend] (see pm/errors.mdx §3). Forwarding is best-effort and can never throw or block. */

const apiBase = import.meta.env.VITE_API_BASE ?? "/api";

function safeString(value: unknown): string {
	try {
		return typeof value === "string" ? value : JSON.stringify(value);
	} catch {
		return String(value);
	}
}

/** Best-effort POST to the public client-error ingest endpoint. Never throws, never blocks. */
function forward(
	level: "error" | "warn",
	message: string,
	extra?: unknown,
): void {
	try {
		const stack =
			extra instanceof Error
				? (extra.stack ?? `${extra.name}: ${extra.message}`)
				: extra !== undefined
					? safeString(extra)
					: undefined;
		const body = JSON.stringify({
			level,
			message,
			stack,
			url: typeof location !== "undefined" ? location.href : undefined,
		});
		const url = `${apiBase}/health/client-error`;
		// sendBeacon survives page unload; fall back to fetch (keepalive) otherwise.
		if (
			typeof navigator !== "undefined" &&
			typeof navigator.sendBeacon === "function"
		) {
			navigator.sendBeacon(url, new Blob([body], { type: "application/json" }));
		} else if (typeof fetch === "function") {
			void fetch(url, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body,
				keepalive: true,
			}).catch(() => {
				/* never let logging throw */
			});
		}
	} catch {
		/* never let logging throw */
	}
}

export const logger = {
	debug: (msg: string, ...rest: unknown[]) =>
		console.debug(`[edh] ${msg}`, ...rest),
	info: (msg: string, ...rest: unknown[]) =>
		console.info(`[edh] ${msg}`, ...rest),
	warn: (msg: string, ...rest: unknown[]) => {
		console.warn(`[edh] ${msg}`, ...rest);
		forward("warn", msg, rest[0]);
	},
	error: (msg: string, ...rest: unknown[]) => {
		console.error(`[edh] ${msg}`, ...rest);
		forward("error", msg, rest[0]);
	},
};

/**
 * Install global handlers so uncaught errors and unhandled promise rejections anywhere in the SPA
 * are forwarded to error.err. Call once at boot (main.tsx). Idempotent.
 */
let installed = false;
export function installGlobalErrorHandlers(): void {
	if (installed || typeof window === "undefined") return;
	installed = true;
	window.addEventListener("error", (event) => {
		logger.error(
			event.message || "Uncaught error",
			event.error ?? event.filename,
		);
	});
	window.addEventListener("unhandledrejection", (event) => {
		logger.error("Unhandled promise rejection", event.reason);
	});
}
