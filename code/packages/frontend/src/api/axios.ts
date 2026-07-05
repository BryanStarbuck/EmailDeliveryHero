import axios from "axios";
import { toast } from "sonner";
import { logger } from "@/lib/logger";

declare module "axios" {
	export interface AxiosRequestConfig {
		_authRetried?: boolean;
	}
}

/**
 * Auth bridge: the @auth/react SDK hooks only work inside React, so <AuthBridge> registers the
 * active session's getToken/reloadSession here for the axios layer (which lives outside the React
 * tree). We never mint, cache, parse, or refresh tokens ourselves — the library owns all of that.
 */
type AuthBridge = {
	getToken: (opts?: { template?: string }) => Promise<string | null>;
	reloadSession: () => Promise<boolean>;
};
let bridge: AuthBridge | null = null;

// Resolves the first time <AuthBridge> registers. Requests fired during the initial render wave run
// before AuthBridge's effect executes; without this they'd race out tokenless and get refused as the
// `default` user even when signed in. The interceptor awaits this (bounded) so the token lands on the
// very first call. Never blocks logged-out use — see BRIDGE_READY_TIMEOUT_MS below.
let resolveBridgeReady: () => void = () => {};
const bridgeReady = new Promise<void>((resolve) => {
	resolveBridgeReady = resolve;
});

/** Grace window for <AuthBridge> to register on first paint before we proceed tokenless (default user). */
const BRIDGE_READY_TIMEOUT_MS = 500;

export const registerAuthBridge = (b: AuthBridge) => {
	bridge = b;
	resolveBridgeReady();
};

/**
 * Single shared axios instance. `withCredentials` lets the auth session cookie travel on calls.
 * The default `X-Requested-With` header makes every app request a non-"simple" CORS request, so a
 * hostile page cannot silently drive a state-changing endpoint cross-origin without a (blocked)
 * preflight (security audit finding #9 — CSRF hardening).
 */
export const api = axios.create({
	baseURL: import.meta.env.VITE_API_BASE ?? "/api",
	withCredentials: true,
	headers: { "X-Requested-With": "XMLHttpRequest" },
});

// Request: attach the short-lived JWT from the active OpenAuthFederated session.
api.interceptors.request.use(async (config) => {
	// Give <AuthBridge> a chance to register before the first request wave, but never block logged-out
	// use: if no bridge appears within the grace window the request proceeds tokenless (default user).
	if (!bridge) {
		await Promise.race([
			bridgeReady,
			new Promise<void>((resolve) =>
				setTimeout(resolve, BRIDGE_READY_TIMEOUT_MS),
			),
		]);
	}
	if (!bridge) return config;
	try {
		const token = await bridge.getToken();
		if (token) config.headers.Authorization = `Bearer ${token}`;
	} catch (err) {
		logger.warn("Failed to attach auth token", err);
	}
	return config;
});

/**
 * Global 403 permission toast (pm/engineering.mdx §5): every refused write surfaces the same
 * "role:admin required" toast without each call site re-implementing it. The fixed sonner id
 * collapses a burst of simultaneous 403s into a single toast.
 */
const notifyForbidden = () => {
	toast.error("Permission denied — this action requires role:admin.", {
		id: "forbidden-403",
	});
};

// Response: a 401 is usually transient (expired access token). Rehydrate from the persistent
// session cookie and retry ONCE with a fresh token before giving up — never eagerly sign out.
// A 403 is a real permission denial (role:admin gating, pm/security.mdx §3.3) → permission toast.
api.interceptors.response.use(
	(response) => response,
	async (error) => {
		const status = error.response?.status;
		const original = error.config;
		if (status === 403) notifyForbidden();
		if (status === 401 && bridge && original && !original._authRetried) {
			original._authRetried = true;
			try {
				if (await bridge.reloadSession()) {
					const token = await bridge.getToken();
					if (token) {
						original.headers = original.headers ?? {};
						original.headers.Authorization = `Bearer ${token}`;
					}
					return api(original);
				}
			} catch (reloadErr) {
				logger.warn("Session reload after 401 failed", reloadErr);
			}
		}
		return Promise.reject(error);
	},
);
