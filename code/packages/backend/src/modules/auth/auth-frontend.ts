import { join } from "node:path";
import {
	createFederatedFrontend,
	type FederatedConnectionConfig,
	FileSessionStore,
	loadOrCreateSecret,
} from "@auth/backend";
import {
	googleCredentialsFromFile,
	googleOAuthRemediation,
} from "@config/credentials-file";
import type { ConfigService } from "@nestjs/config";
import { logError, logInfo, logWarn } from "@shared/logging";
import { resolveStateDir } from "@shared/state-dir";

/**
 * The embedded OpenAuthFederated Frontend API — the whole point of this file.
 *
 * EmailDeliveryHero does NOT implement OAuth/SAML/session signing itself. It CONSUMES the
 * OpenAuthFederated open-source library (`@auth/backend`, linked in package.json from the separate
 * OpenAuthFederated repo) exactly the way our other internal app does. This module only resolves
 * app-specific config (allowed domains, credentials, cookie prefix, session lifetime) and hands it
 * to `createFederatedFrontend()`. The library runs the real Google Workspace sign-in in-process, so
 * there is no separate auth server to deploy.
 *
 * Mounted in main.ts at `/api/v1` (matching the `@auth/react` `frontendApi: '/api'` + `/v1` path).
 */

/**
 * The single disk-backed session store. The embedded Frontend API writes sessions through it; the
 * DI provider (auth.module.ts) injects the SAME instance so sign-out actually revokes on disk.
 * Module-level singleton constructed lazily by getAppSessionStore().
 */
let appSessionStore: FileSessionStore | undefined;

export function getAppSessionStore(): FileSessionStore {
	if (!appSessionStore) {
		appSessionStore = new FileSessionStore(resolveStateDir());
	}
	return appSessionStore;
}

/** The app's stable signing-secret file, under the state dir. */
const SESSION_SECRET_FILE = ".auth_session_secret";

/** Token issuer (`iss`) for this app's embedded tokens — a fixed in-code value so mint === verify. */
const APP_TOKEN_ISSUER = "email-delivery-hero";

/**
 * Resolve the HS256 signing secret from a STABLE on-disk file (never from `.env`). `loadOrCreateSecret`
 * generates a strong random value on first run, persists it 0600 under the state dir, and returns
 * the same value on every boot — so sessions survive restarts with zero configuration.
 */
function resolveSessionSecret(): string {
	return loadOrCreateSecret(join(resolveStateDir(), SESSION_SECRET_FILE));
}

/** Secure-cookie policy: true (HTTPS-only) except on a plain-HTTP localhost dev origin. */
function resolveCookieSecure(
	isProd: boolean,
	webappOrigin: string | undefined,
): boolean {
	if (isProd) return true;
	const isHttp = (webappOrigin ?? "").toLowerCase().startsWith("http://");
	return !isHttp;
}

/**
 * The OAuth redirect URI to register on the Google Cloud client (pm/security.mdx §4.2).
 * `GOOGLE_REDIRECT_URI` wins when set (prod swaps the origin this way); the default is the
 * BACKEND origin — `http://localhost:9312/api/v1/oauth_callback` in dev — because the embedded
 * Frontend API that handles the callback is mounted on the NestJS server itself.
 */
export function resolveGoogleRedirectUri(config: ConfigService): string {
	const override = config.get<string>("GOOGLE_REDIRECT_URI")?.trim();
	if (override) return override;
	const backendPort = config.get<string>("PORT") ?? "9312";
	return `http://localhost:${backendPort}/api/v1/oauth_callback`;
}

/**
 * Build the embedded OpenAuthFederated Frontend API middleware from config. The browser is
 * redirected to Google for a real OIDC consent + id_token; the app session and short-lived access
 * tokens are signed/verified in-process with the app's on-disk secret (embedded mode), so there is
 * no JWKS endpoint to host.
 */
export function buildAuthFrontend(config: ConfigService) {
	const allowedDomains = (
		config.get<string>("AUTH_ALLOWED_DOMAINS") ??
		"whitehatengineering.com,act3ai.com"
	)
		.split(",")
		.map((d) => d.trim().toLowerCase())
		.filter(Boolean);

	const isProd =
		(config.get<string>("NODE_ENV") ?? "development") === "production";
	const webappOrigin = (
		config.get<string>("CORS_ORIGINS") ?? "http://localhost:4444"
	)
		.split(",")[0]
		?.trim();

	const redirectUri = resolveGoogleRedirectUri(config);

	// Env var wins (deploy/CI override); otherwise fall back to the out-of-repo credentials file.
	const fileCreds = googleCredentialsFromFile();
	const clientId =
		(config.get<string>("GOOGLE_CLIENT_ID") || fileCreds.clientId) ?? "";
	const clientSecret =
		(config.get<string>("GOOGLE_CLIENT_SECRET") || fileCreds.clientSecret) ??
		"";

	const sessionSecret = resolveSessionSecret();

	// Credentials are supplied to the library by API — never hard-coded — as a `connections` array.
	const connections: FederatedConnectionConfig[] = [
		{
			strategy: "oauth_google",
			clientId,
			clientSecret,
			redirectUri,
			hostedDomain: config.get<string>("GOOGLE_HOSTED_DOMAIN") || undefined,
		},
	];

	// Session lifetime policy, decided here and passed to the library by API. A signed-in user stays
	// signed in for 10 months across server/browser/OS restarts; access tokens stay short-lived.
	const TEN_MONTHS_SECONDS = 10 * 30 * 24 * 60 * 60;
	const cookiePrefix = config.get<string>("AUTH_COOKIE_PREFIX") ?? "oaf_edh";
	const cookieSecure = resolveCookieSecure(isProd, webappOrigin);

	const sessionCookieSameSite: "Lax" | "Strict" =
		(config.get<string>("AUTH_COOKIE_SAMESITE") ?? "strict").toLowerCase() ===
		"lax"
			? "Lax"
			: "Strict";

	const allowedRedirectOrigins = (
		config.get<string>("CORS_ORIGINS") ??
		webappOrigin ??
		""
	)
		.split(",")
		.map((o) => o.trim())
		.filter(Boolean);

	const frontendConfig: Parameters<typeof createFederatedFrontend>[0] = {
		connections,
		allowedDomains,
		sessionSecret,
		issuer: APP_TOKEN_ISSUER,
		cookiePrefix,
		sessionTtlSeconds: TEN_MONTHS_SECONDS,
		accessTokenTtlSeconds: 15 * 60,
		inactivityTimeoutSeconds: TEN_MONTHS_SECONDS,
		sessionStore: getAppSessionStore(),
		cookieSecure,
		logger: (level, message, meta) => {
			if (level === "error") logError(message, meta, "AuthFrontend");
			else if (level === "warn") logWarn(message, "AuthFrontend");
			else logInfo(message, "AuthFrontend");
		},
	};

	// Hardening options consumed by the library (CSRF SameSite + open-redirect allowlist). Passed
	// through a typed spread so this compiles regardless of the linked library's declared config type.
	const hardening: Record<string, unknown> = {
		sessionCookieSameSite,
		allowedRedirectOrigins,
	};

	const middleware = createFederatedFrontend({
		...frontendConfig,
		...hardening,
	});

	if (!clientId || !clientSecret) {
		logWarn(
			`${googleOAuthRemediation(redirectUri)} — sign-in is disabled until this is set.`,
			"AuthFrontend",
		);
	} else {
		logInfo(
			`OpenAuthFederated frontend ready (issuer=${APP_TOKEN_ISSUER}, redirect=${redirectUri})`,
			"AuthFrontend",
		);
	}

	return middleware;
}
