import {
	credentialsFileExists,
	googleCredentialsFromFile,
} from "@config/credentials-file";
import { resolveGoogleRedirectUri } from "@module/auth/auth-frontend";
import { Public } from "@module/auth/public.decorator";
import { RateLimit } from "@module/auth/rate-limit.decorator";
import { Body, Controller, Get, HttpCode, Post } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ApiOkResponse, ApiOperation, ApiTags } from "@nestjs/swagger";
import { logError, logWarn, stripControlChars } from "@shared/logging";
import { locateTools } from "@shared/tool-runner";
import type { ClientErrorDto } from "./dto/client-error.dto";

/**
 * Unauthenticated health + auth-config probes. These are the only routes reachable before sign-in
 * (marked @Public()). The frontend reads /health/auth-config on load to show a clear "OAuth not
 * configured" message instead of bouncing the user into a broken Google redirect.
 */
@ApiTags("health")
@Controller("health")
export class HealthController {
	constructor(private readonly config: ConfigService) {}

	@Public()
	@Get()
	@ApiOperation({ summary: "Liveness probe" })
	@ApiOkResponse({ description: "Service is up" })
	health(): { status: string; app: string } {
		return { status: "ok", app: "email-delivery-hero" };
	}

	@Public()
	@Get("tools")
	@ApiOperation({
		summary:
			"External-tool discovery diagnostics (dig, openssl, swaks, spamassassin…)",
	})
	tools(): { tools: Record<string, string | null> } {
		// The ToolLocator's resolved map (pm/run_checks.mdx §5.2) — the same override → PATH →
		// conventional-locations resolution a run performs at Stage 0, so Settings can show
		// "dig ✓ /opt/homebrew/bin/dig · spamassassin ✗ not installed". null = not installed
		// (a capability downgrade for the affected checks, never a failure — §5.3).
		return { tools: locateTools() };
	}

	@Public()
	@Get("auth-config")
	@ApiOperation({
		summary:
			"Whether Google OAuth is configured (drives the sign-in page state)",
	})
	authConfig(): {
		googleConfigured: boolean;
		credentialsFilePresent: boolean;
		redirectUri: string;
	} {
		const { clientId, clientSecret } = googleCredentialsFromFile();
		const fromEnv = Boolean(
			process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET,
		);
		return {
			googleConfigured: fromEnv || Boolean(clientId && clientSecret),
			credentialsFilePresent: credentialsFileExists(),
			// The exact URI to register on the Google Cloud OAuth client (pm/security.mdx §4.2) — the
			// sign-in page surfaces this in its remediation message when OAuth is unconfigured (§4.3).
			redirectUri: resolveGoogleRedirectUri(this.config),
		};
	}

	@Public()
  @RateLimit(30, 60_000)
  @Post("client-error")
  @HttpCode(204)
  @ApiOperation({
    summary: "Ingest a browser-side error into the backend fault trail (error.err)",
  })
  clientError(@Body() body: ClientErrorDto): void {
    // The browser has no filesystem, so front-end faults are forwarded here to land in the ONE
    // error file tagged [Frontend] (pm/errors.mdx §3). Public so an error on the sign-in page
    // (pre-auth) is still captured. Every caller-supplied field is control-char-stripped before it
    // is logged so a CR/LF-laced payload cannot forge log lines (security audit finding #8); the
    // route is also rate-limited per source to bound log-flooding. Length caps come from the DTO.
    const context = body.context
      ? `Frontend:${stripControlChars(body.context, 200)}`
      : "Frontend"
    const message = stripControlChars(body.message, 2000)
    const url = body.url ? `url=${stripControlChars(body.url, 500)}` : ""
    const stack = body.stack ? stripControlChars(body.stack, 8000) : ""
    const detail = [url, stack].filter(Boolean).join(" ")
    if (body.level === "warn") logWarn(`${message} ${detail}`.trim(), context)
    else logError(message, detail || undefined, context)
  }
}
