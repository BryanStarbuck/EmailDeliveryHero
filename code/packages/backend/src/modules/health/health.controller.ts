import { credentialsFileExists, googleCredentialsFromFile } from "@config/credentials-file"
import { Controller, Get } from "@nestjs/common"
import { ApiOkResponse, ApiOperation, ApiTags } from "@nestjs/swagger"
import { Public } from "@module/auth/public.decorator"

/**
 * Unauthenticated health + auth-config probes. These are the only routes reachable before sign-in
 * (marked @Public()). The frontend reads /health/auth-config on load to show a clear "OAuth not
 * configured" message instead of bouncing the user into a broken Google redirect.
 */
@ApiTags("health")
@Controller("health")
export class HealthController {
  @Public()
  @Get()
  @ApiOperation({ summary: "Liveness probe" })
  @ApiOkResponse({ description: "Service is up" })
  health(): { status: string; app: string } {
    return { status: "ok", app: "email-delivery-hero" }
  }

  @Public()
  @Get("auth-config")
  @ApiOperation({ summary: "Whether Google OAuth is configured (drives the sign-in page state)" })
  authConfig(): { googleConfigured: boolean; credentialsFilePresent: boolean } {
    const { clientId, clientSecret } = googleCredentialsFromFile()
    const fromEnv = Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET)
    return {
      googleConfigured: fromEnv || Boolean(clientId && clientSecret),
      credentialsFilePresent: credentialsFileExists(),
    }
  }
}
