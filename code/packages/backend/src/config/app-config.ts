import { Injectable } from "@nestjs/common"
import { ConfigService } from "@nestjs/config"

/**
 * Typed configuration accessor. Reads secrets/ports/origins/domains from the environment via
 * Nest's ConfigService and exposes them as plain, validated values. Auth secrets themselves are
 * NOT read here — they are owned by the auth layer (auth-frontend.ts) and the credentials file.
 */
@Injectable()
export class AppConfig {
  constructor(private readonly config: ConfigService) {}

  /** Company Google Workspace domains allowed to sign in. */
  get allowedAuthDomains(): string[] {
    return (this.config.get<string>("AUTH_ALLOWED_DOMAINS") ?? "whitehatengineering.com,act3ai.com")
      .split(",")
      .map((d) => d.trim().toLowerCase())
      .filter(Boolean)
  }

  get isProd(): boolean {
    return (this.config.get<string>("NODE_ENV") ?? "development") === "production"
  }

  get corsOrigins(): string[] {
    return (this.config.get<string>("CORS_ORIGINS") ?? "http://localhost:4444")
      .split(",")
      .map((o) => o.trim())
      .filter(Boolean)
  }

  get port(): number {
    const raw = this.config.get<string>("PORT") ?? "9312"
    const port = Number(raw)
    if (!Number.isFinite(port) || port <= 0 || port > 65535) {
      throw new Error(`Invalid PORT value: ${raw}`)
    }
    return port
  }
}
