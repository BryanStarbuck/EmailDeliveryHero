import { federatedClient } from "@auth/backend"
import { AppConfig } from "@config/app-config"
import { Injectable, UnauthorizedException } from "@nestjs/common"
import { PassportStrategy } from "@nestjs/passport"
import type { AuthUser } from "@shared/current-user.decorator"
import { logDebug, logWarn } from "@shared/logging"
import type { Request } from "express"
import { Strategy } from "passport-custom"

/** Extract the lower-cased domain from an email address, or "" when malformed. */
function emailDomain(email: string): string {
  const at = email.lastIndexOf("@")
  if (at < 0) return ""
  return email.slice(at + 1).trim().toLowerCase()
}

/**
 * Strip control characters (< 0x20 and 0x7F) from a token-controlled string before logging it, so
 * a crafted claim cannot inject forged lines into the error trail. Uses char codes rather than a
 * literal control-char regex so the source file stays clean ASCII.
 */
function sanitizeForLog(value: string): string {
  let out = ""
  for (const ch of value) {
    const code = ch.charCodeAt(0)
    out += code < 0x20 || code === 0x7f ? " " : ch
  }
  return out.slice(0, 128)
}

/**
 * Federated auth strategy. Every request's Bearer token is verified against OpenAuthFederated
 * (networkless — the embedded HS256 secret is configured by createFederatedFrontend) via the
 * library's `federatedClient.verifyToken`. The returned value becomes `request.user`.
 *
 * Registered under the name `'jwt'` so the global JwtAuthGuard works unchanged. Domain enforcement
 * is owned by the library (it rejects non-company identities before a token is minted); this adds a
 * cheap defense-in-depth check that a verified token's domain is on the company allowlist.
 */
@Injectable()
export class AuthFederatedStrategy extends PassportStrategy(Strategy, "jwt") {
  constructor(private readonly appConfig: AppConfig) {
    super()
  }

  async validate(req: Request): Promise<AuthUser> {
    const header = req.headers?.authorization ?? ""
    const token = typeof header === "string" ? header.replace(/^Bearer\s+/i, "") : ""
    if (!token) {
      logDebug("Rejecting request: missing or empty Authorization bearer token", "AuthStrategy")
      throw new UnauthorizedException()
    }

    try {
      const claims = await federatedClient.verifyToken(token)
      const email = claims.email ?? ""

      const allowed = this.appConfig.allowedAuthDomains
      const hd = typeof claims.hd === "string" ? claims.hd.trim().toLowerCase() : ""
      const domain = hd || emailDomain(email)
      if (!domain || !allowed.includes(domain)) {
        const safeDomain = sanitizeForLog(domain || "unknown")
        logWarn(
          `Rejecting token: domain "${safeDomain}" is not an allowed company domain`,
          "AuthStrategy",
        )
        throw new UnauthorizedException()
      }

      return {
        userId: claims.sub,
        email,
        sessionId: typeof claims.sid === "string" ? claims.sid : null,
        orgId: claims.org_id ?? null,
        roles: Array.isArray(claims.roles) ? claims.roles : [],
        permissions: Array.isArray(claims.permissions) ? claims.permissions : [],
      }
    } catch (err) {
      if (err instanceof UnauthorizedException) throw err
      const name = err instanceof Error ? err.name : typeof err
      const message = err instanceof Error ? err.message : String(err)
      logWarn(`Token verification failed: ${name}: ${message}`, "AuthStrategy")
      throw new UnauthorizedException()
    }
  }
}
