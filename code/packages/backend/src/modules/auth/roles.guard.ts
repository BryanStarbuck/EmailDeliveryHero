import {
  type CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Injectable,
} from "@nestjs/common"
import { Reflector } from "@nestjs/core"
import { type AuthUser, DEFAULT_USER } from "@shared/current-user.decorator"
import { logWarn } from "@shared/logging"
import { REQUIRED_PERMISSIONS_KEY, REQUIRED_ROLES_KEY } from "./roles.decorator"

/**
 * Authorization guard (pm/security.mdx §3.3). Runs app-wide AFTER JwtAuthGuard, which always
 * populates `request.user` (the verified identity, or the `default` user when logged out). This
 * guard reads the @RequireRole / @RequirePermission metadata:
 *
 *   - No metadata on the route  → allow (open to everyone, including the `default` user).
 *   - @RequireRole(...)         → the user must hold at least one of the listed roles.
 *   - @RequirePermission(...)   → the user must hold at least one of the listed permissions.
 *   - Both present              → BOTH must be satisfied.
 *
 * The `default` user has no roles/permissions, so any gated route refuses it with 403 — the one
 * place logged-out use is actually stopped. Frontend gating is UX only; this is authoritative.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const targets = [context.getHandler(), context.getClass()]

    let requiredRoles: string[] | undefined
    let requiredPermissions: string[] | undefined
    try {
      requiredRoles = this.reflector.getAllAndOverride<string[]>(REQUIRED_ROLES_KEY, targets)
      requiredPermissions = this.reflector.getAllAndOverride<string[]>(
        REQUIRED_PERMISSIONS_KEY,
        targets,
      )
    } catch (err) {
      // Fail CLOSED: an authz route whose metadata can't be read must not silently open.
      const message = err instanceof Error ? err.message : String(err)
      logWarn(`Failed to read authz metadata, failing closed: ${message}`, "RolesGuard")
      throw new ForbiddenException()
    }

    const needsRole = Array.isArray(requiredRoles) && requiredRoles.length > 0
    const needsPermission = Array.isArray(requiredPermissions) && requiredPermissions.length > 0
    if (!needsRole && !needsPermission) return true // ungated route — open to all users

    const request = context.switchToHttp().getRequest<{ user?: AuthUser }>()
    const user = request.user ?? DEFAULT_USER

    if (needsRole && !requiredRoles?.some((r) => user.roles.includes(r))) {
      this.deny(user, `role in [${requiredRoles?.join(", ")}]`)
    }
    if (needsPermission && !requiredPermissions?.some((p) => user.permissions.includes(p))) {
      this.deny(user, `permission in [${requiredPermissions?.join(", ")}]`)
    }
    return true
  }

  private deny(user: AuthUser, needed: string): never {
    const who = user.authenticated ? user.email : "default (logged-out) user"
    logWarn(`Authorization denied for ${who}: requires ${needed}`, "RolesGuard")
    throw new ForbiddenException("You do not have permission to perform this action")
  }
}
