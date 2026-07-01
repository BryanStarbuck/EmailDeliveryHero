import { SetMetadata } from "@nestjs/common"

/**
 * Authorization decorators (pm/security.mdx §3.3). Authentication (who you are) is optional and
 * owned by the JwtAuthGuard; AUTHORIZATION (what you may do) is opt-in per route via these
 * decorators, enforced by the global RolesGuard. A route with NEITHER decorator is open to every
 * user, including the logged-out `default` user. A route that carries one is refused with 403 for
 * anyone (the `default` user always) who doesn't satisfy it.
 */

export const REQUIRED_ROLES_KEY = "requiredRoles"
export const REQUIRED_PERMISSIONS_KEY = "requiredPermissions"

/**
 * Require the current user to hold at least ONE of the listed roles (from the OpenAuthFederated
 * token, derived from Workspace groups). The common case is `@RequireRole("admin")`, which locks a
 * route to `role:admin` and 403s the `default` (logged-out) user.
 */
export const RequireRole = (...roles: string[]) => SetMetadata(REQUIRED_ROLES_KEY, roles)

/**
 * Require the current user to hold at least ONE of the listed `<feature>:<action>` permissions.
 * Combined with @RequireRole, BOTH constraints must pass (roles: any-of AND permissions: any-of).
 */
export const RequirePermission = (...permissions: string[]) =>
  SetMetadata(REQUIRED_PERMISSIONS_KEY, permissions)
