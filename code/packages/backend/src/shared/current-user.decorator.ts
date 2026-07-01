import { createParamDecorator, type ExecutionContext } from "@nestjs/common"

/**
 * The authenticated principal attached to the request by the federated auth strategy.
 * Built entirely from the verified OpenAuthFederated token claims — there is no local
 * password or DB lookup on the request path.
 */
export interface AuthUser {
  /** OpenAuthFederated user id (`user_…`), from the token `sub`. */
  userId: string
  email: string
  /** Server-side session id (`sess_…`) from the token `sid`, or null. */
  sessionId: string | null
  /** Active organization/tenant id (`org_…`), or null. */
  orgId: string | null
  /** Mapped RBAC roles (from Google Workspace groups). */
  roles: string[]
  /** Mapped `<feature>:<action>` permissions. */
  permissions: string[]
}

/**
 * @CurrentUser() — inject the authenticated user into a controller handler. The global
 * JwtAuthGuard runs first and guarantees `request.user` is populated for guarded routes.
 */
export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): AuthUser => {
    const request = ctx.switchToHttp().getRequest<{ user?: AuthUser }>()
    return request.user as AuthUser
  },
)
