import { createParamDecorator, type ExecutionContext } from "@nestjs/common"

/**
 * The current principal attached to the request by the federated auth strategy.
 *
 * There is ALWAYS a current user (pm/security.mdx §1–§2): when a valid OpenAuthFederated Bearer
 * token is present it is the verified identity (built entirely from the token claims — no local
 * password or DB lookup on the request path); when no valid session is present it is the built-in
 * `default` user. `authenticated` distinguishes the two.
 */
export interface AuthUser {
  /** OpenAuthFederated user id (`user_…`) from the token `sub`, or `"default"` when logged out. */
  userId: string
  /** Verified Workspace email when signed in; the literal `"default"` when logged out. */
  email: string
  /** Server-side session id (`sess_…`) from the token `sid`, or null. */
  sessionId: string | null
  /** Active organization/tenant id (`org_…`), or null. */
  orgId: string | null
  /** Mapped RBAC roles (from Google Workspace groups). Empty for the `default` user. */
  roles: string[]
  /** Mapped `<feature>:<action>` permissions. Empty for the `default` user. */
  permissions: string[]
  /** true for a verified signed-in identity; false for the `default` (logged-out) user. */
  authenticated: boolean
}

/** Reserved username/key for the logged-out user. Verified emails always contain `@`, so no clash. */
export const DEFAULT_USER_ID = "default"

/**
 * The single logged-out principal. Used whenever no valid session is present, so controllers always
 * receive an AuthUser (pm/security.mdx §2.1). Carries NO roles/permissions, so admin gates refuse it.
 * Frozen because it is a shared singleton — never mutate it.
 */
export const DEFAULT_USER: AuthUser = Object.freeze({
  userId: DEFAULT_USER_ID,
  email: DEFAULT_USER_ID,
  sessionId: null,
  orgId: null,
  roles: [],
  permissions: [],
  authenticated: false,
})

/**
 * @CurrentUser() — inject the current user into a controller handler. The global JwtAuthGuard runs
 * first and always populates `request.user` (the verified identity, or the `default` user when
 * logged out). The `?? DEFAULT_USER` is a belt-and-suspenders fallback so a handler can never see
 * `undefined` even on a route that somehow skipped the guard.
 */
export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): AuthUser => {
    const request = ctx.switchToHttp().getRequest<{ user?: AuthUser }>()
    return request.user ?? DEFAULT_USER
  },
)
