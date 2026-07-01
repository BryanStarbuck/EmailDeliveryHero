import type { ExecutionContext } from "@nestjs/common"
import type { Reflector } from "@nestjs/core"
import { type AuthUser, DEFAULT_USER } from "@shared/current-user.decorator"
import { REQUIRED_PERMISSIONS_KEY, REQUIRED_ROLES_KEY } from "./roles.decorator"
import { RolesGuard } from "./roles.guard"

/** A signed-in user with the given roles/permissions. */
function signedIn(roles: string[] = [], permissions: string[] = []): AuthUser {
  return {
    userId: "user_1",
    email: "person@whitehatengineering.com",
    sessionId: "sess_1",
    orgId: null,
    roles,
    permissions,
    authenticated: true,
  }
}

/** Build a guard whose Reflector returns the given route metadata, plus a context with `user`. */
function setup(meta: { roles?: string[]; permissions?: string[] }, user?: AuthUser) {
  const reflector = {
    getAllAndOverride: (key: string) =>
      key === REQUIRED_ROLES_KEY
        ? meta.roles
        : key === REQUIRED_PERMISSIONS_KEY
          ? meta.permissions
          : undefined,
  } as unknown as Reflector
  const guard = new RolesGuard(reflector)
  const context = {
    getHandler: () => () => undefined,
    getClass: () => class {},
    switchToHttp: () => ({ getRequest: () => ({ user }) }),
  } as unknown as ExecutionContext
  return { guard, context }
}

describe("RolesGuard", () => {
  it("allows an ungated route for the default (logged-out) user", () => {
    const { guard, context } = setup({}, DEFAULT_USER)
    expect(guard.canActivate(context)).toBe(true)
  })

  it("refuses @RequireRole('admin') for the default user with 403", () => {
    const { guard, context } = setup({ roles: ["admin"] }, DEFAULT_USER)
    expect(() => guard.canActivate(context)).toThrow(/permission/i)
  })

  it("refuses @RequireRole('admin') for a signed-in non-admin", () => {
    const { guard, context } = setup({ roles: ["admin"] }, signedIn(["member"]))
    expect(() => guard.canActivate(context)).toThrow()
  })

  it("allows @RequireRole('admin') for a signed-in admin", () => {
    const { guard, context } = setup({ roles: ["admin"] }, signedIn(["admin"]))
    expect(guard.canActivate(context)).toBe(true)
  })

  it("enforces @RequirePermission independently of roles", () => {
    const denied = setup({ permissions: ["settings:write"] }, signedIn(["admin"], []))
    expect(() => denied.guard.canActivate(denied.context)).toThrow()

    const allowed = setup({ permissions: ["settings:write"] }, signedIn([], ["settings:write"]))
    expect(allowed.guard.canActivate(allowed.context)).toBe(true)
  })

  it("requires BOTH when role and permission are specified", () => {
    // Has the role but not the permission → denied.
    const { guard, context } = setup(
      { roles: ["admin"], permissions: ["settings:write"] },
      signedIn(["admin"], []),
    )
    expect(() => guard.canActivate(context)).toThrow()
  })

  it("falls back to the default user (denies) when request.user is missing", () => {
    const { guard, context } = setup({ roles: ["admin"] }, undefined)
    expect(() => guard.canActivate(context)).toThrow()
  })
})
