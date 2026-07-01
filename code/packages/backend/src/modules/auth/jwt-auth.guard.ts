import { type ExecutionContext, Injectable } from "@nestjs/common"
import { Reflector } from "@nestjs/core"
import { AuthGuard } from "@nestjs/passport"
import { logWarn } from "@shared/logging"
import { IS_PUBLIC_KEY } from "./public.decorator"

/**
 * Global guard: every route requires a valid OpenAuthFederated Bearer token unless marked
 * @Public(). Registered as APP_GUARD so auth is on by default, app-wide.
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard("jwt") {
  constructor(private readonly reflector: Reflector) {
    super()
  }

  canActivate(context: ExecutionContext) {
    let isPublic = false
    try {
      isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
        context.getHandler(),
        context.getClass(),
      ])
    } catch (err) {
      // Fail closed: if metadata reflection throws, enforce JWT rather than bypass auth.
      const message = err instanceof Error ? err.message : String(err)
      logWarn(`Failed to read @Public metadata, failing closed: ${message}`, "JwtAuthGuard")
      isPublic = false
    }
    if (isPublic) return true
    return super.canActivate(context)
  }
}
