import { type ExecutionContext, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { AuthGuard } from "@nestjs/passport";
import { type AuthUser, DEFAULT_USER } from "@shared/current-user.decorator";
import { logWarn } from "@shared/logging";
import { IS_PUBLIC_KEY } from "./public.decorator";

/**
 * Global guard — "identify, don't gate" (pm/security.mdx §3.3). Login is OPTIONAL: this guard tries
 * to verify an OpenAuthFederated Bearer token and, when one is present and valid, attaches the
 * verified identity. When no token is present or it is invalid, it attaches the built-in `default`
 * user and lets the request proceed — it does NOT return 401. Admin-only routes are separately
 * refused for the `default` user by a `role:admin` permission check (403).
 *
 * Registered as APP_GUARD so it runs app-wide. Routes marked @Public() (health, the embedded auth
 * API) skip it entirely.
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard("jwt") {
	constructor(private readonly reflector: Reflector) {
		super();
	}

	canActivate(context: ExecutionContext) {
		let isPublic = false;
		try {
			isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
				context.getHandler(),
				context.getClass(),
			]);
		} catch (err) {
			// If metadata reflection throws, still run the strategy (which now falls back to `default`).
			const message = err instanceof Error ? err.message : String(err);
			logWarn(`Failed to read @Public metadata: ${message}`, "JwtAuthGuard");
			isPublic = false;
		}
		if (isPublic) return true;
		return super.canActivate(context);
	}

	/**
	 * Never throw for "not authenticated." Passport calls this with the verified user on success, or
	 * with an error / no user on failure or absence of a token. In every non-success case we resolve
	 * to the `default` user so the request continues logged-out instead of returning 401.
	 */
	handleRequest<TUser = AuthUser>(_err: unknown, user: unknown): TUser {
		return (user || DEFAULT_USER) as TUser;
	}
}
