import { AuditController } from "@module/audit/audit.controller";
import { ContentSampleController } from "@module/audit/content-sample.controller";
import { BlacklistsController } from "@module/blacklists/blacklists.controller";
import { DomainsController } from "@module/domains/domains.controller";
import { InstallController } from "@module/install/install.controller";
import { ComplaintsController } from "@module/reports/complaints.controller";
import { ReportsController } from "@module/reports/reports.controller";
import {
	REQUIRE_AUTH_KEY,
	REQUIRED_PERMISSIONS_KEY,
	REQUIRED_ROLES_KEY,
} from "./roles.decorator";

/**
 * Regression guard for the optional-login contract (pm/security.mdx §3.3, §6, AC 1).
 *
 * Login is OPTIONAL: the normal user is the logged-out `default` user, who holds no roles and no
 * permissions. So ANY authorization decorator on the ordinary auditing surface is not "hardening" —
 * it is an outage. A hardening pass once put `@RequireAuth()` across these controllers and made the
 * whole install controller admin-only; the product still rendered (reads are open) but every write
 * and every "Run checks" silently 403'd, and the fault trail filled with RolesGuard denials.
 *
 * These tests assert the decorators are absent, by reading the same metadata keys RolesGuard reads.
 * They are metadata-only (no Nest boot), so they stay fast and cannot be defeated by DI wiring.
 */

type Ctor = new (...args: never[]) => object;

/** Every route-handler method name declared on a controller class. */
function handlerNames(controller: Ctor): string[] {
	return Object.getOwnPropertyNames(controller.prototype).filter(
		(name) => name !== "constructor",
	);
}

/** The authz metadata RolesGuard would see for one handler (handler first, then class fallback). */
function authzFor(controller: Ctor, method: string) {
	const handler = controller.prototype[method as keyof object];
	const read = (key: string) =>
		Reflect.getMetadata(key, handler as object) ??
		Reflect.getMetadata(key, controller);
	return {
		requireAuth: read(REQUIRE_AUTH_KEY) as boolean | undefined,
		roles: read(REQUIRED_ROLES_KEY) as string[] | undefined,
		permissions: read(REQUIRED_PERMISSIONS_KEY) as string[] | undefined,
	};
}

/** True when the logged-out `default` user (no roles, no permissions) would be refused. */
function deniesDefaultUser(controller: Ctor, method: string): boolean {
	const { requireAuth, roles, permissions } = authzFor(controller, method);
	return (
		requireAuth === true ||
		(Array.isArray(roles) && roles.length > 0) ||
		(Array.isArray(permissions) && permissions.length > 0)
	);
}

describe("optional login: the ordinary auditing surface stays open", () => {
	// The controllers that make up normal product use. Gating ANY route here breaks the app for the
	// `default` user, which is how the app is normally used (pm/security.mdx §6 — explicit non-goal).
	const OPEN_CONTROLLERS: Array<[string, Ctor]> = [
		["AuditController", AuditController as unknown as Ctor],
		["DomainsController", DomainsController as unknown as Ctor],
		["BlacklistsController", BlacklistsController as unknown as Ctor],
		["ReportsController", ReportsController as unknown as Ctor],
		["ComplaintsController", ComplaintsController as unknown as Ctor],
		["ContentSampleController", ContentSampleController as unknown as Ctor],
	];

	it.each(OPEN_CONTROLLERS)(
		"%s refuses no route to the logged-out default user",
		(_label, controller) => {
			const gated = handlerNames(controller).filter((m) =>
				deniesDefaultUser(controller, m),
			);
			expect(gated).toEqual([]);
		},
	);

	it("no controller in the auditing surface carries a class-level gate", () => {
		for (const [, controller] of OPEN_CONTROLLERS) {
			expect(Reflect.getMetadata(REQUIRE_AUTH_KEY, controller)).toBeUndefined();
			expect(
				Reflect.getMetadata(REQUIRED_ROLES_KEY, controller),
			).toBeUndefined();
		}
	});
});

describe("install: mutating routes are admin-gated, reads stay open", () => {
	const Install = InstallController as unknown as Ctor;

	// These SHELL OUT to brew/npm/pipx (with maintainer post-install scripts) as the service
	// account. They are real admin configuration and must stay gated (security audit finding #1).
	it.each(["detect", "run"])("%s requires role admin", (method) => {
		expect(authzFor(Install, method).roles).toEqual(["admin"]);
	});

	// Read-only, and `preflight` sits on the critical path of every run: gating it stopped the
	// logged-out user from starting any check at all.
	it.each(["catalog", "preflight", "jobStatus", "jobStream"])(
		"%s is open to the default user",
		(method) => {
			expect(deniesDefaultUser(Install, method)).toBe(false);
		},
	);

	it("has no class-level gate (that is what closed the read routes before)", () => {
		expect(Reflect.getMetadata(REQUIRED_ROLES_KEY, Install)).toBeUndefined();
	});
});
