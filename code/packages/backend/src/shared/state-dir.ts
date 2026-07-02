import { existsSync, mkdirSync, renameSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * The single out-of-repo state directory for EmailDeliveryHero. Everything the app persists —
 * the monitored-domains store, audit history, the auth session store, the auth signing secret,
 * and the two log files (log.log / error.err) — lives here so no runtime data is ever committed
 * to the repo. See pm/storage.mdx §1 and pm/errors.mdx §1.
 *
 * Default: ~/.email_delivery_hero (override with EDH_STATE_DIR). Created on first use. Falls back
 * to a temp dir if os.homedir() is unavailable (rare, sandboxed hosts) so resolution never throws.
 */

/** Last-resort root when os.homedir() is unavailable. */
const FALLBACK_STATE_DIR = "/tmp/.email_delivery_hero";

/**
 * One-time adoption of a legacy state dir (pm/storage.mdx §16 D1): earlier installs kept their
 * state under ~/T/_emaildeliveryhero/. When the canonical ~/.email_delivery_hero/ does not exist
 * yet and the old-path dir does, rename it into place so an upgrade keeps all its data. Attempted
 * once per process, best-effort (a failed rename just means a fresh dir is created — never a
 * crash). Skipped entirely under an EDH_STATE_DIR override.
 */
let legacyAdoptAttempted = false;
function adoptLegacyStateDir(home: string, canonicalDir: string): void {
	if (legacyAdoptAttempted) return;
	legacyAdoptAttempted = true;
	try {
		if (existsSync(canonicalDir)) return;
		const legacy = join(home, "T", "_emaildeliveryhero");
		if (!existsSync(legacy)) return;
		renameSync(legacy, canonicalDir);
	} catch {
		// Best-effort: never let adoption break state-root resolution. (No logger here — logging.ts
		// resolves its paths through this module, so importing it would be circular.)
	}
}

/** Resolve the state root without side effects other than the best-effort mkdir/adopt. */
function computeStateDir(): string {
	const override = process.env.EDH_STATE_DIR?.trim();
	if (override && override.length > 0) return override;
	try {
		const home = homedir();
		if (home && home.trim() !== "") {
			const dir = join(home, ".email_delivery_hero");
			adoptLegacyStateDir(home, dir);
			return dir;
		}
	} catch {
		// homedir() can throw on a misconfigured host — fall through to the temp dir.
	}
	return FALLBACK_STATE_DIR;
}

export function resolveStateDir(): string {
	const dir = computeStateDir();
	try {
		mkdirSync(dir, { recursive: true });
	} catch {
		// Best-effort: the store/logger retry the mkdir on write, and never crash on a missing folder.
	}
	return dir;
}

/**
 * The log directory. Defaults to the state root so everything for one install lives in one place;
 * override with EDH_LOG_DIR to point logs elsewhere without moving the rest of the state.
 */
export function resolveLogDir(): string {
	const override = process.env.EDH_LOG_DIR?.trim();
	if (override && override.length > 0) {
		try {
			mkdirSync(override, { recursive: true });
		} catch {
			/* best-effort */
		}
		return override;
	}
	return resolveStateDir();
}

/** A subdirectory under the state dir, created on demand. */
export function stateSubdir(...parts: string[]): string {
	const dir = join(resolveStateDir(), ...parts);
	try {
		mkdirSync(dir, { recursive: true });
	} catch {
		/* best-effort */
	}
	return dir;
}
