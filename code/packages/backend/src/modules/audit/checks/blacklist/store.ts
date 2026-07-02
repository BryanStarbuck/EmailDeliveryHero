import { existsSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { withFileLock } from "@shared/config-store";
import { stateSubdir } from "@shared/state-dir";
import { readYaml, writeYaml } from "@shared/yaml-store";
import type {
	BlacklistHistoryEntry,
	BlacklistRunResults,
	PortalUserState,
	ProviderPortal,
} from "./blacklist-types";

/**
 * Per-run persistence for the Blacklists checker (pm/checks/blacklists.mdx §12). Layout under the
 * app state dir (EDH_STATE_DIR). Keyed by the domain NAME (sanitized), not the monitored-domain
 * UUID — deliberately operator-facing, consistent with the runs/<domain>/ rule
 * (pm/storage.mdx §7A/D11):
 *
 *   blacklists/<domain-name>/latest.yaml          — the most recent full BlacklistRunResults
 *   blacklists/<domain-name>/runs/<auditId>.yaml  — append-only history (pruned to MAX_RUNS)
 *   blacklists/<domain-name>/portals.yaml         — the user's provider-portal checklist state
 *
 * The audit engine's audits.json stays latest-only; this store is what powers the diff (§6) and the
 * history sparkline (§13.2). Plain functions (no DI) so both the checker and the Nest controller
 * can use them.
 */

const MAX_RUNS = 50;

function domainDir(domain: string): string {
	return stateSubdir("blacklists", sanitize(domain));
}

function sanitize(part: string): string {
	return part.replace(/[^a-zA-Z0-9._-]/g, "_");
}

export function saveBlacklistRun(
	domain: string,
	run: BlacklistRunResults,
): void {
	const dir = domainDir(domain);
	const runsDir = join(dir, "runs");
	writeYaml(join(runsDir, `${sanitize(run.audit_id)}.yaml`), run);
	writeYaml(join(dir, "latest.yaml"), run);
	pruneRuns(runsDir);
}

function pruneRuns(runsDir: string): void {
	if (!existsSync(runsDir)) return;
	const files = readdirSync(runsDir)
		.filter((f) => f.endsWith(".yaml"))
		.sort(); // audit ids are timestamp-prefixed, so lexical order = chronological
	for (const stale of files.slice(0, Math.max(0, files.length - MAX_RUNS))) {
		try {
			rmSync(join(runsDir, stale));
		} catch {
			// Pruning is best-effort; a leftover run file is harmless.
		}
	}
}

export function readLatestBlacklistRun(
	domain: string,
): BlacklistRunResults | null {
	return readYaml<BlacklistRunResults | null>(
		join(domainDir(domain), "latest.yaml"),
		null,
	);
}

export function readBlacklistHistory(domain: string): BlacklistHistoryEntry[] {
	const runsDir = join(domainDir(domain), "runs");
	if (!existsSync(runsDir)) return [];
	const entries: BlacklistHistoryEntry[] = [];
	for (const file of readdirSync(runsDir)
		.filter((f) => f.endsWith(".yaml"))
		.sort()) {
		const run = readYaml<BlacklistRunResults | null>(join(runsDir, file), null);
		if (!run) continue;
		entries.push({
			audit_id: run.audit_id,
			ran_at: run.ran_at,
			listed: run.summary.listed,
			clean: run.summary.clean,
			inconclusive: run.summary.inconclusive,
			worst_severity: run.summary.worst_severity,
		});
	}
	return entries;
}

/**
 * Full per-run history (chronological, oldest→newest) for one domain — the complete
 * BlacklistRunResults documents, not the compact BlacklistHistoryEntry rows. Powers the
 * reputation check's `content.blocklist_history` trend (pm/checks/reputation_metrics.mdx §2/§7),
 * which needs per-(zone, target) listing detail across runs that the compact summary lacks.
 * Read-only; capped by the store's MAX_RUNS pruning.
 */
export function readBlacklistRuns(domain: string): BlacklistRunResults[] {
	const runsDir = join(domainDir(domain), "runs");
	if (!existsSync(runsDir)) return [];
	const runs: BlacklistRunResults[] = [];
	for (const file of readdirSync(runsDir)
		.filter((f) => f.endsWith(".yaml"))
		.sort()) {
		const run = readYaml<BlacklistRunResults | null>(join(runsDir, file), null);
		if (run) runs.push(run);
	}
	return runs;
}

/**
 * All (sanitized) domain NAMES that have at least one persisted blacklist run — the store's
 * directory keys, not monitored-domain UUIDs (pm/storage.mdx §7A/D11).
 */
export function listBlacklistDomains(): string[] {
	const root = stateSubdir("blacklists");
	if (!existsSync(root)) return [];
	return readdirSync(root, { withFileTypes: true })
		.filter(
			(e) => e.isDirectory() && existsSync(join(root, e.name, "latest.yaml")),
		)
		.map((e) => e.name);
}

type PortalStateFile = Record<string, PortalUserState>;

export function readPortalStates(domain: string): PortalStateFile {
	return readYaml<PortalStateFile>(join(domainDir(domain), "portals.yaml"), {});
}

/**
 * Read-modify-write of the user's portal checklist, serialized per file (pm/storage.mdx §9 —
 * every read-modify-write gets a serialization guard, so two concurrent PATCHes in server mode
 * can never drop each other's state).
 */
export function writePortalState(
	domain: string,
	provider: string,
	state: PortalUserState,
): Promise<PortalStateFile> {
	const path = join(domainDir(domain), "portals.yaml");
	return withFileLock(path, () => {
		const states = readYaml<PortalStateFile>(path, {});
		states[provider] = state;
		writeYaml(path, states);
		return states;
	});
}

export function applyPortalStates(
	portals: Array<Omit<ProviderPortal, "user_state">>,
	states: PortalStateFile,
): ProviderPortal[] {
	return portals.map((p) => ({
		...p,
		user_state: states[p.provider] ?? "unverified",
	}));
}
