import { existsSync, readdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { readJson, writeJson } from "@shared/json-store";
import { stateSubdir } from "@shared/state-dir";
import type { ComplaintBoard } from "./complaint.types";

/**
 * Per-run complaint snapshots (pm/Email_Complaints.mdx §12).
 *
 * "Snapshots persist as `complaints.json` beside the run … so a historical run renders its complaint
 * board exactly as it was." Reports keep arriving after a run finishes, so rebuilding the board live
 * for an old run would show today's evidence under yesterday's heading — the run-scoped routes in
 * §9.6 would silently lie. The snapshot is written once when the run is persisted and is never
 * edited afterward, exactly like the run YAML it sits beside:
 *
 *   <state>/runs/<domain>/complaints/<runId>.json
 *
 * A snapshot is best-effort: failing to write one must never fail the audit run that produced it.
 */

/** A path-safe file stem — the same rule report-store.ts uses. */
function safeStem(value: string): string {
	const cleaned = (value ?? "")
		.replace(/[^A-Za-z0-9._@+-]+/g, "_")
		.replace(/\.\./g, "_");
	return cleaned.length > 0 ? cleaned : "unknown";
}

/**
 * The snapshot directory for one domain. `domainDir` is the same sanitized directory name
 * runs-store.ts writes the run YAML into, so the snapshot really does sit beside the run.
 */
function snapshotDir(domainDir: string): string {
	return stateSubdir("runs", safeStem(domainDir), "complaints");
}

function snapshotPath(domainDir: string, runId: string): string {
	return join(snapshotDir(domainDir), `${safeStem(runId)}.json`);
}

/**
 * Persist one run's complaint board. Written once — an existing snapshot is left alone, because run
 * history is immutable and a re-persist would rewrite the past.
 */
export function saveComplaintSnapshot(
	domainDir: string,
	runId: string,
	board: ComplaintBoard,
): void {
	const path = snapshotPath(domainDir, runId);
	if (existsSync(path)) return;
	writeJson(path, board);
}

/** One run's stored board, or null when that run predates snapshots (or none was written). */
export function readComplaintSnapshot(
	domainDir: string,
	runId: string,
): ComplaintBoard | null {
	return readJson<ComplaintBoard | null>(snapshotPath(domainDir, runId), null);
}

/**
 * Every stored snapshot for one domain, newest window-end first. Backs the §10.4 run-history strip,
 * which trends one complaint's volume across the last 10 windows.
 */
export function listComplaintSnapshots(domainDir: string): ComplaintBoard[] {
	let files: string[] = [];
	try {
		files = readdirSync(snapshotDir(domainDir)).filter((f) =>
			f.endsWith(".json"),
		);
	} catch {
		return [];
	}
	const out: ComplaintBoard[] = [];
	for (const file of files) {
		const board = readJson<ComplaintBoard | null>(
			join(snapshotDir(domainDir), file),
			null,
		);
		if (board) out.push(board);
	}
	return out.sort((a, b) =>
		(b.window?.end ?? "").localeCompare(a.window?.end ?? ""),
	);
}

/**
 * Drop one run's snapshot. Called when the run itself is pruned or deleted, so snapshots can never
 * outlive the runs they describe and accumulate forever.
 */
export function deleteComplaintSnapshot(
	domainDir: string,
	runId: string,
): void {
	const path = snapshotPath(domainDir, runId);
	try {
		if (existsSync(path)) unlinkSync(path);
	} catch {
		// Best-effort: an orphaned snapshot is harmless, a throw during run deletion is not.
	}
}
