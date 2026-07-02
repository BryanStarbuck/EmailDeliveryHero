/**
 * The run-report regression diff (pm/use_cases/view_health_check_run.mdx §7): annotate each of a
 * run's sub-tests relative to the SAME domain's previous run — the preceding run file in the
 * domain's history. Mirrors the periodic scheduler's run-diff (pm/engineering.mdx §8) but is
 * computed on the client from the domain's run list so it works for any historical run being
 * viewed, not just the newest.
 *
 * * NEW — a problem present in this run, absent from the prior run.
 * * STILL PRESENT — a problem carried over from the prior run.
 * * RESOLVED — a sub-test that was a problem in the prior run and now passes / is gone.
 *
 * When there is no prior run to diff against (the domain's first run), `hasPrev` is false and
 * every sub-test is simply shown at its current severity (annotations omitted).
 */
import type { AuditResult, Finding } from "@/api/types";

export type RunAnnotation = "new" | "still";

/** The three regression filters of the §7 "vs previous run" toggle. */
export type RegressionMode = "all" | "new" | "resolved";

export interface RunDiff {
	/** True when a previous run exists for this domain to diff against. */
	hasPrev: boolean;
	/** The previous (chronologically preceding) run, when one exists. */
	prevRun?: AuditResult;
	/** id → "new" | "still" for every open problem in the current run. */
	annotationById: Map<string, RunAnnotation>;
	/** Findings that were problems in the prior run but pass / are gone now (from the prior run). */
	resolved: Finding[];
}

export function isProblem(f: Finding): boolean {
	return f.severity === "warning" || f.severity === "critical";
}

const EMPTY: RunDiff = {
	hasPrev: false,
	annotationById: new Map(),
	resolved: [],
};

/**
 * Diff `current` against the chronologically previous run in `domainRuns` (which the API returns
 * newest-startedAt first). Matching is by finding id — the per-sub-test row id — so a problem that
 * persists across runs is recognised even as its detail text changes.
 */
export function computeRunDiff(
	current: AuditResult | undefined,
	domainRuns: AuditResult[] | undefined,
): RunDiff {
	if (!current) return EMPTY;
	const runs = domainRuns ?? [];
	// Locate the current run in the newest-first list; the previous run is the next-older entry.
	const idx = current.runId
		? runs.findIndex((r) => r.runId === current.runId)
		: runs.findIndex((r) => r.startedAt === current.startedAt);
	const prev = idx >= 0 ? runs[idx + 1] : undefined;
	if (!prev) return EMPTY;

	const prevProblems = new Map(
		prev.findings.filter(isProblem).map((f) => [f.id, f]),
	);
	const currentById = new Map(current.findings.map((f) => [f.id, f]));

	const annotationById = new Map<string, RunAnnotation>();
	for (const f of current.findings) {
		if (!isProblem(f)) continue;
		annotationById.set(f.id, prevProblems.has(f.id) ? "still" : "new");
	}

	const resolved: Finding[] = [];
	for (const [id, f] of prevProblems) {
		const now = currentById.get(id);
		if (!now || !isProblem(now)) resolved.push(f);
	}

	return { hasPrev: true, prevRun: prev, annotationById, resolved };
}
