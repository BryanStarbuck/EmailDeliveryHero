/**
 * The shared shape of a per-technology problem-state catalog entry (pm/checks/*.mdx §9) and the
 * matching helpers. Each technology (DMARC, SPF, …) owns its own catalog file (dmarc-problems.ts,
 * spf-problems.ts); the drill-down pages render this one shape via <ProblemDrilldown>.
 */
import type { Finding } from "@/api/types";

export interface ProblemState {
	id: string;
	title: string;
	/** One-line hook shown on the problem-state card. */
	hook: string;
	severity: "ok" | "info" | "warning" | "critical";
	/** Finding ids whose presence at warning/critical severity matches this state. */
	findingIds: string[];
	/** 2–3 short paragraphs explaining the concept. */
	concept: string[];
	/** Which test-result fields to look at (the §5 YAML of the owning spec). */
	dataFields: string[];
	/** Copyable terminal commands to diagnose it yourself (`<domain>` is substituted). */
	commands: string[];
	tools: string[];
	/** Further health metrics to watch. */
	metrics: string[];
	/** Numbered steps to progress forward. */
	pathForward: string[];
}

/** Problem states matched by the latest run's failing findings. */
export function matchProblemStates<T extends ProblemState>(
	states: T[],
	findings: Finding[],
): T[] {
	const failing = new Set(
		findings
			.filter((f) => f.severity === "warning" || f.severity === "critical")
			.map((f) => f.id),
	);
	return states.filter((ps) => ps.findingIds.some((id) => failing.has(id)));
}

export function problemStateById<T extends ProblemState>(
	states: T[],
	id: string,
): T | undefined {
	return states.find((ps) => ps.id === id);
}
