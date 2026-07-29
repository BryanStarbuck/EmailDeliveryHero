import type {
	BoardVerdict,
	Complaint,
	ComplaintCode,
	ComplaintTrend,
} from "./complaint.types";

/**
 * The verdict model (pm/Email_Complaints.mdx §8) — the two pure scoring functions the board is
 * assembled from, kept in their own module because §14's code map names them here and because they
 * are the part of the surface most worth testing in isolation.
 *
 *   §8.2 `boardVerdict()` — the domain-level answer to "am I OK?", first match wins
 *   §8.4 `trendOf()`      — is this complaint getting better or worse than the previous window?
 *
 * §8.3's escalation thresholds live in board.ts's `escalate()`, because they need the per-code
 * volumes and the observed policy, which only exist once the rows have been classified.
 */

/**
 * §8.4 — one complaint's trend versus the previous window of equal length.
 *
 * `resolved` is deliberately reachable: a complaint that fired last window and not this one stays on
 * the board for one further window (greyed) so the user sees their fix land. That is what turns the
 * page from a nag into feedback.
 */
export function trendOf(current: number, previous: number): ComplaintTrend {
	if (previous === 0) return current > 0 ? "new" : "steady";
	if (current === 0) return "resolved";
	const ratio = current / previous;
	if (ratio > 1.2) return "worse";
	if (ratio < 0.8) return "better";
	return "steady";
}

/**
 * §8.2 — the domain-level verdict shown at the top of the page. Conditions are evaluated in order
 * and the first match wins, so the worst true statement is the one the user reads.
 *
 * `insufficient_data` is checked first and on purpose: silence must never render as health. Fewer
 * than three reports, or a window with no messages at all, is not "all clear" — it is "we cannot
 * tell yet", and saying so is the honest answer.
 */
export function boardVerdict(
	complaints: Complaint[],
	totals: { messages: number; authenticatedPct: number },
	reportCount: number,
): BoardVerdict {
	if (reportCount < 3 || totals.messages === 0) return "insufficient_data";

	const has = (code: ComplaintCode) =>
		complaints.some((c) => c.code === code && c.messages > 0);
	const c03 = complaints.find((c) => c.code === "C03");

	// 🚨 Action required — a critical complaint, our own mail being blocked (C10), or unauthorized
	// mail getting delivered at ≥1% of volume (C03).
	if (
		complaints.some((c) => c.severity === "critical") ||
		has("C10") ||
		(c03 && c03.sharePct >= 1)
	)
		return "action";

	// ⚠️ Needs attention — a warning-level complaint, or a dual-alignment rate under 95%.
	if (
		complaints.some((c) => c.severity === "warning") ||
		totals.authenticatedPct < 95
	)
		return "attention";

	// 👀 Healthy, with things to watch.
	if (complaints.some((c) => c.verdict === "watch")) return "watch";

	// ✅ All clear — only `ok` complaints, which includes a spoofer being correctly rejected.
	return "ok";
}
