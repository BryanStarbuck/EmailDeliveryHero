import type {
	BoardVerdict,
	Complaint,
	ComplaintTrend,
	ComplaintVerdict,
} from "@/api/types";

/**
 * UI copy and grouping for the Email Complaints surface (pm/Email_Complaints.mdx §8/§10).
 *
 * The wording here carries most of the product's value. Half of what receivers report is the system
 * WORKING — a spoofer rejected, a forward rescued by ARC — and rendering that as a red alarm is the
 * single most common failure of DMARC dashboards. So verdicts are always spelled out in words as
 * well as colour (§10.5), and the "not your problem" group says so in its heading.
 */

export const BOARD_VERDICT_COPY: Record<
	BoardVerdict,
	{ label: string; icon: string; blurb: string; tone: string; accent: string }
> = {
	action: {
		label: "Action required",
		icon: "🚨",
		blurb: "Something is broken, or is about to be.",
		tone: "border-red-200 bg-red-50 text-red-900",
		accent: "text-red-700",
	},
	attention: {
		label: "Needs attention",
		icon: "⚠️",
		blurb: "Nothing is failing yet, but something will.",
		tone: "border-amber-200 bg-amber-50 text-amber-900",
		accent: "text-amber-700",
	},
	watch: {
		label: "Healthy, with things to watch",
		icon: "👀",
		blurb: "Your mail is authenticating. A few streams are fragile.",
		tone: "border-sky-200 bg-sky-50 text-sky-900",
		accent: "text-sky-700",
	},
	ok: {
		label: "All clear",
		icon: "✅",
		blurb: "Everything receivers reported authenticated correctly.",
		tone: "border-emerald-200 bg-emerald-50 text-emerald-900",
		accent: "text-emerald-700",
	},
	insufficient_data: {
		label: "Not enough data",
		icon: "⬜",
		blurb: "Too few reports have arrived to draw a conclusion.",
		tone: "border-slate-200 bg-slate-50 text-slate-800",
		accent: "text-slate-600",
	},
};

/** The three Zone B groups, in their fixed render order (§10.2). */
export const COMPLAINT_GROUPS: {
	verdict: ComplaintVerdict;
	heading: string;
	sub: string;
	chip: string;
}[] = [
	{
		verdict: "problem",
		heading: "⚠️ Action required",
		sub: "These are yours to fix. Each one has a step in the plan below.",
		chip: "bg-red-100 text-red-800",
	},
	{
		verdict: "watch",
		heading: "👀 Worth watching",
		sub: "Working today, fragile or unexplained. No emergency.",
		chip: "bg-sky-100 text-sky-800",
	},
	{
		verdict: "ok",
		heading: "✅ Not your problem — the system worked",
		sub: "Listed so the numbers add up, and so a blocked attacker is never mistaken for a bug.",
		chip: "bg-emerald-100 text-emerald-800",
	},
];

export const TREND_COPY: Record<
	ComplaintTrend,
	{ glyph: string; label: string; tone: string }
> = {
	new: { glyph: "●", label: "new", tone: "text-fuchsia-700" },
	worse: { glyph: "▲", label: "worse", tone: "text-red-700" },
	steady: { glyph: "▬", label: "steady", tone: "text-slate-500" },
	better: { glyph: "▼", label: "better", tone: "text-emerald-700" },
	resolved: { glyph: "✔", label: "resolved", tone: "text-emerald-700" },
};

/** Zone B filter tabs (§10.2). */
export const COMPLAINT_FILTERS = [
	{ id: "all", label: "All" },
	{ id: "problem", label: "Problems" },
	{ id: "watch", label: "Watch" },
	{ id: "ok", label: "Working as intended" },
] as const;

export type ComplaintFilter = (typeof COMPLAINT_FILTERS)[number]["id"];

/**
 * The trend chip for one complaint. Direction alone is not a verdict: a rise in C00 "fully
 * authenticated mail" is good news, and rendering it as a red ▲ worse would be a lie. For `ok`
 * complaints the sense is inverted, and the colour follows whether the movement HELPS.
 */
export function trendFor(complaint: Complaint): {
	glyph: string;
	label: string;
	tone: string;
} {
	const base = TREND_COPY[complaint.trend];
	if (complaint.verdict !== "ok") return base;
	if (complaint.trend === "worse")
		return { glyph: "▲", label: "more", tone: "text-emerald-700" };
	if (complaint.trend === "better")
		return { glyph: "▼", label: "less", tone: "text-slate-500" };
	return { ...base, tone: "text-slate-500" };
}

export function filterComplaints(
	complaints: Complaint[],
	filter: ComplaintFilter,
): Complaint[] {
	return filter === "all"
		? complaints
		: complaints.filter((c) => c.verdict === filter);
}

/** Numbers always carry their denominator, and small ones are never rounded away (§10.5). */
export function formatVolume(messages: number, sharePct: number): string {
	// The share arrives rounded to one decimal, so a genuine 0.04% comes back as 0. A real count
	// must never read as "0%" — that says "none", which is the opposite of the truth (§10.5).
	const share =
		messages > 0 && sharePct < 0.1 ? "<0.1%" : `${sharePct}%`;
	return `${messages.toLocaleString()} msg${messages === 1 ? "" : "s"} · ${share}`;
}

/** A delta rendered with its sign, or an em dash when there is no prior window. */
export function formatDelta(value: number, unit = ""): string {
	if (!Number.isFinite(value) || value === 0) return "—";
	const sign = value > 0 ? "+" : "";
	return `${sign}${Math.round(value * 10) / 10}${unit}`;
}
