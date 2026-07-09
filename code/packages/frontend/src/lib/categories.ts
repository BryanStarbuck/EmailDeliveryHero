/**
 * The seven dashboard categories (pm/ui.mdx §1.1) and the roll-up from a flat finding list to one
 * color-coded StatusCell per category. Every checker's finding lands in exactly one category,
 * chosen by the prefix of its `checkId` (`checkId.split(".")[0]`): spf, dkim, dmarc/arc,
 * blacklist/dnsbl, infra, content — plus DNSSEC, which is carved out of `infra.*` into its own
 * column (matched on the `infra.dnssec` id prefix, ahead of the generic first-segment lookup). ARC
 * has no cell of its own — it feeds DMARC; `dnsbl` is the Blacklists prefix the specs use,
 * `blacklist` the checker's registry id.
 */
import type { Finding, Severity } from "@/api/types";

/** The dashboard column keys, in display order. */
export type CategoryKey =
	| "spf"
	| "dkim"
	| "dmarc"
	| "blacklists"
	| "dnsInfra"
	| "dnssec"
	| "spamContent";

/** Cell color drives the Tailwind background (pm/ui.mdx §1.2). */
export type CellColor = "green" | "amber" | "red" | "gray";

export interface CellStatus {
	color: CellColor;
	/** Short metric string, ≤10 chars ideal. */
	label: string;
	/** Longer text for the cell tooltip (the top open problem, or a healthy summary). */
	title: string;
}

interface CategoryDef {
	key: CategoryKey;
	header: string;
	/** `checkId` prefixes that roll into this category. */
	prefixes: string[];
}

/** The categories in their display order. `dnssec` sits next to its parent `DNS` column. */
export const CATEGORIES: CategoryDef[] = [
	{ key: "spf", header: "SPF", prefixes: ["spf"] },
	// DKIM2 (pm/checks/dkim2.mdx) is a companion of DKIM — its findings roll into the DKIM cell.
	{ key: "dkim", header: "DKIM", prefixes: ["dkim", "dkim2"] },
	// DMARCbis (pm/checks/dmarcbis.mdx) is the standards-conformance companion of DMARC, like ARC.
	{ key: "dmarc", header: "DMARC", prefixes: ["dmarc", "arc", "dmarcbis"] },
	{ key: "blacklists", header: "Blacklists", prefixes: ["blacklist", "dnsbl"] },
	// Header shortened to "DNS" (pm/ui.mdx §1.1) so the column is narrow; DNSSEC is split out below.
	{ key: "dnsInfra", header: "DNS", prefixes: ["infra"] },
	{ key: "dnssec", header: "DNSSEC", prefixes: ["infra.dnssec"] },
	{ key: "spamContent", header: "Spam & Content", prefixes: ["content"] },
];

const PREFIX_TO_KEY: Record<string, CategoryKey> = Object.fromEntries(
	CATEGORIES.flatMap((c) => c.prefixes.map((p) => [p, c.key])),
) as Record<string, CategoryKey>;

/** Which category a finding belongs to (by its checkId prefix). */
export function categoryOf(checkId: string): CategoryKey | null {
	// DNSSEC findings share the `infra.` first segment with the rest of DNS & Infrastructure but get
	// their own dashboard column (pm/ui.mdx §1.1) — match their `infra.dnssec*` ids before the
	// generic first-segment lookup so they land in the DNSSEC cell, not the DNS cell.
	if (checkId.startsWith("infra.dnssec")) return "dnssec";
	return PREFIX_TO_KEY[checkId.split(".")[0]] ?? null;
}

/**
 * Categories that have a dedicated full-page technology view (pm/checks/*.mdx §6): the chevron on
 * their Dashboard cell / run-detail chip routes here. Extend as more check pages are built.
 */
export const TECH_PAGE_ROUTES = {
	spf: "/domains/$id/spf",
	dkim: "/domains/$id/dkim",
	dmarc: "/domains/$id/dmarc",
	// Newest-run alias of the run-scoped Blacklists page (pm/checks/blacklists.mdx §13.2).
	blacklists: "/domains/$id/blacklists",
	dnsInfra: "/domains/$id/dns",
	// The Content-scoring full page (pm/checks/content_scoring.mdx §4).
	spamContent: "/domains/$id/content",
} as const;

export function techPageRoute(
	key: CategoryKey,
): (typeof TECH_PAGE_ROUTES)[keyof typeof TECH_PAGE_ROUTES] | null {
	return key in TECH_PAGE_ROUTES
		? TECH_PAGE_ROUTES[key as keyof typeof TECH_PAGE_ROUTES]
		: null;
}

/** The never-run cell — no audit has produced this category yet. */
export const NEVER_CELL: CellStatus = {
	color: "gray",
	label: "Never",
	title: "Never run",
};

const WORST: Record<Severity, number> = {
	ok: 0,
	info: 1,
	warning: 2,
	critical: 3,
};

function colorFor(worst: Severity): CellColor {
	if (worst === "critical") return "red";
	if (worst === "warning") return "amber";
	return "green"; // ok / info → healthy (info never turns a cell amber)
}

/** Roll one category's findings into a StatusCell. */
function cellFor(key: CategoryKey, findings: Finding[]): CellStatus {
	if (findings.length === 0) return NEVER_CELL;

	let worst: Severity = "ok";
	for (const f of findings)
		if (WORST[f.severity] > WORST[worst]) worst = f.severity;
	const color = colorFor(worst);

	const failing = findings.filter(
		(f) => f.severity === "warning" || f.severity === "critical",
	);
	const top = [...failing].sort(
		(a, b) => WORST[b.severity] - WORST[a.severity],
	)[0];

	// Metric text (pm/dashboard.mdx §5.2 / pm/ui.mdx §1.3): ONE at-a-glance convention across every
	// cell — all sub-tests pass → the literal "Healthy"; otherwise "K of M fail". No cell shows a
	// policy string, selector count, key size, or percentage on the dashboard — that decision-detail
	// lives on the drill-in page, so a green cell always reads "Healthy" and never something the user
	// has to interpret (e.g. a green "p=reject"). Blacklists is the one count-oriented exception, since
	// a blacklist listing is a problem count rather than a pass/fail ratio.
	let label: string;
	if (failing.length === 0) {
		label = "Healthy";
	} else if (key === "blacklists") {
		label = failing.length === 1 ? "1 problem" : `${failing.length} problems`;
	} else {
		label = `${failing.length} of ${findings.length} fail`;
	}

	const title = top ? `${top.title}` : `${findings.length} checks passed`;
	return { color, label, title };
}

/**
 * Roll a whole audit's findings into the category cells (in display order). Each cell's color is the
 * worst finding severity in that category and its label is the uniform "Healthy" / "K of M fail"
 * metric (see cellFor). The optional `_results` argument is accepted for call-site compatibility but
 * no longer consulted: every richer per-category metric (DKIM selector count + key strength, DMARC
 * policy level, Spam & Content percentage) has moved off the dashboard cell and onto the drill-in
 * page, so the dashboard never shows a value the user has to interpret.
 */
export function rollupCategories(
	findings: Finding[] | undefined,
	_results?: Record<string, unknown>,
): Record<CategoryKey, CellStatus> {
	const out = {} as Record<CategoryKey, CellStatus>;
	for (const cat of CATEGORIES) {
		if (!findings) {
			out[cat.key] = NEVER_CELL;
			continue;
		}
		out[cat.key] = cellFor(
			cat.key,
			findings.filter((f) => categoryOf(f.checkId) === cat.key),
		);
	}
	return out;
}
