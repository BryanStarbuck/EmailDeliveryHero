/**
 * The six LOCKED dashboard categories (pm/ui.mdx §1.1) and the roll-up from a flat finding list to
 * one color-coded StatusCell per category. Every checker's finding lands in exactly one category,
 * chosen by the prefix of its `checkId` (`checkId.split(".")[0]`): spf, dkim, dmarc/arc,
 * blacklist/dnsbl, infra, content — the six categories of pm/checks/overview.mdx. ARC has no cell
 * of its own — it feeds DMARC; `dnsbl` is the Blacklists prefix the specs use, `blacklist` the
 * checker's registry id.
 */
import type {
	DkimResults,
	DmarcResults,
	DmarcSection,
	Finding,
	Severity,
} from "@/api/types";
import { normalizeDmarcSection } from "@/lib/dmarc";

/** The six locked column keys, in display order. */
export type CategoryKey =
	| "spf"
	| "dkim"
	| "dmarc"
	| "blacklists"
	| "dnsInfra"
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

/** The six categories in their locked order. */
export const CATEGORIES: CategoryDef[] = [
	{ key: "spf", header: "SPF", prefixes: ["spf"] },
	{ key: "dkim", header: "DKIM", prefixes: ["dkim"] },
	{ key: "dmarc", header: "DMARC", prefixes: ["dmarc", "arc"] },
	{ key: "blacklists", header: "Blacklists", prefixes: ["blacklist", "dnsbl"] },
	{ key: "dnsInfra", header: "DNS & Infrastructure", prefixes: ["infra"] },
	{ key: "spamContent", header: "Spam & Content", prefixes: ["content"] },
];

const PREFIX_TO_KEY: Record<string, CategoryKey> = Object.fromEntries(
	CATEGORIES.flatMap((c) => c.prefixes.map((p) => [p, c.key])),
) as Record<string, CategoryKey>;

/** Which of the six categories a finding belongs to (by its checkId prefix). */
export function categoryOf(checkId: string): CategoryKey | null {
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

	// Metric text per test (pm/dashboard.mdx §5.2 / pm/ui.mdx §1.3): Blacklists is count-oriented
	// ("N problems"); Spam & Content is naturally a percentage (inbox placement — until seed-list
	// placement data exists, the passing-sub-test rate is the percent); everything else is
	// "K of M fail". Healthy cells show the literal "Healthy" except the percent-style cell.
	let label: string;
	if (key === "spamContent") {
		label = `${Math.round(((findings.length - failing.length) / findings.length) * 100)}%`;
	} else if (failing.length === 0) {
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
 * The DKIM cell's decision-relevant metric (pm/checks/dkim.mdx §6.1): working selectors and key
 * strength — `2 selectors · 2048-bit` / `1 of 2 selectors failing` / `selector "s1" missing` /
 * `No selectors`. Falls back to the generic label when the run predates structured DKIM results.
 */
function dkimLabel(dkim: DkimResults): string {
	const probed = dkim.selectors.length;
	if (probed === 0) return "No selectors";
	const failing = dkim.selectors.filter(
		(s) => !s.present || !s.parses || s.is_revoked,
	);
	if (failing.length === 1 && probed <= 2 && !failing[0].present) {
		return `selector "${failing[0].selector}" missing`;
	}
	if (failing.length > 0) {
		return `${failing.length} of ${probed} selector${probed === 1 ? "" : "s"} failing`;
	}
	const rsaBits = dkim.selectors
		.filter((s) => s.key_type === "rsa" && s.key_bits !== null)
		.map((s) => s.key_bits as number);
	const weakest = rsaBits.length > 0 ? Math.min(...rsaBits) : null;
	return `${probed} selector${probed === 1 ? "" : "s"}${weakest ? ` · ${weakest}-bit` : " · ed25519"}`;
}

/**
 * The DMARC cell's decision-relevant metric (pm/checks/dmarc.mdx §6.1): the **policy level** —
 * `p=reject` / `p=quarantine` / `p=none` / `No record`. A record that yields no valid policy
 * (broken syntax, duplicates) keeps the generic "K of M fail" label.
 */
function dmarcLabel(record: DmarcResults, fallback: string): string {
	if (!record.record_found) return "No record";
	if (record.policy) return `p=${record.policy}`;
	return fallback;
}

/**
 * Roll a whole audit's findings into the six category cells (in locked order). Pass the run's
 * structured `results` too when available — categories whose spec defines a richer cell metric
 * (DKIM: working selectors + key strength, pm/checks/dkim.mdx §6.1; DMARC: the policy level,
 * pm/checks/dmarc.mdx §6.1) use it for the label; the color always stays the worst finding
 * severity.
 */
export function rollupCategories(
	findings: Finding[] | undefined,
	results?: Record<string, unknown>,
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
	const dkim = results?.dkim as DkimResults | undefined;
	if (findings && dkim && out.dkim !== NEVER_CELL) {
		out.dkim = { ...out.dkim, label: dkimLabel(dkim) };
	}
	const dmarcRaw = results?.dmarc as DmarcSection | DmarcResults | undefined;
	if (findings && dmarcRaw && out.dmarc !== NEVER_CELL) {
		const { record } = normalizeDmarcSection(dmarcRaw);
		if (record)
			out.dmarc = { ...out.dmarc, label: dmarcLabel(record, out.dmarc.label) };
	}
	return out;
}
