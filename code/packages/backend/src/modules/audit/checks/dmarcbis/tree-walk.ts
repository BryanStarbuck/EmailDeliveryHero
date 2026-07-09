/**
 * The RFC 9989 DNS **tree walk** (pm/checks/dmarcbis.mdx §1/§4) — the headline DMARCbis change that
 * replaces the static Public Suffix List with a live, ordered series of `_dmarc.<name>` TXT lookups
 * climbing from the Author Domain toward the root to find the **Organizational Domain**.
 *
 * This module is a **pure helper**: `resolveOrgDomain` takes an INJECTED async TXT resolver
 * (`TxtResolver`) so the checker wires it to `dns-util.resolveTxt` in production while the unit tests
 * feed a fake resolver — no real DNS, fully deterministic. Nothing here imports `node:dns`.
 *
 * Algorithm (pm/checks/dmarcbis.mdx §1):
 *   1. Query `_dmarc.<author-domain>` first.
 *   2. If nothing definitive, drop labels from the LEFT and query each parent, **capped at 8 queries**.
 *      For a name of ≤7 labels strip ONE label at a time; for a longer name remove SEVERAL at once so
 *      only 7 remain, then continue one at a time.
 *   3. Select the Org Domain, longest → shortest: a `psd=n` record marks its own domain (stop); a
 *      `psd=y` record that is not the starting rung puts the Org Domain one label below it; else the
 *      record with the fewest labels wins.
 */

/**
 * The injected TXT resolver: given a full query name (e.g. `_dmarc.example.com`) it returns the raw
 * TXT strings found (empty when none) and an optional transient `error`. Mirrors the relevant slice
 * of `dns-util.resolveTxt`'s result so the checker can adapt it in one line.
 */
export type TxtResolver = (
	name: string,
) => Promise<{ records: string[]; error?: string }>;

/** One rung of the walk actually queried, in walk order (longest → shortest). */
export interface QueryRung {
	/** The full DNS name queried, e.g. `_dmarc.example.com`. */
	name: string;
	/** Label count of the DOMAIN part (the name minus the `_dmarc.` prefix) — `example.com` ⇒ 2. */
	labels: number;
	/** A `v=DMARC1` record was found at this rung. */
	recordFound: boolean;
	/** The rung record's `psd` value (lower-cased) — `n` | `y` | `u` — or null when absent/no record. */
	psd: string | null;
}

/** How the Organizational Domain was chosen (pm/checks/dmarcbis.mdx §5 `selected_by`). */
export type SelectedBy = "psd=n" | "psd=y-below" | "fewest-labels";

/** How the walk terminated (pm/checks/dmarcbis.mdx §5 `found_via`). */
export type FoundVia = "treewalk" | "parent" | "tld-cap";

/** The full result of one tree walk — maps 1:1 onto the run YAML's `org_domain:` block (§5). */
export interface OrgDomainResolution {
	/** The Author Domain the walk started from. */
	authorDomain: string;
	/** The selected Organizational Domain (bare, no `_dmarc.`); null when no record was found. */
	resolvedOrgDomain: string | null;
	/** `treewalk` (own record) | `parent` (covered by an ancestor) | `tld-cap` (no record found). */
	foundVia: FoundVia;
	/** Which selection rule fired; null when no record was found. */
	selectedBy: SelectedBy | null;
	/** Label count of the resolved Org Domain; null when none. */
	labelCount: number | null;
	/** Every rung actually queried, in order. */
	queryPath: QueryRung[];
	/** True when the Org Domain is a strict ancestor of the Author Domain (parent governs via `sp`). */
	coveredByParent: boolean;
}

/** The DMARCbis query cap (RFC 9989 §1) — the walk never issues more than this many lookups. */
export const TREE_WALK_QUERY_CAP = 8;

/** True when a raw TXT string is a DMARC record (starts with `v=DMARC1`, case-insensitive). */
export function isDmarcRecord(raw: string): boolean {
	return raw.trim().toLowerCase().startsWith("v=dmarc1");
}

/** Read one tag (e.g. `psd`, `v`) out of a raw DMARC record; null when absent. Value trimmed. */
export function readTag(raw: string, name: string): string | null {
	const m = new RegExp(`(?:^|;)\\s*${name}\\s*=\\s*([^;]*)`, "i").exec(raw);
	return m ? m[1].trim() : null;
}

/** Strip the leading `_dmarc.` label from a query name to get the bare domain. */
function bareDomain(queryName: string): string {
	return queryName.replace(/^_dmarc\./i, "");
}

/** The last `k` labels of `domain`, joined — the ancestor `k` levels up from the leaf. */
function suffixLabels(domain: string, k: number): string {
	return domain.split(".").filter(Boolean).slice(-k).join(".");
}

/**
 * The ordered list of DOMAIN names (bare, no `_dmarc.`) the walk will query for one author domain,
 * following the §1 algorithm and capped at 8. Exported for unit tests that assert the exact
 * 8-query sequence of the canonical `a.b.c.d.e.f.g.h.i.j.mail.example.com` example.
 */
export function buildWalkNames(author: string): string[] {
	const labels = author.split(".").filter(Boolean);
	const n = labels.length;
	const names: string[] = [author];
	// ≤7 labels: strip one at a time from n-1 down. >7 labels: jump to 7 (remove several at once),
	// then one at a time down to a single-label parent.
	const start = n > 7 ? 7 : n - 1;
	for (let k = start; k >= 1; k--) names.push(labels.slice(-k).join("."));
	return names.slice(0, TREE_WALK_QUERY_CAP);
}

/**
 * Select the Organizational Domain from an already-walked query path (longest → shortest, per §1).
 * Pure and separately testable: `queryPath` is assumed to be in walk order (longest name first).
 */
export function selectOrgDomain(
	author: string,
	queryPath: QueryRung[],
): Pick<
	OrgDomainResolution,
	"resolvedOrgDomain" | "foundVia" | "selectedBy" | "labelCount" | "coveredByParent"
> {
	const authorLabels = author.split(".").filter(Boolean).length;
	const withRecord = queryPath.filter((r) => r.recordFound);
	if (withRecord.length === 0) {
		return {
			resolvedOrgDomain: null,
			foundVia: "tld-cap",
			selectedBy: null,
			labelCount: null,
			coveredByParent: false,
		};
	}

	const finalize = (
		dom: string,
		selectedBy: SelectedBy,
		labelCount: number,
	): ReturnType<typeof selectOrgDomain> => ({
		resolvedOrgDomain: dom,
		selectedBy,
		labelCount,
		foundVia: labelCount === authorLabels ? "treewalk" : "parent",
		coveredByParent: dom !== author,
	});

	// 1. Longest rung declaring psd=n → its own domain is the Org Domain (stop).
	const psdN = withRecord.find((r) => r.psd === "n");
	if (psdN) return finalize(bareDomain(psdN.name), "psd=n", psdN.labels);

	// 2. A psd=y rung that is NOT the walk's starting rung → Org Domain is one label below it.
	const startName = queryPath[0]?.name;
	const psdY = withRecord.find((r) => r.psd === "y" && r.name !== startName);
	if (psdY) {
		const k = psdY.labels + 1;
		return finalize(suffixLabels(author, k), "psd=y-below", k);
	}

	// 3. Otherwise the record with the fewest labels wins.
	const fewest = withRecord.reduce((a, b) => (b.labels < a.labels ? b : a));
	return finalize(bareDomain(fewest.name), "fewest-labels", fewest.labels);
}

/**
 * Run the ordered RFC 9989 tree walk toward the root using the injected resolver, then select the
 * Organizational Domain. Stops early the moment a rung's record declares `psd=n` (its own domain is
 * the Org Domain) or, at a non-starting rung, `psd=y` (Org Domain one label below) — otherwise it
 * walks the full capped sequence and falls back to the fewest-labels record.
 */
export async function resolveOrgDomain(
	author: string,
	resolver: TxtResolver,
): Promise<OrgDomainResolution> {
	const names = buildWalkNames(author);
	const queryPath: QueryRung[] = [];
	for (const dom of names) {
		const q = `_dmarc.${dom}`;
		const res = await resolver(q);
		const record = (res.records ?? []).find(isDmarcRecord);
		const psd = record ? (readTag(record, "psd")?.toLowerCase() ?? null) : null;
		queryPath.push({
			name: q,
			labels: dom.split(".").filter(Boolean).length,
			recordFound: Boolean(record),
			psd,
		});
		// Stop conditions (§1 selection, evaluated as we descend longest → shortest):
		if (record && psd === "n") break; // this domain IS the Org Domain
		if (record && psd === "y" && queryPath.length > 1) break; // Org Domain is one below
	}
	return { authorDomain: author, ...selectOrgDomain(author, queryPath), queryPath };
}
