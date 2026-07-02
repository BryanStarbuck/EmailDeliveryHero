import { resolve4, resolve6, resolveCname, resolveTxt } from "../dns-util";
import type { CheckContext, Checker, CheckOutcome, Finding } from "../types";

/**
 * BIMI (Brand Indicators for Message Identification). Looks up the `default._bimi.<domain>` TXT
 * record (plus every configured/observed BIMI selector) and validates everything answerable from
 * DNS and the domain's DMARC state: the record's presence, its `v=BIMI1` tag grammar, that exactly
 * one record exists, that DMARC is at enforcement (BIMI's hard prerequisite — the logo renders
 * nowhere on `p=none`), that the `l=` (SVG logo) and `a=` (VMC/CMC) tags are present, and that each
 * URL is a syntactically valid HTTPS URL whose host resolves. The DMARC prerequisite is read from
 * the sibling `dmarc` checker's structured result in the SAME run (the run graph orders dmarc
 * before content.bimi — pm/checks/bimi.mdx §3) rather than re-querying DNS. Fetching the SVG body
 * or the VMC certificate over HTTPS — SVG Tiny-PS profile validation, certificate
 * chain/issuer/expiry checks against the `checks.bimi.mvaAllowList`, and logo-hash matching — is a
 * future round (gated behind the shared HTTPS/TLS probe); those are surfaced here as a single
 * `info` placeholder, never as a warning/critical.
 */

const CHECK_ID = "content.bimi";

/**
 * One selector's structured observation — the JSON-file analog of one `bimi_check_results` row
 * keyed `(audit_run_id, domain_id, selector)` (pm/checks/bimi.mdx §5). The `svgValid` / `vmcValid`
 * / `vmcNotAfter` / `vmcIssuer` columns stay `null` until the future HTTPS/SVG/certificate round.
 */
export interface BimiSelectorResult {
	selector: string;
	present: boolean;
	rawRecord: string | null;
	svgUrl: string | null;
	vmcUrl: string | null;
	dmarcEnforcing: boolean;
	svgValid: boolean | null;
	vmcValid: boolean | null;
	vmcNotAfter: string | null;
	vmcIssuer: string | null;
	checkedAt: string;
}

/**
 * Structured payload persisted as `results["content.bimi"]` (pm/checks/bimi.mdx §5/§8.9). The
 * top-level fields are the primary (`default`-selector) row; `selectors` lists every audited
 * selector's row — the file-store analog of the per-selector unique key.
 */
export interface BimiResults extends BimiSelectorResult {
	selectors: BimiSelectorResult[];
}

interface BimiTags {
	tags: Map<string, string>;
	firstTag: string | null;
	strayTokens: string[];
	unknownTags: string[];
}

/** Tokenize a BIMI TXT record on `;` into a tag map, tracking ordering and malformed/unknown tokens. */
function parseTags(record: string): BimiTags {
	const tags = new Map<string, string>();
	const strayTokens: string[] = [];
	const unknownTags: string[] = [];
	const known = new Set(["v", "l", "a"]);
	let firstTag: string | null = null;
	const parts = record
		.split(";")
		.map((p) => p.trim())
		.filter((p) => p.length > 0);
	for (const part of parts) {
		const eq = part.indexOf("=");
		if (eq === -1) {
			strayTokens.push(part);
			continue;
		}
		const key = part.slice(0, eq).trim().toLowerCase();
		const value = part.slice(eq + 1).trim();
		if (firstTag === null) firstTag = key;
		if (!known.has(key)) unknownTags.push(key);
		if (!tags.has(key)) tags.set(key, value);
	}
	return { tags, firstTag, strayTokens, unknownTags };
}

/** Resolve a host over A then AAAA. "ok" = at least one address; "empty" = genuinely none; "error" = transient. */
async function hostResolves(host: string): Promise<"ok" | "empty" | "error"> {
	const v4 = await resolve4(host);
	if (v4.records.length > 0) return "ok";
	if (v4.error) return "error";
	const v6 = await resolve6(host);
	if (v6.records.length > 0) return "ok";
	if (v6.error) return "error";
	return "empty";
}

/** Parse a URL string, returning the URL and lowercased scheme (no trailing colon), or nulls if unparseable. */
function parseUrl(value: string): { url: URL | null; scheme: string | null } {
	try {
		const url = new URL(value);
		return { url, scheme: url.protocol.replace(/:$/, "").toLowerCase() };
	} catch {
		return { url: null, scheme: null };
	}
}

/**
 * Validate a `l=`/`a=` URL: it must be a syntactically valid HTTPS URL whose host resolves.
 * `http://`, an unparseable value, or an unresolvable host is `critical`; a transient resolver
 * error degrades to `info`; success is `ok`. (The `200`-status body fetch is a future round.)
 */
async function urlFinding(
	id: string,
	label: string,
	value: string,
	publishRemediation: string,
): Promise<Finding> {
	const { url, scheme } = parseUrl(value);
	if (!url) {
		return {
			id,
			checkId: CHECK_ID,
			title: `${label} is not a valid URL`,
			severity: "critical",
			detail: `The ${label} value "${value}" is not a parseable URL, so receivers cannot fetch it.`,
			remediation: publishRemediation,
			evidence: value,
		};
	}
	if (scheme !== "https") {
		return {
			id,
			checkId: CHECK_ID,
			title: `${label} is not HTTPS`,
			severity: "critical",
			detail: `The ${label} value uses "${scheme}://"; receivers reject non-HTTPS BIMI URLs and will not display the logo.`,
			remediation: publishRemediation,
			evidence: value,
		};
	}
	const state = await hostResolves(url.hostname);
	if (state === "error") {
		return {
			id,
			checkId: CHECK_ID,
			title: `${label} host could not be resolved`,
			severity: "info",
			detail: `A transient DNS error occurred resolving "${url.hostname}" (the ${label} host). Retry the audit later.`,
			remediation:
				"Retry the audit; if it persists, verify the host's authoritative nameservers respond.",
			evidence: value,
		};
	}
	if (state === "empty") {
		return {
			id,
			checkId: CHECK_ID,
			title: `${label} host does not resolve`,
			severity: "critical",
			detail: `The ${label} host "${url.hostname}" has no A/AAAA record, so receivers cannot fetch it and the logo will not render.`,
			remediation: publishRemediation,
			evidence: value,
		};
	}
	return {
		id,
		checkId: CHECK_ID,
		title: `${label} is a valid HTTPS URL`,
		severity: "ok",
		detail: `${label} is an HTTPS URL whose host "${url.hostname}" resolves. (Body fetch / 200-status validation is a future round.)`,
		evidence: value,
	};
}

interface DmarcState {
	state: "enforcing" | "not_enforcing" | "error";
	policy: string | null;
	record?: string;
}

/**
 * The sibling `dmarc` checker's structured result from THIS run (pm/checks/bimi.mdx §3): the run
 * graph guarantees dmarc finishes before content.bimi starts, so the policy is read from
 * `ctx.upstream.dmarc` instead of re-querying `_dmarc.<domain>`.
 */
function dmarcFromSibling(ctx: CheckContext): DmarcState | null {
	const dmarc = ctx.upstream?.dmarc as
		| { is_enforcing?: unknown; policy?: unknown; raw_record?: unknown }
		| undefined;
	if (!dmarc || typeof dmarc !== "object") return null;
	if (typeof dmarc.is_enforcing !== "boolean") return null;
	return {
		state: dmarc.is_enforcing ? "enforcing" : "not_enforcing",
		policy:
			typeof dmarc.policy === "string" ? dmarc.policy.toLowerCase() : null,
		record: typeof dmarc.raw_record === "string" ? dmarc.raw_record : undefined,
	};
}

/** Fallback only (dmarc checker disabled/errored): read `_dmarc.<domain>` directly. */
async function dmarcEnforcement(domain: string): Promise<DmarcState> {
	const { records, error } = await resolveTxt(`_dmarc.${domain}`);
	if (error) return { state: "error", policy: null };
	const dmarc = records.filter((r) => r.toLowerCase().startsWith("v=dmarc1"));
	if (dmarc.length === 0) return { state: "not_enforcing", policy: null };
	const record = dmarc[0];
	const policy =
		/\bp\s*=\s*(none|quarantine|reject)\b/i.exec(record)?.[1]?.toLowerCase() ??
		null;
	const enforcing = policy === "quarantine" || policy === "reject";
	return { state: enforcing ? "enforcing" : "not_enforcing", policy, record };
}

/**
 * The `s=` selector named by the sample message's `BIMI-Selector:` header (pm/checks/bimi.mdx §3
 * selector handling), or null when no sample/header/s= is present.
 */
export function parseBimiSelectorHeader(
	sampleMessage: string | undefined,
): string | null {
	if (!sampleMessage) return null;
	// Unfold folded header lines (RFC 5322 §2.2.3) before matching.
	const unfolded = sampleMessage.replace(/\r?\n[ \t]+/g, " ");
	const header = /^bimi-selector:\s*(.+)$/im.exec(unfolded)?.[1];
	if (!header) return null;
	const selector = /(?:^|;)\s*s\s*=\s*([a-z0-9-]{1,63})\s*(?:;|$)/i.exec(
		header,
	)?.[1];
	return selector ? selector.toLowerCase() : null;
}

/**
 * Whether a `_bimi` CNAME target is alive at all. A BIMI CNAME target hosts the TXT record — it
 * need not have any A/AAAA — so TXT presence counts as alive before falling back to A/AAAA.
 */
async function cnameTargetAlive(
	target: string,
): Promise<"ok" | "empty" | "error"> {
	const txt = await resolveTxt(target);
	if (txt.records.length > 0) return "ok";
	const host = await hostResolves(target);
	if (host === "ok") return "ok";
	if (txt.error || host === "error") return "error";
	return "empty";
}

/**
 * `content.bimi_dns_health` (pm/checks/bimi.mdx §2): the `_bimi` name must resolve cleanly — no
 * dangling CNAME to a dead/unclaimed host. Runs whether or not a TXT record was served: the
 * classic silent-disappearance case is a `_bimi` CNAME whose target lapsed, which makes the TXT
 * lookup come back EMPTY, so this is checked in the no-record path too.
 */
async function dnsHealthFinding(name: string): Promise<Finding> {
	const cname = await resolveCname(name);
	if (cname.records.length === 0) {
		return {
			id: "content.bimi_dns_health",
			checkId: CHECK_ID,
			title: "BIMI _bimi name resolves cleanly",
			severity: "ok",
			detail: `${name} resolves directly with no dangling CNAME.`,
		};
	}
	const target = cname.records[0];
	const targetState = await cnameTargetAlive(target);
	if (targetState === "empty") {
		return {
			id: "content.bimi_dns_health",
			checkId: CHECK_ID,
			title: "Dangling CNAME on _bimi",
			severity: "warning",
			detail: `${name} is a CNAME to "${target}", which does not resolve — the BIMI record depends on an unclaimed/dead host and silently disappears.`,
			remediation: `Point ${name} directly at the TXT record or a claimed host; remove the dangling CNAME to "${target}".`,
			evidence: `${name} CNAME ${target}`,
		};
	}
	if (targetState === "error") {
		return {
			id: "content.bimi_dns_health",
			checkId: CHECK_ID,
			title: "Could not verify the _bimi CNAME target",
			severity: "info",
			detail: `${name} is a CNAME to "${target}", but a transient DNS error prevented verifying the target. Retry the audit later.`,
			remediation:
				"Retry the audit; if it persists, verify the CNAME target's authoritative nameservers respond.",
			evidence: `${name} CNAME ${target}`,
		};
	}
	return {
		id: "content.bimi_dns_health",
		checkId: CHECK_ID,
		title: "BIMI _bimi name resolves cleanly",
		severity: "ok",
		detail: `${name} is a CNAME to "${target}", which resolves.`,
		evidence: `${name} CNAME ${target}`,
	};
}

/** An empty per-selector result row (future-round columns null — pm/checks/bimi.mdx §5). */
function emptyRow(
	selector: string,
	dmarcEnforcing: boolean,
	checkedAt: string,
): BimiSelectorResult {
	return {
		selector,
		present: false,
		rawRecord: null,
		svgUrl: null,
		vmcUrl: null,
		dmarcEnforcing,
		svgValid: null,
		vmcValid: null,
		vmcNotAfter: null,
		vmcIssuer: null,
		checkedAt,
	};
}

/**
 * Probe one non-default selector's `_bimi` name and emit its `content.bimi_selector.<selector>`
 * finding (pm/checks/bimi.mdx §2/§8.7). `fromHeader` marks the selector as referenced by the
 * sample message's `BIMI-Selector:` header (vs. only configured in the domain settings).
 */
async function probeSelector(
	domain: string,
	selector: string,
	fromHeader: boolean,
	row: BimiSelectorResult,
): Promise<Finding> {
	const name = `${selector}._bimi.${domain}`;
	const source = fromHeader
		? `the sample message's BIMI-Selector: header (s=${selector})`
		: "the domain's configured BIMI selectors";
	const { records, error } = await resolveTxt(name);
	if (error) {
		return {
			id: `content.bimi_selector.${selector}`,
			checkId: CHECK_ID,
			title: `Could not look up BIMI selector "${selector}"`,
			severity: "info",
			detail: `DNS lookup for TXT ${name} failed (${error}). Retry the audit later.`,
			remediation:
				"Retry the audit; if it persists, verify the domain's authoritative nameservers respond for _bimi.",
		};
	}
	const bimiRecords = records.filter((r) =>
		r.trim().toLowerCase().startsWith("v=bimi1"),
	);
	if (bimiRecords.length === 0) {
		return {
			id: `content.bimi_selector.${selector}`,
			checkId: CHECK_ID,
			title: `No _bimi record for selector "${selector}"`,
			severity: "warning",
			detail: `${source[0].toUpperCase()}${source.slice(1)} references selector "${selector}", but ${name} has no v=BIMI1 TXT record — messages sent with BIMI-Selector: v=BIMI1; s=${selector} get no logo.`,
			remediation: `Publish a TXT record at ${name} (v=BIMI1; l=https://${domain}/bimi/logo.svg; a=https://${domain}/bimi/vmc.pem) for every selector your mail streams reference in BIMI-Selector:, or drop the header and use default.`,
		};
	}
	row.present = true;
	row.rawRecord = bimiRecords[0];
	const { tags } = parseTags(bimiRecords[0]);
	row.svgUrl = tags.get("l") ?? null;
	row.vmcUrl = tags.get("a") ?? null;
	return {
		id: `content.bimi_selector.${selector}`,
		checkId: CHECK_ID,
		title: `BIMI selector "${selector}" record present`,
		severity: "ok",
		detail: `${name} publishes a v=BIMI1 TXT record, matching ${source}.`,
		evidence: bimiRecords[0],
	};
}

export const bimiCheck: Checker = {
	id: CHECK_ID,
	label: "BIMI",
	async run(ctx): Promise<CheckOutcome> {
		const checkedAt = new Date().toISOString();
		const name = `default._bimi.${ctx.domain}`;
		const publishRecord = `v=BIMI1; l=https://${ctx.domain}/bimi/logo.svg; a=https://${ctx.domain}/bimi/vmc.pem`;
		const publishRemediation = `Publish a single TXT record at ${name}: ${publishRecord}`;

		// DMARC-at-enforcement prerequisite — read from the sibling dmarc result of this run (§3);
		// fall back to a direct (memoized) _dmarc lookup only when the dmarc checker didn't publish.
		const dmarc = dmarcFromSibling(ctx) ?? (await dmarcEnforcement(ctx.domain));
		const dmarcEnforcing = dmarc.state === "enforcing";

		const findings: Finding[] = [];
		const defaultRow = emptyRow("default", dmarcEnforcing, checkedAt);
		const rows: BimiSelectorResult[] = [defaultRow];
		const outcome = (): CheckOutcome => ({
			findings,
			results: { ...defaultRow, selectors: rows } satisfies BimiResults,
		});

		// Extra selectors (§2/§3 selector handling): the domain's configured BIMI selectors plus the
		// selector named by the sample message's BIMI-Selector: header, deduped, excluding default.
		const headerSelector = parseBimiSelectorHeader(ctx.bimi?.sampleMessage);
		const extraSelectors = [
			...new Set(
				[
					...(ctx.bimi?.selectors ?? []),
					...(headerSelector ? [headerSelector] : []),
				]
					.map((s) => s.trim().toLowerCase())
					.filter((s) => s.length > 0 && s !== "default"),
			),
		];
		const probeExtras = async (): Promise<void> => {
			for (const selector of extraSelectors) {
				const row = emptyRow(selector, dmarcEnforcing, checkedAt);
				rows.push(row);
				findings.push(
					await probeSelector(
						ctx.domain,
						selector,
						selector === headerSelector,
						row,
					),
				);
			}
		};

		const { records, error } = await resolveTxt(name);

		// Transient resolver failure — distinct from a genuinely-absent record. No structured row is
		// written for an inconclusive lookup.
		if (error) {
			findings.push({
				id: "content.bimi_present",
				checkId: CHECK_ID,
				title: "Could not look up BIMI",
				severity: "info",
				detail: `DNS lookup for TXT ${name} failed (${error}). Retry the audit later.`,
				remediation:
					"Retry the audit; if it persists, verify the domain's authoritative nameservers respond for _bimi.",
			});
			return { findings };
		}

		// Anything at the _bimi name carrying v=BIMI1 counts as a BIMI record candidate — a record
		// whose v= tag is not FIRST is still a (malformed) BIMI record, caught by bimi_syntax below.
		const bimiRecords = records.filter((r) =>
			r.toLowerCase().includes("v=bimi1"),
		);

		// No BIMI record at all → warning (a brand that should have one), never critical. (§8.1)
		if (bimiRecords.length === 0) {
			findings.push({
				id: "content.bimi_present",
				checkId: CHECK_ID,
				title: "No BIMI record",
				severity: "warning",
				detail: `${name} has no v=BIMI1 TXT record, so supporting receivers (Gmail, Apple Mail, Yahoo, Fastmail) show a generic avatar instead of your brand logo.`,
				remediation: publishRemediation,
			});
			// DNS health still runs with no record (§2 bimi_dns_health): the classic cause of a BIMI
			// record silently disappearing is a `_bimi` CNAME whose target lapsed — surface the dangling
			// CNAME as the reason the TXT lookup came back empty.
			findings.push(await dnsHealthFinding(name));
			// The header/configured selectors are still audited (§8.7) even with no default record.
			await probeExtras();
			return outcome();
		}

		defaultRow.present = true;
		defaultRow.rawRecord = bimiRecords[0];

		findings.push({
			id: "content.bimi_present",
			checkId: CHECK_ID,
			title: "BIMI record present",
			severity: "ok",
			detail: `Found a v=BIMI1 TXT record at ${name}.`,
			evidence: bimiRecords[0],
		});

		// Exactly one record at the _bimi name. (§8.6)
		if (bimiRecords.length > 1) {
			findings.push({
				id: "content.bimi_single",
				checkId: CHECK_ID,
				title: "Multiple BIMI records",
				severity: "warning",
				detail: `${name} publishes ${bimiRecords.length} v=BIMI1 records; multiple records are ambiguous and receivers may ignore BIMI.`,
				remediation:
					"Delete the extra TXT so exactly one v=BIMI1 record remains at the _bimi name.",
				evidence: bimiRecords.join(" | "),
			});
		} else {
			findings.push({
				id: "content.bimi_single",
				checkId: CHECK_ID,
				title: "Single BIMI record",
				severity: "ok",
				detail: "Exactly one v=BIMI1 TXT record is published.",
			});
		}

		const record = bimiRecords[0];
		const { tags, firstTag, strayTokens, unknownTags } = parseTags(record);
		const l = tags.get("l");
		const a = tags.get("a");
		defaultRow.svgUrl = l ?? null;
		defaultRow.vmcUrl = a ?? null;

		// Syntax: v=BIMI1 must be first, only known tags (v/l/a), no stray tokens. (§8 — malformed → critical)
		const vValue = tags.get("v");
		const syntaxProblems: string[] = [];
		if (firstTag !== "v" || (vValue ?? "").toUpperCase() !== "BIMI1") {
			syntaxProblems.push("v=BIMI1 must be the first tag");
		}
		if (strayTokens.length > 0) {
			syntaxProblems.push(`stray token(s): ${strayTokens.join(", ")}`);
		}
		if (unknownTags.length > 0) {
			syntaxProblems.push(`unknown tag(s): ${unknownTags.join(", ")}`);
		}
		if (syntaxProblems.length > 0) {
			findings.push({
				id: "content.bimi_syntax",
				checkId: CHECK_ID,
				title: "Malformed BIMI record",
				severity: "critical",
				detail: `The BIMI record does not parse cleanly (${syntaxProblems.join("; ")}); receivers will ignore it.`,
				remediation:
					'Fix the offending tag so the record reads like "v=BIMI1; l=https://…/logo.svg; a=https://…/vmc.pem" — v=BIMI1 must be first and l= must be a valid HTTPS URL.',
				evidence: record,
			});
		} else {
			findings.push({
				id: "content.bimi_syntax",
				checkId: CHECK_ID,
				title: "BIMI record syntax valid",
				severity: "ok",
				detail:
					"The record parses: v=BIMI1 first, only known tags, valid ;-separated tag=value pairs.",
				evidence: record,
			});
		}

		// Declined record (v=BIMI1; l=; a=;) is intentionally "no logo" → info, not a failure. (§3)
		const declined = tags.has("l") && (l ?? "") === "" && (a ?? "") === "";
		if (declined) {
			findings.push({
				id: "content.bimi_l_present",
				checkId: CHECK_ID,
				title: "BIMI declined (empty l=)",
				severity: "info",
				detail:
					"This is a valid declined BIMI record (empty l=), meaning the domain intentionally publishes no logo.",
				evidence: record,
			});
			await probeExtras();
			return outcome();
		}

		// DMARC-at-enforcement prerequisite. Record present + DMARC not enforcing → critical. (§8.2/8.3)
		if (dmarc.state === "error") {
			findings.push({
				id: "content.bimi_dmarc_prereq",
				checkId: CHECK_ID,
				title: "Could not determine DMARC state",
				severity: "info",
				detail: `A transient DNS error prevented reading _dmarc.${ctx.domain}, so BIMI's DMARC prerequisite could not be confirmed. Retry the audit later.`,
				remediation:
					"Retry the audit; if it persists, verify the domain's nameservers respond for _dmarc.",
			});
		} else if (dmarc.state === "enforcing") {
			findings.push({
				id: "content.bimi_dmarc_prereq",
				checkId: CHECK_ID,
				title: `DMARC enforcing (p=${dmarc.policy})`,
				severity: "ok",
				detail: `DMARC is published at p=${dmarc.policy}, satisfying BIMI's hard prerequisite so the logo can render.`,
				evidence: dmarc.record,
			});
		} else {
			const stateText = dmarc.policy ? `p=${dmarc.policy}` : "absent";
			findings.push({
				id: "content.bimi_dmarc_prereq",
				checkId: CHECK_ID,
				title: "BIMI ignored: DMARC not at enforcement",
				severity: "critical",
				detail: `A BIMI record is published but DMARC is ${stateText}. Receivers ignore BIMI unless DMARC is p=quarantine or p=reject, so the logo renders nowhere.`,
				remediation: `Move DMARC to p=quarantine then p=reject (see the DMARC check) — e.g. publish "v=DMARC1; p=quarantine; rua=mailto:dmarc@${ctx.domain}" at _dmarc.${ctx.domain} and tighten to p=reject. Until then BIMI will never render.`,
				evidence: dmarc.record,
			});
		}

		// l= (SVG logo URL) presence. (§8 — bimi_l_present)
		if (!tags.has("l") || (l ?? "") === "") {
			findings.push({
				id: "content.bimi_l_present",
				checkId: CHECK_ID,
				title: "BIMI l= (logo URL) missing",
				severity: "warning",
				detail:
					"The record has no non-empty l= tag, so no logo will show even where DMARC and the VMC are in place.",
				remediation: `Set l= to the HTTPS URL of your SVG Tiny-PS logo, e.g. l=https://${ctx.domain}/bimi/logo.svg`,
				evidence: record,
			});
		} else {
			findings.push({
				id: "content.bimi_l_present",
				checkId: CHECK_ID,
				title: "BIMI l= (logo URL) present",
				severity: "ok",
				detail: "The l= (SVG logo URL) tag is present.",
				evidence: l,
			});
			findings.push(
				await urlFinding(
					"content.bimi_svg_url",
					"l= (SVG logo URL)",
					l as string,
					`Host the SVG at an https:// URL that returns 200, e.g. l=https://${ctx.domain}/bimi/logo.svg`,
				),
			);
		}

		// a= (VMC/CMC URL) presence — Gmail/Apple won't render a logo without a verified mark. (§8.5)
		if (!tags.has("a") || (a ?? "") === "") {
			findings.push({
				id: "content.bimi_vmc",
				checkId: CHECK_ID,
				title: "No VMC/CMC (a= tag missing)",
				severity: "warning",
				detail:
					"The record has l= but no a= tag. Gmail and Apple Mail will not show a logo without a valid Verified Mark Certificate (VMC) or Common Mark Certificate (CMC).",
				remediation:
					"Obtain a VMC (registered trademark) or CMC (non-trademark mark) from a Mark Verifying Authority (e.g. DigiCert or Entrust) and publish its PEM URL in a=, e.g. a=https://" +
					ctx.domain +
					"/bimi/vmc.pem",
				evidence: record,
			});
		} else {
			findings.push({
				id: "content.bimi_vmc",
				checkId: CHECK_ID,
				title: "VMC/CMC (a= tag) present",
				severity: "ok",
				detail: "The a= (VMC/CMC certificate URL) tag is present.",
				evidence: a,
			});
			findings.push(
				await urlFinding(
					"content.bimi_vmc_url",
					"a= (VMC/CMC URL)",
					a as string,
					`Host the VMC PEM at an https:// URL returning 200, e.g. a=https://${ctx.domain}/bimi/vmc.pem`,
				),
			);
		}

		// Non-default selectors (§2/§8.7): configured selectors + the BIMI-Selector header compare.
		await probeExtras();

		// DNS health: a dangling CNAME on the _bimi name means the record silently disappears. (§2 — bimi_dns_health)
		findings.push(await dnsHealthFinding(name));

		// Future round: SVG body (Tiny-PS profile / square viewBox) and VMC certificate (chain against
		// the checks.bimi.mvaAllowList, expiry, logo-hash match) all require an HTTPS fetch. Never
		// emitted as warn/critical; the UI shows this as the "future round" placeholder (§4).
		findings.push({
			id: "content.bimi_future_validation",
			checkId: CHECK_ID,
			title: "Logo & certificate validation pending (future round)",
			severity: "info",
			detail:
				"A future round will fetch the l= SVG over HTTPS to validate the SVG Tiny-PS profile (baseProfile=tiny-ps, square viewBox, no scripts/external refs/animation, size cap) and fetch the a= VMC PEM to verify its chain against the Mark Verifying Authority allow-list, its expiry, and that its embedded logotype matches the served SVG. These are not checked in the first (DNS-only) round.",
		});

		return outcome();
	},
};
