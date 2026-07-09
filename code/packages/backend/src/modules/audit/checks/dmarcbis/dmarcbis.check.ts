import { locateTool, runTool } from "@shared/tool-runner";
import type { DmarcSection } from "../dmarc/dmarc.check";
import { doggoTxtValues, extractDoggoAnswers } from "../dmarc/dmarc.check";
import { resolveTxt } from "../dns-util";
import type {
	CheckContext,
	Checker,
	CheckOutcome,
	Finding,
	Severity,
} from "../types";
import {
	type OrgDomainResolution,
	type QueryRung,
	isDmarcRecord,
	resolveOrgDomain,
	type TxtResolver,
} from "./tree-walk";

/**
 * DMARCbis (pm/checks/dmarcbis.mdx) — the RFC 9989 standards-conformance + migration lens layered on
 * top of the operational `dmarc` checker. It is a **companion, not a replacement**: it does NOT
 * re-tokenize the `_dmarc` record. The run graph orders `dmarcbis ← dmarc`, so DMARCbis reads the
 * sibling `dmarc` result (`ctx.upstream.dmarc`, a §5 `DmarcSection`) for the already-parsed tag map,
 * `found_at`, policy, and `external_report_auth[]` — exactly as ARC consumes the DMARC policy — and
 * runs its OWN pure `node:dns/promises` tree walk (tree-walk.ts) to resolve the Organizational Domain.
 *
 * First-round sub-checks (§2, all DNS/sibling-answerable, tops out at `warning` — no criticals):
 *   dmarcbis.tree_walk, dmarcbis.psd, dmarcbis.np, dmarcbis.testing_flag, dmarcbis.removed_tags,
 *   dmarcbis.sp_semantics, dmarcbis.reject_advisory (advisory), dmarcbis.external_auth.
 * FUTURE (needs ingested rua/ruf reports, ../emails.mdx): dmarcbis.report_schema and
 * dmarcbis.failure_report_conformance — stubbed as a single `info`, never fabricated.
 *
 * Every `dmarcbis.*` finding carries `checkId: "dmarcbis"` and rolls into the DMARC dashboard cell.
 * Returns findings plus `results.dmarcbis` — the §5 `dmarcbis:` run-YAML section (status, read_from,
 * org_domain, tags, tool_runs[], tests[], problem_states).
 */

const POLICIES = ["none", "quarantine", "reject"] as const;
type Policy = (typeof POLICIES)[number];
const POLICY_RANK: Record<Policy, number> = { none: 0, quarantine: 1, reject: 2 };
function asPolicy(v: string | null | undefined): Policy | null {
	return v && (POLICIES as readonly string[]).includes(v) ? (v as Policy) : null;
}

/** The DMARCbis valid tag set (RFC 9989): np/psd/t IN, pct/rf/ri OUT. */
const VALID_TAGS = new Set([
	"v",
	"p",
	"sp",
	"np",
	"adkim",
	"aspf",
	"fo",
	"rua",
	"ruf",
	"psd",
	"t",
]);
/** Tags removed in DMARCbis — receivers ignore them, but they are non-conformant noise. */
const REMOVED_TAGS = ["pct", "rf", "ri"] as const;

// ---------------------------------------------------------------------------------------------
// The §5 `dmarcbis:` section shapes. `tool_runs[]` / `tests[]` reuse the shapes LOCKED across all
// category specs (identical to dmarc.check.ts's DmarcToolRun / DmarcTestRow).
// ---------------------------------------------------------------------------------------------

/** One external-tool invocation — the LOCKED `tool_runs[]` entry shape (pm/checks/dmarcbis.mdx §3). */
export interface DmarcbisToolRun {
	tool: string;
	command: string;
	started_at: string;
	duration_ms: number;
	exit_code: number | null;
	output_format: "json" | "text";
	parsed: unknown | null;
	error: string | null;
}

/** One per-sub-test row of §5's `tests:` list (`result` ⇔ finding severity ok/critical/warning/info). */
export interface DmarcbisTestRow {
	id: string;
	title: string;
	result: "pass" | "fail" | "warn" | "info";
	detail?: string;
	evidence?: string;
	dns_value_expected?: string;
	fix?: string;
}

/** One rung of the §5 `org_domain.query_path[]` (snake_case serialization of a tree-walk QueryRung). */
export interface DmarcbisQueryRung {
	name: string;
	labels: number;
	record_found: boolean;
	psd: string | null;
}

/** The §5 `org_domain:` block — the resolved Organizational Domain + the tree-walk provenance. */
export interface DmarcbisOrgDomain {
	author_domain: string;
	resolved_org_domain: string | null;
	found_via: "treewalk" | "parent" | "tld-cap" | null;
	matches_enforced_record: boolean | null;
	query_path: DmarcbisQueryRung[];
	selected_by: "psd=n" | "psd=y-below" | "fewest-labels" | null;
	label_count: number | null;
	psd_verdict: "ok" | "misdeclared_y" | "missing_y" | null;
	covered_by_parent: boolean;
}

/** The §5 `tags.reject_reality` sub-object — the `p=reject` cross-category reality check. */
export interface DmarcbisRejectReality {
	policy: string | null;
	dkim_aligned_ok: boolean | null;
	spf_only_risk: boolean;
}

/** The §5 `tags:` snapshot — conformance read from the sibling parsed map (NOT re-parsed). */
export interface DmarcbisTags {
	valid_set_ok: boolean | null;
	np: string | null;
	psd: string | null;
	t: string | null;
	removed_tags_present: string[];
	reject_reality: DmarcbisRejectReality;
}

/** The whole `dmarcbis:` section of the run YAML (pm/checks/dmarcbis.mdx §5) — `results.dmarcbis`. */
export interface DmarcbisSection {
	status: Severity;
	/** Provenance: consumed `results.dmarc` via the run graph (dmarcbis ← dmarc). */
	read_from: "dmarc";
	org_domain: DmarcbisOrgDomain;
	tags: DmarcbisTags;
	tool_runs: DmarcbisToolRun[];
	tests: DmarcbisTestRow[];
	/** Matched §9 DMARCbis-nn problem-state ids (disjoint from dmarc's PS-nn). */
	problem_states: string[];
}

const SEVERITY_RANK: Record<Severity, number> = {
	ok: 0,
	info: 1,
	warning: 2,
	critical: 3,
};

/** Finding severity ⇔ §5 `tests[].result` (ok→pass, critical→fail, warning→warn, info→info). */
const RESULT_OF: Record<Severity, DmarcbisTestRow["result"]> = {
	ok: "pass",
	critical: "fail",
	warning: "warn",
	info: "info",
};

export function worstSeverity(findings: Finding[]): Severity {
	let worst: Severity = "ok";
	for (const f of findings)
		if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) worst = f.severity;
	return worst;
}

/** Findings → §5 `tests[]` rows — pass rows included so the explainer renders one row per test. */
export function buildTests(findings: Finding[]): DmarcbisTestRow[] {
	return findings.map((f) => ({
		id: f.id,
		title: f.title,
		result: RESULT_OF[f.severity],
		...(f.detail ? { detail: f.detail } : {}),
		...(f.evidence ? { evidence: f.evidence } : {}),
		...(f.remediation ? { fix: f.remediation } : {}),
	}));
}

/**
 * The §9 problem-state mapping: each non-ok `dmarcbis.*` finding id → its `DMARCbis-nn` id (disjoint
 * from dmarc's PS-nn and arc's ARC-nn). The FUTURE `dmarcbis.report_schema` placeholder and the
 * infrastructure `dmarcbis.tool_missing` info are NOT problem states. When nothing fired, the healthy
 * goal state `DMARCbis-00` is returned.
 */
const PROBLEM_STATE_OF: Record<string, string> = {
	"dmarcbis.tree_walk": "DMARCbis-01",
	"dmarcbis.psd": "DMARCbis-02",
	"dmarcbis.np": "DMARCbis-03",
	"dmarcbis.testing_flag": "DMARCbis-04",
	"dmarcbis.removed_tags": "DMARCbis-05",
	"dmarcbis.sp_semantics": "DMARCbis-06",
	"dmarcbis.reject_advisory": "DMARCbis-07",
	"dmarcbis.external_auth": "DMARCbis-08",
};

export function deriveProblemStates(findings: Finding[]): string[] {
	const out = new Set<string>();
	for (const f of findings) {
		if (f.severity === "ok") continue;
		const ps = PROBLEM_STATE_OF[f.id];
		if (ps) out.add(ps);
	}
	if (out.size === 0) return ["DMARCbis-00"];
	return [...out].sort();
}

// ---------------------------------------------------------------------------------------------
// Sibling `dmarc` consumption (pm/checks/dmarcbis.mdx §4 — read results.dmarc, never re-parse).
// ---------------------------------------------------------------------------------------------

interface DmarcRead {
	parsed: Record<string, string>;
	foundAt: string | null;
	policy: Policy | null;
	subdomainPolicy: Policy | null;
	npPolicy: string | null;
	externalReportAuth: {
		report_kind: string;
		report_domain: string;
		auth_name: string;
		authorized: boolean;
	}[];
}

/**
 * Read the sibling `dmarc` §5 section this run produced (`ctx.upstream.dmarc`). Returns null when it
 * is absent (the `dmarc` checker was disabled or errored) — the caller then early-returns a single
 * info. A flat legacy shape is tolerated for older persisted payloads, mirroring ARC's read.
 */
function readSiblingDmarc(ctx: CheckContext): DmarcRead | null {
	const dmarc = ctx.upstream?.dmarc as Partial<DmarcSection> | undefined;
	if (!dmarc || typeof dmarc !== "object") return null;
	const record = (dmarc as { record?: unknown }).record;
	if (!record || typeof record !== "object") return null;
	const r = record as {
		parsed?: unknown;
		found_at?: unknown;
		policy?: unknown;
		subdomain_policy?: unknown;
		np_policy?: unknown;
		external_report_auth?: unknown;
	};
	const parsed =
		r.parsed && typeof r.parsed === "object"
			? (r.parsed as Record<string, string>)
			: {};
	return {
		parsed,
		foundAt: typeof r.found_at === "string" ? r.found_at : null,
		policy: asPolicy(typeof r.policy === "string" ? r.policy : null),
		subdomainPolicy: asPolicy(
			typeof r.subdomain_policy === "string" ? r.subdomain_policy : null,
		),
		npPolicy: typeof r.np_policy === "string" ? r.np_policy : null,
		externalReportAuth: Array.isArray(r.external_report_auth)
			? (r.external_report_auth as DmarcRead["externalReportAuth"])
			: [],
	};
}

// ---------------------------------------------------------------------------------------------
// Shell-out provenance (§3) — mirrors dmarc.check.ts exactly. In-process node:dns tree-walk lookups
// are NOT tool runs; only external-binary invocations land in tool_runs[].
// ---------------------------------------------------------------------------------------------

const TOOL_INSTALL: Record<string, string> = {
	checkdmarc: "checkdmarc",
	doggo: "doggo",
	kdig: "knot",
};
const CHECKDMARC_TIMEOUT_MS = 60_000;
const DOGGO_TIMEOUT_MS = 10_000;
const KDIG_TIMEOUT_MS = 10_000;

/** Resolve a tool binary: the run's Stage-0 discovery map when provided, else a PATH search. */
function toolPath(ctx: CheckContext, name: string): string | null {
	if (ctx.tools && name in ctx.tools) return ctx.tools[name];
	return locateTool(name);
}

interface ToolInvocation {
	entry: DmarcbisToolRun;
	stdout: string | null;
}

/** One ToolRunner spawn → one locked-shape `tool_runs[]` entry (§3 execution rules). */
async function invokeTool(
	path: string,
	tool: string,
	args: readonly string[],
	timeoutMs: number,
	format: "json" | "text",
	prune: (parsed: unknown, stdout: string) => unknown,
	signal?: AbortSignal,
): Promise<ToolInvocation> {
	const started_at = new Date().toISOString();
	const t0 = Date.now();
	const res = await runTool(path, args, { timeoutMs, signal });
	const base = {
		tool,
		command: `${tool} ${args.join(" ")}`,
		started_at,
		duration_ms: Date.now() - t0,
		output_format: format,
	};
	if (res.timedOut)
		return {
			entry: {
				...base,
				exit_code: null,
				parsed: null,
				error: `timeout after ${timeoutMs}ms`,
			},
			stdout: null,
		};
	if (res.code !== 0)
		return {
			entry: {
				...base,
				exit_code: res.code,
				parsed: null,
				error: res.stderr.trim() || `exit ${res.code ?? "?"}`,
			},
			stdout: null,
		};
	if (format === "text")
		return {
			entry: {
				...base,
				exit_code: 0,
				parsed: prune(null, res.stdout),
				error: null,
			},
			stdout: res.stdout,
		};
	try {
		const parsed = prune(JSON.parse(res.stdout), res.stdout);
		return {
			entry: { ...base, exit_code: 0, parsed, error: null },
			stdout: res.stdout,
		};
	} catch {
		return {
			entry: {
				...base,
				exit_code: 0,
				parsed: null,
				error: "stdout was not parseable JSON",
			},
			stdout: res.stdout,
		};
	}
}

/** Prune checkdmarc's JSON to the `dmarc` object fields we consume (§3 row 1). */
function pruneCheckdmarc(parsed: unknown): unknown {
	if (parsed && typeof parsed === "object" && "dmarc" in parsed) {
		const d = (parsed as { dmarc: unknown }).dmarc;
		if (d && typeof d === "object") {
			const src = d as Record<string, unknown>;
			const keep: Record<string, unknown> = {};
			for (const k of ["record", "valid", "location", "tags", "warnings", "error"])
				if (k in src) keep[k] = src[k];
			return { dmarc: keep };
		}
		return { dmarc: d };
	}
	return parsed;
}

/** Append a cross-check note to the first present finding among `ids` (mismatch provenance, §3). */
function appendDetail(findings: Finding[], ids: string[], note: string): void {
	const f =
		ids.map((id) => findings.find((x) => x.id === id)).find(Boolean) ??
		findings[0];
	if (f) f.detail = f.detail ? `${f.detail} ${note}` : note;
}

// ---------------------------------------------------------------------------------------------
// Empty section (early return when the sibling dmarc result is absent).
// ---------------------------------------------------------------------------------------------

function emptyOrgDomain(author: string): DmarcbisOrgDomain {
	return {
		author_domain: author,
		resolved_org_domain: null,
		found_via: null,
		matches_enforced_record: null,
		query_path: [],
		selected_by: null,
		label_count: null,
		psd_verdict: null,
		covered_by_parent: false,
	};
}

function emptyTags(): DmarcbisTags {
	return {
		valid_set_ok: null,
		np: null,
		psd: null,
		t: null,
		removed_tags_present: [],
		reject_reality: { policy: null, dkim_aligned_ok: null, spf_only_risk: false },
	};
}

function toQueryPath(rungs: QueryRung[]): DmarcbisQueryRung[] {
	return rungs.map((r) => ({
		name: r.name,
		labels: r.labels,
		record_found: r.recordFound,
		psd: r.psd,
	}));
}

/** Sibling DKIM category health — copied from dmarc.check.ts's dkimUnhealthy read. */
function dkimIsHealthy(ctx: CheckContext): boolean {
	const dkim = ctx.upstream?.dkim as { working_selectors?: number } | undefined;
	return typeof dkim?.working_selectors === "number" && dkim.working_selectors > 0;
}

export const dmarcbisCheck: Checker = {
	id: "dmarcbis",
	label: "DMARCbis (RFC 9989 conformance)",
	async run(ctx): Promise<CheckOutcome> {
		// 1. Read the sibling dmarc result. Absent → one info, empty section, stop (§4, AC1).
		const sibling = readSiblingDmarc(ctx);
		if (!sibling) {
			const finding: Finding = {
				id: "dmarcbis.unavailable",
				checkId: "dmarcbis",
				title: "DMARCbis conformance could not be evaluated (no DMARC result this run)",
				severity: "info",
				detail:
					"The operational DMARC check did not complete this run, so its parsed record was not available. DMARCbis is a conformance lens over the DMARC record and cannot run without it.",
				remediation:
					"Re-run the audit; if the DMARC check keeps failing, resolve that first (its findings appear in the same DMARC category cell).",
			};
			const section: DmarcbisSection = {
				status: "info",
				read_from: "dmarc",
				org_domain: emptyOrgDomain(ctx.domain),
				tags: emptyTags(),
				tool_runs: [],
				tests: buildTests([finding]),
				problem_states: [],
			};
			return { findings: [finding], results: section };
		}

		const findings: Finding[] = [];
		const map = sibling.parsed;
		const policy = sibling.policy;
		const enforcing = policy === "quarantine" || policy === "reject";
		const enforcedDomain = sibling.foundAt
			? sibling.foundAt.replace(/^_dmarc\./i, "")
			: null;

		// 2. The tree walk (pure node:dns/promises via the injected resolver) — the headline feature.
		const resolver: TxtResolver = async (name) => {
			const r = await resolveTxt(name);
			return { records: r.records, error: r.error };
		};
		const walk: OrgDomainResolution = await resolveOrgDomain(ctx.domain, resolver);
		const matches =
			walk.resolvedOrgDomain !== null && walk.resolvedOrgDomain === enforcedDomain;

		// psd verdict (also feeds the psd sub-check below).
		const psdVal = map.psd?.toLowerCase() ?? null;
		const orgLabelCount =
			walk.labelCount ??
			(walk.resolvedOrgDomain
				? walk.resolvedOrgDomain.split(".").filter(Boolean).length
				: null);
		// Best-effort ordinary-domain heuristic (§2/§4): a 2-label registrable domain declaring psd=y.
		const psdMisdeclaredY =
			psdVal === "y" && (orgLabelCount ?? ctx.domain.split(".").length) <= 2;
		const psdVerdict: DmarcbisOrgDomain["psd_verdict"] = psdMisdeclaredY
			? "misdeclared_y"
			: "ok";

		// ---- dmarcbis.tree_walk ----
		if (walk.resolvedOrgDomain === null) {
			findings.push({
				id: "dmarcbis.tree_walk",
				checkId: "dmarcbis",
				title: "Tree walk found no DMARC record along the path to the root",
				severity: "info",
				detail: `The RFC 9989 tree walk from ${ctx.domain} (${walk.queryPath.length} quer${walk.queryPath.length === 1 ? "y" : "ies"}) found no v=DMARC1 record at any rung, so the Organizational Domain could not be resolved from DNS this run.`,
				remediation: `Publish a record at _dmarc.${ctx.domain} (or its Organizational Domain) so the tree walk can resolve it.`,
			});
		} else if (!matches) {
			findings.push({
				id: "dmarcbis.tree_walk",
				checkId: "dmarcbis",
				title: `Tree walk selects ${walk.resolvedOrgDomain}, not the enforced record${enforcedDomain ? ` (${enforcedDomain})` : ""}`,
				severity: "warning",
				detail: `Under RFC 7489 the Public Suffix List decided your Organizational Domain; DMARCbis walks DNS instead. The walk selected ${walk.resolvedOrgDomain} (via ${walk.selectedBy}) but the record you enforce is at ${enforcedDomain ?? "an unknown domain"} — receivers applying the new standard evaluate a different policy than you expect.`,
				remediation: `Publish _dmarc at ${walk.resolvedOrgDomain} (the tree-walk Org Domain), or confirm the parent's sp= is the policy you intend; publish _dmarc.<subdomain> explicitly if a subdomain needs its own policy.`,
				evidence: walk.queryPath.map((r) => r.name).join(" → "),
			});
		} else if (walk.coveredByParent) {
			findings.push({
				id: "dmarcbis.tree_walk",
				checkId: "dmarcbis",
				title: `Covered by the parent Org Domain ${walk.resolvedOrgDomain}`,
				severity: "info",
				detail: `${ctx.domain} has no record of its own; the tree walk resolves the Organizational Domain to the parent ${walk.resolvedOrgDomain}, whose sp= governs this domain.`,
				remediation: `Publish a dedicated _dmarc.${ctx.domain} record if this subdomain needs its own policy, or confirm ${walk.resolvedOrgDomain}'s sp= is intended.`,
				evidence: walk.queryPath.map((r) => r.name).join(" → "),
			});
		} else {
			findings.push({
				id: "dmarcbis.tree_walk",
				checkId: "dmarcbis",
				title: "Tree-walk Organizational Domain matches the enforced record",
				severity: "ok",
				detail: `The RFC 9989 tree walk selected ${walk.resolvedOrgDomain} (via ${walk.selectedBy}, ${orgLabelCount} labels) and it matches the enforced record at ${sibling.foundAt}.`,
				evidence: walk.queryPath.map((r) => r.name).join(" → "),
			});
		}

		// ---- dmarcbis.psd ----
		if (psdMisdeclaredY) {
			findings.push({
				id: "dmarcbis.psd",
				checkId: "dmarcbis",
				title: "psd=y on an ordinary organizational domain",
				severity: "warning",
				detail: `${ctx.domain} declares psd=y, which marks it as a public-suffix / registry operator and pushes the tree-walk Org Domain a label the wrong way for everything beneath it. Ordinary organizations are psd=n (or absent → the default u).`,
				remediation: "Set psd=n (or remove the psd tag → default u); only registries set psd=y.",
				evidence: map.psd ? `psd=${map.psd}` : undefined,
			});
		} else {
			findings.push({
				id: "dmarcbis.psd",
				checkId: "dmarcbis",
				title: psdVal
					? `psd tag correct (psd=${psdVal})`
					: "psd tag absent (defaults to u — unknown)",
				severity: "ok",
				detail: psdVal
					? `psd=${psdVal} is consistent with the domain's tree-walk role.`
					: "No psd tag, so the tree walk treats the domain as psd=u (unknown) — correct for an ordinary organization.",
			});
		}

		// ---- dmarcbis.np (fallback np → sp → p) ----
		const npVal = map.np?.toLowerCase() ?? null;
		const npEffective = asPolicy(npVal ?? sibling.subdomainPolicy ?? policy);
		if (enforcing && policy) {
			if (npVal && npEffective && POLICY_RANK[npEffective] < POLICY_RANK[policy]) {
				findings.push({
					id: "dmarcbis.np",
					checkId: "dmarcbis",
					title: `np=${npVal} is weaker than p=${policy}`,
					severity: "warning",
					detail: `Under p=${policy} the non-existent-subdomain policy np=${npVal} leaves made-up subdomains (NXDOMAIN, RFC 8020) treated more leniently than the apex — attackers spoof invoices.${ctx.domain} when no such host exists.`,
					remediation: "Set np=reject if you never legitimately send from non-existent subdomains.",
					evidence: `np=${npVal}`,
				});
			} else if (!npVal) {
				findings.push({
					id: "dmarcbis.np",
					checkId: "dmarcbis",
					title: "No np= (non-existent-subdomain) policy while enforcing",
					severity: "info",
					detail: `p=${policy} is enforcing but no np= is set, so made-up subdomains that do not exist in DNS (NXDOMAIN, RFC 8020) are not explicitly rejected — the phantom-subdomain spoofing gap.`,
					remediation: "Add np=reject if you never send from non-existent subdomains.",
				});
			} else {
				findings.push({
					id: "dmarcbis.np",
					checkId: "dmarcbis",
					title: `np=${npVal} is at least as strict as p=${policy}`,
					severity: "ok",
					detail: "Non-existent subdomains are covered at least as strictly as the apex.",
				});
			}
		} else {
			findings.push({
				id: "dmarcbis.np",
				checkId: "dmarcbis",
				title: "np= not required (policy is not enforcing)",
				severity: "ok",
				detail: "np= only matters under an enforcing p= (quarantine/reject).",
			});
		}

		// ---- dmarcbis.testing_flag (t=y softens enforcement one level) ----
		const tVal = map.t?.toLowerCase() ?? null;
		if (tVal === "y") {
			findings.push({
				id: "dmarcbis.testing_flag",
				checkId: "dmarcbis",
				title: "Testing flag softens enforcement (t=y)",
				severity: "warning",
				detail: `t=y tells receivers to treat the policy as advisory — DMARCbis softens enforcement one level (reject→quarantine, quarantine→none). Your printed p=${policy ?? "?"} is one level stronger than what receivers actually apply.`,
				remediation: "Remove t=y (or set t=n) once you are ready to enforce the published policy as written.",
				evidence: "t=y",
			});
		} else {
			findings.push({
				id: "dmarcbis.testing_flag",
				checkId: "dmarcbis",
				title: `Testing flag not softening enforcement (t=${tVal ?? "n"})`,
				severity: "ok",
				detail: "The published policy is enforced as written (t=n or absent).",
			});
		}

		// ---- dmarcbis.removed_tags (pct/rf/ri removed in RFC 9989) ----
		const removedPresent = REMOVED_TAGS.filter((t) => t in map);
		const validSetOk = Object.keys(map).every((k) => VALID_TAGS.has(k));
		if (removedPresent.length > 0) {
			findings.push({
				id: "dmarcbis.removed_tags",
				checkId: "dmarcbis",
				title: `Removed tag${removedPresent.length === 1 ? "" : "s"} present (${removedPresent.join(", ")})`,
				severity: "info",
				detail: `${removedPresent.join(", ")} ${removedPresent.length === 1 ? "was" : "were"} removed in RFC 9989; receivers ignore ${removedPresent.length === 1 ? "it" : "them"} (no breakage) but ${removedPresent.length === 1 ? "it is" : "they are"} non-conformant noise. Cross-ref the operational dmarc.pct / dmarc.deprecated_tags findings.`,
				remediation: `Delete ${removedPresent.join(", ")} at the next DNS edit; keep the record to the DMARCbis tag set.`,
				evidence: removedPresent.map((t) => `${t}=${map[t]}`).join("; "),
			});
		} else {
			findings.push({
				id: "dmarcbis.removed_tags",
				checkId: "dmarcbis",
				title: "No removed tags — record uses the DMARCbis tag set",
				severity: "ok",
				detail: "No pct/rf/ri present; the record conforms to the DMARCbis valid tag set.",
			});
		}

		// ---- dmarcbis.sp_semantics (sp read ONLY from the Org-Domain record) ----
		const sp = sibling.subdomainPolicy;
		if (
			enforcing &&
			policy &&
			map.sp &&
			sp &&
			POLICY_RANK[sp] < POLICY_RANK[policy]
		) {
			findings.push({
				id: "dmarcbis.sp_semantics",
				checkId: "dmarcbis",
				title: `Existing subdomains weaker than the apex (sp=${sp})`,
				severity: "warning",
				detail: `sp=${sp} on the Org-Domain record leaves existing subdomains more spoofable than p=${policy}. DMARCbis reads sp only from the record at the Organizational Domain.`,
				remediation: `Set sp=${policy} on the Org-Domain record so existing subdomains match the apex.`,
				evidence: `p=${policy}; sp=${sp}`,
			});
		} else if (walk.coveredByParent && map.sp) {
			findings.push({
				id: "dmarcbis.sp_semantics",
				checkId: "dmarcbis",
				title: "sp on a subdomain record is ineffective under DMARCbis",
				severity: "warning",
				detail: `This domain is covered by the parent Org Domain ${walk.resolvedOrgDomain}; DMARCbis reads sp= only from the Org-Domain record, so an sp published here is ignored.`,
				remediation: `Move the intended subdomain policy to sp= on the Org-Domain record (${walk.resolvedOrgDomain}).`,
				evidence: `sp=${map.sp}`,
			});
		} else {
			findings.push({
				id: "dmarcbis.sp_semantics",
				checkId: "dmarcbis",
				title: "sp semantics conformant under the tree walk",
				severity: "ok",
				detail: sp
					? `sp=${sp} is read from the Org-Domain record and covers subdomains.`
					: "No sp gap: subdomains inherit the apex policy.",
			});
		}

		// ---- dmarcbis.reject_advisory (advisory, cross-category) ----
		const dkimHealthy = dkimIsHealthy(ctx);
		let rejectReality: DmarcbisRejectReality = {
			policy: policy ?? null,
			dkim_aligned_ok: null,
			spf_only_risk: false,
		};
		if (policy === "reject") {
			rejectReality = {
				policy: "reject",
				dkim_aligned_ok: dkimHealthy,
				spf_only_risk: !dkimHealthy,
			};
			if (!dkimHealthy) {
				findings.push({
					id: "dmarcbis.reject_advisory",
					checkId: "dmarcbis",
					title: "p=reject leans on SPF alone (DKIM unhealthy/absent)",
					severity: "warning",
					detail:
						"DMARCbis says a domain at p=reject MUST apply aligned DKIM and MUST NOT rely on SPF alone, because DKIM survives forwarding while SPF does not. The sibling DKIM category is unhealthy or absent this run, so authentication effectively leans on SPF — forwarded mail will bounce.",
					remediation:
						"DKIM-sign every sending stream with an aligned d= before staying at p=reject; ramp none→quarantine→reject if users post to mailing lists.",
					evidence: "p=reject",
				});
			} else {
				findings.push({
					id: "dmarcbis.reject_advisory",
					checkId: "dmarcbis",
					title: "p=reject backed by aligned DKIM",
					severity: "ok",
					detail: "The sibling DKIM category is healthy, so p=reject does not rely on SPF alone.",
				});
			}
		}

		// ---- dmarcbis.external_auth (reuse sibling external_report_auth[]) ----
		const externalAuth = sibling.externalReportAuth;
		const unauthorized = externalAuth.filter((e) => !e.authorized);
		if (externalAuth.length > 0) {
			if (unauthorized.length > 0) {
				findings.push({
					id: "dmarcbis.external_auth",
					checkId: "dmarcbis",
					title: `External report destination${unauthorized.length === 1 ? "" : "s"} not authorized under the RFC 9990 consent model`,
					severity: "info",
					detail: `RFC 9990 keeps the _report._dmarc external-destination consent requirement. ${unauthorized.map((e) => e.report_domain).join(", ")} lack${unauthorized.length === 1 ? "s" : ""} the authorization record, so ${unauthorized.length === 1 ? "it" : "they"} silently receive nothing. The operational dmarc check raises the critical; DMARCbis notes the conformance angle.`,
					remediation: `Have the destination publish <domain>._report._dmarc.<provider> = "v=DMARC1", or report to an in-domain mailbox (see dmarc.external_report_auth).`,
					evidence: unauthorized.map((e) => e.auth_name).join("; "),
				});
			} else {
				findings.push({
					id: "dmarcbis.external_auth",
					checkId: "dmarcbis",
					title: "External-report consent model conformant",
					severity: "ok",
					detail: "All external rua/ruf destinations publish the _report._dmarc authorization (RFC 9990).",
				});
			}
		} else {
			findings.push({
				id: "dmarcbis.external_auth",
				checkId: "dmarcbis",
				title: "No external report destinations to authorize",
				severity: "ok",
				detail: "All rua/ruf destinations are in-domain, so no _report._dmarc consent record is required.",
			});
		}

		// ---- FUTURE: report-schema conformance (needs ingested reports, ../emails.mdx) ----
		findings.push({
			id: "dmarcbis.report_schema",
			checkId: "dmarcbis",
			title: "DMARCbis report-schema conformance not yet evaluated",
			severity: "info",
			detail:
				"dmarcbis.report_schema (RFC 9990 dmarc-2.0 namespace, discovery_method=treewalk, named DKIM selector) and dmarcbis.failure_report_conformance (RFC 9991 dmarc failure type + Identity-Alignment) can only be verified once aggregate/failure reports are ingested for this domain — the pm/emails.mdx pipeline. They are gated as FUTURE and never fabricated.",
			remediation:
				"No action on your side — these reflect receiver conformance and will populate once report ingestion lands.",
		});

		// ---- Shell-out provenance (§3 execution table, rows 1–3) ----------------------------------
		const toolRuns: DmarcbisToolRun[] = [];
		const missingTools: string[] = [];
		let disagreeRung: string | null = null;

		// Row 1: checkdmarc — the conformance oracle cross-validating our tree-walk Org Domain + tags.
		const checkdmarcPath = toolPath(ctx, "checkdmarc");
		if (!checkdmarcPath) {
			missingTools.push("checkdmarc");
		} else {
			const inv = await invokeTool(
				checkdmarcPath,
				"checkdmarc",
				[ctx.domain, "-f", "json"],
				CHECKDMARC_TIMEOUT_MS,
				"json",
				pruneCheckdmarc,
				ctx.signal,
			);
			toolRuns.push(inv.entry);
			if (inv.entry.exit_code === 0 && inv.entry.parsed && walk.resolvedOrgDomain) {
				const loc = (inv.entry.parsed as { dmarc?: { location?: unknown } }).dmarc
					?.location;
				if (
					typeof loc === "string" &&
					loc.replace(/^_dmarc\./i, "") !== walk.resolvedOrgDomain
				) {
					appendDetail(
						findings,
						["dmarcbis.tree_walk"],
						`Cross-check: checkdmarc resolved the record at ${loc} — compare its output in the tool-runs footer.`,
					);
				}
			}
		}

		// Row 2: doggo — one invocation per DISTINCT parent name the walk queried (raw TXT evidence).
		const doggoPath = toolPath(ctx, "doggo");
		if (!doggoPath) {
			missingTools.push("doggo");
		} else {
			for (const qname of [...new Set(walk.queryPath.map((r) => r.name))]) {
				const inv = await invokeTool(
					doggoPath,
					"doggo",
					[qname, "TXT", "--json"],
					DOGGO_TIMEOUT_MS,
					"json",
					(p) => ({ answers: extractDoggoAnswers(p) }),
					ctx.signal,
				);
				toolRuns.push(inv.entry);
				if (!disagreeRung && inv.entry.exit_code === 0 && inv.entry.parsed) {
					const values = doggoTxtValues(
						(inv.entry.parsed as { answers: Record<string, unknown>[] }).answers,
					).filter(isDmarcRecord);
					const rung = walk.queryPath.find((r) => r.name === qname);
					if (rung && values.length > 0 !== rung.recordFound) disagreeRung = qname;
				}
			}
		}

		// Row 3 (conditional): kdig against a public resolver — only on a walk/doggo disagreement.
		if (disagreeRung) {
			const kdigPath = toolPath(ctx, "kdig");
			if (!kdigPath) {
				missingTools.push("kdig");
			} else {
				const inv = await invokeTool(
					kdigPath,
					"kdig",
					["@8.8.8.8", "+short", "TXT", disagreeRung],
					KDIG_TIMEOUT_MS,
					"text",
					(_p, stdout) => ({ lines: stdout.trim().split("\n").filter(Boolean) }),
					ctx.signal,
				);
				toolRuns.push(inv.entry);
			}
		}

		// Missing binary → invocation skipped, surfaced ONCE per run as an info finding (§3).
		if (missingTools.length > 0) {
			const formulas = [...new Set(missingTools.map((m) => TOOL_INSTALL[m] ?? m))];
			findings.push({
				id: "dmarcbis.tool_missing",
				checkId: "dmarcbis",
				title: `Debug tool${missingTools.length === 1 ? "" : "s"} not installed: ${missingTools.join(", ")}`,
				severity: "info",
				detail: `The ${missingTools.join(", ")} invocation${missingTools.length === 1 ? " was" : "s were"} skipped; the in-process node:dns tree walk and the sibling-read conformance checks above still ran.`,
				remediation: `brew install ${formulas.join(" ")}`,
			});
		}

		// ---- The §5 `dmarcbis:` section ----------------------------------------------------------
		const orgDomain: DmarcbisOrgDomain = {
			author_domain: ctx.domain,
			resolved_org_domain: walk.resolvedOrgDomain,
			found_via: walk.resolvedOrgDomain === null ? "tld-cap" : walk.foundVia,
			matches_enforced_record:
				walk.resolvedOrgDomain === null ? null : matches,
			query_path: toQueryPath(walk.queryPath),
			selected_by: walk.selectedBy,
			label_count: orgLabelCount,
			psd_verdict: psdVerdict,
			covered_by_parent: walk.coveredByParent,
		};
		const tags: DmarcbisTags = {
			valid_set_ok: validSetOk,
			np: npVal,
			psd: psdVal,
			t: tVal,
			removed_tags_present: removedPresent,
			reject_reality: rejectReality,
		};
		const section: DmarcbisSection = {
			status: worstSeverity(findings),
			read_from: "dmarc",
			org_domain: orgDomain,
			tags,
			tool_runs: toolRuns,
			tests: buildTests(findings),
			problem_states: deriveProblemStates(findings),
		};
		return { findings, results: section };
	},
};
