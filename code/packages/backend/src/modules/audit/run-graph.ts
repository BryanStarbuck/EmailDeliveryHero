import type { Checker } from "./checks/types";

/**
 * The check dependency graph (pm/run_checks.mdx §2). One domain's run is a dependency-ordered
 * graph, not a lockstep sequence: every check with no entry here is a Stage-1 FOUNDATION check and
 * launches immediately; a check listed here starts the moment ITS OWN named prerequisites finish —
 * there is no barrier (`mta_sts` can run while `spf` is still expanding its include graph).
 *
 * The edges come from the per-check specs (verify there before changing them here):
 *  - dmarc ← spf + dkim         alignment evaluation consumes both results
 *  - bimi  ← dmarc              BIMI requires DMARC enforcement; reads the sibling dmarc result
 *  - arc   ← dmarc              advisory verdict is framed by the DMARC policy
 *  - mta_sts ← mx_routing       the policy's mx: patterns are validated against the real MX list
 *  - dane_tlsa ← mx_routing + dnssec   TLSA lives at _25._tcp.<mx>; DANE without DNSSEC is meaningless
 *  - tls_transport / smtp_security ← mx_routing   the future SMTP probes consume the Stage-1 MX list
 *  - content.scoring ← dmarc + the DNS foundations   SpamAssassin scoring is CPU-bound, so it runs
 *    after the pure-DNS checks (pm/checks/content_scoring.mdx §3/§6)
 */
export const CHECK_DEPENDENCIES: Record<string, string[]> = {
	dmarc: ["spf", "dkim"],
	// dkim2 ← dkim: the DKIM2 companion reuses the DKIM selector observations and key-readiness
	//   (pm/checks/dkim2.mdx §3); its applicability is also framed by the DMARC policy it reads
	//   from the shared upstream, but the only hard prerequisite is the DKIM selector scan.
	dkim2: ["dkim"],
	arc: ["dmarc"],
	// dmarcbis ← dmarc: the conformance lens reads the already-parsed DMARC record instead of
	//   re-tokenizing it (pm/checks/dmarcbis.mdx §4 — "read the sibling dmarc result first").
	dmarcbis: ["dmarc"],
	"content.bimi": ["dmarc"],
	"content.scoring": [
		"dmarc",
		"infra.mx_routing",
		"infra.dnssec",
		"infra.dns_health",
	],
	// The unsubscribe-host reputation cross-check reuses content.url's URI-zone answers
	// (pm/checks/list_unsubscribe.mdx §2 content.list_unsub_url_reputation / §6 "reuses
	// link_url_reputation"), so the list-management pass starts after the link scan publishes.
	"content.list_unsubscribe": ["content.url"],
	"infra.mta_sts": ["infra.mx_routing"],
	"infra.dane_tlsa": ["infra.mx_routing", "infra.dnssec"],
	"infra.tls_transport": ["infra.mx_routing"],
	"infra.smtp_security": ["infra.mx_routing"],
	// The report-email corpus scan runs FIRST, then the per-category report derivations read the
	// store it just refreshed (pm/emails.mdx §13.1 "Ordering" / AC 14): dmarc.reports emits the §5
	// dmarc.report_* findings, infra.tls_rpt appends infra.tls_rpt_reports_ingested.
	"dmarc.reports": ["content.report_emails"],
	"infra.tls_rpt": ["content.report_emails"],
};

/**
 * Execute the registry as a promise-graph (pm/run_checks.mdx §3.1): each check's `runOne` is
 * `Promise.all(itsDeps).then(run)` — the dependency table IS the schedule. All Stage-1 checks
 * start simultaneously; each dependent check starts as soon as its named prerequisites settle.
 *
 * `runOne` is expected never to reject (the audit runner contains checker errors per
 * pm/errors.mdx); if it does anyway, dependents still run — a failed prerequisite must never
 * silently drop the rest of its subtree, and the graph as a whole always settles.
 */
export async function runCheckerGraph(
	checkers: readonly Checker[],
	runOne: (checker: Checker) => Promise<void>,
): Promise<void> {
	const byId = new Map(checkers.map((c) => [c.id, c]));
	const started = new Map<string, Promise<void>>();

	const promiseFor = (
		checker: Checker,
		visiting: Set<string>,
	): Promise<void> => {
		const existing = started.get(checker.id);
		if (existing) return existing;
		// Cycle guard: a mis-declared back edge is ignored rather than deadlocking the run.
		const nextVisiting = new Set(visiting).add(checker.id);
		const deps = (CHECK_DEPENDENCIES[checker.id] ?? [])
			.filter((id) => !nextVisiting.has(id))
			.map((id) => byId.get(id))
			.filter((dep): dep is Checker => dep !== undefined)
			.map((dep) => promiseFor(dep, nextVisiting));
		const run = Promise.allSettled(deps).then(() => runOne(checker));
		started.set(checker.id, run);
		return run;
	};

	await Promise.allSettled(checkers.map((c) => promiseFor(c, new Set())));
}
