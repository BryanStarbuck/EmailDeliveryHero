/**
 * The audit engine's shared vocabulary. Each deliverability check is a small pluggable `Checker`
 * that inspects one aspect of a domain's email setup (SPF, DKIM, DMARC, MX, blacklist) and returns
 * zero or more `Finding`s. A finding always carries a severity and, when something is wrong, a
 * concrete `remediation` string telling the user exactly how to fix it.
 */

export type Severity = "ok" | "info" | "warning" | "critical";

export interface Finding {
	/** Stable id for the finding kind, e.g. "spf.missing". */
	id: string;
	/** Which checker produced it, e.g. "spf". */
	checkId: string;
	title: string;
	severity: Severity;
	/** Human explanation of what was observed. */
	detail: string;
	/** How to fix it (present when severity is warning/critical; omitted when ok). */
	remediation?: string;
	/** Raw evidence (the DNS record found, the blocklist that matched, etc.). */
	evidence?: string;
	/**
	 * Regression flag (pm/engineering.mdx §8): true when this problem newly appeared — or worsened in
	 * severity — versus the domain's previous run. Only set on warning/critical findings, and only
	 * when a previous run exists to diff against.
	 */
	isNew?: boolean;
	/**
	 * Evidence provenance (pm/emails.mdx §9): "report" when the finding derives from an ingested
	 * DMARC-aggregate/TLS-RPT report email rather than a live DNS lookup/probe. The run-detail UI
	 * renders these with a "from reports" chip (pm/emails.mdx §7.2).
	 */
	source?: "report";
}

/** A DKIM public-key hash observed on another monitored domain (latest audit). */
export interface PeerDkimKey {
	domain: string;
	selector: string;
	keySha256: string;
}

/**
 * One forwarder / mailing list a domain declares it sends through (pm/checks/arc.mdx §4/§5 — the
 * `arc_forwarders` reference table, stored per-domain as `arc.forwarders` in domains.yaml today).
 */
export interface ArcForwarderConfig {
	/** Human label, e.g. "acme-users Google Group". */
	label: string;
	/** The probe target that forwards to us. */
	forwardAddress: string;
	/** Expected ARC signing domain (d=); nullable until configured or observed from a sample. */
	signerDomain?: string;
	/** Expected ARC signing selector (s=). */
	signerSelector?: string;
	/** Where the forwarded copy lands for capture (drives the future swaks probe). */
	probeMailbox?: string;
}

/** Per-domain ARC / forwarding configuration (pm/checks/arc.mdx §4 per-domain config inputs). */
export interface ArcConfig {
	/** Operator-declared "this domain sends through forwarders/lists" flag. */
	usesForwarding: boolean;
	/** The declared forwarders / mailing lists. */
	forwarders: ArcForwarderConfig[];
}

/**
 * Per-domain DNS-health expectations/config (pm/checks/dns_health.mdx §4/§5 — the
 * `dns_health_expectations` table mapped onto the domain store as `dnsHealth`).
 */
export interface DnsHealthConfig {
	/** Extra subdomain labels to include in the dangling-CNAME scan beyond the mail defaults. */
	extraLabels: string[];
	/** Optional NS allow-list; the checker flags drift when the published NS set differs. */
	expectedNs: string[];
	/** Skip the (future) AXFR zone-transfer probe for this domain. */
	skipAxfrProbe: boolean;
}

/**
 * Per-domain mail-routing expectations (pm/checks/mx_routing.mdx §4/§5 — the `mx_expectations`
 * table mapped onto the domain store as `mx`): the "this domain receives mail" intent toggle that
 * drives whether an empty/null MX is critical vs expected, an optional expected-MX allow-list
 * (drift detection), and the skip-SMTP-probe switch for hosts whose egress blocks port 25.
 */
export interface MxRoutingConfig {
	/** Declared intent: the domain is expected to receive mail (schema default TRUE). */
	receivesMail?: boolean;
	/** Optional allow-list of MX FQDNs; the checker flags drift when the published set differs. */
	expectedHosts?: string[];
	/** Skip the (future) TCP/25 SMTP probes for this domain (egress-blocked hosts). */
	skipSmtpProbe?: boolean;
}

/**
 * Per-domain Domain-Registration-Reputation config (pm/checks/domain_reputation.mdx §4 per-domain
 * config inputs, admin-only): the org brand string(s) for `infra.name_similarity`, the expiry /
 * age warning thresholds (both default 30 days), the "registrant is intentionally public" toggle
 * that silences `infra.registrant_privacy`, and the (future) active cousin-domain scan toggle.
 */
export interface DomainReputationConfig {
	/** Org brand string(s) compared against the apex for lookalike/cousin detection. */
	brands: string[];
	/** Days-to-expiry below which infra.domain_expiry warns (default 30). */
	expiryWarnDays?: number;
	/** Registration age (days) below which infra.domain_age warns (default 30). */
	ageWarnDays?: number;
	/** The registrant contact is deliberately public — silences infra.registrant_privacy. */
	registrantPublicIntentional?: boolean;
	/** Enable the (future) active cousin-domain scan (default off — RDAP cost/rate limits). */
	cousinScan?: boolean;
}

/**
 * Per-domain List-Unsubscribe / one-click configuration (pm/checks/list_unsubscribe.mdx §3/§4
 * per-domain config inputs, stored on the domain record in domains.yaml).
 */
export interface ListUnsubDomainConfig {
	/**
	 * Bulk-sender scope (> 5,000 msgs/day to Gmail/Yahoo users). When true, a missing one-click
	 * header / mailto:-only header escalates from warning to critical (§3).
	 */
	isBulkSender: boolean;
	/**
	 * Opt-in live endpoint probe (default off — §3 Safety): when true (and globally permitted),
	 * the checker POSTs `List-Unsubscribe=One-Click` to the https URI, which MAY unsubscribe the
	 * sampled recipient. Drives content.list_unsub_reachable / _https_get_safe / _tls.
	 */
	probeUnsubEndpoint: boolean;
}

/**
 * Per-domain BIMI configuration (pm/checks/bimi.mdx §4 per-domain config inputs): optional extra
 * BIMI selectors beyond `default`, and an optional sample message whose `BIMI-Selector:` header
 * names the selector the domain's mail streams actually reference.
 */
export interface BimiDomainConfig {
	/** BIMI selectors to audit beyond "default" — each is looked up at `<selector>._bimi.<domain>`. */
	selectors: string[];
	/** Raw sample message (headers suffice) — the checker reads its `BIMI-Selector:` header. */
	sampleMessage?: string;
}

/**
 * Per-domain DANE / TLSA configuration (pm/checks/dane_tlsa.mdx §4 per-domain config inputs,
 * admin-only). DANE needs no input beyond the auto-discovered MX list — the single optional knob
 * is a pinned "expected next-cert SPKI digest" so the app can proactively warn when the rollover
 * record for a planned renewal is not yet staged in DNS.
 */
export interface DaneDomainConfig {
	/**
	 * Hex SHA-256 of the NEXT certificate's SubjectPublicKeyInfo (the `3 1 1` association data the
	 * admin plans to roll to). When set, `infra.dane_rollover` warns until a TLSA record with this
	 * exact digest is published alongside the current one.
	 */
	expectedNextSpki?: string;
}

/**
 * Per-domain MTA-STS configuration (pm/checks/mta_sts.mdx §4 per-domain config inputs, admin-only):
 * the "Desired MTA-STS mode" target the `infra.mta_sts_mode` sub-check compares the served policy
 * against. Absent ⇒ the default target is `enforce` (spec §5); `off` silences the comparison.
 */
export interface MtaStsDomainConfig {
	desiredMode: "enforce" | "testing" | "off";
}

/**
 * Per-domain Link / URL-reputation configuration (pm/checks/link_url_reputation.mdx §4 per-domain
 * config inputs): the domain's own/related/allow-listed link domains for
 * `content.url_domain_alignment` — tracking/click/CDN domains the org controls that should count
 * as "on-brand" even though they differ from the sending domain. Absent = only the sending
 * domain's registrable domain (and its subdomains) count as aligned.
 */
export interface LinkUrlDomainConfig {
	/** Registrable domains treated as aligned (own/related/allow-listed), e.g. ["clicks.example.net"]. */
	allowedDomains: string[];
}

/** Everything a checker needs to inspect one domain. */
export interface CheckContext {
	domain: string;
	/**
	 * The monitored domain's store id — keys per-domain stores (e.g. content sample messages and
	 * the per-domain report store `<state>/reports/<domainId>/`, pm/emails.mdx §9).
	 */
	domainId?: string;
	/**
	 * The envelope run id this checker execution belongs to (timestamp-prefixed, generated at run
	 * start). A checker with its own deep store records it as/with its store id so the run-record
	 * snapshot and the deep-store copy join (pm/storage.mdx §7A/§16 D8+D12 — e.g. the blacklist
	 * store's `audit_id`). Absent on spot checks and probes, which never persist.
	 */
	runId?: string;
	/** DKIM selectors to probe, e.g. ["google", "default"]. */
	dkimSelectors: string[];
	/** Sending IPs to test against DNS blacklists (optional; MX IPs are used when empty). */
	sendingIps: string[];
	/** sha256(decoded p=) per selector across the OTHER monitored domains — powers dkim.duplicate_key. */
	peerDkimKeys?: PeerDkimKey[];
	/**
	 * Every monitored domain (id + name) — powers the report-email corpus test's per-domain
	 * attribution (pm/emails.mdx §13.1): each report names its own policy domain, and the scanner
	 * routes it to the matching monitored domain's store, never to the domain being audited.
	 */
	monitoredDomains?: { id: string; name: string }[];
	/** The previous audit's structured results for this domain — powers dkim.rotation first-seen carry-forward. */
	previousResults?: Record<string, unknown>;
	/** Per-domain ARC / forwarding config — powers arc.applicable / arc.forwarding_risk / arc.selector_dns. */
	arc?: ArcConfig;
	/**
	 * Per-domain DNS-health expectations (pm/checks/dns_health.mdx §4) — extra dangling-scan labels,
	 * an optional expected-NS allow-list (drift detection), and the skip-AXFR-probe toggle.
	 */
	dnsHealth?: DnsHealthConfig;
	/**
	 * Per-domain mail-routing expectations (pm/checks/mx_routing.mdx §4) — the receives-mail intent
	 * (infra.mx_present / infra.mx_null severity), the expected-MX allow-list (drift detection), and
	 * the skip-SMTP-probe toggle. Absent = receives mail, no allow-list, probes allowed.
	 */
	mx?: MxRoutingConfig;
	/**
	 * Per-domain DANE config (pm/checks/dane_tlsa.mdx §4) — the optional pinned expected next-cert
	 * SPKI digest that lets `infra.dane_rollover` proactively warn when the pre-staged rollover
	 * TLSA record is missing.
	 */
	dane?: DaneDomainConfig;
	/**
	 * Per-domain MTA-STS config (pm/checks/mta_sts.mdx §4, admin-only) — the "Desired MTA-STS mode"
	 * target the `infra.mta_sts_mode` sub-check compares the served policy's `mode:` against.
	 * Absent ⇒ the default target is `enforce` (spec §5); `off` silences the comparison.
	 */
	mtaSts?: MtaStsDomainConfig;
	/** Per-domain BIMI config — powers content.bimi_selector (extra selectors + BIMI-Selector header compare). */
	bimi?: BimiDomainConfig;
	/**
	 * Per-domain list-management config (pm/checks/list_unsubscribe.mdx §3/§4): the isBulkSender
	 * severity escalator and the opt-in probeUnsubEndpoint toggle for the one-click POST probe.
	 */
	listUnsub?: ListUnsubDomainConfig;
	/**
	 * Per-domain registration-reputation config (pm/checks/domain_reputation.mdx §4) — brand
	 * strings, expiry/age thresholds, and the registrant-public / cousin-scan toggles.
	 */
	domainReputation?: DomainReputationConfig;
	/**
	 * Per-domain Link / URL-reputation config (pm/checks/link_url_reputation.mdx §4) — the
	 * own/related/allow-listed link domains that count as aligned for content.url_domain_alignment.
	 */
	linkUrl?: LinkUrlDomainConfig;
	/**
	 * Which trigger started this run — pure data (pm/run_checks.mdx §9): the run graph never
	 * branches on it. The registration checker alone reads it, to bypass its long-TTL RDAP cache on
	 * a manual run-now (pm/checks/domain_reputation.mdx §6 "a manual run always bypasses the cache").
	 */
	trigger?: AuditTrigger;
	/**
	 * Cooperative cancellation from the per-domain run deadline (pm/run_checks.mdx §10). Checkers
	 * pass it to DNS calls and child processes so a deadline reclaims sockets and kills children.
	 */
	signal?: AbortSignal;
	/**
	 * Stage-0 tool discovery (pm/run_checks.mdx §5.2): the external tools resolved to absolute
	 * paths once per run (null = not installed → the checker degrades, never fails).
	 */
	tools?: Record<string, string | null>;
	/**
	 * Shared upstream outputs (pm/run_checks.mdx §2 Stage 1): the structured `results` payload of
	 * every already-finished checker in THIS run, keyed by checker id. This is how `mx_routing`'s
	 * resolved MX list is published for Stage-2/3 consumers, which must not re-derive it.
	 */
	upstream?: Record<string, unknown>;
}

/**
 * A checker may return a bare finding list, or findings plus a structured machine-readable payload
 * (pm/checks/*.mdx §5 "Information schema" — e.g. the parsed DMARC tag map). The payload lands in
 * `AuditResult.results[checker.id]` and powers the per-technology detail pages.
 */
export interface CheckOutcome {
	findings: Finding[];
	results?: unknown;
}

export interface Checker {
	id: string;
	label: string;
	run(ctx: CheckContext): Promise<Finding[] | CheckOutcome>;
}

/**
 * Who started a run (pm/run_checks.mdx §1/§9). The tag is pure DATA — `runForDomain` contains
 * zero conditional logic on it; it only lands on the audit record and in the log lines so the
 * history view and logs can distinguish who asked even though what ran is identical.
 */
export type AuditTrigger =
	| "manual"
	| "scheduled-inprocess"
	| "scheduled-os"
	| "api";

/**
 * The result of auditing one domain — the full finding list plus a rolled-up score/status.
 * Vocabulary (pm/dashboard.mdx §1): this is one RUN — per domain, with start/stop date-times.
 * Inside it, the six categories are TESTS and each finding belongs to a SUB-TEST.
 */
export interface AuditResult {
	/** Unique id for this run (pm/dashboard.mdx §1). Absent only on pre-history persisted data. */
	runId: string;
	domainId: string;
	domain: string;
	/** ISO date-time the run started. */
	startedAt: string;
	/** ISO date-time the run stopped. */
	finishedAt: string;
	/** Kept for older readers; always equals finishedAt. */
	ranAt: string;
	/** Which trigger started this run (pm/run_checks.mdx §9). Absent on pre-history data. */
	trigger?: AuditTrigger;
	/**
	 * Category scope of the run (pm/checks/blacklists.mdx §21 / AC 26; pm/checks/dkim.mdx §7.7;
	 * pm/checks/dns.mdx §15.1): absent = a full run of all six categories; "blacklists" / "dkim" /
	 * "dns" = a category-scoped re-run that executed only that category; "dns.<family_key>" (e.g.
	 * "dns.reverse_dns") = a single DNS & Infrastructure family re-run. The run file carries
	 * `run.scope: <value>`. Scoped runs appear in prev/next stepping and the history strip
	 * chip-tagged with this value.
	 */
	scope?: "blacklists" | "dkim" | "dns" | `dns.${string}`;
	/**
	 * Category prefixes a scoped re-run executed (pm/checks/spf.mdx §6.5 — e.g. ["spf"] on a
	 * `POST /audit/run/:domainId?checks=spf` run whose sibling categories were carried forward
	 * verbatim). Absent on a full run of all six categories.
	 */
	checks?: string[];
	/** 0–100, derived from finding severities. */
	score: number;
	status: Severity;
	findings: Finding[];
	counts: Record<Severity, number>;
	/**
	 * How many findings in this run are NEW problems versus the previous run (pm/engineering.mdx §8
	 * regression detection) — i.e. how many findings carry `isNew: true`. 0 on a domain's first run.
	 */
	newProblemCount?: number;
	/** Structured per-check payloads keyed by checker id (e.g. results.dmarc — the parsed record). */
	results?: Record<string, unknown>;
}

/** Severity ordering used by the regression diff — higher rank = worse. */
const SEVERITY_RANK: Record<Severity, number> = {
	ok: 0,
	info: 1,
	warning: 2,
	critical: 3,
};

/**
 * Regression detection (pm/engineering.mdx §8): diff a run's findings against the domain's
 * previous run. A warning/critical finding is flagged `isNew` when its `id` did not exist in the
 * previous run, or when it existed at a lower severity (it worsened). Mutates the passed findings
 * in place and returns how many were flagged. With no previous run there is no baseline to
 * regress from, so nothing is flagged.
 */
export function flagNewProblems(
	previous: Finding[] | undefined,
	current: Finding[],
): number {
	if (!previous) return 0;
	const previousRank = new Map<string, number>();
	for (const f of previous) {
		const rank = SEVERITY_RANK[f.severity];
		const seen = previousRank.get(f.id);
		if (seen === undefined || rank > seen) previousRank.set(f.id, rank);
	}
	let flagged = 0;
	for (const f of current) {
		if (f.severity !== "warning" && f.severity !== "critical") continue;
		const before = previousRank.get(f.id);
		if (before === undefined || SEVERITY_RANK[f.severity] > before) {
			f.isNew = true;
			flagged++;
		}
	}
	return flagged;
}

/** Points deducted per finding severity (pm/spam_checks.mdx roll-up, pm/settings.mdx §2). */
export interface SeverityWeights {
	critical: number;
	warning: number;
	info: number;
}

/**
 * The built-in weights, mirroring `config.yaml → checks.weights` defaults (pm/settings.mdx §2):
 * critical > warning > info. The audit engine passes the operator-configured weights so the
 * roll-up reflects real-world impact (pm/spam_checks.mdx "Scoring & how categories roll up").
 */
export const DEFAULT_SEVERITY_WEIGHTS: SeverityWeights = {
	critical: 40,
	warning: 15,
	info: 0,
};

/** Roll a flat finding list into a 0–100 score, an overall status, and per-severity counts. */
export function summarize(
	findings: Finding[],
	weights: SeverityWeights = DEFAULT_SEVERITY_WEIGHTS,
): {
	score: number;
	status: Severity;
	counts: Record<Severity, number>;
} {
	const counts: Record<Severity, number> = {
		ok: 0,
		info: 0,
		warning: 0,
		critical: 0,
	};
	for (const f of findings) counts[f.severity]++;

	// Weighted deduction per finding (critical > warning > info — pm/engineering.mdx §6.2); floor at 0.
	const penalty =
		counts.critical * weights.critical +
		counts.warning * weights.warning +
		counts.info * weights.info;
	const score = Math.max(0, 100 - penalty);

	const status: Severity =
		counts.critical > 0
			? "critical"
			: counts.warning > 0
				? "warning"
				: counts.info > 0
					? "info"
					: "ok";

	return { score, status, counts };
}
