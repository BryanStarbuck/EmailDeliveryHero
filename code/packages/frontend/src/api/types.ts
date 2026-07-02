/** Shared API types — mirror the backend DTOs (packages/backend/src/modules/*). */

export type Severity = "ok" | "info" | "warning" | "critical";

/** One declared forwarder / mailing list a domain sends through (pm/checks/arc.mdx §4). */
export interface ArcForwarderConfig {
	/** Human label, e.g. "acme-users Google Group". */
	label: string;
	/** The probe target that forwards to us. */
	forwardAddress: string;
	/** Expected ARC signing domain (d=); absent until configured or observed from a sample. */
	signerDomain?: string;
	/** Expected ARC signing selector (s=). */
	signerSelector?: string;
	/** Where the forwarded copy lands for capture (future swaks probe). */
	probeMailbox?: string;
}

/** Per-domain ARC / forwarding configuration (pm/checks/arc.mdx §4 per-domain config inputs). */
export interface ArcConfig {
	/** Operator-declared "this domain sends through forwarders/lists" flag. */
	usesForwarding: boolean;
	forwarders: ArcForwarderConfig[];
}

/** Per-domain BIMI configuration (pm/checks/bimi.mdx §4 per-domain config inputs). */
export interface BimiDomainConfig {
	/** BIMI selectors to audit beyond "default" (each checked at <selector>._bimi.<domain>). */
	selectors: string[];
	/** Raw sample message (headers suffice) — the checker reads its BIMI-Selector: header. */
	sampleMessage?: string;
}

/** Per-domain DNS-health expectations (pm/checks/dns_health.mdx §4 per-domain config inputs). */
export interface DnsHealthConfig {
	/** Extra subdomain labels to include in the dangling-CNAME scan beyond the mail defaults. */
	extraLabels: string[];
	/** Optional NS allow-list; the checker flags drift when the published NS set differs. */
	expectedNs: string[];
	/** Skip the (future) AXFR zone-transfer probe for this domain. */
	skipAxfrProbe: boolean;
}

/**
 * Per-domain Domain-Registration-Reputation config (pm/checks/domain_reputation.mdx §4 per-domain
 * config inputs, admin-only) — mirrors the backend DomainReputationConfigDto.
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
 * Per-domain mail-routing expectations (pm/checks/mx_routing.mdx §4 per-domain config inputs —
 * the "Mail routing" panel, the §5 `mx_expectations` shape) — mirrors the backend
 * MxRoutingConfigDto.
 */
export interface MxRoutingConfig {
	/** Declared intent: the domain is expected to receive mail (default true). */
	receivesMail?: boolean;
	/** Optional allow-list of MX FQDNs; the checker flags drift when the published set differs. */
	expectedHosts?: string[];
	/** Skip the (future) TCP/25 SMTP probes for this domain (egress-blocked hosts). */
	skipSmtpProbe?: boolean;
}

/**
 * Per-domain Link / URL-reputation config (pm/checks/link_url_reputation.mdx §4 per-domain config
 * inputs) — mirrors the backend LinkUrlConfigDto.
 */
export interface LinkUrlDomainConfig {
	/** Registrable domains treated as aligned (own/related/allow-listed), e.g. ["clicks.example.net"]. */
	allowedDomains: string[];
}

/**
 * Per-domain List-Unsubscribe / one-click config (pm/checks/list_unsubscribe.mdx §3/§4 per-domain
 * config inputs) — mirrors the backend ListUnsubConfigDto.
 */
export interface ListUnsubDomainConfig {
	/** Bulk sender (> 5,000 msgs/day): escalates missing one-click / mailto:-only to critical. */
	isBulkSender: boolean;
	/** Opt-in live one-click POST probe (default off — may unsubscribe the sampled recipient). */
	probeUnsubEndpoint: boolean;
}

export interface MonitoredDomain {
	id: string;
	name: string;
	label: string;
	dkimSelectors: string[];
	sendingIps: string[];
	/** Whether this domain is included in recurring scheduled checks (ANDed with the global switch). */
	scheduleEnabled: boolean;
	/** ARC / forwarding config (pm/checks/arc.mdx §4). Absent = no forwarding declared. */
	arc?: ArcConfig;
	/** BIMI config (pm/checks/bimi.mdx §4). Absent = only the default selector is audited. */
	bimi?: BimiDomainConfig;
	/** DNS-health expectations (pm/checks/dns_health.mdx §4). Absent = defaults only. */
	dnsHealth?: DnsHealthConfig;
	/**
	 * Mail-routing expectations (pm/checks/mx_routing.mdx §4): receives-mail intent, expected-MX
	 * allow-list (drift detection), and the skip-SMTP-probe toggle. Absent = receives mail.
	 */
	mx?: MxRoutingConfig;
	/** Registration-reputation config (pm/checks/domain_reputation.mdx §4). Absent = defaults. */
	domainReputation?: DomainReputationConfig;
	/** Link / URL-reputation config (pm/checks/link_url_reputation.mdx §4). Absent = sender-domain only. */
	linkUrl?: LinkUrlDomainConfig;
	/**
	 * List-management config (pm/checks/list_unsubscribe.mdx §4): the isBulkSender escalator and
	 * the opt-in probeUnsubEndpoint toggle. Absent = not a bulk sender, probe off.
	 */
	listUnsub?: ListUnsubDomainConfig;
	addedBy: string;
	createdAt: string;
	updatedAt: string;
}

export interface Finding {
	id: string;
	checkId: string;
	title: string;
	severity: Severity;
	detail: string;
	remediation?: string;
	evidence?: string;
	/**
	 * Regression flag (pm/engineering.mdx §8): true when this problem newly appeared — or worsened
	 * in severity — versus the domain's previous run.
	 */
	isNew?: boolean;
	/**
	 * Evidence provenance (pm/emails.mdx §7.2/§9): "report" when the finding derives from an
	 * ingested DMARC-aggregate/TLS-RPT report email — rendered with a "from reports" chip.
	 */
	source?: "report";
}

/** One external rua/ruf destination and its `_report._dmarc` authorization state. */
export interface DmarcExternalAuth {
	report_kind: "rua" | "ruf";
	report_uri: string;
	report_domain: string;
	auth_name: string;
	authorized: boolean;
}

/** The parsed DMARC observation — §5's `record:` block (pm/checks/dmarc.mdx). */
export interface DmarcResults {
	query_name: string;
	record_found: boolean;
	record_count: number;
	found_at: string | null;
	raw_record: string | null;
	parsed: Record<string, string> | null;
	policy: "none" | "quarantine" | "reject" | null;
	subdomain_policy: "none" | "quarantine" | "reject" | null;
	np_policy: string | null;
	pct: number | null;
	adkim: string;
	aspf: string;
	rua_uris: string[];
	ruf_uris: string[];
	fo: string | null;
	ri: number | null;
	is_enforcing: boolean;
	external_reports_authorized: boolean | null;
	external_report_auth: DmarcExternalAuth[];
}

/** One captured external-tool invocation (`dmarc.tool_runs[]`, pm/checks/dmarc.mdx §3/§5). */
export interface DmarcToolRun {
	tool: string;
	command: string;
	started_at: string;
	duration_ms: number;
	exit_code: number | null;
	output_format: "json" | "text";
	parsed: unknown | null;
	error: string | null;
}

/** One per-sub-test row (`dmarc.tests[]`, pm/checks/dmarc.mdx §5). */
export interface DmarcTestRow {
	id: string;
	title: string;
	result: "pass" | "fail" | "warn" | "info";
	detail?: string;
	evidence?: string;
	/** The exact DNS record the fix expects, e.g. `<auth_name> TXT "v=DMARC1"` (§5 example). */
	dns_value_expected?: string;
	fix?: string;
}

/**
 * The whole `dmarc:` run-YAML section (`results.dmarc`, pm/checks/dmarc.mdx §5): worst-severity
 * status, the parsed observation, the shell-out provenance, the per-test rows, and the derived
 * §9 problem-state ids. Runs persisted before this shape may hold the bare record instead.
 */
export interface DmarcSection {
	status: Severity;
	record: DmarcResults;
	tool_runs: DmarcToolRun[];
	tests: DmarcTestRow[];
	problem_states: string[];
}

/**
 * The per-run ARC observation (`results.arc`, pm/checks/arc.mdx §5). First round is advisory-only,
 * so the sample-derived fields stay null until a forwarded message sample is captured (FUTURE).
 */
export interface ArcForwarderObservation {
	label: string;
	forwardAddress: string;
	signerDomain: string | null;
	signerSelector: string | null;
	selectorResolves: boolean | null;
	/** §9.11 recorded data — optional so runs persisted before the fields existed still render. */
	rawKeyRecord?: string | null;
	keyType?: string | null;
	keyBits?: number | null;
}

export interface ArcResults {
	applicable: boolean | null;
	forwardingRisk: boolean | null;
	forwarders: ArcForwarderObservation[];
	messageSampleId: string | null;
	chainPresent: boolean | null;
	chainLength: number | null;
	cvResult: string | null;
	sealValid: boolean | null;
	amsValid: boolean | null;
	instancesOk: boolean | null;
	oldestPass: boolean | null;
	instances: unknown[] | null;
	probeSentAt: string | null;
	notes: string | null;
	/** The DMARC p= the applicability verdict used + its provenance (pm/checks/arc.mdx §9.11). */
	dmarcPolicy?: string | null;
	policySource?: "sibling" | "dns" | null;
}

/** One parsed apex-level SPF term (mechanism or redirect/exp modifier). */
export interface SpfMechanism {
	qualifier: "+" | "-" | "~" | "?";
	type: string;
	value: string | null;
	/** Whether evaluating this term costs one of the 10 allowed DNS lookups. */
	lookup: boolean;
	raw: string;
}

/** One node of the recursively expanded include/redirect graph. */
export interface SpfTreeNode {
	term: string;
	depth: number;
	cost_lookups: number;
	is_void: boolean;
	resolved_to: string[];
	children: SpfTreeNode[];
}

export interface SpfIpCoverage {
	ip: string;
	covered: boolean;
	matched_by: string | null;
}

/** One captured external-tool invocation (`spf.tool_runs[]`, pm/checks/spf.mdx §3/§5). */
export interface SpfToolRun {
	tool: string;
	command: string;
	started_at: string;
	duration_ms: number;
	exit_code: number | null;
	output_format: "json" | "text";
	parsed: unknown;
	error: string | null;
}

/** The parsed SPF observation (`results.spf`, pm/checks/spf.mdx §5). */
export interface SpfResults {
	query_name: string;
	record_found: boolean;
	record_count: number;
	raw_record: string | null;
	mechanisms: SpfMechanism[];
	lookup_count: number;
	void_count: number;
	all_qualifier: "-all" | "~all" | "?all" | "+all" | null;
	has_redirect: boolean;
	byte_length: number;
	/** valid | permerror | temperror | none. */
	eval_result: string;
	/** Apex TXT RRset TTL from dig (null when dig is absent) — drives the TTL posture chip. */
	ttl: number | null;
	/** Local vs 8.8.8.8 public-resolver view of the v=spf1 set (null when dig is absent). */
	cross_resolver: {
		resolver: string;
		agrees: boolean;
		public_records: string[];
	} | null;
	/** IPv6-completeness posture (spf.ipv6). */
	ipv6: { pass_set_v6_count: number; mx_has_aaaa: boolean };
	/** Declared mail role vs the record (spf.mail_posture). */
	mail_posture: {
		has_mx: boolean;
		null_mx: boolean;
		non_sending_record: boolean;
	};
	/** DNS-side DMARC alignment posture (spf.alignment_prep): the _dmarc record's aspf= tag. */
	alignment: { dmarc_found: boolean; aspf: "r" | "s" | null };
	include_tree: SpfTreeNode | null;
	pass_set: { cidr: string; source: string }[];
	ip_coverage: SpfIpCoverage[];
	/** External tool invocations captured during the run (file-only forensics, §5). */
	tool_runs?: SpfToolRun[];
}

/** One probed DKIM selector (`results.dkim.selectors[]`, pm/checks/dkim.mdx §5). */
export interface DkimSelectorResult {
	selector: string;
	query_name: string;
	source: "configured" | "discovered";
	resolved_via: "txt" | "cname" | "none";
	cname_target: string | null;
	present: boolean;
	parses: boolean;
	raw_record: string | null;
	dkim_version: string | null;
	key_type: string | null;
	key_bits: number | null;
	key_sha256: string | null;
	has_test_flag: boolean;
	has_strict_flag: boolean;
	is_revoked: boolean;
	txt_record_count: number;
	oversize_chunk: boolean;
	flags: Record<string, string>;
	/**
	 * Local vs 8.8.8.8/1.1.1.1 view (dkim.mdx §2.2 `dkim.resolver_agreement`): true = agree,
	 * false = split view, null = not cross-checked. Absent on older persisted runs.
	 */
	resolvers_agree?: boolean | null;
	first_seen_at: string | null;
}

/** Historic ADSP leftover at `_adsp._domainkey.<domain>` (`results.dkim.adsp`, dkim.mdx §5). */
export interface DkimAdspObservation {
	present: boolean;
	/** The raw TXT when present, e.g. "dkim=discardable". */
	record: string | null;
	practice: "unknown" | "all" | "discardable" | null;
}

/** Pre-DKIM DomainKeys policy record at `_domainkey.<domain>` (`results.dkim.legacy_domainkeys`). */
export interface DkimLegacyDomainKeysObservation {
	present: boolean;
	/** The raw TXT when present, e.g. "o=-; n=notes". */
	record: string | null;
}

/** One external tool invocation captured by a run (`results.dkim.tool_runs[]`, dkim.mdx §3/§5). */
export interface DkimToolRun {
	tool: string;
	/** The exact argv string with every input argument inlined — paste-and-reproduce. */
	command: string;
	started_at: string;
	duration_ms: number;
	/** null when the tool never ran (missing binary / spawn failure / killed). */
	exit_code: number | null;
	output_format: "json" | "text";
	parsed: unknown;
	/** null, or the failure string (timeout, ENOENT with the brew install hint, bad JSON…). */
	error: string | null;
}

/** One per-sub-test row (`results.dkim.tests[]`, pm/checks/dkim.mdx §5). */
export interface DkimTestRow {
	id: string;
	/** Present on per-selector rows (finding ids are suffixed `.<selector>`). */
	selector?: string;
	title: string;
	result: "pass" | "fail" | "warn" | "info";
	detail?: string;
	evidence?: string;
	fix?: string;
}

/** The parsed DKIM observation (`results.dkim`, pm/checks/dkim.mdx §5). */
export interface DkimResults {
	/** Worst severity across the run's DKIM tests. Absent on older persisted runs. */
	status?: Severity;
	selectors_configured: string[];
	discovery_ran: boolean;
	working_selectors: number;
	wildcard_shadow: boolean;
	duplicate_keys: { key_sha256: string; seen_on: string[] }[];
	/** Historic ADSP leftover observation (dkim.mdx §5). Absent on older persisted runs. */
	adsp?: DkimAdspObservation;
	/** Legacy DomainKeys policy observation (dkim.mdx §5). Absent on older persisted runs. */
	legacy_domainkeys?: DkimLegacyDomainKeysObservation;
	selectors: DkimSelectorResult[];
	/** Absent on runs persisted before the tool-runs capture landed. */
	tool_runs?: DkimToolRun[];
	/** The per-sub-test rows (§5 `tests[]`). Absent on older persisted runs. */
	tests?: DkimTestRow[];
	/** Matched §9 problem-state ids (PS-00…PS-12, PS-17, PS-18). Absent on older persisted runs. */
	problem_states?: string[];
}

// ---- DNS & Infrastructure snapshots (pm/checks/dns.mdx §5 — snake_case mirrors the YAML) -------

/**
 * The topology-level MX verdict — the JSON analog of one `mx_check_results` row
 * (pm/checks/mx_routing.mdx §5). Absent on runs persisted before the summary landed.
 */
export interface MxCheckSummary {
	/** Number of MX RRs returned (null-MX records included). */
	mx_count: number;
	/** RFC 7505 "." present. */
	has_null_mx: boolean;
	distinct_priorities: number;
	/** >= 2 resolvable hosts. */
	redundant: boolean;
	/** null until an ASN feed exists (future) — first round approximates by /24,/48 prefixes. */
	asn_diverse: boolean | null;
	/** No MX, but the domain's A record exists (RFC 5321 implicit MX). */
	implicit_a_fallback: boolean;
	/** null in the first round — node:dns does not expose the RRset TTL (needs dig, future). */
	rrset_ttl: number | null;
	/** Declared intent snapshot (pm/checks/mx_routing.mdx §4 "This domain receives mail"). */
	receives_mail: boolean;
	worst_severity: Severity;
	checked_at: string;
}

/** The MX topology snapshot (`results["infra.mx_routing"]` — pm/checks/mx_routing.mdx §5). */
export interface MxRoutingResults {
	mx_found: boolean;
	null_mx: boolean;
	implicit_a_fallback: boolean;
	/** The mx_check_results row (§5). Absent on older persisted runs. */
	summary?: MxCheckSummary;
	hosts: {
		host: string;
		priority: number;
		is_cname: boolean;
		cname_target: string | null;
		ips: string[];
		/** Spec-named mirror of `ips` (the mx_records.resolved_ips column). Absent on older runs. */
		resolved_ips?: string[];
		/** false when any resolved address is RFC1918/loopback/link-local/CGNAT/unspecified. */
		is_public?: boolean;
		non_public: { ip: string; cls: string }[];
		/** null until the SMTP probe round (future). */
		reachable?: boolean | null;
		/** 220 greeting (future). */
		banner?: string | null;
		/** Resolved ASN (future). */
		asn?: number | null;
	}[];
	redundancy: { host_count: number; network_count: number };
}

/** One PTR/FCrDNS row of the reverse-DNS map (`results["infra.reverse_dns"]`). */
export interface ReverseDnsIpResult {
	ip: string;
	source: "mx" | "sending_ip";
	ptr: string | null;
	forward_confirmed: boolean;
	generic: boolean;
	/** Every PTR host returned (multi-PTR evidence) — pm/checks/reverse_dns.mdx §11. */
	ptrs?: string[];
	/** Number of PTR records returned (parsed-table row + trend marker). */
	ptr_count?: number;
	/** Addresses the PTR host(s) forward-resolved to (raw panel / FCrDNS loop). */
	forward_ips?: string[];
	/** Which generic/dynamic pattern matched; null when non-generic. */
	generic_pattern?: string | null;
	/** Transient resolver error observed this run (ETIMEOUT | ESERVFAIL | …), else null. */
	error?: string | null;
}

export interface ReverseDnsResults {
	ips: ReverseDnsIpResult[];
}

/** One dangling record observed this run (pm/checks/dns_health.mdx §5 `dns_health_results.dangling`). */
export interface DnsDanglingEntry {
	/** The owner name carrying the dangling reference. */
	name: string;
	/** The record type holding the reference. */
	type: "CNAME" | "SPF" | "MX" | "NS";
	/** The dead / unclaimed target. */
	target: string;
	kind: "cname" | "include" | "mx" | "ns";
}

/**
 * One CNAME chain observed by the dangling sweep, live ones included
 * (pm/checks/dns_health.mdx §12 `cname_chains`).
 */
export interface DnsCnameChain {
	/** The owner name the chain starts at. */
	name: string;
	/** The CNAME nodes visited, in order (the owner name first). */
	chain: string[];
	/** The final non-CNAME target. */
	final: string;
	status: "live" | "dead" | "loop";
}

/** The zone snapshot (`results["infra.dns_health"]`); null fields = probe not run yet. */
export interface DnsHealthResults {
	ns: {
		host: string;
		ips: string[];
		/** "/24 + /48" diversity key(s); absent on pre-upgrade runs. */
		net_group?: string;
		/** NS target is itself a CNAME (RFC 2181 §10.3 violation). */
		is_cname?: boolean;
		/** First-round inference: the NS resolves to no address. */
		lame?: boolean;
	}[];
	ns_count: number;
	network_count: number;
	/**
	 * `dns_health_results.ns_asn_diverse` (pm/checks/dns_health.mdx §5): false = all NS share one
	 * /24+/48 prefix; null = pending the real-ASN feed. Absent on pre-upgrade runs.
	 */
	ns_asn_diverse?: boolean | null;
	/** Lame/no-answer NS observed this run (first-round inference); absent on pre-upgrade runs. */
	lame_ns?: { host: string; reason: string }[];
	parent_child_match: boolean | null;
	soa: {
		mname: string;
		rname: string;
		serial: number;
		refresh: number;
		retry: number;
		expire: number;
		min_ttl: number;
	} | null;
	/** Extracted SOA serial for the cross-run monotonic compare; absent on pre-upgrade runs. */
	soa_serial?: number | null;
	ttls: Record<string, number> | null;
	wildcard: { detected: boolean; probe: string; types: string[] };
	/** Spec-named mirror of `wildcard.types` (`dns_health_results.wildcard_types`); absent on pre-upgrade runs. */
	wildcard_types?: string[];
	cname_at_apex: boolean;
	/** Spec-named mirror of `cname_at_apex` (`dns_health_results.apex_is_cname`); absent on pre-upgrade runs. */
	apex_is_cname?: boolean;
	/** Dangling CNAME / SPF-include / MX / sub-delegated-NS targets; absent on pre-upgrade runs. */
	dangling?: DnsDanglingEntry[];
	/** Apex TXT RRset size; absent on pre-upgrade runs. */
	txt_record_count?: number;
	/** How many v=spf1 TXT records the apex publishes (>1 = permerror); absent on pre-upgrade runs. */
	spf_record_count?: number;
	/** NULL until the parent-glue probe ships (future); absent on pre-upgrade runs. */
	glue_ok?: boolean | null;
	/** NULL until the AXFR probe ships (future); absent on pre-upgrade runs. */
	axfr_open?: boolean | null;
	/** §12: apex TXT set size in octets; absent on pre-upgrade runs. */
	txt_total_octets?: number;
	/** §12: the labels the dangling sweep actually resolved this run; absent on pre-upgrade runs. */
	scanned_labels?: string[];
	/** §12: every CNAME chain observed this run, live ones included; absent on pre-upgrade runs. */
	cname_chains?: DnsCnameChain[];
	/** §12: zone-file-style render strings built at check time; absent on pre-upgrade runs. */
	raw?: {
		ns_lines: string[];
		soa_line: string | null;
		apex_txt_meta: string | null;
	};
	/** The worst DNS-health severity this run; absent on pre-upgrade runs. */
	worst_severity?: Severity;
	/** ISO timestamp of the DNS-health pass; absent on pre-upgrade runs. */
	checked_at?: string;
}

/** One apex DNSKEY, parsed (pm/checks/dnssec.mdx §5 `dnskey_algos` element). */
export interface DnssecDnskeyAlgo {
	keyTag: number;
	flags: number;
	alg: number;
	algName: string;
	bits: number | null;
}

/**
 * The DNSSEC state (`results["infra.dnssec"]`); null = could not be determined this run.
 * The snake_case fields are the DNS-page Zone-panel one-liner (pm/checks/dns.mdx §5); the
 * camelCase fields are the `dnssec_check_results` row (pm/checks/dnssec.mdx §5) — optional
 * because runs persisted before that schema shipped lack them.
 */
export interface DnssecResults {
	signed: boolean;
	ds_present: boolean | null;
	ds_digest_types: number[];
	algorithms: number[];
	ds_matches_dnskey: boolean | null;
	dane_ready: boolean;
	dsPresent?: boolean | null;
	validates?: boolean | null;
	bogus?: boolean;
	dnskeyAlgos?: DnssecDnskeyAlgo[];
	dsDigestType?: number | null;
	dsAlgoMatch?: boolean | null;
	nsec3?: boolean;
	nsec3Iterations?: number | null;
	nsec3Optout?: boolean | null;
	rrsigEarliestExpiry?: string | null;
	resolverUsed?: string | null;
	checkedAt?: string;
}

/**
 * One external-tool invocation the DNS & Infrastructure category made this run
 * (`results["infra.tool_runs"]` ⇔ the run file's `dns_infra.tool_runs[]`, pm/checks/dns.mdx
 * §3.1/§5). `command` is the verbatim argv string; a timeout stores `exit_code: null` and a
 * non-null `error`. Append-only within a run — the evidence trail, never the verdict.
 */
export interface InfraToolRun {
	tool: string;
	command: string;
	started_at: string;
	duration_ms: number;
	exit_code: number | null;
	output_format: "json" | "text";
	parsed: unknown;
	error: string | null;
}

/**
 * One live re-run of a single DNS & Infrastructure family checker (pm/checks/dns.mdx §6.2 item 6
 * — the ⟳ spot-check / the explainer page's "run this check now"). Never persisted: run files are
 * immutable history; this is a fresh observation returned straight to the UI.
 */
export interface DnsSpotCheckResult {
	checkId: string;
	domainId: string;
	domain: string;
	startedAt: string;
	finishedAt: string;
	findings: Finding[];
	/** The checker's structured payload (its §5 snapshot shape), when it produces one. */
	results?: unknown;
	/** Every external-tool invocation the spot check made (pm/checks/dns.mdx §3.1 shape). */
	toolRuns: InfraToolRun[];
}

/** One TLSA RR observed at `_25._tcp.<mx>` (pm/checks/dane_tlsa.mdx §5 `tlsa_records`). */
export interface DaneTlsaRecord {
	usage: number;
	selector: number;
	mtype: number;
	data: string;
	ttl: number | null;
}

/**
 * One row per MX host of the DANE audit (`results["infra.dane_tlsa"][]`, pm/checks/dane_tlsa.mdx
 * §5 `checkResults.dane[]` — camelCase exactly as the spec's JSON example). `certMatch` and
 * `starttlsOffered` stay null until the FUTURE :25 STARTTLS probe is enabled.
 */
export interface DaneHostResult {
	mxHost: string;
	mxPreference: number | null;
	/** The TLSA owner name queried (`_25._tcp.<canonical>`); absent on runs before spec §11. */
	tlsaName?: string;
	/** MX→canonical CNAME chain (host first, canonical last); null when not cnamed. */
	cnameChain?: string[] | null;
	/** The TLSA answer lines exactly as returned, one per RR — powers the raw pane + copy. */
	rawAnswer?: string[];
	dnssecSigned: boolean;
	/** An RRSIG observed at the TLSA name itself (split out of dnssecSigned, spec §11 item 4). */
	rrsigObserved?: boolean;
	tlsaPresent: boolean;
	tlsaRecords: DaneTlsaRecord[];
	paramsOk: boolean | null;
	recommended311: boolean | null;
	certMatch: boolean | null;
	rolloverReady: boolean;
	starttlsOffered: boolean | null;
	probeError: string | null;
	checkedAt: string;
}

export type DaneTlsaResults = DaneHostResult[];

/**
 * POST /api/audit/tlsa-record response (pm/checks/dane_tlsa.mdx §4 — the DANE subsection's
 * one-click generator): the exact `3 1 1` record to publish for a pasted PEM certificate.
 */
export interface GeneratedTlsaRecord {
	mxHost: string;
	/** The TLSA owner name, e.g. `_25._tcp.mail.example.com.` */
	recordName: string;
	/** Hex SHA-256 of the certificate's DER SubjectPublicKeyInfo. */
	spkiSha256: string;
	/** The complete zone-file line: `_25._tcp.<mx>. <ttl> IN TLSA 3 1 1 <digest>`. */
	record: string;
	/** Certificate subject — confirms the right cert was pasted. */
	subject: string;
	/** Certificate notAfter. */
	validTo: string;
}

/**
 * The persisted domain-registration snapshot (`results["infra.domain_reputation"]`,
 * pm/checks/domain_reputation.mdx §5 — snake_case exactly mirrors the target `domain_registration`
 * columns; dates as ISO strings). Powers the Registration summary panel on the DNS page (§4).
 */
export interface DomainRegistrationResults {
	registrar: string | null;
	registrar_iana_id: number | null;
	created_date: string | null;
	expiry_date: string | null;
	updated_date: string | null;
	transfer_date: string | null;
	/** Normalized camelCase EPP status codes, e.g. ["clientTransferProhibited"]. */
	statuses: string[];
	privacy_enabled: boolean | null;
	dnssec_at_registrar: boolean | null;
	/** null = unknown (registrar-API confirmation is a future round). */
	auto_renew: boolean | null;
	/** null = the HTTP landing-page classification is a future round. */
	parked: boolean | null;
	parking_nameservers: boolean | null;
	nameservers: string[];
	age_days: number | null;
	days_to_expiry: number | null;
	source: "rdap" | "whois";
	/** Full RDAP JSON (or parsed WHOIS map) for the audit trail. */
	raw_record: unknown;
	checked_at: string;
}

// ---- Content scoring (pm/checks/content_scoring.mdx §5 — snake_case mirrors the backend) -------

/** One fired SpamAssassin rule (`rules_fired[]`). */
export interface ContentRuleFired {
	rule: string;
	score: number;
	description: string;
}

/** The scoring result for one run (`results["content.scoring"]` — the content_score_results row). */
export interface ContentScoreResults {
	schema_version: 1;
	sample_id: string;
	from_header: string | null;
	subject: string | null;
	sample_uploaded_at: string;
	total_score: number;
	threshold: number;
	passed: boolean;
	rules_fired: ContentRuleFired[];
	sa_version: string | null;
	engine: string;
	checked_at: string;
}

// ---- BIMI (pm/checks/bimi.mdx §5 — mirrors the backend BimiResults payload) --------------------

/**
 * One selector's structured BIMI observation — the JSON analog of one `bimi_check_results` row.
 * `svgValid`/`vmcValid`/`vmcNotAfter`/`vmcIssuer` stay null until the future HTTPS/VMC round.
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

/** `results["content.bimi"]`: the default-selector row plus every audited selector's row. */
export interface BimiResults extends BimiSelectorResult {
	selectors: BimiSelectorResult[];
}

// ---- Link / URL reputation (pm/checks/link_url_reputation.mdx §5 — mirrors the backend payload) --

/** One decoded URI-zone answer for a link domain (`message_urls.listings[]` element). */
export interface UrlZoneListing {
	zone: string;
	listed: boolean;
	/** The 127.0.0.x / 127.0.1.x return code. */
	code: string;
	/** Decoded sub-list / bitmask label, e.g. "phishing domain" or "black". */
	bit: string;
}

/** One extracted URL (= one `message_urls` row, camelCase per the spec §5 JSON example). */
export interface UrlLinkResult {
	url: string;
	/** PSL-registrable domain of the URL host (the raw IP for IP-literal hosts). */
	linkDomain: string;
	/** Registrable domain after redirect/shortener expansion — null until the probe round. */
	finalDomain: string | null;
	isShortener: boolean;
	isHttps: boolean;
	isIpLiteral: boolean;
	isPunycode: boolean;
	/** Brand a punycode host impersonates (critical homograph), or null. */
	homographOf: string | null;
	/** Redirect hops followed — null while the probe is disabled (first round). */
	redirectHops: number | null;
	listings: UrlZoneListing[];
	/** Link domain matches sender/org/allow-list; null = not evaluated (e.g. IP literal). */
	aligned: boolean | null;
}

/** The per-run roll-up (= the `url_check_results` row of spec §5). */
export interface UrlCheckSummary {
	totalLinks: number;
	uniqueDomains: number;
	listedDomains: number;
	shortenerCount: number;
	httpCount: number;
	ipLiteralCount: number;
	punycodeCount: number;
	offbrandCount: number;
	/** Zone(s) unavailable / paid feed unconfigured / redirect probe disabled. */
	inconclusive: boolean;
	weightedWorst: Severity;
}

/** §6 scheduler diff over the pinned sample's link-domain set (inconclusive transitions ignored). */
export interface UrlRunDiff {
	/** clean → listed this run: "zone|domain" pairs. */
	newListings: string[];
	/** listed → clean this run (domain still linked, zone conclusive both runs). */
	resolved: string[];
	/** The compared runs used different samples (diff is advisory across a sample change). */
	sampleChanged: boolean;
}

/** `results["content.url"]` — the audit-JSON `content.url` payload (spec §5). */
export interface LinkUrlResults {
	schema_version: 1;
	/** The pinned content_sample_messages id this audit ran against. */
	sampleId: string | null;
	summary: UrlCheckSummary;
	links: UrlLinkResult[];
	/** URI zones queried conclusively this run. */
	zonesQueried: string[];
	/** Zones whose RFC 5782 test point failed — inconclusive, never listed. */
	zonesInconclusive: string[];
	/** Zones skipped for missing registration/paid credentials. */
	zonesSkipped: Array<{ zone: string; reason: string }>;
	diff: UrlRunDiff;
	checkedAt: string;
}

// ---- List-Unsubscribe / one-click (pm/checks/list_unsubscribe.mdx §5 — mirrors the backend) ----

/** The raw header lines the §4 "Sample headers" disclosure shows verbatim. */
export interface ListUnsubRawHeaders {
	listUnsubscribe: string | null;
	listUnsubscribePost: string | null;
	from: string | null;
	returnPath: string | null;
	dkimSignature: string | null;
	precedence: string | null;
	autoSubmitted: string | null;
	xPriority: string | null;
	priority: string | null;
	importance: string | null;
	listId: string | null;
}

/**
 * `results["content.list_unsubscribe"]` — the parsed list-management observation
 * (pm/checks/list_unsubscribe.mdx §5 `results.content.listUnsubscribe`, the future
 * `list_unsub_check_results` row). Probe fields stay null until the opt-in endpoint probe runs.
 */
export interface ListUnsubResults {
	sampleId: string | null;
	hasHeader: boolean;
	hasOneclick: boolean;
	hasHttps: boolean;
	hasMailto: boolean;
	httpsUri: string | null;
	mailtoUri: string | null;
	endpointOk: boolean | null;
	endpointStatus: number | null;
	getSafe: boolean | null;
	tlsValid: boolean | null;
	fromAligned: boolean;
	fromSpfAligned: boolean;
	fromDkimAligned: boolean;
	precedenceBulk: boolean;
	priorityAbuse: boolean;
	listId: string | null;
	isBulkSender: boolean;
	checkedAt: string;
	/** When the one-click POST probe last actually fired (null = never). */
	probedAt: string | null;
	/** POST round-trip latency in ms (§4 "Endpoint probe" panel); null = not probed. */
	probeLatencyMs: number | null;
	/** RFC 2369 grammar verdict backing content.list_unsub_syntax. */
	syntaxOk: boolean;
	/** The §4 "Sample headers" disclosure content — the raw header values verbatim. */
	rawHeaders: ListUnsubRawHeaders;
}

/** One stored sample message (GET/PUT /audit/content-sample/:domainId). */
export interface ContentSampleView {
	id: string;
	domain_id: string;
	uploaded_at: string;
	from_header: string | null;
	subject: string | null;
	active: boolean;
	byte_size: number;
	raw_path: string | null;
}

// ---- Inbox placement (pm/checks/inbox_placement.mdx §5 — mirrors the backend placementPayload) --

/** One per-seed verdict (an `inbox_placement_results` row mapped onto the audit JSON). */
export interface PlacementSeedResult {
	provider: string;
	folder: "inbox" | "spam" | "promotions" | "missing";
	gmailTab: "primary" | "promotions" | "social" | "updates" | "forums" | null;
	spfPass: boolean | null;
	dkimPass: boolean | null;
	dmarcPass: boolean | null;
	latencySecs: number | null;
	/** Hard 5xx bounce vs accepted-then-dropped (only on missing seeds). */
	missingReason?: "bounced" | "dropped";
}

/** One provider row of the §4 placement matrix (the backend ProviderAggregate). */
export interface PlacementProviderAggregate {
	provider: string;
	total: number;
	inbox: number;
	spam: number;
	promotions: number;
	missing: number;
	bounced: number;
	delivered: number;
	inboxRatePct: number | null;
	spfFails: number;
	dkimFails: number;
	dmarcFails: number;
	authParsed: number;
	maxLatencySecs: number | null;
}

/** One point of the §4 trend sparkline (oldest → newest). */
export interface PlacementTrendPoint {
	sentAt: string;
	overallPct: number | null;
	byProvider: Record<string, number | null>;
}

/**
 * `results["content.inbox_placement"]` — the seed-test envelope + per-seed results (spec §5).
 * `configured: false` is the light-gray "configure seed list" state; configured with no
 * `testToken` means the integration is armed but the first test has not been recorded yet.
 */
export interface InboxPlacementResults {
	configured: boolean;
	seedService?: string;
	sampleId?: string | null;
	testToken?: string;
	sentAt?: string;
	settledAt?: string | null;
	seedCount?: number;
	deliveredCount?: number;
	/** Present only on the configured-but-no-test payload. */
	testCount?: number;
	overallInbox?: number | null;
	results?: PlacementSeedResult[];
	providers?: PlacementProviderAggregate[];
	trend?: PlacementTrendPoint[];
}

export interface AuditResult {
	/** Unique id of this run (pm/dashboard.mdx §1). Optional: pre-history persisted data lacks it. */
	runId?: string;
	domainId: string;
	domain: string;
	/** ISO date-times the run started/stopped (pm/dashboard.mdx §1). Optional on old data. */
	startedAt?: string;
	finishedAt?: string;
	ranAt: string;
	score: number;
	status: Severity;
	findings: Finding[];
	counts: Record<Severity, number>;
	/**
	 * How many findings in this run are NEW problems versus the previous run (pm/engineering.mdx §8
	 * regression detection). 0 on a domain's first run; absent on pre-history persisted data.
	 */
	newProblemCount?: number;
	/**
	 * Category scope of the run (pm/checks/blacklists.mdx §21 / AC 26): absent = a full run of all
	 * six categories; "blacklists" / "dkim" = a category-scoped re-run (run.scope) — the UI
	 * chip-tags it wherever the run is named so a partial run is never mistaken for a full audit.
	 */
	scope?: "blacklists" | "dkim";
	/** Structured per-check payloads keyed by checker id (e.g. results.dmarc, results.spf). */
	results?: {
		dmarc?: DmarcSection | DmarcResults;
		arc?: ArcResults;
		spf?: SpfResults;
		dkim?: DkimResults;
		blacklist?: BlacklistRunResults;
		"infra.mx_routing"?: MxRoutingResults;
		"infra.reverse_dns"?: ReverseDnsResults;
		"infra.dns_health"?: DnsHealthResults;
		"infra.dnssec"?: DnssecResults;
		"infra.dane_tlsa"?: DaneTlsaResults;
		"infra.domain_reputation"?: DomainRegistrationResults;
		"infra.tool_runs"?: InfraToolRun[];
		"content.scoring"?: ContentScoreResults;
		"content.bimi"?: BimiResults;
		"content.url"?: LinkUrlResults;
		"content.list_unsubscribe"?: ListUnsubResults;
		"content.inbox_placement"?: InboxPlacementResults;
		/** pm/emails.mdx §16.3 — the run-scoped ingested-reports aggregate snapshot. */
		"dmarc.reports"?: DmarcReportsSnapshot;
	} & Record<string, unknown>;
}

// ---- Blacklists (pm/checks/blacklists.mdx §12 — snake_case mirrors the persisted YAML) ---------

export type ZoneTier = "high" | "medium" | "low";
export type ZoneKind = "ip" | "domain";
export type ZoneHealthStatus =
	| "ok"
	| "dead"
	| "wildcarding"
	| "blocked"
	| "slow";
export type ProblemStateId =
	| "PS-0"
	| "PS-1"
	| "PS-2"
	| "PS-3"
	| "PS-4"
	| "PS-5"
	| "PS-6"
	| "PS-7"
	| "PS-8"
	| "PS-9"
	| "PS-10"
	| "PS-11"
	| "PS-12"
	| "PS-13";
export type PortalUserState =
	| "unverified"
	| "verified_clean"
	| "problem_reported";

export interface BlacklistIpTarget {
	ip: string;
	source:
		| "sending_ips"
		| "mx_resolved"
		| "spf_authorized"
		| "email_report"
		| "primary";
	ptr: string | null;
	fcrdns_ok: boolean | null;
	asn: { number: number | null; org: string | null } | null;
}

export interface BlacklistDomainTarget {
	domain: string;
	source: string;
	created: string | null;
}

export interface BlacklistZoneHealth {
	zone: string;
	status: ZoneHealthStatus;
	positive_probe: string;
	negative_probe: string;
	probe_ms: number;
}

export interface BlacklistZoneResult {
	zone: string;
	name: string;
	tier: ZoneTier;
	kind: ZoneKind;
	target: string;
	listed: boolean;
	return_code: string | null;
	sub_list: string | null;
	reason_txt: string | null;
	lookup_url: string;
	delist_url: string;
	severity: Severity | null;
	inconclusive: boolean;
	refusal_code: string | null;
	query_ms: number;
	problem_state: ProblemStateId | null;
	paid_delist_offered: boolean;
	auto_expires: string | null;
}

export interface BlacklistPositiveReputation {
	dnswl: { listed: boolean; category: string | null; trust: number | null };
	senderscore: { score: number | null; severity: Severity };
	mailspike_rep: { code: string | null; label: string | null };
}

export interface ProviderPortal {
	provider: string;
	name: string;
	check_url: string;
	delist_url: string;
	user_state: PortalUserState;
}

export interface BlacklistDiff {
	new_listings: Array<{
		zone: string;
		target: string;
		sub_list: string | null;
	}>;
	cleared: Array<{ zone: string; target: string; sub_list: string | null }>;
	escalated: Array<{ zone: string; target: string; from: string; to: string }>;
	first_run: boolean;
}

/** One captured tool invocation (pm/checks/blacklists.mdx §10.4 locked shape). */
export interface BlacklistToolRun {
	tool: string;
	command: string;
	started_at: string;
	duration_ms: number;
	exit_code: 0 | 1;
	output_format: "json" | "text";
	parsed: unknown;
	error: string | null;
}

/** One per-sub-test row of the run's `tests[]` (§12) — pass and fail alike. */
export interface BlacklistTest {
	id: string;
	title: string;
	result: "pass" | "fail" | "warn" | "info";
	evidence: string;
	fix?: string;
}

export interface BlacklistSummary {
	zones_enabled: number;
	pairs_queried: number;
	listed: number;
	clean: number;
	inconclusive: number;
	dead_zones_skipped: number;
	worst_severity: Severity;
	problem_states: ProblemStateId[];
}

/** The whole per-run document (test_results.yaml / results.blacklist / GET /blacklists/results). */
export interface BlacklistRunResults {
	schema_version: 1;
	technology: "blacklists";
	domain: string;
	audit_id: string;
	ran_at: string;
	duration_ms: number;
	/** Worst post-weighting severity (§12 `status`) — optional on runs persisted before it existed. */
	status?: Severity;
	resolver: {
		mode: "system" | "custom";
		server: string | null;
		refusals_detected: boolean;
	};
	targets: { ips: BlacklistIpTarget[]; domains: BlacklistDomainTarget[] };
	zone_health: BlacklistZoneHealth[];
	results: BlacklistZoneResult[];
	/** §10.4 audit trail — optional on runs persisted before it existed. */
	tool_runs?: BlacklistToolRun[];
	/** §12 per-sub-test rows — optional on runs persisted before it existed. */
	tests?: BlacklistTest[];
	positive_reputation: BlacklistPositiveReputation;
	provider_portals: ProviderPortal[];
	summary: BlacklistSummary;
	/** §16 states detected this run — optional on runs persisted before it existed. */
	problem_states?: ProblemStateId[];
	diff: BlacklistDiff;
}

export interface BlacklistHistoryEntry {
	audit_id: string;
	ran_at: string;
	listed: number;
	clean: number;
	inconclusive: number;
	worst_severity: Severity;
}

/** Meaning of one decoded return code (or bitmask bit) — the §20.6 decoder table rows. */
export interface BlacklistCodeMeaning {
	label: string;
	severity: Severity;
	problem_state?: ProblemStateId;
}

/** One effective catalog row from GET /blacklists/zones (pm/checks/blacklists.mdx §18). */
export interface BlocklistZoneRow {
	zone: string;
	name: string;
	kind: ZoneKind;
	tier: ZoneTier;
	weight: number;
	lookup_url: string;
	delist_url: string;
	enabled: boolean;
	severity: Severity;
	/** Registry prose — the §20.3 zone explainer's "What this is" block (never computed). */
	description?: string;
	/** Operator homepage from the registry — the explainer's References block. */
	url?: string;
	/** Exact return-code map — feeds the zone explainer's decoder table (§20.6). */
	codes?: Record<string, BlacklistCodeMeaning>;
	/** Bitmask decode of the answer's last octet (SURBL/URIBL style). */
	bitmask?: Record<string, BlacklistCodeMeaning>;
	requires_registration?: boolean;
	is_paid?: boolean;
	paid_delist_offered?: boolean;
	auto_expires?: string;
	positive?: boolean;
	notes?: string;
}

/** The effective registry view — checked-in blacklists.yaml ⊕ operator overrides (§17.1 panel 5). */
export interface BlacklistRegistryInfo {
	compiled: string;
	lists_total: number;
	zones: BlocklistZoneRow[];
	dead_zones: Array<{
		zone: string;
		name: string;
		died?: string | number;
		reason?: string;
	}>;
	aggregators: Array<{ name: string; url: string; description: string }>;
}

/** Overlay verdict of one live-recheck row vs the stored run (pm/checks/blacklists.mdx §21.3). */
export type BlacklistRecheckChange =
	| "now_listed"
	| "now_clean"
	| "unchanged"
	| "inconclusive"
	| "untracked";

/** One live-recheck row — a ZoneResult plus its diff against the compared stored run. */
export interface BlacklistRecheckRow extends BlacklistZoneResult {
	stored_listed: boolean | null;
	change: BlacklistRecheckChange;
}

/** POST /blacklists/:domainId/recheck — ephemeral live recheck; never writes a run file (AC 27). */
export interface BlacklistLiveRecheck {
	domain: string;
	checked_at: string;
	resolver: { mode: "system" | "custom"; server: string | null };
	compared_run_id: string | null;
	results: BlacklistRecheckRow[];
	summary: {
		listed: number;
		clean: number;
		inconclusive: number;
		pairs_queried: number;
	};
}

// ---- Report-email ingestion (pm/emails.mdx §7.1 — mirrors backend modules/reports) -------------

/** One merged per-source row of the expandable DMARC details table (pm/emails.mdx §7.1). */
export interface DmarcSourceRow {
	sourceIp: string;
	count: number;
	disposition: string;
	spfEvaluated: string;
	dkimEvaluated: string;
	spfAligned: boolean;
	dkimAligned: boolean;
	dmarcPass: boolean;
	headerFrom: string;
	envelopeSpfDomain: string;
	dkimSigningDomains: string[];
	reporters: string[];
}

/** The DMARC-aggregate rollup over the rolling window (pm/emails.mdx §4.6). */
export interface DmarcReportAggregate {
	reportCount: number;
	reporters: string[];
	window: { begin: string; end: string };
	totalMessages: number;
	/** Dual-aligned volume — §12's "DMARC-aligned pass" figure. */
	alignedPassMessages: number;
	dmarcPassMessages: number;
	passRatePct: number;
	policyPublished: {
		domain: string;
		p: string;
		sp: string | null;
		adkim: string;
		aspf: string;
		pct: string | null;
		np: string | null;
	} | null;
	rows: DmarcSourceRow[];
	totalReportsStored: number;
}

/** One reporter/day row of the TLS-RPT details table (pm/emails.mdx §7.1). */
export interface TlsRptReporterDay {
	reporterOrg: string;
	reportDate: string;
	policyType: string;
	successCount: number;
	failureCount: number;
	failureDetails: { resultType: string; count: number }[];
}

export interface TlsRptReportAggregate {
	reportCount: number;
	reporters: string[];
	window: { begin: string; end: string };
	totalSuccess: number;
	totalFailure: number;
	policyTypes: string[];
	rows: TlsRptReporterDay[];
	totalReportsStored: number;
}

/** GET /domains/:id/reports — the per-domain Reports view (pm/emails.mdx §7.1). */
export interface DomainReportsView {
	domainId: string;
	domain: string;
	ingestionEnabled: boolean;
	windowDays: number;
	lastIngestAt: string | null;
	dmarc: DmarcReportAggregate;
	tlsrpt: TlsRptReportAggregate;
	findings: Finding[];
}

/** What one "Ingest now" pass did (POST /domains/:id/reports/ingest). */
export interface ReportIngestSummary {
	scanned: number;
	ingested: number;
	duplicates: number;
	skipped: number;
	errors: string[];
}

/**
 * The run-scoped `dmarc.reports` snapshot (pm/emails.mdx §16.3) the dmarc-reports checker
 * serializes into the run file (snake_case, mirroring the backend `DmarcAggregate`). It makes the
 * explainer's block-2 aggregate-breakdown and per-source-IP tables RUN-SCOPED — an older run stays
 * a historical snapshot rather than reading the live store.
 */
export interface DmarcReportsSnapshotRow {
	source_ip: string;
	count: number;
	disposition: string;
	spf_evaluated: string;
	spf_aligned: boolean;
	dkim_evaluated: string;
	dkim_aligned: boolean;
	dmarc_pass: boolean;
	header_from: string;
	envelope: string;
	dkim_signing_domains: string[];
	reporters: string[];
}

export interface DmarcReportsSnapshot {
	report_count: number;
	reporters: string[];
	window: { begin: string; end: string };
	window_days: number;
	total_messages: number;
	aligned_pass_messages: number;
	dmarc_pass_messages: number;
	pass_rate_pct: number;
	dkim_only: number;
	spf_only: number;
	both_fail: number;
	quarantined: number;
	rejected: number;
	policy_published: {
		p: string;
		sp: string | null;
		adkim: string;
		aspf: string;
		pct: string | null;
		np: string | null;
	} | null;
	rows: DmarcReportsSnapshotRow[];
}
