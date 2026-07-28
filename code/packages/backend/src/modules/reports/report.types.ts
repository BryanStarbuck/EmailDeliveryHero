/**
 * Report-email ingestion vocabulary (pm/emails.mdx §4.4/§9) — the normalized shapes a parsed
 * DMARC aggregate (rua) XML report and a TLS-RPT JSON report reduce to. These map 1:1 to the
 * future `dmarc_aggregate_reports` / `tls_rpt_reports` SQL tables declared in the per-check specs
 * (pm/checks/dmarc.mdx §5, pm/checks/tls_rpt.mdx §5); today they persist as JSON files under
 * `<state>/reports/<domainId>/` (report-store.ts).
 */

/**
 * One `<policy_evaluated><reason>` override the receiver applied (RFC 7489 §6.7,
 * pm/Email_Complaints.mdx §4.3). `type` is one of forwarded | sampled_out | trusted_forwarder |
 * mailing_list | local_policy | other; `comment` is free text — Google writes "arc=pass" there,
 * which is the ARC-rescue signal behind complaint C07.
 */
export interface DmarcPolicyOverride {
	type: string;
	comment: string | null;
}

/** One `<auth_results><dkim>` element (pm/Email_Complaints.mdx §4.5). */
export interface DmarcDkimAuthResult {
	/** The signing domain (d=). */
	domain: string;
	/** The selector (s=) — null when the reporter omits it. */
	selector: string | null;
	/** pass | fail | policy | neutral | temperror | permerror | none. */
	result: string;
	/** RFC-defined but emitted by no reporter in the corpus; parsed anyway. */
	humanResult: string | null;
}

/** One `<auth_results><spf>` element (pm/Email_Complaints.mdx §4.5). */
export interface DmarcSpfAuthResult {
	domain: string;
	/** mfrom | helo — null when the reporter omits it. */
	scope: string | null;
	/** Lower-cased: KDDI emits a capitalised "Fail". */
	result: string;
}

/** One normalized `<record>` row of a DMARC aggregate report (pm/emails.mdx §4.4). */
export interface DmarcReportRow {
	sourceIp: string;
	count: number;
	/** The receiver's applied disposition: none | quarantine | reject. */
	disposition: string;
	/** Raw SPF result from <auth_results> (pass/fail/none/…). */
	spfEvaluated: string;
	/** Raw DKIM result from <auth_results>. */
	dkimEvaluated: string;
	/** Aligned SPF per <policy_evaluated><spf> — pass means "passed AND aligned". */
	spfAligned: boolean;
	/** Aligned DKIM per <policy_evaluated><dkim>. */
	dkimAligned: boolean;
	/** dmarcPass = spfAligned || dkimAligned (pm/emails.mdx §4.4). */
	dmarcPass: boolean;
	headerFrom: string;
	/** The envelope (Return-Path / mfrom) domain from <auth_results><spf><domain>. */
	envelopeSpfDomain: string;
	/** Every d= that signed, from <auth_results><dkim><domain>. */
	dkimSigningDomains: string[];
	/**
	 * The remaining RFC 7489 detail the complaint taxonomy needs (pm/Email_Complaints.mdx §4).
	 * All optional: reports stored by an earlier build lack them, and the classifier degrades
	 * gracefully rather than reprocessing the corpus.
	 */
	/** `<identifiers><envelope_to>` — who the sender was aiming at. Only KDDI populates it. */
	envelopeTo?: string | null;
	/** `<policy_evaluated><reason>` overrides — the ARC-rescue / sampled-out signals. */
	reasons?: DmarcPolicyOverride[];
	/** Full per-signature DKIM results, including the selector that makes forgery visible. */
	dkimResults?: DmarcDkimAuthResult[];
	/** Full per-identity SPF results. */
	spfResults?: DmarcSpfAuthResult[];
}

/** The <policy_published> block — the DMARC policy the reporter saw. */
export interface DmarcPolicyPublished {
	domain: string;
	p: string;
	sp: string | null;
	adkim: string;
	aspf: string;
	pct: string | null;
	np: string | null;
	/** `fo=` forensic-report options — present on some reporters only (pm/Email_Complaints.mdx §4.2). */
	fo?: string | null;
}

/** One parsed DMARC aggregate report — persisted as reports/<domainId>/dmarc/<org>-<id>.json. */
export interface ParsedDmarcReport {
	kind: "dmarc";
	reporterOrg: string;
	reportId: string;
	/** `<report_metadata><email>` — the reporter's contact address (pm/Email_Complaints.mdx §2.1). */
	reporterEmail?: string | null;
	/** `<report_metadata><extra_contact_info>` — the reporter's help URL; present for 4 of 7. */
	reporterContact?: string | null;
	/** `<report_metadata><error>` — a reporter-declared problem; drives complaint C15. */
	reporterError?: string | null;
	/** Report window as ISO date-times (converted from the XML's epoch seconds). */
	window: { begin: string; end: string };
	policyPublished: DmarcPolicyPublished;
	rows: DmarcReportRow[];
}

/** One failure-details entry of a TLS-RPT policy result (RFC 8460 §4.3). */
export interface TlsRptFailureDetail {
	resultType: string;
	count: number;
}

/** One policies[] entry, normalized (pm/emails.mdx §4.4). */
export interface TlsRptPolicyResult {
	/** sts | tlsa | no-policy-found */
	policyType: string;
	/** The domain the policy applies to — routes the report to a monitored domain. */
	policyDomain: string;
	successCount: number;
	failureCount: number;
	failureDetails: TlsRptFailureDetail[];
}

/** One parsed TLS-RPT report — persisted as reports/<domainId>/tlsrpt/<org>-<date>.json. */
export interface ParsedTlsRptReport {
	kind: "tlsrpt";
	reporterOrg: string;
	/** The report's date (YYYY-MM-DD of the window start) — half the dedupe key. */
	reportDate: string;
	/** Full window as ISO date-times. */
	window: { begin: string; end: string };
	policies: TlsRptPolicyResult[];
}

export type ParsedReport = ParsedDmarcReport | ParsedTlsRptReport;

/** Cursor + processed-ids file: reports/<domainId>/ingest-state.json (pm/emails.mdx §9). */
export interface IngestState {
	lastIngestAt: string | null;
	/** Drop-folder file names / mailbox message ids already processed (idempotence, §4.5). */
	processedIds: string[];
}

/** What one ingest pass did — returned by POST /domains/:id/reports/ingest. */
export interface IngestSummary {
	scanned: number;
	/** New reports stored (post-dedupe). */
	ingested: number;
	/** Reports skipped because their (reporter, id/date) key was already stored. */
	duplicates: number;
	/** Files/parts that were not reports, or reports for a domain we do not monitor. */
	skipped: number;
	errors: string[];
}
