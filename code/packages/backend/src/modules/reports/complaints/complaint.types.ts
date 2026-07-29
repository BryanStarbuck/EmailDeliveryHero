/**
 * The Email Complaints vocabulary (pm/Email_Complaints.mdx §7/§8/§12) — the domain-owner-facing
 * reading of the DMARC-aggregate and TLS-RPT report emails receivers send us.
 *
 * A COMPLAINT is one named, de-duplicated, scored problem statement derived from one or more report
 * rows, phrased from the domain owner's point of view, carrying a verdict (is this a problem?), a
 * size (how much mail), a trend (is it getting worse?) and a fix. It is not a report and not a row.
 */

/** The 16 complaint codes (pm/Email_Complaints.mdx §7). */
export type ComplaintCode =
	| "C00"
	| "C01"
	| "C02"
	| "C03"
	| "C04"
	| "C05"
	| "C06"
	| "C07"
	| "C08"
	| "C09"
	| "C10"
	| "C11"
	| "C12"
	| "C13"
	| "C14"
	| "C15";

/** The three-value verdict vocabulary (pm/Email_Complaints.mdx §8.1). */
export type ComplaintVerdict = "ok" | "watch" | "problem";

/** The domain-level verdict (pm/Email_Complaints.mdx §8.2), worst-first. */
export type BoardVerdict =
	| "action"
	| "attention"
	| "watch"
	| "ok"
	| "insufficient_data";

/** Trend vs. the previous window of equal length (pm/Email_Complaints.mdx §8.4). */
export type ComplaintTrend =
	| "new"
	| "worse"
	| "steady"
	| "better"
	| "resolved";

/** One row of a complaint's evidence table (pm/Email_Complaints.mdx §10.2). */
export interface ComplaintSource {
	sourceIp: string;
	/**
	 * Reverse DNS for `sourceIp` — null when it has no PTR or the lookup has not run. This is the
	 * column that turns an evidence table from a list of numbers into something a person can read:
	 * `mail-sor-f41.google.com` identifies a sender at a glance where `209.85.220.69` does not, and
	 * a spoofer's IP characteristically has no PTR at all.
	 */
	ptr: string | null;
	count: number;
	disposition: string;
	spfDomain: string;
	spfResult: string;
	spfAligned: boolean;
	dkimDomain: string;
	dkimSelector: string;
	dkimResult: string;
	dkimAligned: boolean;
	envelopeTo: string | null;
	reasons: { type: string; comment: string | null }[];
	reporters: string[];
	firstSeen: string;
	lastSeen: string;
}

/** One complaint on the board (pm/Email_Complaints.mdx §12). */
export interface Complaint {
	code: ComplaintCode;
	/** Stable slug, e.g. "esp_default_dkim_key" — the drill-down route param. */
	key: string;
	title: string;
	verdict: ComplaintVerdict;
	severity: "ok" | "info" | "warning" | "critical";
	messages: number;
	sharePct: number;
	trend: ComplaintTrend;
	previousMessages: number;
	/** Plain English, 2–4 sentences, real values interpolated (pm/Email_Complaints.mdx §10.2). */
	explanation: string;
	evidenceSummary: string;
	fixIds: string[];
	sources: ComplaintSource[];
}

/** One DNS record a fix asks the user to publish. */
export interface FixRecord {
	name: string;
	type: string;
	value: string;
	note?: string;
}

/** One step of the ordered fix plan (pm/Email_Complaints.mdx §11). */
export interface ComplaintFix {
	id: string;
	title: string;
	appliesTo: ComplaintCode[];
	messagesFixed: number;
	steps: string[];
	records: FixRecord[];
	verify: string[];
	/** Which checker "Re-check this now" should run; null when nothing to re-run. */
	recheckCheckId: string | null;
}

/** One reporter chip of the coverage strip (pm/Email_Complaints.mdx §10.1). */
export interface ComplaintReporter {
	org: string;
	email: string | null;
	contactUrl: string | null;
	reportCount: number;
	messages: number;
	lastSeen: string | null;
	/** True for an expected reporter that contributed nothing this window — complaint C13. */
	expectedButMissing: boolean;
}

/** One daily bucket of the Zone A chart (pm/Email_Complaints.mdx §10.1). */
export interface ComplaintSeriesPoint {
	date: string;
	aligned: number;
	oneMechanism: number;
	failedBoth: number;
	quarantined: number;
	rejected: number;
}

/** One distinct `policy_published` tuple a reporter observed (pm/Email_Complaints.mdx §4.2). */
export interface ObservedPolicy {
	p: string;
	sp: string | null;
	np: string | null;
	adkim: string;
	aspf: string;
	pct: string | null;
	fo: string | null;
	reporters: string[];
	firstSeen: string;
	lastSeen: string;
}

/**
 * One stored report in the window — the key the §10.4 "View raw report" link resolves against
 * (`<org>/<id>`). Listed on the board so the drill-down can offer a picker without a second index.
 */
export interface ComplaintReportRef {
	org: string;
	/** The report id for a DMARC aggregate, or the report date for a TLS-RPT report. */
	id: string;
	kind: "dmarc" | "tlsrpt";
	windowBegin: string;
	windowEnd: string;
}

/** GET /api/domains/:id/complaints (pm/Email_Complaints.mdx §12). */
export interface ComplaintBoard {
	domainId: string;
	domain: string;
	verdict: BoardVerdict;
	/** The one-sentence Zone A summary naming the largest problem. */
	headline: string;
	ingestionEnabled: boolean;
	window: { begin: string; end: string; days: number };
	previousWindow: { begin: string; end: string };
	totals: {
		messages: number;
		authenticated: number;
		dmarcPassing: number;
		notAligned: number;
		blocked: number;
		spoof: number;
		authenticatedPct: number;
	};
	deltas: { authenticatedPct: number; messages: number };
	reporters: ComplaintReporter[];
	/** Every report in the window, newest first — backs the §10.4 raw-report picker. */
	reports: ComplaintReportRef[];
	series: ComplaintSeriesPoint[];
	policyObserved: ObservedPolicy[];
	complaints: Complaint[];
	fixes: ComplaintFix[];
	ingest: {
		lastIngestAt: string | null;
		reportsStored: number;
		undecodable: { file: string; stage: string; message: string }[];
	};
}
