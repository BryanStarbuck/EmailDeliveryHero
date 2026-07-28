import type {
	DmarcReportRow,
	ParsedDmarcReport,
	ParsedTlsRptReport,
} from "../report.types";
import { COMPLAINT_CATALOG, EXPECTED_REPORTERS } from "./catalog";
import {
	type ClassifyContext,
	classifyRow,
	isEspDefaultDomain,
	isKnownSender,
	underDomain,
} from "./classify";
import type {
	BoardVerdict,
	Complaint,
	ComplaintBoard,
	ComplaintCode,
	ComplaintReporter,
	ComplaintSeriesPoint,
	ComplaintSource,
	ComplaintTrend,
	ObservedPolicy,
} from "./complaint.types";
import { type FixBuildContext, buildFixPlan } from "./fixes";

/**
 * Complaint-board assembly (pm/Email_Complaints.mdx §8/§12): take the stored, parsed report emails
 * for one domain and produce the whole `/domains/:id/complaints` payload — window totals, the daily
 * series, the reporter coverage strip, the observed-policy set, the classified complaints with
 * trends, the ordered fix plan, and the domain-level verdict.
 *
 * Windows anchor on the NEWEST report end rather than `now`, matching pm/emails.mdx §4.6, so a
 * historical corpus still analyzes instead of rendering an empty page.
 */

const DAY_MS = 24 * 60 * 60 * 1000;

export interface BuildBoardInput {
	domainId: string;
	domain: string;
	dmarcReports: ParsedDmarcReport[];
	tlsReports: ParsedTlsRptReport[];
	windowDays: number;
	ingestionEnabled: boolean;
	lastIngestAt: string | null;
	/** IPs authorized by the domain's own SPF record, when a run has resolved them (§7.1 rule 4). */
	spfAuthorizedIps?: ReadonlySet<string>;
	/** Files that failed to decode during ingest — complaint C15. */
	undecodable?: { file: string; stage: string; message: string }[];
}

function overlaps(
	begin: string,
	end: string,
	start: string,
	stop: string,
): boolean {
	return begin <= stop && end >= start;
}

/** A stable key for one evidence row: source + identities + verdict shape. */
function sourceKey(row: DmarcReportRow): string {
	const dkim = (row.dkimResults ?? [])
		.map((d) => `${d.domain}/${d.selector ?? "-"}:${d.result}`)
		.join(",");
	return `${row.sourceIp}|${row.envelopeSpfDomain}|${dkim}|${row.spfAligned}|${row.dkimAligned}|${row.disposition}`;
}

function toSource(
	row: DmarcReportRow,
	reporter: string,
	windowBegin: string,
	windowEnd: string,
): ComplaintSource {
	const dkim = (row.dkimResults ?? [])[0];
	const spf = (row.spfResults ?? [])[0];
	return {
		sourceIp: row.sourceIp,
		count: row.count,
		disposition: row.disposition,
		spfDomain: spf?.domain ?? row.envelopeSpfDomain ?? "",
		spfResult: spf?.result ?? row.spfEvaluated,
		spfAligned: row.spfAligned,
		dkimDomain: dkim?.domain ?? row.dkimSigningDomains[0] ?? "",
		dkimSelector: dkim?.selector ?? "",
		dkimResult: dkim?.result ?? row.dkimEvaluated,
		dkimAligned: row.dkimAligned,
		envelopeTo: row.envelopeTo ?? null,
		reasons: row.reasons ?? [],
		reporters: [reporter],
		firstSeen: windowBegin,
		lastSeen: windowEnd,
	};
}

function mergeSource(into: ComplaintSource, from: ComplaintSource): void {
	into.count += from.count;
	for (const r of from.reporters)
		if (!into.reporters.includes(r)) into.reporters.push(r);
	if (from.firstSeen < into.firstSeen) into.firstSeen = from.firstSeen;
	if (from.lastSeen > into.lastSeen) into.lastSeen = from.lastSeen;
}

/** Per-code row volumes and evidence for one set of reports. */
function classifyReports(
	reports: ParsedDmarcReport[],
	ctx: ClassifyContext,
): Map<ComplaintCode, { messages: number; sources: Map<string, ComplaintSource> }> {
	const out = new Map<
		ComplaintCode,
		{ messages: number; sources: Map<string, ComplaintSource> }
	>();
	for (const report of reports) {
		for (const row of report.rows) {
			const code = classifyRow(row, ctx);
			const bucket = out.get(code) ?? { messages: 0, sources: new Map() };
			bucket.messages += row.count;
			const key = sourceKey(row);
			const source = toSource(
				row,
				report.reporterOrg,
				report.window.begin,
				report.window.end,
			);
			const existing = bucket.sources.get(key);
			if (existing) mergeSource(existing, source);
			else bucket.sources.set(key, source);
			out.set(code, bucket);
		}
	}
	return out;
}

/** §8.4 trend of one complaint versus the previous window of equal length. */
export function trendOf(current: number, previous: number): ComplaintTrend {
	if (previous === 0) return current > 0 ? "new" : "steady";
	if (current === 0) return "resolved";
	const ratio = current / previous;
	if (ratio > 1.2) return "worse";
	if (ratio < 0.8) return "better";
	return "steady";
}

/** §8.2 domain verdict — first match wins, worst first. */
export function boardVerdict(
	complaints: Complaint[],
	totals: { messages: number; authenticatedPct: number },
	reportCount: number,
): BoardVerdict {
	if (reportCount < 3 || totals.messages === 0) return "insufficient_data";
	const has = (code: ComplaintCode) =>
		complaints.some((c) => c.code === code && c.messages > 0);
	const c03 = complaints.find((c) => c.code === "C03");
	if (
		complaints.some((c) => c.severity === "critical") ||
		has("C10") ||
		(c03 && c03.sharePct >= 1)
	)
		return "action";
	if (
		complaints.some((c) => c.severity === "warning") ||
		totals.authenticatedPct < 95
	)
		return "attention";
	if (complaints.some((c) => c.verdict === "watch")) return "watch";
	return "ok";
}

/** Human summary sentence for Zone A (§10.1 item 1). */
function headlineFor(
	verdict: BoardVerdict,
	complaints: Complaint[],
	domain: string,
): string {
	if (verdict === "insufficient_data")
		return `Not enough reports yet for ${domain}. Receivers usually start reporting 24–72 hours after you publish a rua= address.`;
	const worst = complaints
		.filter((c) => c.verdict === "problem")
		.sort((a, b) => b.messages - a.messages)[0];
	if (worst) return worst.explanation.split(". ")[0].concat(".");
	const watch = complaints
		.filter((c) => c.verdict === "watch")
		.sort((a, b) => b.messages - a.messages)[0];
	if (watch)
		return `Nothing is broken. ${watch.title} is the one thing worth keeping an eye on.`;
	return `Everything receivers reported about ${domain} authenticated correctly.`;
}

/**
 * The plain-English explanation for one complaint (§10.2): 2–4 sentences, written for a non-expert,
 * with the domain's real numbers interpolated. This is the text a user actually reads, so it says
 * what happened, why it matters, and — for `ok` codes — explicitly that there is nothing to do.
 */
function explain(
	code: ComplaintCode,
	messages: number,
	sharePct: number,
	sources: ComplaintSource[],
	domain: string,
	totalMessages: number,
): string {
	const ips = new Set(sources.map((s) => s.sourceIp)).size;
	const reporters = new Set(sources.flatMap((s) => s.reporters));
	const espDomains = [
		...new Set(
			sources.map((s) => s.dkimDomain).filter((d) => d && isEspDefaultDomain(d)),
		),
	];
	const selectors = [
		...new Set(sources.map((s) => s.dkimSelector).filter(Boolean)),
	];
	const targets = [
		...new Set(sources.map((s) => s.envelopeTo).filter((t): t is string => !!t)),
	];
	const spfDomains = [
		...new Set(sources.map((s) => s.spfDomain).filter(Boolean)),
	];
	const aligned = totalMessages - messages;

	switch (code) {
		case "C00":
			return `${messages.toLocaleString()} messages (${sharePct}% of your mail) passed both SPF and DKIM with both aligned to ${domain}. This is the outcome you want for everything you send. Keep it above 95%.`;
		case "C01":
			return `${messages} message${messages === 1 ? "" : "s"} from ${ips} address${ips === 1 ? "" : "es"} forged your From address${selectors.length > 0 ? `, using made-up DKIM selectors (${selectors.slice(0, 2).join(", ")})` : ""}${targets.length > 0 ? `, aimed at ${targets.slice(0, 2).join(" and ")}` : ""}. ${[...reporters].join(", ")} rejected or quarantined every one of them because of your published policy. Not your problem — this is DMARC doing exactly its job, and there is nothing to fix.`;
		case "C02":
			return `${messages.toLocaleString()} of your messages (${sharePct}% of your mail) are signed with ${espDomains[0] ?? "your provider's own domain"} instead of ${domain}, so the signature can never match your From address. ${aligned > 0 ? `The other ${aligned.toLocaleString()} messages use a key that does match.` : ""} These messages pass today only because SPF happens to align — the moment a forward, a Return-Path change or an ESP switch breaks SPF, all ${messages.toLocaleString()} start failing DMARC and get rejected. Turning on your own DKIM key removes the whole risk.`;
		case "C03":
			return `${messages.toLocaleString()} message${messages === 1 ? "" : "s"} (${sharePct}%) from ${ips} source${ips === 1 ? "" : "s"} failed both SPF and DKIM alignment, and the receivers delivered them anyway. That is either a sender of yours nobody wrote down, or someone spoofing you while your policy is not strict enough to stop it. Work out which for each source in the table below — the two answers need opposite fixes.`;
		case "C04":
			return `${messages.toLocaleString()} message${messages === 1 ? "" : "s"} carry a DKIM signature naming a selector (${selectors.slice(0, 3).join(", ") || "unknown"}) for which ${domain} publishes no key, so receivers cannot verify it. Usually the key was generated in a console but never published in DNS, or the DNS provider mangled the long TXT value. Publish the key and the signatures start verifying immediately.`;
		case "C05":
			return `${messages.toLocaleString()} message${messages === 1 ? "" : "s"} (${sharePct}%) pass DMARC on SPF alone — DKIM does not align. SPF does not survive forwarding, so every forwarded copy of this mail fails authentication at its final destination. Getting DKIM aligned on this stream makes it survive forwards.`;
		case "C06":
			return `${messages.toLocaleString()} message${messages === 1 ? "" : "s"} (${sharePct}%) pass DMARC on DKIM alone — the Return-Path (${spfDomains.slice(0, 2).join(", ") || "envelope"}) does not align with ${domain}. That is fine today and it survives forwarding, but the stream now depends on a single signing key: one rotation or misconfiguration and all of it fails. Branding the Return-Path gives it a second leg to stand on.`;
		case "C07":
			return `${messages.toLocaleString()} message${messages === 1 ? "" : "s"} were forwarded, which broke the original authentication, and the receiver delivered them anyway because it trusted the ARC chain the forwarder added. This is the failure mode ARC exists to absorb. Nothing to fix.`;
		case "C08":
			return `${messages.toLocaleString()} message${messages === 1 ? "" : "s"} were signed correctly as ${domain} but the signature did not verify at ${[...reporters].join(", ")}. Something between you and the receiver — a gateway, a mailing list, a security appliance — modified the message after signing. Isolated cases are normal; a persistent pattern from one receiver is a real interoperability bug.`;
		case "C09":
			return `${messages.toLocaleString()} message${messages === 1 ? "" : "s"} came from ${spfDomains.slice(0, 2).join(", ") || "an unrecognized identity"}, which is not authorized to send as ${domain}. Low volume like this is usually a SaaS tool somebody signed up for. Authorize it if it is yours; otherwise just watch it.`;
		case "C10":
			return `${messages.toLocaleString()} message${messages === 1 ? "" : "s"} from sources you DO recognize were quarantined or rejected by ${[...reporters].join(", ")}. This is your own mail being blocked by your own policy — the most damaging thing on this page. Fix the authentication on ${ips} source${ips === 1 ? "" : "s"} below before more mail is lost.`;
		case "C11":
			return `Receivers covering overlapping days reported different DMARC records for ${domain}. Reporters do not invent these values, so either the record changed mid-window, or there is more than one _dmarc TXT record, or reporters are filling in absent tags differently. A DNS check alone cannot see this, because it only ever sees the record as it is right now.`;
		case "C12":
			return `Your DMARC record's pct= tag means the policy is only applied to part of your mail, so some messages skip enforcement entirely. That is a legitimate step while you ramp up, but it leaves a gap open. Finish the ramp to pct=100.`;
		case "C13":
			return `A receiver that normally reports on ${domain} sent nothing this window. Either your rua= address broke, or the report mailbox is full or misrouted, or you genuinely sent them no mail. Silence is not the same as health, which is why it is listed here.`;
		case "C14":
			return `${messages} TLS session${messages === 1 ? "" : "s"} were reported for mail delivered TO ${domain}. This measures encryption on inbound mail, and confirms senders enforcing MTA-STS or DANE can reach you.`;
		case "C15":
			return `A report arrived that we could not decode, so its contents are not counted anywhere on this page. An unreadable report looks exactly like a report that found no problems, which is why this is flagged rather than ignored.`;
		default:
			return "";
	}
}

/** One-line evidence summary under the card title (§10.2). */
function evidenceSummaryFor(sources: ComplaintSource[]): string {
	if (sources.length === 0) return "No per-message evidence for this complaint.";
	const ips = new Set(sources.map((s) => s.sourceIp)).size;
	const signing = new Set(sources.map((s) => s.dkimDomain).filter(Boolean)).size;
	const selectors = new Set(
		sources.map((s) => s.dkimSelector).filter(Boolean),
	).size;
	const reporters = new Set(sources.flatMap((s) => s.reporters)).size;
	return `${ips} source IP${ips === 1 ? "" : "s"} · ${signing} signing domain${signing === 1 ? "" : "s"} · ${selectors} selector${selectors === 1 ? "" : "s"} · seen by ${reporters} receiver${reporters === 1 ? "" : "s"}`;
}

/** §8.3 severity escalations applied on top of the catalog baseline. */
function escalate(
	code: ComplaintCode,
	base: Complaint["severity"],
	sharePct: number,
	messages: number,
	policyEnforcing: boolean,
): Complaint["severity"] {
	if (code === "C02")
		return sharePct > 10 && policyEnforcing ? "critical" : sharePct > 1 ? "warning" : "info";
	if (code === "C03")
		return sharePct > 1 || messages > 100 ? "critical" : "warning";
	if (code === "C01") return sharePct > 5 || messages > 1000 ? "warning" : "info";
	return base;
}

/** Daily buckets for the Zone A chart (§10.1 item 3), volume-weighted per report window. */
function buildSeries(reports: ParsedDmarcReport[]): ComplaintSeriesPoint[] {
	const byDay = new Map<string, ComplaintSeriesPoint>();
	for (const report of reports) {
		const date = (report.window.begin || report.window.end).slice(0, 10);
		const point =
			byDay.get(date) ??
			({
				date,
				aligned: 0,
				oneMechanism: 0,
				failedBoth: 0,
				quarantined: 0,
				rejected: 0,
			} satisfies ComplaintSeriesPoint);
		for (const row of report.rows) {
			if (row.dkimAligned && row.spfAligned) point.aligned += row.count;
			else if (row.dkimAligned || row.spfAligned) point.oneMechanism += row.count;
			else point.failedBoth += row.count;
			if (row.disposition === "quarantine") point.quarantined += row.count;
			else if (row.disposition === "reject") point.rejected += row.count;
		}
		byDay.set(date, point);
	}
	return [...byDay.values()].sort((a, b) => a.date.localeCompare(b.date));
}

/** The reporter coverage strip, including expected-but-silent reporters (§10.1 item 4 / C13). */
function buildReporters(
	current: ParsedDmarcReport[],
	all: ParsedDmarcReport[],
): ComplaintReporter[] {
	const seen = new Map<string, ComplaintReporter>();
	for (const report of current) {
		const entry = seen.get(report.reporterOrg) ?? {
			org: report.reporterOrg,
			email: report.reporterEmail ?? null,
			contactUrl: report.reporterContact ?? null,
			reportCount: 0,
			messages: 0,
			lastSeen: null,
			expectedButMissing: false,
		};
		entry.reportCount++;
		entry.messages += report.rows.reduce((n, r) => n + r.count, 0);
		if (!entry.lastSeen || report.window.end > entry.lastSeen)
			entry.lastSeen = report.window.end;
		entry.email ??= report.reporterEmail ?? null;
		entry.contactUrl ??= report.reporterContact ?? null;
		seen.set(report.reporterOrg, entry);
	}

	// Expected reporters: the well-known four, plus anyone who has ever reported for this domain.
	const historic = new Set(all.map((r) => r.reporterOrg));
	const expected = new Set<string>([...EXPECTED_REPORTERS, ...historic].map((s) => s.toLowerCase()));
	for (const org of expected) {
		const present = [...seen.keys()].some((k) => k.toLowerCase() === org);
		if (present) continue;
		const known = all.find((r) => r.reporterOrg.toLowerCase() === org);
		seen.set(org, {
			org: known?.reporterOrg ?? org,
			email: known?.reporterEmail ?? null,
			contactUrl: known?.reporterContact ?? null,
			reportCount: 0,
			messages: 0,
			lastSeen: known?.window.end ?? null,
			expectedButMissing: true,
		});
	}
	return [...seen.values()].sort((a, b) => b.messages - a.messages);
}

/** Every distinct `policy_published` tuple observed — the raw material for C11 (§4.2). */
function buildObservedPolicies(reports: ParsedDmarcReport[]): ObservedPolicy[] {
	const byTuple = new Map<string, ObservedPolicy>();
	for (const report of reports) {
		const p = report.policyPublished;
		const key = `${p.p}|${p.sp}|${p.np}|${p.adkim}|${p.aspf}|${p.pct}|${p.fo ?? null}`;
		const entry = byTuple.get(key) ?? {
			p: p.p,
			sp: p.sp,
			np: p.np,
			adkim: p.adkim,
			aspf: p.aspf,
			pct: p.pct,
			fo: p.fo ?? null,
			reporters: [],
			firstSeen: report.window.begin,
			lastSeen: report.window.end,
		};
		if (!entry.reporters.includes(report.reporterOrg))
			entry.reporters.push(report.reporterOrg);
		if (report.window.begin < entry.firstSeen) entry.firstSeen = report.window.begin;
		if (report.window.end > entry.lastSeen) entry.lastSeen = report.window.end;
		byTuple.set(key, entry);
	}
	return [...byTuple.values()].sort((a, b) =>
		a.firstSeen.localeCompare(b.firstSeen),
	);
}

/** Build the whole board (pm/Email_Complaints.mdx §12). */
export function buildComplaintBoard(input: BuildBoardInput): ComplaintBoard {
	const {
		domainId,
		domain,
		dmarcReports,
		tlsReports,
		windowDays,
		ingestionEnabled,
		lastIngestAt,
	} = input;

	// Anchor on the newest report so a historical corpus still analyzes (pm/emails.mdx §4.6).
	const newestEnd =
		dmarcReports
			.map((r) => r.window.end)
			.sort()
			.at(-1) ?? new Date().toISOString();
	const anchor = Number.isFinite(Date.parse(newestEnd))
		? Date.parse(newestEnd)
		: Date.now();
	const window = {
		begin: new Date(anchor - windowDays * DAY_MS).toISOString(),
		end: new Date(anchor).toISOString(),
		days: windowDays,
	};
	const previousWindow = {
		begin: new Date(anchor - 2 * windowDays * DAY_MS).toISOString(),
		end: window.begin,
	};

	const current = dmarcReports.filter((r) =>
		overlaps(r.window.begin, r.window.end, window.begin, window.end),
	);
	const previous = dmarcReports.filter((r) =>
		overlaps(r.window.begin, r.window.end, previousWindow.begin, previousWindow.end),
	);

	const ctx: ClassifyContext = {
		domain,
		spfAuthorizedIps: input.spfAuthorizedIps,
	};
	const currentByCode = classifyReports(current, ctx);
	const previousByCode = classifyReports(previous, ctx);

	// ─── Totals ───────────────────────────────────────────────────────────────────────────────
	let messages = 0;
	let authenticated = 0;
	let dmarcPassing = 0;
	let blocked = 0;
	for (const report of current) {
		for (const row of report.rows) {
			messages += row.count;
			if (row.dkimAligned && row.spfAligned) authenticated += row.count;
			if (row.dkimAligned || row.spfAligned) dmarcPassing += row.count;
			if (row.disposition === "quarantine" || row.disposition === "reject")
				blocked += row.count;
		}
	}
	const spoof = currentByCode.get("C01")?.messages ?? 0;
	const authenticatedPct =
		messages === 0 ? 0 : Math.round((authenticated / messages) * 1000) / 10;

	let prevMessages = 0;
	let prevAuthenticated = 0;
	for (const report of previous) {
		for (const row of report.rows) {
			prevMessages += row.count;
			if (row.dkimAligned && row.spfAligned) prevAuthenticated += row.count;
		}
	}
	const prevPct =
		prevMessages === 0 ? 0 : Math.round((prevAuthenticated / prevMessages) * 1000) / 10;

	const policyObserved = buildObservedPolicies(current);
	const policyEnforcing = policyObserved.some((p) => p.p === "reject" || p.p === "quarantine");

	// ─── Row-level complaints ─────────────────────────────────────────────────────────────────
	const complaints: Complaint[] = [];
	for (const [code, bucket] of currentByCode) {
		const descriptor = COMPLAINT_CATALOG[code];
		const sources = [...bucket.sources.values()].sort((a, b) => b.count - a.count);
		const sharePct =
			messages === 0 ? 0 : Math.round((bucket.messages / messages) * 1000) / 10;
		const previousMessages = previousByCode.get(code)?.messages ?? 0;
		complaints.push({
			...descriptor,
			severity: escalate(
				code,
				descriptor.severity,
				sharePct,
				bucket.messages,
				policyEnforcing,
			),
			messages: bucket.messages,
			sharePct,
			trend: trendOf(bucket.messages, previousMessages),
			previousMessages,
			explanation: explain(code, bucket.messages, sharePct, sources, domain, messages),
			evidenceSummary: evidenceSummaryFor(sources),
			sources,
		});
	}

	// Resolved complaints stay visible for one further window so a fix reads as feedback (§8.4).
	for (const [code, bucket] of previousByCode) {
		if (currentByCode.has(code) || bucket.messages === 0) continue;
		const descriptor = COMPLAINT_CATALOG[code];
		complaints.push({
			...descriptor,
			severity: "ok",
			verdict: "ok",
			messages: 0,
			sharePct: 0,
			trend: "resolved",
			previousMessages: bucket.messages,
			explanation: `${descriptor.title} affected ${bucket.messages.toLocaleString()} messages in the previous window and has not appeared at all in this one. Whatever you changed worked.`,
			evidenceSummary: "Resolved — kept visible for one window.",
			sources: [],
		});
	}

	// ─── Report-level complaints (C11–C15) ────────────────────────────────────────────────────
	const addReportLevel = (
		code: ComplaintCode,
		explanation: string,
		messagesValue = 0,
		severity?: Complaint["severity"],
		verdict?: Complaint["verdict"],
	) => {
		const descriptor = COMPLAINT_CATALOG[code];
		complaints.push({
			...descriptor,
			severity: severity ?? descriptor.severity,
			verdict: verdict ?? descriptor.verdict,
			messages: messagesValue,
			sharePct: 0,
			trend: "steady",
			previousMessages: 0,
			explanation,
			evidenceSummary: "",
			sources: [],
		});
	};

	// C11 — reporters disagree about the published policy.
	if (policyObserved.length > 1) {
		// Show only the tags that actually DIFFER. Listing "adkim=s/aspf=s/p=reject" twice because
		// the tuples differ by an invisible np= reads as a rendering bug rather than as evidence.
		const differing = (
			["p", "sp", "np", "adkim", "aspf", "pct", "fo"] as const
		).filter(
			(tag) => new Set(policyObserved.map((p) => String(p[tag]))).size > 1,
		);
		const variants = [
			...new Set(
				policyObserved.map((p) =>
					differing.map((tag) => `${tag}=${p[tag] ?? "absent"}`).join("/"),
				),
			),
		]
			.slice(0, 3)
			.join(", ");
		addReportLevel(
			"C11",
			`${explain("C11", 0, 0, [], domain, messages)} ${policyObserved.length} different records were reported (${variants}${policyObserved.length > 3 ? ", …" : ""}).`,
		);
	}

	// C12 — the policy is sampled. Only report-level when no row already carries sampled_out.
	const sampledPolicy = policyObserved.find(
		(p) => p.pct !== null && p.pct !== "" && Number(p.pct) < 100,
	);
	if (sampledPolicy && !currentByCode.has("C12")) {
		addReportLevel(
			"C12",
			`Your DMARC record publishes pct=${sampledPolicy.pct}, so receivers apply your policy to only ${sampledPolicy.pct}% of your mail. Finish the ramp to pct=100 once the authenticated rate is stable.`,
		);
	}

	// C13 — an expected receiver went silent.
	const reporters = buildReporters(current, dmarcReports);
	const missing = reporters.filter((r) => r.expectedButMissing);
	if (missing.length > 0 && current.length > 0) {
		addReportLevel(
			"C13",
			`${explain("C13", 0, 0, [], domain, messages)} Silent this window: ${missing.map((m) => m.org).join(", ")}.`,
			0,
			missing.length >= 2 ? "warning" : "info",
			missing.length >= 2 ? "problem" : "watch",
		);
	}

	// C14 — inbound TLS. Healthy is still reported, as the baseline a regression is measured against.
	const tlsCurrent = tlsReports.filter((r) =>
		overlaps(
			r.window.begin || r.reportDate,
			r.window.end || r.reportDate,
			window.begin,
			window.end,
		),
	);
	if (tlsCurrent.length > 0) {
		let success = 0;
		let failure = 0;
		const resultTypes = new Set<string>();
		for (const report of tlsCurrent) {
			for (const policy of report.policies) {
				success += policy.successCount;
				failure += policy.failureCount;
				for (const d of policy.failureDetails) resultTypes.add(d.resultType);
			}
		}
		const failurePct =
			success + failure === 0 ? 0 : (failure / (success + failure)) * 100;
		addReportLevel(
			"C14",
			failure > 0
				? `${failure} of ${success + failure} inbound TLS sessions to ${domain} failed (${[...resultTypes].join(", ") || "no detail given"}). Senders that enforce MTA-STS or DANE bounce or downgrade mail when this happens, so it is silent mail loss.`
				: `${explain("C14", success, 0, [], domain, messages)} All ${success} succeeded and none failed — a clean baseline.`,
			success + failure,
			failure > 0 ? (failurePct > 1 ? "critical" : "warning") : "ok",
			failure > 0 ? "problem" : "ok",
		);
	}

	// C15 — a report we could not read.
	const undecodable = input.undecodable ?? [];
	const reporterErrors = current.filter((r) => (r.reporterError ?? "").length > 0);
	if (undecodable.length > 0 || reporterErrors.length > 0) {
		addReportLevel(
			"C15",
			`${explain("C15", 0, 0, [], domain, messages)} ${undecodable.length} file(s) failed to decode${reporterErrors.length > 0 ? `, and ${reporterErrors.length} report(s) carried a reporter-declared error` : ""}.`,
		);
	}

	// ─── Ordering, verdict, fixes ─────────────────────────────────────────────────────────────
	const VERDICT_RANK: Record<Complaint["verdict"], number> = {
		problem: 0,
		watch: 1,
		ok: 2,
	};
	complaints.sort(
		(a, b) =>
			VERDICT_RANK[a.verdict] - VERDICT_RANK[b.verdict] ||
			b.messages - a.messages ||
			a.code.localeCompare(b.code),
	);

	const totals = {
		messages,
		authenticated,
		dmarcPassing,
		notAligned: messages - authenticated,
		blocked,
		spoof,
		authenticatedPct,
	};
	const verdict = boardVerdict(complaints, totals, current.length);

	const fixCtx: FixBuildContext = {
		domain,
		byCode: new Map(complaints.map((c) => [c.code, c])),
		tlsResultTypes: [
			...new Set(
				tlsCurrent.flatMap((r) =>
					r.policies.flatMap((p) => p.failureDetails.map((d) => d.resultType)),
				),
			),
		],
		brokenSelectors: [
			...new Set(
				(currentByCode.get("C04")?.sources
					? [...currentByCode.get("C04")!.sources.values()]
					: []
				)
					.map((s) => s.dkimSelector)
					.filter(Boolean),
			),
		],
		espDomains: [
			...new Set(
				(currentByCode.get("C02")?.sources
					? [...currentByCode.get("C02")!.sources.values()]
					: []
				)
					.map((s) => s.dkimDomain)
					.filter((d) => d && isEspDefaultDomain(d)),
			),
		],
	};

	return {
		domainId,
		domain,
		verdict,
		headline: headlineFor(verdict, complaints, domain),
		ingestionEnabled,
		window,
		previousWindow,
		totals,
		deltas: {
			authenticatedPct: Math.round((authenticatedPct - prevPct) * 10) / 10,
			messages: messages - prevMessages,
		},
		reporters,
		series: buildSeries(current),
		policyObserved,
		complaints,
		fixes: buildFixPlan(fixCtx),
		ingest: {
			lastIngestAt,
			reportsStored: dmarcReports.length + tlsReports.length,
			undecodable,
		},
	};
}

/** Re-exported so the controller and tests share one known-sender definition (§7.1). */
export { isKnownSender, underDomain };
