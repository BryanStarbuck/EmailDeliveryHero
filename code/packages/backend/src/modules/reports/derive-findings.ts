import type { Finding } from "@module/audit/checks/types";
import { readAppConfig } from "@shared/config-store";
import type {
	DmarcPolicyOverride,
	DmarcReportRow,
	ParsedDmarcReport,
	ParsedTlsRptReport,
} from "./report.types";
import { listDmarcReports, listTlsRptReports } from "./report-store";

/**
 * Report → Finding derivation (pm/emails.mdx §3/§5). Aggregates the stored, parsed reports over a
 * rolling window (default 7 days, anchored on NOW) and scores them against the problem catalog.
 * Every finding carries `source: "report"` and rolls into the EXISTING categories: `dmarc.*`
 * (DMARC column) and `infra.*` (DNS & Infrastructure column) — no seventh category (§6).
 *
 * FINDINGS DESCRIBE THE PRESENT. The window is anchored on the clock, never on the newest stored
 * report: a fault that receivers stopped reporting must age out of the window on its own, so a
 * corpus that stops arriving reports "no current data" rather than freezing the last known verdict
 * forever. Older reports stay in the store — they still feed the trend/new-source baselines — but
 * they never keep a resolved problem lit.
 */

// ─── Aggregation shapes (also served raw to the Reports UI, §7.1) ────────────────────────────────

/** One merged per-source row of the expandable details table (§7.1 "Open the details"). */
export interface DmarcSourceRow {
	sourceIp: string;
	count: number;
	/**
	 * What receivers DID with this slice. Part of the row's identity, not a summary across the
	 * source: one IP rejected by one receiver and delivered by another yields two rows.
	 */
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
	/**
	 * `<policy_evaluated><reason>` overrides the receivers declared, unioned across merged rows. The
	 * receiver telling us WHY it overrode DMARC is the strongest evidence available about a row —
	 * see wasForwardedByReceiver.
	 */
	reasons?: DmarcPolicyOverride[];
}

export interface DmarcAggregate {
	reportCount: number;
	reporters: string[];
	window: { begin: string; end: string };
	totalMessages: number;
	/**
	 * FULLY-aligned volume — both SPF and DKIM align (§12's "DMARC-aligned pass" figure: 1,157 of
	 * 1,195 for the corpus). A single-mechanism pass still passes DMARC (dmarcPassMessages) but
	 * counts as "failing alignment" here — it is the fragile slice the pass-rate finding flags.
	 */
	alignedPassMessages: number;
	/** Volume passing DMARC at all (either mechanism aligned) — what receivers actually deliver. */
	dmarcPassMessages: number;
	/** Dual-aligned percentage 0–100 (100 when no volume) — §12's 96.8%. */
	passRatePct: number;
	/**
	 * The REAL DMARC pass percentage 0–100 — either mechanism aligned, i.e. what receivers actually
	 * enforce on. Always >= passRatePct; the gap between the two is fragility, not failure.
	 */
	dmarcPassRatePct: number;
	policyPublished: ParsedDmarcReport["policyPublished"] | null;
	rows: DmarcSourceRow[];
	/** Stored reports that fall OUTSIDE the current window — history, deliberately not scored. */
	staleReportCount: number;
	/** Newest window end across ALL stored reports (not just in-window); null when the store is empty. */
	newestReportEnd: string | null;
}

export interface TlsRptReporterDay {
	reporterOrg: string;
	reportDate: string;
	policyType: string;
	successCount: number;
	failureCount: number;
	failureDetails: { resultType: string; count: number }[];
}

export interface TlsRptAggregate {
	reportCount: number;
	reporters: string[];
	window: { begin: string; end: string };
	totalSuccess: number;
	totalFailure: number;
	policyTypes: string[];
	rows: TlsRptReporterDay[];
	/** Stored reports that fall OUTSIDE the current window — history, deliberately not scored. */
	staleReportCount: number;
	/** Newest report date across ALL stored reports; null when the store is empty. */
	newestReportEnd: string | null;
}

/** True when `child` equals `parent` or is a subdomain of it. */
export function underDomain(child: string, parent: string): boolean {
	const c = child.replace(/\.$/, "").toLowerCase();
	const p = parent.replace(/\.$/, "").toLowerCase();
	return c === p || c.endsWith(`.${p}`);
}

/** "Known sender" heuristic (§3.1): the row's envelope or a DKIM d= traces to the org domain. */
export function isKnownSender(row: DmarcReportRow, domain: string): boolean {
	if (row.envelopeSpfDomain && underDomain(row.envelopeSpfDomain, domain))
		return true;
	return row.dkimSigningDomains.some((d) => underDomain(d, domain));
}

/**
 * Every source IP that has passed DMARC for this domain at some point across the WHOLE stored
 * corpus — the only evidence available here that a source is genuinely ours.
 */
export function authenticatedSourceIps(
	reports: ParsedDmarcReport[],
): Set<string> {
	const ips = new Set<string>();
	for (const report of reports)
		for (const row of report.rows) if (row.dmarcPass) ips.add(row.sourceIp);
	return ips;
}

/**
 * Ownership test for a row that failed BOTH alignments. `isKnownSender` must NOT be used here: the
 * row failed SPF, so its envelope is an unverified claim, and it failed DKIM, so its `d=` is too —
 * forging both is precisely what makes spoofed mail look like an own stream. Only independent
 * evidence counts: the IP is configured as a sending IP, or it has authenticated for us before.
 */
export function isOwnUnalignedSender(
	row: DmarcReportRow,
	knownIps: Set<string>,
): boolean {
	return knownIps.has(row.sourceIp);
}

/** "reject" → "rejected", "quarantine" → "quarantined" — for readable finding titles. */
export function dispositionPast(disposition: string): string {
	if (disposition === "reject") return "rejected";
	if (disposition === "quarantine") return "quarantined";
	return disposition;
}

/** RFC 7489 §7.2 override types that mean "the receiver identified this as relayed mail". */
const FORWARDING_OVERRIDES = new Set([
	"forwarded",
	"trusted_forwarder",
	"mailing_list",
]);

/**
 * Did the RECEIVER tell us this row is forwarded mail? A `<policy_evaluated><reason>` override is
 * the reporter's own explanation for why it did not apply the policy, and forwarding is the reason
 * a legitimate message arrives unaligned: the relay rewrote the Return-Path and the original DKIM
 * no longer matches the org domain. Google emits `local_policy` with an `arc=pass` comment for
 * exactly this. Such a row is relayed mail, not a forgery attempt, and must not be scored as one.
 */
export function wasForwardedByReceiver(row: {
	reasons?: DmarcPolicyOverride[];
}): boolean {
	return (row.reasons ?? []).some((r) => {
		const type = (r.type ?? "").toLowerCase();
		if (FORWARDING_OVERRIDES.has(type)) return true;
		return type === "local_policy" && /\barc\s*=\s*pass\b/i.test(r.comment ?? "");
	});
}

/**
 * The four realities behind "failed BOTH alignments". Only `own` is our misconfiguration and only
 * `delivered` is an unanswered threat — `forwarded` and `blocked` are the system working as designed
 * and must never raise a flag or generate an "add it to SPF" nudge.
 */
export type UnalignedKind = "own" | "forwarded" | "blocked" | "delivered";

export function classifyUnaligned(
	row: DmarcReportRow & { reasons?: DmarcPolicyOverride[] },
	knownIps: Set<string>,
): UnalignedKind {
	if (isOwnUnalignedSender(row, knownIps)) return "own";
	if (wasForwardedByReceiver(row)) return "forwarded";
	if (row.disposition === "reject" || row.disposition === "quarantine")
		return "blocked";
	return "delivered";
}

/** Is this failure something the operator can actually act on? */
export function isActionableUnaligned(kind: UnalignedKind): boolean {
	return kind === "own" || kind === "delivered";
}

/**
 * Volume breakdown of a DMARC aggregate (pm/emails.mdx §13.3/§16.3 snapshot fields): how many
 * messages passed on one mechanism only (the fragile slices), failed both, or were actively
 * quarantined/rejected by receivers.
 */
export function dmarcVolumeBreakdown(agg: DmarcAggregate): {
	dkimOnly: number;
	spfOnly: number;
	bothFail: number;
	quarantined: number;
	rejected: number;
} {
	let dkimOnly = 0;
	let spfOnly = 0;
	let bothFail = 0;
	let quarantined = 0;
	let rejected = 0;
	for (const row of agg.rows) {
		if (row.dkimAligned && !row.spfAligned) dkimOnly += row.count;
		else if (row.spfAligned && !row.dkimAligned) spfOnly += row.count;
		else if (!row.spfAligned && !row.dkimAligned) bothFail += row.count;
		if (row.disposition === "quarantine") quarantined += row.count;
		else if (row.disposition === "reject") rejected += row.count;
	}
	return { dkimOnly, spfOnly, bothFail, quarantined, rejected };
}

/**
 * The §7.1 fragile-stream detection, shared by the per-source dmarc.report_alignment_fragility
 * enumeration (§5) and the aggregate content.report_fragility verdict (§13.2): OWN streams that
 * pass DMARC on only one mechanism. DKIM-only rows count only when the envelope traces to the org
 * domain (an ESP subdomain under aspf=s); a DKIM-only row with an unrelated envelope is forwarded
 * mail — benign when DKIM aligns (§3.1). SPF-only rows count when the stream is otherwise ours.
 */
export function fragileStreams(
	agg: DmarcAggregate,
	domain: string,
): Map<string, { count: number; ips: Set<string>; dkimOnly: boolean }> {
	const fragile = new Map<
		string,
		{ count: number; ips: Set<string>; dkimOnly: boolean }
	>();
	for (const row of agg.rows) {
		if (!row.dmarcPass || row.spfAligned === row.dkimAligned) continue;
		const dkimOnly = row.dkimAligned && !row.spfAligned;
		if (
			dkimOnly &&
			!(row.envelopeSpfDomain && underDomain(row.envelopeSpfDomain, domain))
		)
			continue;
		if (!dkimOnly && !isKnownSender(row, domain)) continue;
		const streamKey = `${row.envelopeSpfDomain || row.sourceIp}|${dkimOnly ? "dkim" : "spf"}`;
		const entry = fragile.get(streamKey) ?? {
			count: 0,
			ips: new Set<string>(),
			dkimOnly,
		};
		entry.count += row.count;
		entry.ips.add(row.sourceIp);
		fragile.set(streamKey, entry);
	}
	return fragile;
}

/** Reports whose window overlaps [start, end]. */
function inWindow(
	begin: string,
	end: string,
	start: string,
	stop: string,
): boolean {
	return begin <= stop && end >= start;
}

/**
 * The rolling window, anchored on NOW (§4.6). Deliberately NOT anchored on the newest stored
 * report: that froze the window on whatever day reports last arrived, so an already-fixed fault
 * stayed inside it and kept re-firing on every rescan.
 */
function windowFor(windowDays: number): { begin: string; end: string } {
	const now = Date.now();
	return {
		begin: new Date(now - windowDays * 24 * 60 * 60 * 1000).toISOString(),
		end: new Date(now).toISOString(),
	};
}

export function aggregateDmarc(
	reports: ParsedDmarcReport[],
	windowDays: number,
): DmarcAggregate {
	const window = windowFor(windowDays);
	const current = reports.filter((r) =>
		inWindow(r.window.begin, r.window.end, window.begin, window.end),
	);
	const newestReportEnd =
		reports
			.map((r) => r.window.end)
			.sort()
			.at(-1) ?? null;

	const bySource = new Map<string, DmarcSourceRow>();
	let total = 0;
	let dualAligned = 0;
	let dmarcPass = 0;
	for (const report of current) {
		for (const row of report.rows) {
			total += row.count;
			if (row.spfAligned && row.dkimAligned) dualAligned += row.count;
			if (row.dmarcPass) dmarcPass += row.count;
			// `disposition` and `headerFrom` are part of the identity, NOT details to be reconciled
			// after the fact. Severity keys on disposition, so collapsing rows that differ on it and
			// keeping the strongest — the old behaviour — reported a source Gmail rejected and Yahoo
			// DELIVERED as wholly rejected, hiding the delivered volume (the one case that is an
			// unanswered threat) behind the label of the case that is the policy working.
			const key = `${row.sourceIp}|${row.envelopeSpfDomain}|${row.spfAligned}|${row.dkimAligned}|${row.disposition}|${row.headerFrom}`;
			const merged = bySource.get(key);
			if (merged) {
				merged.count += row.count;
				for (const d of row.dkimSigningDomains) {
					if (!merged.dkimSigningDomains.includes(d))
						merged.dkimSigningDomains.push(d);
				}
				if (!merged.reporters.includes(report.reporterOrg))
					merged.reporters.push(report.reporterOrg);
				// Union the receiver-declared overrides: they are the classifier's best evidence, so a
				// merge must never drop the one row that carried the explanation.
				for (const reason of row.reasons ?? []) {
					merged.reasons ??= [];
					if (
						!merged.reasons.some(
							(r) => r.type === reason.type && r.comment === reason.comment,
						)
					)
						merged.reasons.push(reason);
				}
			} else {
				bySource.set(key, {
					...row,
					dkimSigningDomains: [...row.dkimSigningDomains],
					reporters: [report.reporterOrg],
					reasons: row.reasons ? [...row.reasons] : undefined,
				});
			}
		}
	}

	return {
		reportCount: current.length,
		reporters: [...new Set(current.map((r) => r.reporterOrg))].sort(),
		window,
		totalMessages: total,
		alignedPassMessages: dualAligned,
		dmarcPassMessages: dmarcPass,
		passRatePct:
			total === 0 ? 100 : Math.round((dualAligned / total) * 1000) / 10,
		dmarcPassRatePct:
			total === 0 ? 100 : Math.round((dmarcPass / total) * 1000) / 10,
		policyPublished: current[0]?.policyPublished ?? null,
		rows: [...bySource.values()].sort((a, b) => b.count - a.count),
		staleReportCount: reports.length - current.length,
		newestReportEnd,
	};
}

export function aggregateTlsRpt(
	reports: ParsedTlsRptReport[],
	windowDays: number,
): TlsRptAggregate {
	const window = windowFor(windowDays);
	const current = reports.filter((r) =>
		inWindow(
			r.window.begin || r.reportDate,
			r.window.end || r.reportDate,
			window.begin,
			window.end,
		),
	);
	const newestReportEnd =
		reports
			.map((r) => r.window.end || r.reportDate)
			.sort()
			.at(-1) ?? null;

	const rows: TlsRptReporterDay[] = [];
	let success = 0;
	let failure = 0;
	for (const report of current) {
		for (const policy of report.policies) {
			success += policy.successCount;
			failure += policy.failureCount;
			rows.push({
				reporterOrg: report.reporterOrg,
				reportDate: report.reportDate,
				policyType: policy.policyType,
				successCount: policy.successCount,
				failureCount: policy.failureCount,
				failureDetails: policy.failureDetails,
			});
		}
	}
	rows.sort((a, b) => b.reportDate.localeCompare(a.reportDate));

	return {
		reportCount: current.length,
		reporters: [...new Set(current.map((r) => r.reporterOrg))].sort(),
		window,
		totalSuccess: success,
		totalFailure: failure,
		policyTypes: [...new Set(rows.map((r) => r.policyType))].sort(),
		rows,
		staleReportCount: reports.length - current.length,
		newestReportEnd,
	};
}

// ─── Findings (§5 table) ─────────────────────────────────────────────────────────────────────────

const DMARC_CHECK_ID = "dmarc.reports";
const TLS_CHECK_ID = "infra.tls_rpt";

function fmtWindow(w: { begin: string; end: string }): string {
	return `${w.begin.slice(0, 10)}→${w.end.slice(0, 10)}`;
}

/** Whole days between an ISO instant and now; null when unparseable. */
export function ageInDays(iso: string | null): number | null {
	if (!iso) return null;
	const ms = Date.parse(iso);
	if (!Number.isFinite(ms)) return null;
	return Math.max(0, Math.floor((Date.now() - ms) / (24 * 60 * 60 * 1000)));
}

/**
 * The store holds reports but NONE inside the current window. Every scored row goes to `info` "no
 * current data" rather than reusing the last in-window verdict — the whole point of the clock-
 * anchored window is that a problem nobody is reporting any more stops being a current problem.
 * `content.report_freshness` / the age note below is the one row that stays loud, because a corpus
 * that stopped arriving IS the live fault worth acting on.
 */
function staleCorpusFindings(
	ids: string[],
	checkId: string,
	domain: string,
	windowDays: number,
	newestReportEnd: string | null,
	storedCount: number,
): Finding[] {
	const age = ageInDays(newestReportEnd);
	const detail = `No report covering the last ${windowDays} day(s) has been ingested for ${domain}, so there is no current field data to score. ${storedCount} older report(s) remain in the store${age === null ? "" : `, the newest ${age} day(s) old`} — kept as history for trend baselines, deliberately not scored as a present-day problem.`;
	return ids.map((id) => ({
		id,
		checkId,
		title: `No DMARC report data in the last ${windowDays} day(s)`,
		severity: "info" as const,
		detail,
		remediation: `Confirm receivers are still sending to the rua= address on _dmarc.${domain} and that the report mailbox/drop folder is wired up (Settings → Admin), then Ingest now on the Reports page.`,
		source: "report" as const,
	}));
}

/** The single muted finding when the admin master switch is off (pm/emails.mdx §8). */
export function ingestionDisabledFinding(id: string, checkId: string): Finding {
	return {
		id,
		checkId,
		title: "Report ingestion disabled",
		severity: "info",
		detail:
			"Report-email ingestion is switched off in Settings → Admin, so this check contributes nothing to the score.",
		remediation:
			"Enable report ingestion under Settings → Admin to feed this check with real receiver data.",
		source: "report",
	};
}

/** DMARC-aggregate findings for one domain (dmarc.* — the DMARC dashboard column, §5/§6). */
export function deriveDmarcReportFindings(
	domainId: string,
	domain: string,
	configuredSendingIps: string[] = [],
): Finding[] {
	const config = readAppConfig().reports;
	if (!config.enabled) {
		return [ingestionDisabledFinding("dmarc.real_pass_rate", DMARC_CHECK_ID)];
	}
	const reports = listDmarcReports(domainId);
	if (reports.length === 0) {
		return [
			{
				id: "dmarc.real_pass_rate",
				checkId: DMARC_CHECK_ID,
				title: "No DMARC aggregate reports ingested yet",
				severity: "info",
				detail: `No rua aggregate reports have been ingested for ${domain}; the real-world DMARC pass rate is unknown until receivers' reports arrive (typically 24–72h after publishing rua=).`,
				remediation: `Publish rua=mailto:dmarc@${domain} on _dmarc.${domain} and point the report mailbox or drop folder here (Settings → Admin), then Ingest now on the Reports page.`,
				source: "report",
			},
		];
	}

	const agg = aggregateDmarc(reports, config.windowDays);
	if (agg.reportCount === 0) {
		return staleCorpusFindings(
			[
				"dmarc.real_pass_rate",
				"dmarc.report_unaligned_source",
				"dmarc.report_alignment_fragility",
				"dmarc.report_enforcement",
			],
			DMARC_CHECK_ID,
			domain,
			config.windowDays,
			agg.newestReportEnd,
			reports.length,
		);
	}

	const findings: Finding[] = [];
	const enforced = (agg.policyPublished?.p ?? "none") === "reject";
	// Ownership evidence for the both-fail rows: configured sending IPs plus every IP that has ever
	// authenticated for us across the whole store (see isOwnUnalignedSender on why not the envelope).
	const knownIps = authenticatedSourceIps(reports);
	for (const ip of configuredSendingIps) knownIps.add(ip);

	// dmarc.real_pass_rate — the pass rate receivers actually enforce on (§5 row 1). DMARC passes on
	// EITHER aligned mechanism, so severity keys on that; the dual-aligned figure is reported
	// alongside it as the fragility signal it is, and is scored by report_alignment_fragility below.
	const fragileVolume = agg.totalMessages - agg.alignedPassMessages;
	const failVolume = agg.totalMessages - agg.dmarcPassMessages;
	const failSources = new Set(
		agg.rows.filter((r) => !r.dmarcPass).map((r) => r.sourceIp),
	).size;
	// dmarc.report_unaligned_source — rows failing BOTH alignments (§5 row 2). !dmarcPass is exactly
	// this set, so one classification serves the pass rate, the per-source rows and enforcement.
	const bothFail = agg.rows.filter(
		(r) => !r.spfAligned && !r.dkimAligned && r.count > 0,
	);
	const kindOf = new Map(
		bothFail.map((r) => [r, classifyUnaligned(r, knownIps)] as const),
	);
	// Failures nobody can act on (forged mail the policy stopped, receiver-declared forwards) must not
	// generate a "go fix your senders" instruction — that is how a healthy domain reads as broken.
	const actionableVolume = bothFail
		.filter((r) => isActionableUnaligned(kindOf.get(r) ?? "delivered"))
		.reduce((n, r) => n + r.count, 0);
	findings.push({
		id: "dmarc.real_pass_rate",
		checkId: DMARC_CHECK_ID,
		title: `DMARC pass rate ${agg.dmarcPassRatePct}%`,
		severity:
			actionableVolume > 0 && agg.dmarcPassRatePct < 99.5 ? "warning" : "info",
		detail: `${agg.dmarcPassRatePct}% of mail passes DMARC (${agg.dmarcPassMessages} / ${agg.totalMessages} msgs, ${fmtWindow(agg.window)}) — one aligned mechanism is all DMARC requires. ${failVolume} msg(s) from ${failSources} source(s) fail it outright, of which ${actionableVolume} msg(s) are yours to fix (the rest is forged mail the policy stopped, or receiver-declared forwarding). Of the passing mail, ${agg.passRatePct}% is dual-aligned (${agg.alignedPassMessages} msgs); the remaining ${fragileVolume} msg(s) rely on a single mechanism — resilience, scored separately below, not a delivery failure. Reporters: ${agg.reporters.join(", ")}.`,
		remediation:
			actionableVolume > 0
				? `Fix or authorize the failing sources (SPF include: / DKIM selector / alignment) ${enforced ? "— they are being evaluated under p=reject right now" : "before raising the policy"}.`
				: undefined,
		source: "report",
	});
	if (bothFail.length === 0) {
		findings.push({
			id: "dmarc.report_unaligned_source",
			checkId: DMARC_CHECK_ID,
			title: "No unauthorized senders",
			severity: "ok",
			detail: `0 rows fail both SPF and DKIM alignment across ${agg.totalMessages} msgs — no spoofing or forgotten sender is visible in the reports.`,
			source: "report",
		});
	} else {
		for (const row of bothFail) {
			const kind = kindOf.get(row) ?? "delivered";
			const own = kind === "own";
			const shape = {
				own: {
					title: `Own stream failing all authentication (${row.sourceIp})`,
					severity: "warning" as const,
					why: "This IP has authenticated for the domain before, so it is a real sender that has broken.",
					fix: `Authorize this sender: add it to SPF (include:) and enable DKIM signing with a selector under ${domain}.`,
				},
				forwarded: {
					title: `Forwarded mail arriving unaligned (${row.sourceIp})`,
					severity: "info" as const,
					why: `The reporter declared a policy override (${(row.reasons ?? []).map((r) => r.type + (r.comment ? `: ${r.comment}` : "")).join("; ")}) — it identified this as relayed mail and delivered it. A relay rewrites the Return-Path and breaks the original DKIM, so unaligned is expected here, not forged.`,
					fix: undefined,
				},
				blocked: {
					title: `Spoofed mail ${dispositionPast(row.disposition)} (${row.sourceIp})`,
					severity: "info" as const,
					why: `Neither mechanism authenticated, this IP has never authenticated for ${domain}, and no receiver declared it as relayed — so its envelope (${row.envelopeSpfDomain || "-"}) and DKIM d= (${row.dkimSigningDomains.join(",") || "-"}) are forged claims. Receivers ${dispositionPast(row.disposition)} it: the published policy is doing its job.`,
					fix: `No action needed — do NOT add this IP to SPF. Keep the policy at p=${agg.policyPublished?.p ?? "reject"} and report high-volume abuse to the netblock's abuse contact.`,
				},
				delivered: {
					title: `Unauthorized sender ${row.sourceIp}`,
					severity: "critical" as const,
					why: `Neither mechanism authenticated for ${domain} and this IP has never done so, yet receivers DELIVERED the mail — unaligned mail is reaching inboxes as ${row.headerFrom || domain}.`,
					fix: `Raise enforcement so receivers drop this: publish p=reject on _dmarc.${domain}. Do NOT add this IP to SPF unless you can independently confirm it is yours.`,
				},
			}[kind];
			findings.push({
				// Disposition is part of the identity: one source can be rejected by one receiver and
				// delivered by another, which is two different findings at two different severities.
				id: `dmarc.report_unaligned_source.${row.sourceIp}.${row.disposition}`,
				checkId: DMARC_CHECK_ID,
				title: shape.title,
				severity: shape.severity,
				detail: `Source ${row.sourceIp} sent ${row.count} msg(s) as ${row.headerFrom || domain} — SPF ${row.spfEvaluated}/aligned ${row.spfAligned}, DKIM ${row.dkimEvaluated}/aligned ${row.dkimAligned} (disposition: ${row.disposition}). ${shape.why}`,
				remediation: shape.fix,
				evidence: `${row.sourceIp} envelope=${row.envelopeSpfDomain || "-"} dkim_d=${row.dkimSigningDomains.join(",") || "-"} spf=${row.spfEvaluated} dkim=${row.dkimEvaluated} ever_authenticated=${own} classified=${kind}`,
				source: "report",
			});
		}
	}

	// dmarc.report_alignment_fragility — own streams passing via ONE mechanism only (§5 row 3);
	// detection shared with the aggregate content.report_fragility verdict (fragileStreams above).
	const fragile = fragileStreams(agg, domain);
	if (fragile.size === 0) {
		findings.push({
			id: "dmarc.report_alignment_fragility",
			checkId: DMARC_CHECK_ID,
			title: "All passing streams are dual-aligned",
			severity: "ok",
			detail:
				"Every known stream that passes DMARC aligns on both SPF and DKIM — no single point of failure.",
			source: "report",
		});
	} else {
		const aspf = agg.policyPublished?.aspf ?? "r";
		const adkim = agg.policyPublished?.adkim ?? "r";
		for (const [key, s] of fragile) {
			const envelope = key.split("|")[0];
			findings.push({
				id: `dmarc.report_alignment_fragility.${envelope}`,
				checkId: DMARC_CHECK_ID,
				title: s.dkimOnly
					? `Stream is DKIM-only (${envelope})`
					: `Stream is SPF-only (${envelope})`,
				severity: "warning",
				detail: s.dkimOnly
					? `${s.count} msg(s) from ${[...s.ips].slice(0, 4).join(", ")} (envelope ${envelope}) pass DMARC via DKIM only — SPF alignment fails under aspf=${aspf}. One DKIM key rotation/breakage and the whole stream fails DMARC${(agg.policyPublished?.p ?? "") === "reject" ? " and is rejected under p=reject" : ""}.`
					: `${s.count} msg(s) from ${[...s.ips].slice(0, 4).join(", ")} (envelope ${envelope}) pass DMARC via SPF only — DKIM fails or does not align under adkim=${adkim}. A Return-Path change or a forward breaks the stream.`,
				remediation: s.dkimOnly
					? `Set aspf=r on _dmarc.${domain}, or brand the Return-Path (e.g. bounces.${domain} CNAME'd at the ESP) so the envelope aligns and the stream has dual-auth resilience.`
					: `Enable DKIM signing with a selector under ${domain} (selector._domainkey.${domain}) at this sender, and/or set adkim=r.`,
				evidence: s.dkimOnly
					? `v=DMARC1; p=${agg.policyPublished?.p ?? "reject"}; aspf=r`
					: `selector._domainkey.${domain}`,
				source: "report",
			});
		}
	}

	// dmarc.report_enforcement — own mail actively quarantined/rejected (§5 row 4).
	const enforcedRows = agg.rows.filter(
		(r) => r.disposition === "quarantine" || r.disposition === "reject",
	);
	if (enforcedRows.length === 0) {
		findings.push({
			id: "dmarc.report_enforcement",
			checkId: DMARC_CHECK_ID,
			title: "No mail quarantined or rejected",
			severity: "info",
			detail: `Every reported row carries disposition=none — receivers are not dropping mail sent as ${domain}.`,
			source: "report",
		});
	} else {
		for (const row of enforcedRows) {
			// Mail dropped because it was spoofed is the policy working, not our mail being lost. Only
			// a drop of a source we can independently tie to this domain is a real delivery failure.
			const kind = kindOf.get(row);
			const own = row.dmarcPass || kind === "own" || kind === "forwarded";
			const past = dispositionPast(row.disposition);
			findings.push({
				id: `dmarc.report_enforcement.${row.sourceIp}.${row.disposition}`,
				checkId: DMARC_CHECK_ID,
				title: own
					? `Our mail ${past} by receivers (${row.sourceIp})`
					: `Spoofed mail ${past} by receivers (${row.sourceIp})`,
				severity: own ? "critical" : "info",
				detail: own
					? `${row.count} msg(s) from ${row.sourceIp} were ${past} by ${row.reporters.join(", ")} — this is a source that authenticates for ${domain}, so real mail is being dropped.`
					: `${row.count} msg(s) from ${row.sourceIp} were ${past} by ${row.reporters.join(", ")}. The source failed both SPF and DKIM alignment and has never authenticated for ${domain} — this is forged mail the published policy correctly stopped, not lost mail of ours.`,
				remediation: own
					? `Identify the failing source ${row.sourceIp}, authorize it (SPF include: / DKIM selector under ${domain}), and confirm alignment before it recurs.`
					: undefined,
				source: "report",
			});
		}
	}

	// dmarc.report_new_source — sources unseen in prior windows (§5 row 5). Needs a prior baseline.
	const prior = reports.filter((r) => r.window.end < agg.window.begin);
	if (prior.length > 0) {
		const priorIps = new Set(
			prior.flatMap((r) => r.rows.map((row) => row.sourceIp)),
		);
		const fresh = agg.rows.filter((r) => !priorIps.has(r.sourceIp));
		if (fresh.length > 0) {
			const totalNew = fresh.reduce((n, r) => n + r.count, 0);
			findings.push({
				id: "dmarc.report_new_source",
				checkId: DMARC_CHECK_ID,
				title: `${fresh.length} new sending source(s) appeared this window`,
				severity: "info",
				detail: `New sending source(s) ${fresh
					.slice(0, 5)
					.map((r) => r.sourceIp)
					.join(
						", ",
					)}${fresh.length > 5 ? ", …" : ""} (${totalNew} msg(s)) appeared this window and were absent from prior windows.`,
				remediation: `Reconcile against your known senders; add to SPF/DKIM if yours, else monitor for spoofing.`,
				source: "report",
			});
		}
	}

	return findings;
}

/** TLS-RPT findings for one domain (infra.tls_rpt_reports_ingested — DNS & Infra column, §5). */
export function deriveTlsRptFindings(
	domainId: string,
	domain: string,
): Finding[] {
	const config = readAppConfig().reports;
	if (!config.enabled) {
		return [
			ingestionDisabledFinding("infra.tls_rpt_reports_ingested", TLS_CHECK_ID),
		];
	}
	const reports = listTlsRptReports(domainId);
	if (reports.length === 0) {
		return [
			{
				id: "infra.tls_rpt_reports_ingested",
				checkId: TLS_CHECK_ID,
				title: "No TLS reports ingested yet",
				severity: "info",
				detail:
					"No RFC 8460 TLS-RPT reports have been ingested; failure volume and trend (starttls-not-supported, certificate-host-mismatch, validation-failure) are unknown until reports arrive.",
				remediation: `Publish rua=mailto:tls-reports@${domain} on _smtp._tls.${domain} and point the report mailbox or drop folder here (Settings → Admin), then Ingest now on the Reports page.`,
				source: "report",
			},
		];
	}

	const agg = aggregateTlsRpt(reports, config.windowDays);
	if (agg.reportCount === 0) {
		const age = ageInDays(agg.newestReportEnd);
		return [
			{
				id: "infra.tls_rpt_reports_ingested",
				checkId: TLS_CHECK_ID,
				title: `No TLS report data in the last ${config.windowDays} day(s)`,
				severity: "info",
				detail: `No TLS-RPT report covering the last ${config.windowDays} day(s) has been ingested for ${domain}, so inbound TLS health is currently unknown. ${reports.length} older report(s) remain in the store${age === null ? "" : `, the newest ${age} day(s) old`} — history only, deliberately not scored as a present-day problem.`,
				remediation: `Confirm receivers are still sending to the rua= address on _smtp._tls.${domain} and that the report mailbox/drop folder is wired up (Settings → Admin).`,
				source: "report",
			},
		];
	}

	const findings: Finding[] = [];

	if (agg.totalFailure > 0) {
		const types = [
			...new Set(
				agg.rows.flatMap((r) => r.failureDetails.map((d) => d.resultType)),
			),
		];
		const fixes: Record<string, string> = {
			"starttls-not-supported": "ensure every MX offers STARTTLS",
			"certificate-host-mismatch":
				"replace the MX certificate so its name matches the MX host",
			"certificate-expired": "renew the expired MX certificate",
			"validation-failure": "install a certificate from a trusted CA on the MX",
			"tlsa-invalid": "repair the TLSA record after the key roll",
			"dnssec-invalid": "fix the DNSSEC chain for the TLSA record",
			"sts-policy-fetch-error": `make https://mta-sts.${domain}/.well-known/mta-sts.txt reachable`,
			"sts-policy-invalid": "correct the MTA-STS policy file syntax",
			"sts-webpki-invalid": "fix the certificate on the mta-sts policy host",
		};
		const layerFixes = types
			.map((t) => fixes[t] ?? `investigate ${t}`)
			.join("; ");
		findings.push({
			id: "infra.tls_rpt_reports_ingested",
			checkId: TLS_CHECK_ID,
			title: `Inbound TLS failures reported (${agg.totalFailure} session(s))`,
			severity: "warning",
			detail: `${agg.reporters.join(", ")}: ${agg.totalSuccess} ok / ${agg.totalFailure} failed TLS sessions over ${fmtWindow(agg.window)} (${types.join(", ") || "no failure-details given"}). Senders enforcing MTA-STS/DANE bounce or downgrade mail on these failures.`,
			remediation: `Fix the reported layer: ${layerFixes || `check the MX certificates and MTA-STS/TLSA records for ${domain}`}.`,
			evidence: types.join(", "),
			source: "report",
		});
	} else {
		findings.push({
			id: "infra.tls_rpt_reports_ingested",
			checkId: TLS_CHECK_ID,
			title: "Inbound TLS healthy",
			severity: "info",
			detail: `${agg.reporters.join(", ")}: ${agg.totalSuccess} ok / 0 failed TLS sessions over ${fmtWindow(agg.window)} (policy: ${agg.policyTypes.join(", ") || "n/a"}). Healthy baseline recorded so a later regression is detectable.`,
			source: "report",
		});
	}

	// no-policy-found where a policy is expected (§3.2 row 3) — another reporter saw sts/tlsa.
	const sawPolicy = agg.rows.some(
		(r) => r.policyType === "sts" || r.policyType === "tlsa",
	);
	const noPolicy = agg.rows.filter((r) => r.policyType === "no-policy-found");
	if (sawPolicy && noPolicy.length > 0) {
		findings.push({
			id: "infra.tls_rpt_no_policy_found",
			checkId: TLS_CHECK_ID,
			title: "A reporter saw no TLS policy",
			severity: "warning",
			detail: `${noPolicy.map((r) => r.reporterOrg).join(", ")} reported policy-type no-policy-found while other reporters saw your MTA-STS/DANE policy — the policy is not consistently visible.`,
			remediation: `Verify the _mta-sts.${domain} TXT record and the HTTPS policy file (or the TLSA record) resolve from everywhere.`,
			source: "report",
		});
	}

	return findings;
}
