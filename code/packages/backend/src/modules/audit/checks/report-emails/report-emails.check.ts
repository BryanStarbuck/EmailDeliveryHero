import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import {
	ageInDays,
	aggregateDmarc,
	aggregateTlsRpt,
	authenticatedSourceIps,
	type DmarcAggregate,
	dmarcVolumeBreakdown,
	fragileStreams,
	ingestionDisabledFinding,
	isOwnUnalignedSender,
	type TlsRptAggregate,
	wasForwardedByReceiver,
} from "@module/reports/derive-findings";
import { parseDmarcAggregateXml } from "@module/reports/dmarc-xml";
import { classifyPayload, extractReportPayloads } from "@module/reports/mime";
import type { ParsedTlsRptReport } from "@module/reports/report.types";
import {
	listDmarcReports,
	listTlsRptReports,
	saveDmarcReport,
	saveTlsRptReport,
} from "@module/reports/report-store";
import { parseTlsRptJson } from "@module/reports/tlsrpt-json";
import { readAppConfig } from "@shared/config-store";
import { logInfo } from "@shared/logging";
import { stateSubdir } from "@shared/state-dir";
import type { CheckContext, Checker, CheckOutcome, Finding } from "../types";

/**
 * The run-time Spam & Content `report_emails` test (pm/emails.mdx §13 — family #7 of the Spam &
 * Content category, pm/checks/spam_content.mdx §1/§4). Every audit run:
 *
 *   1. scans the analysis directory (`reports.analyzeDir`, §8; empty ⇒ the repo `emails/` corpus
 *      in development, else the §4.1 drop folder) IN PLACE — files are never moved or renamed,
 *   2. decodes exactly like §2 (MIME walk, base64, magic-byte decompression, §4.2 classification
 *      by media type + payload root — never filename/subject),
 *   3. attributes each report to a monitored domain by the report's OWN payload domain
 *      (`<policy_published><domain>` / TLS-RPT policy-domain): exact name first, else the closest
 *      monitored parent; other monitored domains get the report stored under THEM, unmatched
 *      domains are counted as orphans (§13.1.3),
 *   4. aggregates THIS domain's stored reports over the rolling window and scores them against
 *      the §3 catalog into the eight aggregate `content.report_*` findings (§13.2).
 *
 * The §4.5 dedupe keys make every re-scan idempotent (already-stored reports count as duplicates,
 * never as new data). In the run graph this scan runs BEFORE `dmarc.reports` and the TLS-RPT
 * derivation (run-graph.ts), so the per-category §5 findings read a store this run just
 * refreshed — scan once, analyze everywhere. The structured payload lands at
 * `results["content.report_emails"]` → the run file's `spam_content.report_emails` snapshot
 * (§13.3). Aggregate rows only: the per-source-IP enumeration stays under `dmarc.report_*` /
 * `infra.*` (§5) — one problem, one severity per surface.
 */

const CHECK_ID = "content.report_emails";

/** File extensions the analysis directory scan accepts (pm/emails.mdx §13.1). */
const SCAN_EXTENSIONS = /\.(eml|xml|json|gz|zip)$/i;

interface ScanTally {
	dir: string;
	scannedFiles: number;
	parsedReports: number;
	duplicates: number;
	skipped: number;
	decodeErrors: string[];
	/** Reports attributed to the audited domain. */
	thisDomain: number;
	/** Reports routed to OTHER monitored domains, counted per domain name. */
	otherDomains: Record<string, number>;
	/** Report domains no monitored domain matches, with counts (§13.1.3 orphans). */
	orphans: Record<string, number>;
}

/**
 * The §13.1.3 routing rule: exact monitored-domain name first, else the closest monitored parent
 * (a report for `em2598.act3ai.com` rolls up to `act3ai.com`). Null = orphan.
 */
function matchDomain(
	reportDomain: string,
	monitored: { id: string; name: string }[],
): { id: string; name: string } | null {
	const wanted = reportDomain.replace(/\.$/, "").toLowerCase();
	if (!wanted) return null;
	const exact = monitored.find((d) => d.name.toLowerCase() === wanted);
	if (exact) return exact;
	const parents = monitored.filter((d) =>
		wanted.endsWith(`.${d.name.toLowerCase()}`),
	);
	parents.sort((a, b) => b.name.length - a.name.length);
	return parents[0] ?? null;
}

/**
 * The effective analysis directory (pm/emails.mdx §8/§13.1): the configured `reports.analyzeDir`;
 * "" ⇒ the repo `emails/` corpus when present (development — how the §12 worked example runs),
 * else the §4.1 drop folder (its configured path, or the default `<state>/reports/inbox`).
 */
export function resolveAnalyzeDir(): string {
	const config = readAppConfig().reports;
	const configured = config.analyzeDir.trim();
	if (configured.length > 0) return configured;
	// Dev auto-detect: the repo emails/ corpus, from the source tree (src|dist/modules/audit/checks/
	// report-emails → repo root) or the backend package cwd.
	const candidates = [
		join(__dirname, "..", "..", "..", "..", "..", "..", "..", "..", "emails"),
		join(process.cwd(), "..", "..", "..", "emails"),
		join(process.cwd(), "emails"),
	];
	for (const dir of candidates) {
		try {
			if (existsSync(dir) && statSync(dir).isDirectory()) return dir;
		} catch {
			// Unreadable candidate — keep looking.
		}
	}
	const dropFolder = config.dropFolder.trim();
	return dropFolder.length > 0 ? dropFolder : stateSubdir("reports", "inbox");
}

/**
 * Scan the analysis directory IN PLACE (§13.1 step 1–3): decode every candidate file, attribute
 * each parsed report to a monitored domain by its payload domain, and store it (deduped) under
 * that domain. Read-only on the corpus — nothing is ever moved, renamed, or deleted.
 */
function scanCorpus(
	dir: string,
	auditedDomainId: string,
	monitored: { id: string; name: string }[],
): ScanTally {
	const tally: ScanTally = {
		dir,
		scannedFiles: 0,
		parsedReports: 0,
		duplicates: 0,
		skipped: 0,
		decodeErrors: [],
		thisDomain: 0,
		otherDomains: {},
		orphans: {},
	};
	let files: string[] = [];
	try {
		files = readdirSync(dir)
			.filter((f) => SCAN_EXTENSIONS.test(f))
			.filter((f) => {
				try {
					return statSync(join(dir, f)).isFile();
				} catch {
					return false;
				}
			})
			.sort();
	} catch {
		return tally; // Directory absent/unreadable ⇒ the empty-corpus info row (§13.2), never a throw.
	}

	for (const file of files) {
		tally.scannedFiles++;
		let payloads: ReturnType<typeof extractReportPayloads>;
		try {
			payloads = extractReportPayloads(readFileSync(join(dir, file)));
		} catch (err) {
			tally.decodeErrors.push(
				`${file}: ${err instanceof Error ? err.message : String(err)}`,
			);
			continue;
		}
		if (payloads.length === 0) {
			tally.skipped++; // Not a report email — counted, never an error (§13.1 step 2).
			continue;
		}
		for (const payload of payloads) {
			const kind = classifyPayload(payload);
			if (kind === "dmarc") {
				const report = parseDmarcAggregateXml(payload.content.toString("utf8"));
				if (!report) {
					tally.decodeErrors.push(`${file}: DMARC aggregate XML did not parse`);
					continue;
				}
				tally.parsedReports++;
				const match = matchDomain(report.policyPublished.domain, monitored);
				if (!match) {
					const d = report.policyPublished.domain;
					tally.orphans[d] = (tally.orphans[d] ?? 0) + 1;
				} else {
					if (!saveDmarcReport(match.id, report)) tally.duplicates++;
					if (match.id === auditedDomainId) tally.thisDomain++;
					else
						tally.otherDomains[match.name] =
							(tally.otherDomains[match.name] ?? 0) + 1;
				}
			} else if (kind === "tlsrpt") {
				const report = parseTlsRptJson(payload.content.toString("utf8"));
				if (!report) {
					tally.decodeErrors.push(`${file}: TLS-RPT JSON did not parse`);
					continue;
				}
				tally.parsedReports++;
				routeTlsRpt(report, auditedDomainId, monitored, tally);
			} else {
				tally.skipped++;
			}
		}
	}
	return tally;
}

/** A TLS-RPT report routes per policy-domain — one stored copy per matching monitored domain. */
function routeTlsRpt(
	report: ParsedTlsRptReport,
	auditedDomainId: string,
	monitored: { id: string; name: string }[],
	tally: ScanTally,
): void {
	const byDomain = new Map<string, ParsedTlsRptReport>();
	const seenDomains = new Set<string>();
	for (const policy of report.policies) {
		const match = matchDomain(policy.policyDomain, monitored);
		if (!match) {
			if (!seenDomains.has(policy.policyDomain)) {
				seenDomains.add(policy.policyDomain);
				tally.orphans[policy.policyDomain] =
					(tally.orphans[policy.policyDomain] ?? 0) + 1;
			}
			continue;
		}
		const existing = byDomain.get(match.id);
		if (existing) existing.policies.push(policy);
		else byDomain.set(match.id, { ...report, policies: [policy] });
	}
	for (const [domainId, routed] of byDomain) {
		const storedNew = saveTlsRptReport(domainId, routed);
		if (!storedNew) tally.duplicates++;
		if (domainId === auditedDomainId) tally.thisDomain++;
		else {
			const name = monitored.find((d) => d.id === domainId)?.name ?? domainId;
			tally.otherDomains[name] = (tally.otherDomains[name] ?? 0) + 1;
		}
	}
}

function fmtWindow(w: { begin: string; end: string }): string {
	return `${w.begin.slice(0, 10)}→${w.end.slice(0, 10)}`;
}

/** The §13.3 run-YAML snapshot — lands as `spam_content.report_emails` in the run file. */
function buildSnapshot(
	tally: ScanTally,
	dmarc: DmarcAggregate,
	tlsrpt: TlsRptAggregate,
): Record<string, unknown> {
	const breakdown = dmarcVolumeBreakdown(dmarc);
	const pp = dmarc.policyPublished;
	const policy = pp
		? [
				`p=${pp.p}`,
				pp.sp ? `sp=${pp.sp}` : null,
				`adkim=${pp.adkim}`,
				`aspf=${pp.aspf}`,
				pp.pct ? `pct=${pp.pct}` : null,
				pp.np ? `np=${pp.np}` : null,
			]
				.filter(Boolean)
				.join("; ")
		: null;
	// The analysis window: the DMARC aggregation window when DMARC reports exist, else TLS-RPT's.
	const window = dmarc.reportCount > 0 ? dmarc.window : tlsrpt.window;
	return {
		dir: tally.dir,
		scanned_files: tally.scannedFiles,
		parsed_reports: tally.parsedReports,
		duplicates: tally.duplicates,
		skipped: tally.skipped,
		decode_errors: tally.decodeErrors,
		attribution: {
			this_domain: tally.thisDomain,
			other_domains: tally.otherDomains,
			orphans: Object.entries(tally.orphans).map(([domain, count]) => ({
				domain,
				count,
			})),
		},
		window: { begin: window.begin.slice(0, 10), end: window.end.slice(0, 10) },
		dmarc: {
			reports: dmarc.reportCount,
			stale_reports_excluded: dmarc.staleReportCount,
			newest_report_end: dmarc.newestReportEnd,
			reporters: dmarc.reporters,
			messages: dmarc.totalMessages,
			dual_aligned: dmarc.alignedPassMessages,
			pass_rate_pct: dmarc.passRatePct,
			dmarc_pass_rate_pct: dmarc.dmarcPassRatePct,
			dkim_only: breakdown.dkimOnly,
			spf_only: breakdown.spfOnly,
			both_fail: breakdown.bothFail,
			quarantined: breakdown.quarantined,
			rejected: breakdown.rejected,
			policy,
		},
		tlsrpt: {
			reports: tlsrpt.reportCount,
			stale_reports_excluded: tlsrpt.staleReportCount,
			newest_report_end: tlsrpt.newestReportEnd,
			reporters: tlsrpt.reporters,
			sessions_ok: tlsrpt.totalSuccess,
			sessions_failed: tlsrpt.totalFailure,
			policy_types: tlsrpt.policyTypes,
		},
	};
}

/** The eight aggregate `content.report_*` findings (§13.2) — all `source: "report"`. */
function deriveCorpusFindings(
	ctx: CheckContext,
	tally: ScanTally,
	dmarc: DmarcAggregate,
	tlsrpt: TlsRptAggregate,
	windowDays: number,
	hasStoredDmarc: boolean,
	hasStoredTls: boolean,
	knownIps: Set<string>,
): Finding[] {
	const domain = ctx.domain;
	const findings: Finding[] = [];
	// Stored vs CURRENT: the aggregates are windowed on the clock, so a store full of month-old
	// reports has data but nothing to score. Only in-window volume may raise a flag.
	const hasCurrentDmarc = dmarc.reportCount > 0;
	const hasCurrentTls = tlsrpt.reportCount > 0;

	// content.report_corpus — the "did the test actually look at my emails" row.
	if (tally.decodeErrors.length > 0) {
		findings.push({
			id: "content.report_corpus",
			checkId: CHECK_ID,
			title: `${tally.decodeErrors.length} report file(s) failed to decode`,
			severity: "warning",
			detail: `${tally.scannedFiles} file(s) scanned in ${tally.dir}: ${tally.parsedReports} report(s) parsed (${tally.duplicates} duplicate(s)), ${tally.skipped} skipped, but ${tally.decodeErrors.length} failed to decode/parse: ${tally.decodeErrors.slice(0, 5).join("; ")}${tally.decodeErrors.length > 5 ? "; …" : ""}.`,
			remediation:
				"Inspect the named file(s) — a truncated download or a non-report attachment; remove or re-fetch them and re-run.",
			source: "report",
		});
	} else if (tally.scannedFiles === 0) {
		findings.push({
			id: "content.report_corpus",
			checkId: CHECK_ID,
			title: "No report emails found",
			severity: "info",
			detail: `No report emails found at ${tally.dir}. Publish rua= on the DMARC/TLS-RPT records so receivers send reports, and point the analysis directory or drop folder there (Settings → Admin).`,
			source: "report",
		});
	} else {
		findings.push({
			id: "content.report_corpus",
			checkId: CHECK_ID,
			title: `Scanned ${tally.scannedFiles} file(s), parsed ${tally.parsedReports} report(s)`,
			severity: "info",
			detail: `${tally.scannedFiles} file(s) scanned in place at ${tally.dir}: ${tally.parsedReports} report(s) parsed (${tally.duplicates} duplicate(s)), ${tally.skipped} skipped.`,
			source: "report",
		});
	}

	// content.report_domain_attribution — every report on the right domain (§13.1.3).
	if (tally.parsedReports > 0) {
		const orphanEntries = Object.entries(tally.orphans);
		const othersText = Object.entries(tally.otherDomains)
			.map(([name, count]) => `${name} (${count})`)
			.join(", ");
		if (orphanEntries.length > 0) {
			findings.push({
				id: "content.report_domain_attribution",
				checkId: CHECK_ID,
				title: `${orphanEntries.reduce((n, [, c]) => n + c, 0)} orphan report(s) for unmonitored domain(s)`,
				severity: "warning",
				detail: `${tally.thisDomain} report(s) for ${domain}${othersText ? `, others routed to: ${othersText}` : ""}; orphans: ${orphanEntries.map(([d, c]) => `${d} (${c})`).join(", ")} — the mailbox is receiving reports for a domain nobody monitors.`,
				remediation:
					"Add the orphan domain(s) as monitored domains, or fix the rua= address on their DMARC/TLS-RPT records.",
				source: "report",
			});
		} else {
			findings.push({
				id: "content.report_domain_attribution",
				checkId: CHECK_ID,
				title: "Every report attributed to a monitored domain",
				severity: "info",
				detail: `${tally.thisDomain} report(s) for ${domain}${othersText ? `, others routed to: ${othersText}` : ""}; 0 orphans.`,
				source: "report",
			});
		}
	}

	// content.report_pass_rate — mirrors dmarc.real_pass_rate (§5), aggregate row only.
	if (!hasStoredDmarc) {
		findings.push({
			id: "content.report_pass_rate",
			checkId: CHECK_ID,
			title: "No DMARC aggregate reports for this domain",
			severity: "info",
			detail: `The corpus holds no DMARC aggregate report whose policy domain resolves to ${domain}; the field pass rate is unknown.`,
			source: "report",
		});
	} else if (!hasCurrentDmarc) {
		const age = ageInDays(dmarc.newestReportEnd);
		findings.push({
			id: "content.report_pass_rate",
			checkId: CHECK_ID,
			title: `No DMARC report data in the last ${windowDays} day(s)`,
			severity: "info",
			detail: `${dmarc.staleReportCount} stored DMARC report(s) for ${domain} all fall outside the ${windowDays}-day window${age === null ? "" : ` (newest is ${age} day(s) old)`}, so there is no current field data to score. Older reports are kept as history and never re-flagged as a present-day problem — see content.report_freshness for the live issue.`,
			remediation: `Confirm receivers are still sending to the rua= address on _dmarc.${domain} and that the report mailbox/drop folder is wired up (Settings → Admin).`,
			source: "report",
		});
	} else {
		const failVolume = dmarc.totalMessages - dmarc.dmarcPassMessages;
		const fragileVolume = dmarc.totalMessages - dmarc.alignedPassMessages;
		const failSources = new Set(
			dmarc.rows.filter((r) => !r.dmarcPass).map((r) => r.sourceIp),
		).size;
		findings.push({
			id: "content.report_pass_rate",
			checkId: CHECK_ID,
			title: `${dmarc.dmarcPassRatePct}% of mail passes DMARC`,
			severity:
				failVolume > 0 && dmarc.dmarcPassRatePct < 99.5 ? "warning" : "info",
			detail: `${dmarc.dmarcPassRatePct}% of ${dmarc.totalMessages} msgs pass DMARC over ${fmtWindow(dmarc.window)} (${failVolume} msgs from ${failSources} source(s) fail outright). ${dmarc.passRatePct}% is dual-aligned; the other ${fragileVolume} msg(s) pass on a single mechanism — resilience, tracked by content.report_fragility, not lost mail.`,
			remediation:
				failVolume > 0
					? "Authorize/align the failing streams (SPF include: / DKIM selector / alignment) before tightening policy."
					: undefined,
			source: "report",
		});

		// content.report_spoofing — the corpus-wide spoofing verdict (aggregate; per-IP rows stay §5).
		const bothFail = dmarc.rows.filter(
			(r) => !r.spfAligned && !r.dkimAligned && r.count > 0,
		);
		if (bothFail.length === 0) {
			findings.push({
				id: "content.report_spoofing",
				checkId: CHECK_ID,
				title: "No spoofing visible in the reports",
				severity: "ok",
				detail: `0 of ${dmarc.totalMessages} msgs fail both SPF and DKIM alignment — every source traces to an authenticated stream.`,
				source: "report",
			});
		} else {
			// Ownership comes from independent evidence only (isOwnUnalignedSender) — a both-fail row's
			// envelope and d= are unverified claims a spoofer forges for free. Rows the RECEIVER
			// declared as relayed are forwarded mail, unaligned by design, and are neither.
			const own = bothFail.filter((r) => isOwnUnalignedSender(r, knownIps));
			const relayed = bothFail.filter(
				(r) => !isOwnUnalignedSender(r, knownIps) && wasForwardedByReceiver(r),
			);
			const spoofed = bothFail.filter(
				(r) => !isOwnUnalignedSender(r, knownIps) && !wasForwardedByReceiver(r),
			);
			const unblocked = spoofed.filter(
				(r) => r.disposition !== "reject" && r.disposition !== "quarantine",
			);
			const ownVolume = own.reduce((n, r) => n + r.count, 0);
			const relayedVolume = relayed.reduce((n, r) => n + r.count, 0);
			const spoofVolume = spoofed.reduce((n, r) => n + r.count, 0);
			const unblockedVolume = unblocked.reduce((n, r) => n + r.count, 0);
			// Spoofing the policy already stops is the policy working. Only own breakage (amber) or
			// forged mail receivers still DELIVERED (red) is a fault.
			const severity =
				unblockedVolume > 0 ? "critical" : ownVolume > 0 ? "warning" : "info";
			findings.push({
				id: "content.report_spoofing",
				checkId: CHECK_ID,
				title:
					unblockedVolume > 0
						? `${unblocked.length} spoofing source(s) not being blocked`
						: ownVolume > 0
							? `Own stream(s) failing all authentication (${ownVolume} msgs)`
							: spoofVolume > 0
								? `${spoofed.length} spoofing source(s) blocked by policy`
								: `${relayedVolume} forwarded msg(s) unaligned, no spoofing`,
				severity,
				detail: [
					ownVolume > 0
						? `${ownVolume} msg(s) from ${own.length} source(s) that have authenticated for ${domain} before now fail BOTH SPF and DKIM alignment — a real sender that has broken.`
						: null,
					spoofVolume > 0
						? `${spoofVolume} msg(s) from ${spoofed.length} source(s) fail both mechanisms and have never authenticated for ${domain} — forged mail, of which ${spoofVolume - unblockedVolume} msg(s) were quarantined/rejected by receivers${unblockedVolume > 0 ? ` and ${unblockedVolume} msg(s) were still DELIVERED` : " exactly as the policy intends"}.`
						: null,
					relayedVolume > 0
						? `A further ${relayedVolume} msg(s) from ${relayed.length} source(s) arrived unaligned but the receivers themselves declared them relayed (ARC/forwarding override) — forwarding breaks alignment by design and is not spoofing.`
						: null,
					"Per-IP detail: the DMARC category's unaligned-source rows.",
				]
					.filter(Boolean)
					.join(" "),
				remediation:
					unblockedVolume > 0
						? `Forged mail is still landing — publish p=reject on _dmarc.${domain} so receivers drop it. Do NOT add these IPs to SPF.`
						: ownVolume > 0
							? `Authorize the failing own sender(s): SPF include: and a DKIM selector under ${domain}. Leave the spoofing sources alone — adding them to SPF would authorize the forgery.`
							: undefined,
				source: "report",
			});
		}

		// content.report_fragility — own streams passing on ONE mechanism only (the §12 SendGrid case).
		const fragile = fragileStreams(dmarc, domain);
		if (fragile.size === 0) {
			findings.push({
				id: "content.report_fragility",
				checkId: CHECK_ID,
				title: "All passing streams are dual-aligned",
				severity: "ok",
				detail:
					"Every own stream that passes DMARC aligns on both SPF and DKIM.",
				source: "report",
			});
		} else {
			const aspf = dmarc.policyPublished?.aspf ?? "r";
			const streams = [...fragile.entries()].map(([key, s]) => {
				const envelope = key.split("|")[0];
				return `${envelope} (${s.count} msgs, ${s.dkimOnly ? "DKIM" : "SPF"}-only)`;
			});
			const anyDkimOnly = [...fragile.values()].some((s) => s.dkimOnly);
			findings.push({
				id: "content.report_fragility",
				checkId: CHECK_ID,
				title: `${fragile.size} stream(s) pass DMARC on one mechanism only`,
				severity: "warning",
				detail: `${streams.join("; ")} — a single ${anyDkimOnly ? `DKIM key rotation/breakage (SPF alignment fails under aspf=${aspf})` : "Return-Path change or forward"} fails the whole stream.`,
				remediation: anyDkimOnly
					? `Set aspf=r on _dmarc.${domain}, or brand the Return-Path (bounces.${domain} CNAME at the ESP) so the envelope aligns too.`
					: `Enable DKIM signing with a selector under ${domain} at the sender, and/or set adkim=r.`,
				source: "report",
			});
		}

		// content.report_enforcement — OUR mail actively quarantined/rejected right now. Forged mail
		// being dropped is the policy working and must never turn this row red.
		const breakdown = dmarcVolumeBreakdown(dmarc);
		const enforcedVolume = breakdown.quarantined + breakdown.rejected;
		if (enforcedVolume > 0) {
			const enforcedRows = dmarc.rows.filter(
				(r) => r.disposition === "quarantine" || r.disposition === "reject",
			);
			const ownRows = enforcedRows.filter(
				(r) =>
					r.dmarcPass ||
					isOwnUnalignedSender(r, knownIps) ||
					wasForwardedByReceiver(r),
			);
			const ownVolume = ownRows.reduce((n, r) => n + r.count, 0);
			const forgedVolume = enforcedVolume - ownVolume;
			findings.push({
				id: "content.report_enforcement",
				checkId: CHECK_ID,
				title:
					ownVolume > 0
						? `${ownVolume} of our msg(s) quarantined/rejected by receivers`
						: `${forgedVolume} forged msg(s) blocked by policy`,
				severity: ownVolume > 0 ? "critical" : "info",
				detail:
					ownVolume > 0
						? `Receivers dropped ${ownVolume} msg(s) from ${ownRows.length} source(s) that authenticate for ${domain} — real mail is being lost right now${forgedVolume > 0 ? ` (a further ${forgedVolume} dropped msg(s) were forged and are not ours)` : ""}.`
						: `Receivers reported ${breakdown.quarantined} quarantined and ${breakdown.rejected} rejected msg(s) sent as ${domain}, and every one failed both SPF and DKIM alignment from a source that has never authenticated for the domain — forged mail the policy correctly stopped. None of our own mail was dropped.`,
				remediation:
					ownVolume > 0
						? `Identify and authorize the failing source (SPF include: / DKIM selector under ${domain}) before the next send.`
						: undefined,
				source: "report",
			});
		} else {
			findings.push({
				id: "content.report_enforcement",
				checkId: CHECK_ID,
				title: "No mail quarantined or rejected",
				severity: "info",
				detail: "Every reported row carries disposition=none.",
				source: "report",
			});
		}
	}

	// content.report_tls — the corpus-side echo of infra.tls_rpt_reports_ingested.
	if (!hasStoredTls) {
		findings.push({
			id: "content.report_tls",
			checkId: CHECK_ID,
			title: "No TLS-RPT reports for this domain",
			severity: "info",
			detail: `The corpus holds no TLS-RPT report whose policy domain resolves to ${domain}.`,
			source: "report",
		});
	} else if (!hasCurrentTls) {
		const age = ageInDays(tlsrpt.newestReportEnd);
		findings.push({
			id: "content.report_tls",
			checkId: CHECK_ID,
			title: `No TLS-RPT data in the last ${windowDays} day(s)`,
			severity: "info",
			detail: `${tlsrpt.staleReportCount} stored TLS-RPT report(s) for ${domain} all fall outside the ${windowDays}-day window${age === null ? "" : ` (newest is ${age} day(s) old)`}, so inbound TLS health is currently unknown rather than healthy or failing.`,
			source: "report",
		});
	} else if (tlsrpt.totalFailure > 0) {
		const types = [
			...new Set(
				tlsrpt.rows.flatMap((r) => r.failureDetails.map((d) => d.resultType)),
			),
		];
		findings.push({
			id: "content.report_tls",
			checkId: CHECK_ID,
			title: `${tlsrpt.totalFailure} failed TLS session(s) reported`,
			severity: "warning",
			detail: `${tlsrpt.reporters.join(", ")}: ${tlsrpt.totalSuccess} ok / ${tlsrpt.totalFailure} failed TLS sessions (${types.join(", ") || "no failure-details"}) over ${fmtWindow(tlsrpt.window)}.`,
			remediation:
				"Fix the reported layer: MX certificate (host-mismatch/expired), TLSA record (tlsa-invalid), STARTTLS, or the MTA-STS policy — see the DNS & Infrastructure category's TLS rows.",
			source: "report",
		});
	} else {
		findings.push({
			id: "content.report_tls",
			checkId: CHECK_ID,
			title: "Inbound TLS healthy in the reports",
			severity: "info",
			detail: `${tlsrpt.reporters.join(", ")}: ${tlsrpt.totalSuccess} ok / 0 failed sessions, policy ${tlsrpt.policyTypes.join(", ") || "n/a"}.`,
			source: "report",
		});
	}

	// content.report_freshness — reports stopped arriving? (§13.2 last row). Reads the newest STORED
	// report, never the aggregate window: the window now always ends "now", so it can never age.
	if (hasStoredDmarc || hasStoredTls) {
		const newestEnd = [dmarc.newestReportEnd ?? "", tlsrpt.newestReportEnd ?? ""]
			.filter(Boolean)
			.sort()
			.at(-1);
		const ageDays = ageInDays(newestEnd ?? null);
		// The threshold is the window itself, not 2× it. Once the newest report falls outside the
		// window every scored row goes to "no current data" — so a 2× threshold left a whole window's
		// width where nothing could score AND this row still said "current", the one combination that
		// reads as a clean bill of health for a corpus that has stopped arriving.
		if (ageDays !== null && ageDays > windowDays) {
			findings.push({
				id: "content.report_freshness",
				checkId: CHECK_ID,
				title: `Newest report is ${ageDays} days old`,
				severity: "warning",
				detail: `The corpus's newest report is ${ageDays} days old, outside the ${windowDays}-day window — reports may have stopped arriving, and until they resume there is no current field data to score.`,
				remediation:
					"Check the rua= address on the DMARC/TLS-RPT records and the drop folder/mailbox wiring (Settings → Admin).",
				source: "report",
			});
		} else if (ageDays !== null) {
			findings.push({
				id: "content.report_freshness",
				checkId: CHECK_ID,
				title: "Reports are current",
				severity: "info",
				detail: `The newest report is ${ageDays} day(s) old — within the ${windowDays}-day window's freshness bound.`,
				source: "report",
			});
		}
	}

	return findings;
}

export const reportEmailsCheck: Checker = {
	id: CHECK_ID,
	label: "Report-email analysis",
	async run(ctx): Promise<CheckOutcome> {
		const config = readAppConfig().reports;
		if (!config.enabled) {
			// §8 master switch: off ⇒ a single muted info, zero score contribution.
			return {
				findings: [ingestionDisabledFinding("content.report_corpus", CHECK_ID)],
			};
		}
		const domainId = ctx.domainId ?? "";
		const monitored =
			ctx.monitoredDomains && ctx.monitoredDomains.length > 0
				? ctx.monitoredDomains
				: [{ id: domainId, name: ctx.domain }];
		const dir = resolveAnalyzeDir();
		const tally = scanCorpus(dir, domainId, monitored);
		logInfo(
			`Report corpus scan for ${ctx.domain}: ${tally.scannedFiles} file(s), ${tally.parsedReports} report(s) parsed (${tally.duplicates} duplicate(s)), ${tally.skipped} skipped at ${dir}`,
			"ReportEmailsCheck",
		);
		// Aggregate THIS domain's stored reports over the rolling window (anchored on NOW, so a corpus
		// that stopped arriving reports "no current data" instead of freezing its last verdict — §13.1
		// step 4). Ownership evidence spans the WHOLE store, not just the window: an IP that
		// authenticated for us last month is still our sender when it breaks today.
		const dmarcReports = listDmarcReports(domainId);
		const tlsReports = listTlsRptReports(domainId);
		const dmarc = aggregateDmarc(dmarcReports, config.windowDays);
		const tlsrpt = aggregateTlsRpt(tlsReports, config.windowDays);
		const knownIps = authenticatedSourceIps(dmarcReports);
		for (const ip of ctx.sendingIps) knownIps.add(ip);
		const findings = deriveCorpusFindings(
			ctx,
			tally,
			dmarc,
			tlsrpt,
			config.windowDays,
			dmarcReports.length > 0,
			tlsReports.length > 0,
			knownIps,
		);
		return { findings, results: buildSnapshot(tally, dmarc, tlsrpt) };
	},
};
