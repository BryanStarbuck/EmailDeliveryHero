import { existsSync, mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Report-email ingestion against the REAL act3ai.com corpus (pm/emails.mdx §12/§14). The 10 .eml
 * files under <repo>/emails/ are the fixture set the spec is grounded in: 5 google.com + 2
 * protection.outlook.com DMARC aggregates and 3 microsoft.com TLS-RPT reports whose subjects look
 * exactly like the DMARC ones — the classifier must key off media type + payload root, never the
 * subject/filename (§4.2). Skips cleanly when the corpus is absent (e.g. a code-only checkout).
 */

// Isolate the store: state-dir reads EDH_STATE_DIR at call time, so set it before any store call.
process.env.EDH_STATE_DIR = mkdtempSync(join(tmpdir(), "edh-reports-spec-"));

import {
	aggregateDmarc,
	deriveDmarcReportFindings,
	deriveTlsRptFindings,
} from "./derive-findings";
import { parseDmarcAggregateXml } from "./dmarc-xml";
import { classifyPayload, extractReportPayloads } from "./mime";
import type { ParsedDmarcReport, ParsedTlsRptReport } from "./report.types";
import {
	listDmarcReports,
	listTlsRptReports,
	saveDmarcReport,
	saveTlsRptReport,
} from "./report-store";
import { parseTlsRptJson } from "./tlsrpt-json";

const CORPUS_DIR = join(
	__dirname,
	"..",
	"..",
	"..",
	"..",
	"..",
	"..",
	"emails",
);
const DOMAIN_ID = "test-act3ai";

const hasCorpus = existsSync(CORPUS_DIR);
const describeCorpus = hasCorpus ? describe : describe.skip;

function loadCorpus(): {
	dmarc: ParsedDmarcReport[];
	tlsrpt: ParsedTlsRptReport[];
} {
	const dmarc: ParsedDmarcReport[] = [];
	const tlsrpt: ParsedTlsRptReport[] = [];
	for (const file of readdirSync(CORPUS_DIR).filter((f) =>
		f.endsWith(".eml"),
	)) {
		for (const payload of extractReportPayloads(
			readFileSync(join(CORPUS_DIR, file)),
		)) {
			const kind = classifyPayload(payload);
			if (kind === "dmarc") {
				const report = parseDmarcAggregateXml(payload.content.toString("utf8"));
				if (report) dmarc.push(report);
			} else if (kind === "tlsrpt") {
				const report = parseTlsRptJson(payload.content.toString("utf8"));
				if (report) tlsrpt.push(report);
			}
		}
	}
	return { dmarc, tlsrpt };
}

describeCorpus(
	"report ingestion — the act3ai.com corpus (pm/emails.mdx §12)",
	() => {
		const { dmarc, tlsrpt } = loadCorpus();

		it("classifies 71 DMARC aggregates and 3 TLS-RPT reports by payload, not subject (§14.2)", () => {
			expect(dmarc).toHaveLength(71);
			expect(tlsrpt).toHaveLength(3);
			// The three TLS-RPT reports are the microsoft.com ones with DMARC-looking subjects.
			expect(
				tlsrpt.every((r) => r.reporterOrg === "Microsoft Corporation"),
			).toBe(true);
			// Seven reporting organizations (pm/Email_Complaints.mdx §2.1). org_name is free text
			// with inconsistent casing and is not a domain — that is why it is compared verbatim.
			const reporters = new Set(dmarc.map((r) => r.reporterOrg));
			expect(reporters).toEqual(
				new Set([
					"google.com",
					"Outlook.com",
					"Yahoo",
					"Mimecast",
					"au.com",
					"emailsrvr.com",
					"zoho.com",
				]),
			);
		});

		it("parses the DMARC XML per <record>: identities, alignment, dmarcPass (§14.3)", () => {
			for (const report of dmarc) {
				expect(report.policyPublished.domain).toBe("act3ai.com");
				expect(report.policyPublished.p).toBe("reject");
				// adkim/aspf legitimately differ BETWEEN reporters covering overlapping windows —
				// that disagreement is complaint C11 (pm/Email_Complaints.mdx §4.2), not a parse bug.
				expect(["r", "s"]).toContain(report.policyPublished.adkim);
				expect(["r", "s"]).toContain(report.policyPublished.aspf);
				for (const row of report.rows) {
					expect(row.sourceIp).toBeTruthy();
					expect(row.count).toBeGreaterThan(0);
					expect(row.dmarcPass).toBe(row.spfAligned || row.dkimAligned);
				}
			}
		});

		it("parses the TLS-RPT JSON per policy: counts + failure-details (§14.4)", () => {
			for (const report of tlsrpt) {
				expect(report.policies).toHaveLength(1);
				expect(report.policies[0].policyType).toBe("sts");
				expect(report.policies[0].policyDomain).toBe("act3ai.com");
				expect(report.policies[0].failureCount).toBe(0);
			}
			const totalOk = tlsrpt.reduce(
				(n, r) => n + r.policies[0].successCount,
				0,
			);
			expect(totalOk).toBe(7);
		});

		it("aggregates the corpus into a dual-aligned pass rate", () => {
			const agg = aggregateDmarc(dmarc, 365);
			expect(agg.totalMessages).toBe(10177);
			// 7,426 of 10,177 are dual-aligned; the 25.8% gap is complaint C02 — mail signed with
			// Google's default gappssmtp key, which can never align (pm/Email_Complaints.mdx §6).
			expect(agg.alignedPassMessages).toBe(7426);
			expect(agg.passRatePct).toBeGreaterThan(70);
			expect(agg.passRatePct).toBeLessThan(75);
			// The SendGrid stream: DKIM-only rows on the em2598 subdomain envelope.
			const sendgrid = agg.rows.filter(
				(r) =>
					r.envelopeSpfDomain === "em2598.act3ai.com" &&
					r.dkimAligned &&
					!r.spfAligned,
			);
			expect(sendgrid.length).toBeGreaterThan(0);
		});

		it("is idempotent: re-storing the same reports is a no-op (§14.9)", () => {
			let stored = 0;
			for (const r of dmarc) if (saveDmarcReport(DOMAIN_ID, r)) stored++;
			for (const r of tlsrpt) if (saveTlsRptReport(DOMAIN_ID, r)) stored++;
			// The corpus itself contains a few re-downloaded copies of the same report ("… 2.eml"),
			// so `stored` is the DISTINCT count — which is exactly what dedupe is for.
			for (const r of dmarc) if (saveDmarcReport(DOMAIN_ID, r)) stored++;
			for (const r of tlsrpt) if (saveTlsRptReport(DOMAIN_ID, r)) stored++;
			const distinct =
				listDmarcReports(DOMAIN_ID).length + listTlsRptReports(DOMAIN_ID).length;
			expect(stored).toBe(distinct);
			// A second full pass must store nothing at all.
			let duplicates = 0;
			for (const r of dmarc) if (!saveDmarcReport(DOMAIN_ID, r)) duplicates++;
			for (const r of tlsrpt) if (!saveTlsRptReport(DOMAIN_ID, r)) duplicates++;
			expect(duplicates).toBe(dmarc.length + tlsrpt.length);
			expect(
				listDmarcReports(DOMAIN_ID).length + listTlsRptReports(DOMAIN_ID).length,
			).toBe(distinct);
			expect(listTlsRptReports(DOMAIN_ID)).toHaveLength(3);
		});

		it("derives §12's findings: fragility warning, no spoofing, healthy TLS baseline (§14.5-7,12)", () => {
			const findings = deriveDmarcReportFindings(DOMAIN_ID, "act3ai.com");

			const passRate = findings.find((f) => f.id === "dmarc.real_pass_rate");
			expect(passRate?.severity).toBe("warning");
			expect(passRate?.source).toBe("report");

			// Fragile streams: own mail passing DMARC on ONE mechanism only, including the SendGrid
			// em2598 envelope. The gmail.com / whitehatengineering.com rows are benign
			// DKIM-authenticated forwards and must NOT be flagged (§12).
			const fragilities = findings.filter((f) =>
				f.id.startsWith("dmarc.report_alignment_fragility."),
			);
			expect(fragilities.length).toBeGreaterThan(0);
			expect(fragilities.every((f) => f.severity === "warning")).toBe(true);
			// Every flagged stream is one of OURS — a forwarded third-party envelope must never
			// appear here (§12).
			expect(
				fragilities.every(
					(f) =>
						!f.detail.includes("gmail.com") &&
						!f.detail.includes("whitehatengineering.com"),
				),
			).toBe(true);

			// The four KDDI-reported spoofing rows fail both alignments and were rejected — they
			// surface as per-source unaligned findings (complaint C01 on the complaints board).
			const unalignedSources = findings.filter((f) =>
				f.id.startsWith("dmarc.report_unaligned_source."),
			);
			expect(unalignedSources.length).toBeGreaterThan(0);

			// Four messages WERE rejected by receivers, so this is no longer the "nothing enforced"
			// info finding.
			expect(
				findings.some((f) => f.id.startsWith("dmarc.report_enforcement.")),
			).toBe(true);

			// TLS-RPT: healthy baseline, info only — never turns the cell amber (§14.8).
			const tls = deriveTlsRptFindings(DOMAIN_ID, "act3ai.com");
			const ingested = tls.find(
				(f) => f.id === "infra.tls_rpt_reports_ingested",
			);
			expect(ingested?.severity).toBe("info");
			expect(ingested?.detail).toContain("7 ok / 0 failed");
		});
	},
);

describe("report ingestion — empty store", () => {
	it("emits the muted 'not ingested yet' info when a domain has no reports", () => {
		const findings = deriveDmarcReportFindings("no-such-domain", "example.com");
		expect(findings).toHaveLength(1);
		expect(findings[0].id).toBe("dmarc.real_pass_rate");
		expect(findings[0].severity).toBe("info");
		const tls = deriveTlsRptFindings("no-such-domain", "example.com");
		expect(tls).toHaveLength(1);
		expect(tls[0].id).toBe("infra.tls_rpt_reports_ingested");
		expect(tls[0].severity).toBe("info");
	});
});
