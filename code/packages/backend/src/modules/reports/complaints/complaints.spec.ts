import { existsSync, mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * The Email Complaints board against the REAL act3ai.com corpus (pm/Email_Complaints.mdx §6/§15).
 * The .eml files under <repo>/emails/ are the fixture set the whole spec is grounded in — 71 DMARC
 * aggregate reports from 7 providers plus 3 TLS-RPT reports, including the awkward shapes that
 * break naive parsers: a multipart/related nesting from Outlook.com, ISO-2022-JP digest messages
 * carrying KDDI reports, capitalised SPF results, and four forged DKIM selectors.
 *
 * Skips cleanly when the corpus is absent (a code-only checkout).
 */

process.env.EDH_STATE_DIR = mkdtempSync(join(tmpdir(), "edh-complaints-spec-"));

import { classifyPayload, extractReportPayloads } from "../mime";
import { parseDmarcAggregateXml } from "../dmarc-xml";
import type { ParsedDmarcReport, ParsedTlsRptReport } from "../report.types";
import { parseTlsRptJson } from "../tlsrpt-json";
import { buildComplaintBoard } from "./board";
import { classifyRow, isEspDefaultDomain, isKnownSender } from "./classify";
import type { ComplaintCode } from "./complaint.types";

const CORPUS_DIR = join(__dirname, "..", "..", "..", "..", "..", "..", "..", "emails");
const DOMAIN = "act3ai.com";

const hasCorpus = existsSync(CORPUS_DIR);
const describeCorpus = hasCorpus ? describe : describe.skip;

function loadCorpus(): {
	dmarc: ParsedDmarcReport[];
	tlsrpt: ParsedTlsRptReport[];
	files: number;
} {
	const dmarc: ParsedDmarcReport[] = [];
	const tlsrpt: ParsedTlsRptReport[] = [];
	const files = readdirSync(CORPUS_DIR).filter((f) => f.endsWith(".eml"));
	for (const file of files) {
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
	return { dmarc, tlsrpt, files: files.length };
}

function board(windowDays = 365) {
	const { dmarc, tlsrpt } = loadCorpus();
	return buildComplaintBoard({
		domainId: "spec-act3ai",
		domain: DOMAIN,
		dmarcReports: dmarc,
		tlsReports: tlsrpt,
		windowDays,
		ingestionEnabled: true,
		lastIngestAt: null,
	});
}

describe("ESP default DKIM domains (pm/Email_Complaints.mdx §7 C02)", () => {
	it("recognizes the provider domains that can never align", () => {
		expect(isEspDefaultDomain("act3ai-com.20251104.gappssmtp.com")).toBe(true);
		expect(isEspDefaultDomain("contoso.onmicrosoft.com")).toBe(true);
		expect(isEspDefaultDomain("sendgrid.info")).toBe(true);
		expect(isEspDefaultDomain("amazonses.com")).toBe(true);
	});

	it("does not treat the customer's own domain as a provider default", () => {
		expect(isEspDefaultDomain("act3ai.com")).toBe(false);
		expect(isEspDefaultDomain("mail.act3ai.com")).toBe(false);
	});
});

describe("classifyRow (pm/Email_Complaints.mdx §7.2)", () => {
	const base = {
		sourceIp: "203.0.113.1",
		count: 1,
		disposition: "none",
		spfEvaluated: "pass",
		dkimEvaluated: "pass",
		spfAligned: true,
		dkimAligned: true,
		dmarcPass: true,
		headerFrom: DOMAIN,
		envelopeSpfDomain: DOMAIN,
		dkimSigningDomains: [DOMAIN],
	};
	const ctx = { domain: DOMAIN };

	it("C00 — both aligned", () => {
		expect(classifyRow({ ...base }, ctx)).toBe("C00");
	});

	it("C07 — an ARC-rescued forward beats every failure code", () => {
		expect(
			classifyRow(
				{
					...base,
					spfAligned: false,
					dkimAligned: false,
					dmarcPass: false,
					reasons: [{ type: "local_policy", comment: "arc=pass" }],
				},
				ctx,
			),
		).toBe("C07");
	});

	it("C01 — an unknown source that the receiver rejected is spoofing, not a defect", () => {
		expect(
			classifyRow(
				{
					...base,
					disposition: "reject",
					spfAligned: false,
					dkimAligned: false,
					dmarcPass: false,
					envelopeSpfDomain: "",
					dkimSigningDomains: [],
					dkimResults: [
						{ domain: DOMAIN, selector: "forged-1", result: "permerror", humanResult: null },
					],
					spfResults: [{ domain: DOMAIN, scope: "mfrom", result: "fail" }],
				},
				ctx,
			),
		).toBe("C01");
	});

	it("C10 — the SAME shape from a source we recognize is our own mail being blocked", () => {
		expect(
			classifyRow(
				{
					...base,
					disposition: "reject",
					spfAligned: false,
					dkimAligned: false,
					dmarcPass: false,
					envelopeSpfDomain: DOMAIN,
					// A PASSING signature is what makes it ours — a claimed d= alone is not.
					dkimResults: [
						{ domain: DOMAIN, selector: "google", result: "pass", humanResult: null },
					],
				},
				ctx,
			),
		).toBe("C10");
	});

	it("C02 — a provider default key that signed but cannot align", () => {
		expect(
			classifyRow(
				{
					...base,
					dkimAligned: false,
					dkimSigningDomains: ["act3ai-com.20251104.gappssmtp.com"],
					dkimResults: [
						{
							domain: "act3ai-com.20251104.gappssmtp.com",
							selector: "20251104",
							result: "pass",
							humanResult: null,
						},
					],
					spfResults: [{ domain: DOMAIN, scope: null, result: "pass" }],
				},
				ctx,
			),
		).toBe("C02");
	});

	it("C08 — our own signature failed to verify", () => {
		expect(
			classifyRow(
				{
					...base,
					dkimAligned: false,
					dkimResults: [
						{ domain: DOMAIN, selector: "google", result: "fail", humanResult: null },
					],
					spfResults: [{ domain: DOMAIN, scope: "mfrom", result: "pass" }],
				},
				ctx,
			),
		).toBe("C08");
	});

	it("C09 — a foreign identity that soft-failed SPF", () => {
		expect(
			classifyRow(
				{
					...base,
					spfAligned: false,
					spfResults: [{ domain: "gologin.com", scope: null, result: "softfail" }],
					dkimResults: [
						{ domain: DOMAIN, selector: "google", result: "pass", humanResult: null },
					],
				},
				ctx,
			),
		).toBe("C09");
	});

	it("is total — every row lands in exactly one code", () => {
		const weird = classifyRow(
			{
				...base,
				spfAligned: false,
				dkimAligned: true,
				envelopeSpfDomain: "",
				dkimSigningDomains: [],
				dkimResults: [],
				spfResults: [],
			},
			ctx,
		);
		expect(typeof weird).toBe("string");
	});
});

describe("isKnownSender (pm/Email_Complaints.mdx §7.1)", () => {
	const row = {
		sourceIp: "203.0.113.9",
		count: 1,
		disposition: "none",
		spfEvaluated: "fail",
		dkimEvaluated: "fail",
		spfAligned: false,
		dkimAligned: false,
		dmarcPass: false,
		headerFrom: DOMAIN,
		envelopeSpfDomain: "",
		dkimSigningDomains: [],
	};

	it("is false for a bare stranger", () => {
		expect(isKnownSender(row, { domain: DOMAIN })).toBe(false);
	});

	it("is true when a PASSING SPF identity is a subdomain of ours", () => {
		expect(
			isKnownSender(
				{ ...row, spfResults: [{ domain: `em1.${DOMAIN}`, scope: null, result: "pass" }] },
				{ domain: DOMAIN },
			),
		).toBe(true);
	});

	it("is false when the sender merely CLAIMS our domain and the check failed", () => {
		// The spoofing shape: envelope and d= both forged as us, both results negative.
		expect(
			isKnownSender(
				{
					...row,
					envelopeSpfDomain: DOMAIN,
					dkimSigningDomains: [DOMAIN],
					spfResults: [{ domain: DOMAIN, scope: "mfrom", result: "fail" }],
					dkimResults: [
						{ domain: DOMAIN, selector: "forged", result: "permerror", humanResult: null },
					],
				},
				{ domain: DOMAIN },
			),
		).toBe(false);
	});

	it("is true when our own SPF record authorizes the IP (rule 4)", () => {
		expect(
			isKnownSender(row, {
				domain: DOMAIN,
				spfAuthorizedIps: new Set(["203.0.113.9"]),
			}),
		).toBe(true);
	});
});

describeCorpus("the act3ai.com complaint board (pm/Email_Complaints.mdx §6)", () => {
	it("decodes every message in the corpus", () => {
		const { dmarc, tlsrpt, files } = loadCorpus();
		expect(files).toBeGreaterThanOrEqual(70);
		expect(dmarc.length + tlsrpt.length).toBe(files);
		expect(tlsrpt.length).toBe(3);
	});

	it("reconciles: per-code volumes sum to the reported total", () => {
		const b = board();
		const rowLevel: ComplaintCode[] = [
			"C00",
			"C01",
			"C02",
			"C03",
			"C04",
			"C05",
			"C06",
			"C07",
			"C08",
			"C09",
			"C10",
			"C12",
		];
		const sum = b.complaints
			.filter((c) => rowLevel.includes(c.code))
			.reduce((n, c) => n + c.messages, 0);
		expect(sum).toBe(b.totals.messages);
	});

	it("finds the provider-default DKIM key as the largest real problem", () => {
		const b = board();
		const c02 = b.complaints.find((c) => c.code === "C02");
		expect(c02).toBeDefined();
		expect(c02?.verdict).toBe("problem");
		expect(c02?.messages).toBeGreaterThan(2000);
		expect(c02?.explanation).toContain("gappssmtp.com");
	});

	it("files the rejected spoofing under 'working as intended', with no fix", () => {
		const b = board();
		const c01 = b.complaints.find((c) => c.code === "C01");
		expect(c01?.verdict).toBe("ok");
		expect(c01?.fixIds).toHaveLength(0);
		// The forged selectors are the corpus's clearest spoofing signal.
		expect(c01?.sources.some((s) => s.dkimResult === "permerror")).toBe(true);
		expect(b.fixes.every((f) => !f.appliesTo.includes("C01"))).toBe(true);
	});

	it("detects that reporters disagree about the published DMARC record (C11)", () => {
		const b = board();
		expect(b.policyObserved.length).toBeGreaterThan(1);
		expect(b.complaints.some((c) => c.code === "C11")).toBe(true);
	});

	it("ranks the fix plan by the mail each fix repairs", () => {
		const b = board();
		expect(b.fixes.length).toBeGreaterThan(0);
		expect(b.fixes[0].id).toBe("fix.custom_dkim");
		expect(b.fixes[0].records[0].name).toContain(DOMAIN);
		for (let i = 1; i < b.fixes.length; i++)
			expect(b.fixes[i - 1].messagesFixed).toBeGreaterThanOrEqual(
				b.fixes[i].messagesFixed,
			);
	});

	it("names the boring configuration defect, not the dramatic attack, in its headline", () => {
		const b = board();
		// C02 at 25.8% under an enforcing policy escalates to critical (§8.3) → "action" (§8.2).
		expect(b.verdict).toBe("action");
		expect(b.headline).toContain("gappssmtp.com");
		expect(b.headline.toLowerCase()).not.toContain("spoof");
	});

	it("totals reconcile with the raw corpus", () => {
		const b = board();
		expect(b.totals.messages).toBe(10177);
		expect(b.totals.authenticated).toBe(7426);
		expect(b.totals.blocked).toBe(4);
		expect(b.totals.spoof).toBe(4);
	});

	it("records the healthy inbound-TLS baseline (C14)", () => {
		const b = board();
		const c14 = b.complaints.find((c) => c.code === "C14");
		expect(c14?.verdict).toBe("ok");
		expect(c14?.messages).toBe(7);
	});

	it("builds a daily series and a reporter coverage strip", () => {
		const b = board();
		expect(b.series.length).toBeGreaterThan(10);
		expect(b.series.every((p) => /^\d{4}-\d{2}-\d{2}$/.test(p.date))).toBe(true);
		const google = b.reporters.find((r) => r.org === "google.com");
		expect(google?.email).toBe("noreply-dmarc-support@google.com");
		expect(google?.contactUrl).toContain("support.google.com");
	});
});
