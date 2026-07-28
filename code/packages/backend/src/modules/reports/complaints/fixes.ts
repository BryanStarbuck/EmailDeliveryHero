import { TLS_RESULT_FIXES, dkimRecordTemplate } from "./catalog";
import type { Complaint, ComplaintFix } from "./complaint.types";

/**
 * The fix library (pm/Email_Complaints.mdx §11). Each fix is a reusable object rendered identically
 * in Zone C of the Complaints page and in block 4 of the per-complaint drill-down.
 *
 * Zone C is ONLY ever things to do: fixes are emitted for `problem` and `watch` complaints, never
 * for `ok` ones — a rejected spoofing attempt has nothing to fix, and offering a remedy for it is
 * the fastest way to teach a user to ignore the page.
 */

export interface FixBuildContext {
	domain: string;
	/** Complaints present on the board, keyed by code. */
	byCode: Map<string, Complaint>;
	/** Distinct TLS-RPT failure result-types seen this window (drives fix.tls_transport). */
	tlsResultTypes: string[];
	/** Selectors observed with permerror on our own domain (drives fix.publish_selector). */
	brokenSelectors: string[];
	/** Provider domains observed signing with their own default key (drives fix.custom_dkim). */
	espDomains: string[];
}

type Builder = (ctx: FixBuildContext) => Omit<ComplaintFix, "messagesFixed">;

const BUILDERS: Record<string, Builder> = {
	// §11.1 — the highest-value fix in the product: turn the provider's default key off by turning
	// your own key on. Nothing else moves as much mail from "fragile" to "safe".
	"fix.custom_dkim": ({ domain, espDomains }) => ({
		id: "fix.custom_dkim",
		title: "Sign your mail with your own DKIM key",
		appliesTo: ["C02", "C05"],
		steps: [
			espDomains.some((d) => d.endsWith(".gappssmtp.com"))
				? "Google Workspace: Admin console → Apps → Google Workspace → Gmail → Authenticate email. Pick the domain, choose a 2048-bit key, and generate it."
				: "In your sending provider's console, open its domain-authentication / DKIM section and generate a 2048-bit signing key for this domain.",
			"Publish the TXT record the console gives you at the selector it names (the record below shows the shape).",
			"Wait for DNS to propagate. Providers commonly ask for up to 48 hours; in practice it is your TTL.",
			"Return to the provider console and click Start authentication — the new key is NOT used until you do this step.",
			"Confirm in the next DMARC report that the signing domain (d=) is your own domain and the aligned DKIM result is pass.",
		],
		records: [dkimRecordTemplate(domain, "google")],
		verify: [`dig +short google._domainkey.${domain} TXT`],
		recheckCheckId: "dkim",
	}),

	// §11.2 — the selector in the signature has no key in DNS.
	"fix.publish_selector": ({ domain, brokenSelectors }) => ({
		id: "fix.publish_selector",
		title: "Publish the missing DKIM key",
		appliesTo: ["C04"],
		steps: [
			`Read the selector from the evidence table${brokenSelectors.length > 0 ? ` — currently ${brokenSelectors.slice(0, 3).join(", ")}` : ""}.`,
			"Re-export the public key from the platform that signs this stream.",
			"Publish it at <selector>._domainkey." +
				domain +
				" as a TXT record.",
			"Check the classic DNS-provider failure: a long TXT value split into multiple quoted strings that the provider re-joined with whitespace. The joined value must contain no spaces inside p=.",
		],
		records: brokenSelectors
			.slice(0, 3)
			.map((selector) => dkimRecordTemplate(domain, selector)),
		verify: brokenSelectors
			.slice(0, 3)
			.map(
				(selector) =>
					`dig +short ${selector}._domainkey.${domain} TXT | tr -d '" '`,
			),
		recheckCheckId: "dkim",
	}),

	// §11.3 — a sender we actually use is not authorized.
	"fix.authorize_sender": ({ domain }) => ({
		id: "fix.authorize_sender",
		title: "Authorize the senders you actually use",
		appliesTo: ["C03", "C09", "C10"],
		steps: [
			"Identify each source in the evidence table: is it a tool your team uses, or a stranger?",
			`For each one that is yours, add the vendor's include: mechanism to the SPF record on ${domain} — watching the 10-lookup limit.`,
			"Enable DKIM at the vendor using a selector under your own domain, not the vendor's default.",
			"Prefer a branded Return-Path so both SPF and DKIM align, not just one of them.",
			"For sources that are not yours, change nothing here — an enforcing DMARC policy is already the answer.",
		],
		records: [
			{
				name: domain,
				type: "TXT",
				value: "v=spf1 include:_spf.google.com include:<vendor> ~all",
				note: "Add the vendor include; keep the total DNS lookups at or under 10.",
			},
		],
		verify: [`dig +short ${domain} TXT | grep spf1`],
		recheckCheckId: "spf",
	}),

	// §11.4 — move the policy forward, one report window at a time.
	"fix.policy_ramp": ({ domain }) => ({
		id: "fix.policy_ramp",
		title: "Move your DMARC policy forward",
		appliesTo: ["C03", "C12"],
		steps: [
			"Never advance while a problem complaint is open — you would start blocking your own mail.",
			"p=none → p=quarantine; pct=25 → pct=100 → p=reject, waiting one full report window at each step.",
			"Set sp= and np= explicitly so subdomains are covered deliberately rather than by inheritance.",
			"Re-read this page after each step: the authenticated rate must not drop.",
		],
		records: [
			{
				name: `_dmarc.${domain}`,
				type: "TXT",
				value: `v=DMARC1; p=reject; sp=reject; np=reject; adkim=s; aspf=s; pct=100; rua=mailto:dmarc@${domain}`,
				note: "The end state. Step through quarantine first if you are not there yet.",
			},
		],
		verify: [`dig +short _dmarc.${domain} TXT`],
		recheckCheckId: "dmarc",
	}),

	// §11.5 — align the envelope so the stream stops depending on DKIM alone.
	"fix.brand_return_path": ({ domain }) => ({
		id: "fix.brand_return_path",
		title: "Align the Return-Path on your sending platform",
		appliesTo: ["C06"],
		steps: [
			`Point a subdomain (for example bounces.${domain}) at your sending platform, following its branded-links / custom-return-path instructions.`,
			"Re-send a test message and confirm the Return-Path header now shows your subdomain.",
			`Alternative if the platform cannot do it: set aspf=r on _dmarc.${domain} and accept relaxed SPF alignment. The trade-off is that this also authorizes every sibling subdomain, so only do it if you control them all.`,
		],
		records: [
			{
				name: `bounces.${domain}`,
				type: "CNAME",
				value: "<the hostname your sending platform gives you>",
				note: "Exact name and target come from the platform's domain-authentication wizard.",
			},
		],
		verify: [`dig +short bounces.${domain}`],
		recheckCheckId: "spf",
	}),

	// §11.6 — repair inbound TLS, keyed by the RFC 8460 result-type the reporter sent.
	"fix.tls_transport": ({ domain, tlsResultTypes }) => ({
		id: "fix.tls_transport",
		title: "Repair encrypted delivery to your mail servers",
		appliesTo: ["C14"],
		steps:
			tlsResultTypes.length > 0
				? tlsResultTypes.map(
						(t) =>
							`${t}: ${(TLS_RESULT_FIXES[t] ?? `Investigate ${t}.`).replace("<domain>", domain)}`,
					)
				: [
						"No TLS failures were reported this window — this is the healthy baseline, kept so a later regression is visible.",
					],
		records: [],
		verify: [
			`dig +short _smtp._tls.${domain} TXT`,
			`curl -sS https://mta-sts.${domain}/.well-known/mta-sts.txt`,
		],
		recheckCheckId: "tls-rpt",
	}),

	// §11.7 — stop signatures breaking between us and the receiver.
	"fix.signature_survivability": () => ({
		id: "fix.signature_survivability",
		title: "Make your DKIM signatures survive the trip",
		appliesTo: ["C08"],
		steps: [
			"Use relaxed/relaxed canonicalization so trivial whitespace changes do not invalidate the signature.",
			"Do not oversign volatile headers, and drop the l= body-length tag if your signer sets it.",
			"Check the evidence table: if one gateway, list server or receiver accounts for all the failures, that is the middlebox rewriting the message.",
			"Isolated single-message failures are normal internet weather. A persistent pattern is a real interoperability bug worth raising with the receiver.",
		],
		records: [],
		verify: [],
		recheckCheckId: "dkim",
	}),

	// §11.8 — one record, explicit tags.
	"fix.single_dmarc_record": ({ domain }) => ({
		id: "fix.single_dmarc_record",
		title: "Publish exactly one DMARC record, with explicit tags",
		appliesTo: ["C11"],
		steps: [
			`Query _dmarc.${domain} — more than one TXT line starting v=DMARC1 is the bug. Delete the extras.`,
			"Set p, sp, np, adkim, aspf and pct explicitly rather than relying on defaults; reporters fill absent tags differently, which is what produced the disagreement.",
			"Change the record at most once per report window so overlapping reports cannot disagree legitimately.",
		],
		records: [
			{
				name: `_dmarc.${domain}`,
				type: "TXT",
				value: `v=DMARC1; p=reject; sp=reject; np=reject; adkim=s; aspf=s; pct=100; rua=mailto:dmarc@${domain}`,
			},
		],
		verify: [`dig +short _dmarc.${domain} TXT`],
		recheckCheckId: "dmarc",
	}),

	// §11.9 — get the reports flowing again.
	"fix.report_flow": ({ domain }) => ({
		id: "fix.report_flow",
		title: "Get the reports flowing again",
		appliesTo: ["C13"],
		steps: [
			`Confirm _dmarc.${domain} still carries a rua= address, and that the mailbox behind it accepts mail from strangers.`,
			`If rua points at a mailbox outside ${domain}, the receiving domain must authorize it: publish ${domain}._report._dmarc.<their-domain> TXT "v=DMARC1".`,
			"Check the mailbox is not full and is not filing the reports as spam.",
			"Check the drop folder / IMAP settings under Settings → Admin still point at the right place.",
		],
		records: [
			{
				name: `${domain}._report._dmarc.<their-domain>`,
				type: "TXT",
				value: "v=DMARC1",
				note: "Only needed when rua= points outside your own domain.",
			},
		],
		verify: [`dig +short _dmarc.${domain} TXT`],
		recheckCheckId: "dmarc",
	}),

	// §11.10 — a report we could not read is indistinguishable from good news, so it is loud.
	"fix.ingest_error": () => ({
		id: "fix.ingest_error",
		title: "Read the report we could not read",
		appliesTo: ["C15"],
		steps: [
			"Open the failing file listed below from the report drop folder's processed/ directory.",
			"Check the failing stage: a MIME-walk failure means an unexpected nesting, a decompress failure means an unexpected container, a parse failure means unexpected XML/JSON.",
			"A report that cannot be read looks exactly like a report that found no problems, so this is never cosmetic — fix or file it before trusting the board.",
		],
		records: [],
		verify: [],
		recheckCheckId: null,
	}),
};

/**
 * Build the ordered fix plan for a board (pm/Email_Complaints.mdx §10.3): one entry per distinct
 * fix referenced by a non-`ok` complaint, ranked by the message volume it repairs so the biggest
 * win is step ①.
 */
export function buildFixPlan(ctx: FixBuildContext): ComplaintFix[] {
	const wanted = new Map<string, number>();
	for (const complaint of ctx.byCode.values()) {
		if (complaint.verdict === "ok") continue;
		for (const fixId of complaint.fixIds) {
			wanted.set(fixId, (wanted.get(fixId) ?? 0) + complaint.messages);
		}
	}
	const plan: ComplaintFix[] = [];
	for (const [fixId, messagesFixed] of wanted) {
		const build = BUILDERS[fixId];
		if (!build) continue;
		plan.push({ ...build(ctx), messagesFixed });
	}
	// Biggest volume first; ties broken by title so the order is stable across runs.
	plan.sort(
		(a, b) => b.messagesFixed - a.messagesFixed || a.title.localeCompare(b.title),
	);
	return plan;
}

/** The single fix object for one id — used by the drill-down (§10.4 block 4). */
export function buildFix(
	fixId: string,
	ctx: FixBuildContext,
	messagesFixed = 0,
): ComplaintFix | null {
	const build = BUILDERS[fixId];
	return build ? { ...build(ctx), messagesFixed } : null;
}
