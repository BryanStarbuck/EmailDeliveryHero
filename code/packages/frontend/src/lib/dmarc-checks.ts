/**
 * The DMARC sub-test `checkKey` registry (pm/checks/dmarc.mdx §6.3) — the single source for the
 * category page's sub-tests band rows, the finding-id → explainer link map, and the record-tag →
 * explainer link map. One row per explainer unit; a unit groups the §2 finding ids that share one
 * concept. The `arc` and `reports` rows are the sibling units owned by pm/checks/arc.mdx and
 * pm/emails.mdx — this registry owns only their band row (chip source, title, one-liner, route);
 * they slot into the same LOCKED route pattern:
 *
 *   /domains/:domainId/runs/:runId/dmarc/check/:checkKey   (canonical, run-scoped)
 *   /domains/:domainId/dmarc/check/:checkKey               (newest-run alias)
 */
import type { DmarcTestRow, Finding, Severity } from "@/api/types";

export type UnitResult = DmarcTestRow["result"]; // "pass" | "fail" | "warn" | "info"

export interface DmarcReference {
	label: string;
	href: string;
}

export interface DmarcCheckUnit {
	key: string;
	/** Band row title (§6.3 "Sub-test unit"). */
	title: string;
	/** One-line meaning shown on the band row. */
	oneLiner: string;
	/** §2 finding ids this unit owns (exact match; `prefixIds` adds prefix families). */
	findingIds: string[];
	/** Finding-id prefixes covered (the sibling `arc` unit covers every `arc.*` id). */
	prefixIds?: string[];
	/** Record tags owned — the parsed-record tag rows that deep-link here (§6.3 mapping rules). */
	tags: string[];
	/** Sibling units render their band row here but their explainer content is owned elsewhere. */
	sibling?: "arc" | "reports";
	/** Block 1 — What this is (2–4 short plain-language paragraphs). */
	whatItIs: string[];
	/** Block 3 — What it means when the unit passes. */
	meaningPass: string;
	/** Block 3 — What it means while the unit is failing. */
	meaningFail: string;
	/** Block 4 — standing fix guidance (per-test fixes come from the run's tests[] rows). */
	fixSteps: string[];
	/** References footer (§6.4): the owning RFC section + curated further reading. */
	references: DmarcReference[];
}

const RFC_9989: DmarcReference = {
	label: "RFC 9989 — DMARCbis (core)",
	href: "https://www.rfc-editor.org/rfc/rfc9989",
};
const RFC_9990: DmarcReference = {
	label: "RFC 9990 — DMARC aggregate reporting",
	href: "https://www.rfc-editor.org/rfc/rfc9990",
};
const RFC_9991: DmarcReference = {
	label: "RFC 9991 — DMARC failure reporting",
	href: "https://www.rfc-editor.org/rfc/rfc9991",
};
const GMAIL_BULK: DmarcReference = {
	label: "Gmail bulk-sender requirements",
	href: "https://support.google.com/a/answer/81126",
};
const YAHOO_HUB: DmarcReference = {
	label: "Yahoo sender hub",
	href: "https://senders.yahooinc.com/best-practices/",
};
const LEARNDMARC: DmarcReference = {
	label: "learndmarc.com — interactive DMARC debugging",
	href: "https://www.learndmarc.com/",
};
/** One "edit a TXT record" doc per common DNS provider (§6.4 references footer). */
const PROVIDER_DOCS: DmarcReference[] = [
	{
		label: "Cloudflare — manage DNS records",
		href: "https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/",
	},
	{
		label: "Amazon Route 53 — create records",
		href: "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-creating.html",
	},
	{
		label: "Namecheap — add a TXT record",
		href: "https://www.namecheap.com/support/knowledgebase/article.aspx/317/2237/how-do-i-add-txtspfdkimdmarc-records-for-my-domain/",
	},
	{
		label: "Squarespace (Google Domains) — DNS records",
		href: "https://support.squarespace.com/hc/en-us/articles/360002101888",
	},
];

/** The §6.3 registry — table order is the band's registry order. */
export const DMARC_CHECK_UNITS: DmarcCheckUnit[] = [
	{
		key: "presence",
		title: "Record presence & tree walk",
		oneLiner:
			"Is a v=DMARC1 TXT published at _dmarc.<domain> (or a covering parent)?",
		findingIds: ["dmarc.present", "dmarc.missing", "dmarc.lookup_failed"],
		tags: [],
		whatItIs: [
			"DMARC is switched on by publishing one TXT record at the special DNS name _dmarc.<your-domain>, beginning with v=DMARC1. Receivers query exactly that name before deciding what to do with mail claiming to be from you.",
			'When a subdomain has no record of its own, DMARCbis (RFC 9989) has receivers walk up the parent labels — the DNS Tree Walk — and apply the closest parent record\'s subdomain policy (sp=). So a domain can be "covered" without publishing anything itself.',
			"Without any record anywhere on that walk, anyone can put your exact domain in the From: header and receivers have no owner-published instruction to reject it. Since the 2024 Gmail/Yahoo bulk-sender rules, having no DMARC record at all can get volume senders rate-limited or rejected outright.",
		],
		meaningPass:
			"Receivers find your policy where they look for it. Every DMARC protection downstream — policy, alignment, reporting — depends on this record existing.",
		meaningFail:
			"Receivers see no policy at all: spoofed mail using your exact domain is delivered on the receiver's own heuristics, and bulk mail from you is penalized under the Gmail/Yahoo rules. A record that exists but could not be resolved this run is a transient resolver problem — re-run to confirm.",
		fixSteps: [
			"Publish a TXT record at _dmarc.<domain> with the zero-risk monitoring starter: v=DMARC1; p=none; rua=mailto:dmarc@<domain>",
			"Wait for DNS propagation (minutes to an hour on most providers).",
			"Verify: doggo _dmarc.<domain> TXT --json",
		],
		references: [RFC_9989, GMAIL_BULK, YAHOO_HUB, LEARNDMARC, ...PROVIDER_DOCS],
	},
	{
		key: "single-record",
		title: "Exactly one record",
		oneLiner: "Two DMARC records make receivers discard both.",
		findingIds: ["dmarc.multiple"],
		tags: [],
		whatItIs: [
			"The DMARC spec requires exactly one v=DMARC1 record at _dmarc.<domain>. When receivers find two or more, they cannot know which one the owner meant — so the spec tells them to discard all of them and treat the domain as having no policy.",
			"This is the classic aftermath of switching DMARC vendors: the old record never gets deleted, the new vendor's record gets added, and all protection silently evaporates while both dashboards look configured.",
		],
		meaningPass:
			"Receivers read one unambiguous policy. Nothing about your enforcement is receiver-dependent.",
		meaningFail:
			"Every receiver treats your domain as having NO DMARC policy at all — worse than a weak record, because the owner believes protection exists.",
		fixSteps: [
			"List the TXT records at _dmarc.<domain> and identify which one points at the report destination you actually use.",
			"Delete every other v=DMARC1 TXT record so exactly one remains.",
			"Verify only one answer comes back: doggo _dmarc.<domain> TXT --json",
		],
		references: [RFC_9989, LEARNDMARC, ...PROVIDER_DOCS],
	},
	{
		key: "syntax",
		title: "Record syntax & tag order",
		oneLiner: "v=DMARC1 first, p= second — or the record is ignored.",
		findingIds: ["dmarc.syntax", "dmarc.syntax_p_position"],
		tags: ["v"],
		whatItIs: [
			"A DMARC record is a list of tag=value pairs separated by semicolons. The grammar is strict about one thing above all: the first tag must be exactly v=DMARC1, and the policy tag p= is required immediately second.",
			"Records that break the grammar — v=dmarc1 case errors elsewhere are tolerated, but a missing or misplaced v= tag, smart quotes, or comma separators — are discarded whole. The domain then silently has no policy while the owner believes it does.",
		],
		meaningPass:
			"The record parses everywhere. Receivers of every strictness level read the same policy.",
		meaningFail:
			"Strict receivers discard the record entirely — the same outcome as publishing nothing. This is a silent regression: nothing bounces, spam-folders, or alerts; protection just stops.",
		fixSteps: [
			"Rewrite the record so it begins exactly: v=DMARC1; p=<your policy>; …",
			"Use plain ASCII semicolons and quotes — no smart quotes, commas, or colons as separators.",
			"Verify with the conformance oracle: checkdmarc <domain> -f json",
		],
		references: [RFC_9989, LEARNDMARC, ...PROVIDER_DOCS],
	},
	{
		key: "policy",
		title: "Policy level",
		oneLiner: "none / quarantine / reject — the protection dial.",
		findingIds: [
			"dmarc.policy",
			"dmarc.no_policy",
			"dmarc.p_none",
			"dmarc.policy_ok",
		],
		tags: ["p"],
		whatItIs: [
			'The p= tag is the whole point of DMARC: it tells receivers what to do with mail that fails both SPF and DKIM alignment. p=none means "just report it, deliver anyway"; p=quarantine means "send it to spam"; p=reject means "bounce it".',
			"p=none is the right first step — it turns on reporting with zero delivery risk — and the wrong permanent state: it provides zero protection. The rollout ladder is none → quarantine → reject, promoted once aggregate reports confirm legitimate mail passes aligned.",
		],
		meaningPass:
			"Receivers are actively quarantining or rejecting mail that spoofs your exact domain — the single largest lever against direct-domain phishing.",
		meaningFail:
			"At p=none (or with a missing/invalid p=) spoofed mail is delivered normally. You may be collecting reports, but nothing is being blocked on your behalf.",
		fixSteps: [
			"If reports (rua) are flowing and legitimate mail passes aligned, raise the policy one notch: p=none → p=quarantine → p=reject.",
			"Never enforce blind — add rua= first if it is missing.",
			"If legitimate mail starts bouncing after a raise, step back exactly one notch, fix alignment, re-monitor two weeks, and resume.",
		],
		references: [RFC_9989, GMAIL_BULK, YAHOO_HUB, LEARNDMARC, ...PROVIDER_DOCS],
	},
	{
		key: "testing-mode",
		title: "Testing flag",
		oneLiner: "t=y silently turns enforcement off.",
		findingIds: ["dmarc.testing"],
		tags: ["t"],
		whatItIs: [
			'RFC 9989 adds a t= tag: t=y declares the whole record "in testing", telling receivers the policy is advisory and should not be enforced — roughly what pct=0 used to mean.',
			"It is easy to publish t=y during a rollout and forget it. The record then looks enforcing (p=reject!) while receivers treat it as p=none.",
		],
		meaningPass:
			"No testing flag is weakening the published policy — what you see is what receivers enforce.",
		meaningFail:
			"Receivers treat your policy as advisory only. A p=reject record with t=y protects nothing.",
		fixSteps: [
			"Remove the t=y tag (or set t=n) once you are ready to enforce.",
			"Verify: doggo _dmarc.<domain> TXT --json — the answer should carry no t=y.",
		],
		references: [RFC_9989, LEARNDMARC, ...PROVIDER_DOCS],
	},
	{
		key: "subdomain-policy",
		title: "Subdomain & non-existent-subdomain policy",
		oneLiner: "Are subdomains as protected as the org domain?",
		findingIds: ["dmarc.subdomain", "dmarc.subdomain_ok", "dmarc.np"],
		tags: ["sp", "np"],
		whatItIs: [
			"sp= sets the policy for subdomains (it defaults to p= when absent). A strong org policy with a weaker sp= — p=reject; sp=none — locks the front door and leaves every window open: anything@foo.<domain> stays spoofable.",
			"np= (RFC 9989) covers subdomains that do not exist in DNS at all. Made-up subdomains can never have SPF or DKIM, so np=reject is safe for any domain that never sends from non-existent hosts — and attackers actively probe for exactly this gap.",
		],
		meaningPass:
			"The whole domain tree is covered: real subdomains inherit or match the org policy, and non-existent ones are explicitly rejected.",
		meaningFail:
			"Attackers who cannot spoof your apex simply move to a subdomain — invoices.your-domain or a made-up host — and inherit the weaker (or absent) policy there.",
		fixSteps: [
			"Set sp=reject (or remove sp= entirely so subdomains inherit p=).",
			"Add np=reject if you never send from non-existent subdomains.",
			"Verify: doggo _dmarc.<domain> TXT --json and read the sp=/np= values back.",
		],
		references: [RFC_9989, LEARNDMARC, ...PROVIDER_DOCS],
	},
	{
		key: "alignment",
		title: "Alignment modes",
		oneLiner: "Strict alignment breaks ESP and subdomain mail.",
		findingIds: ["dmarc.alignment", "dmarc.adkim_strict", "dmarc.aspf_strict"],
		tags: ["adkim", "aspf"],
		whatItIs: [
			"DMARC passes only when SPF or DKIM passes AND the passing identity aligns with the From: domain. adkim= and aspf= choose how exact that match must be: r (relaxed, the default) accepts the org domain or any subdomain; s (strict) demands an exact match.",
			"Strict alignment is almost never required. Mail signed as mail.<domain>, or sent through an ESP using a subdomain Return-Path, stops passing under s — and the failure only shows up when the policy is enforced, i.e. at the worst possible time.",
		],
		meaningPass:
			"Relaxed alignment lets legitimate subdomain and ESP mail keep passing while still binding authentication to your org domain.",
		meaningFail:
			"Legitimate mail from subdomains or ESPs fails DMARC alignment — spam-foldered at p=quarantine, bounced at p=reject.",
		fixSteps: [
			"Use adkim=r; aspf=r (or remove both tags — relaxed is the default) unless exact-domain matching is a hard requirement.",
			"Before any strict mode, verify each sending system with: npx mailauth report <message.eml>",
		],
		references: [RFC_9989, LEARNDMARC, ...PROVIDER_DOCS],
	},
	{
		key: "pct",
		title: "Legacy percentage sampling",
		oneLiner: "Partial, non-deterministic enforcement — removed in RFC 9989.",
		findingIds: ["dmarc.pct"],
		tags: ["pct"],
		whatItIs: [
			"pct= was RFC 7489's staged-rollout dial: pct=25 asked receivers to enforce the policy on a 25% sample of failing mail. DMARCbis (RFC 9989) removed the tag entirely — modern receivers may ignore it.",
			"A lingering pct<100 is usually an abandoned ramp: protection is partial and non-deterministic, and pct=0 is stealth p=none.",
		],
		meaningPass:
			"No sampling tag — the policy applies to 100% of failing mail, deterministically.",
		meaningFail:
			"Some receivers enforce on a sample, some on everything, some ignore the tag — your protection level is literally receiver-dependent.",
		fixSteps: [
			"Remove the pct tag at the next DNS edit; the policy then applies to all mail.",
			"Verify: checkdmarc <domain> -f json flags obsolete tags explicitly.",
		],
		references: [RFC_9989, LEARNDMARC, ...PROVIDER_DOCS],
	},
	{
		key: "reporting",
		title: "Reporting tags",
		oneLiner: "Are aggregate/failure reports requested and well-formed?",
		findingIds: [
			"dmarc.rua",
			"dmarc.rua_invalid",
			"dmarc.rua_ok",
			"dmarc.rua_limit",
			"dmarc.ruf",
			"dmarc.fo",
			"dmarc.ri",
			"dmarc.rf",
			"dmarc.report_uri_size",
		],
		tags: ["rua", "ruf", "fo", "ri", "rf"],
		whatItIs: [
			"rua= asks receivers to send you daily aggregate XML reports: which IPs sent as your domain, how much, and whether it passed SPF/DKIM alignment. It is the only visibility you get into spoofers and into legitimate streams that would break under enforcement.",
			"ruf= requests per-failure forensic samples (optional and privacy-sensitive; many receivers skip or redact them). fo= tunes when failure reports fire — fo=1 reports when either mechanism fails, which is what you want while diagnosing. ri= and rf= are legacy tags removed in DMARCbis.",
		],
		meaningPass:
			"Reports flow to a mailbox you control — you can see spoofing attempts and verify legitimate mail passes aligned before tightening the policy.",
		meaningFail:
			"You are flying blind: no way to see who sends as your domain, and no safe basis for ever raising the policy.",
		fixSteps: [
			"Add rua=mailto:dmarc@<domain> (or your report-analytics mailbox).",
			"Keep at most two report URIs — the spec only guarantees delivery to two.",
			"If ruf= is set, add fo=1 so single-mechanism failures are reported too.",
			"Drop legacy ri=/rf= tags at the next edit.",
		],
		references: [RFC_9990, RFC_9991, LEARNDMARC, ...PROVIDER_DOCS],
	},
	{
		key: "external-authorization",
		title: "External report authorization",
		oneLiner:
			"Third-party report destinations must authorize you or reports vanish.",
		findingIds: ["dmarc.external_report_auth", "dmarc.external_report_auth_ok"],
		tags: [],
		whatItIs: [
			"When rua= points at another company's domain (a report-analytics provider), that company must publish a TXT record at <your-domain>._report._dmarc.<their-domain> containing v=DMARC1. It is the destination saying \"yes, I agreed to receive this domain's reports\".",
			'Without it, compliant report generators silently skip sending your reports — no bounce, no error. This is the classic "we set up DMARC months ago and never got a single report".',
		],
		meaningPass:
			"Every external destination has opted in — receivers actually deliver your aggregate reports there.",
		meaningFail:
			"You believe you are monitoring, but zero reports arrive: you cannot see spoofers or failing legitimate mail, and policy promotion stays blocked.",
		fixSteps: [
			'Ask the report provider to publish: <your-domain>._report._dmarc.<their-domain> TXT "v=DMARC1" (providers document this; many publish a wildcard).',
			"Or point rua= at a mailbox on your own domain: rua=mailto:dmarc@<domain>",
			"Verify: doggo <your-domain>._report._dmarc.<their-domain> TXT --json",
		],
		references: [RFC_9990, LEARNDMARC, ...PROVIDER_DOCS],
	},
	{
		key: "tag-hygiene",
		title: "Tag hygiene",
		oneLiner: "Obsolete or typo'd tags lingering in the record.",
		findingIds: ["dmarc.deprecated_tags"],
		tags: [],
		whatItIs: [
			"Receivers ignore tags they do not recognize, so an unknown tag never breaks the record — but it almost always means a typo (rau= instead of rua=) whose intended effect silently never happened.",
			"The DMARCbis cleanup also removed pct=, rf=, and ri= from the spec. They do no harm, but a minimal record is easier to audit and less likely to hide a mistake.",
		],
		meaningPass: "The record is minimal and every tag in it does something.",
		meaningFail:
			"A typo'd tag may mean a feature you think is on (often reporting) silently is not; obsolete tags add noise receivers ignore.",
		fixSteps: [
			"Remove obsolete (pct/rf/ri) and unknown tags at the next DNS edit.",
			"Double-check any removed unknown tag was not a typo of a tag you wanted (rua, ruf, sp…).",
		],
		references: [RFC_9989, LEARNDMARC, ...PROVIDER_DOCS],
	},
	{
		key: "arc",
		title: "ARC chain",
		oneLiner: "Preserves authentication through forwarders and mailing lists.",
		findingIds: [],
		prefixIds: ["arc."],
		tags: [],
		sibling: "arc",
		whatItIs: [
			"ARC (Authenticated Received Chain, RFC 8617) lets forwarders and mailing lists record the authentication results they saw before they broke SPF (new connecting IP) or DKIM (rewritten content). Receivers can then trust the sealed chain instead of the now-failing checks.",
			"For a DMARC-enforcing domain, ARC is what keeps legitimate forwarded mail deliverable. The full ARC sub-test content is owned by the ARC check (pm/checks/arc.mdx); its findings roll into this DMARC category.",
		],
		meaningPass:
			"Forwarded copies of your mail carry a verifiable trail, so enforcing DMARC does not bounce legitimate indirect mail.",
		meaningFail:
			"Mail that transits forwarders or lists loses its authentication and fails DMARC downstream — the ARC rows explain what was observed.",
		fixSteps: [
			"Prefer aligned DKIM on every stream (it survives most forwarding) before p=reject.",
			"See the ARC rows in this run for the specific chain observations and fixes.",
		],
		references: [
			{
				label: "RFC 8617 — ARC",
				href: "https://www.rfc-editor.org/rfc/rfc8617",
			},
			RFC_9989,
			LEARNDMARC,
		],
	},
	{
		key: "reports",
		title: "Ingested aggregate reports",
		oneLiner: "What receivers actually saw: real pass rates and spoof sources.",
		findingIds: ["dmarc.real_pass_rate"],
		prefixIds: ["dmarc.reports"],
		tags: [],
		sibling: "reports",
		whatItIs: [
			"The rua= reports receivers send back are XML files listing every source IP that sent as your domain, its volume, and whether it passed SPF/DKIM alignment. Ingesting them turns DMARC from a DNS record into a measurement: the real pass rate.",
			"This unit's content is owned by the report-ingestion pipeline (pm/emails.mdx). Until reports have been ingested for this domain, the unit shows as not measured.",
		],
		meaningPass:
			"Real-world data confirms legitimate mail passes aligned — the safe basis for raising the policy.",
		meaningFail:
			"Ingested reports show unaligned legitimate streams or active spoofing — fix or authorize those sources before enforcing further.",
		fixSteps: [
			"Point rua= at the mailbox this app ingests (see the Reports page), then wait ~48 h for the first reports.",
			"Review the per-source table on the domain's Reports page and fix unaligned legitimate senders vendor by vendor.",
		],
		references: [RFC_9990, LEARNDMARC],
	},
];

/** §6.3 tag → checkKey map (parsed-record tag rows deep-link to the unit that owns the tag). */
export const DMARC_TAG_TO_CHECK_KEY: Record<string, string> = {};
for (const unit of DMARC_CHECK_UNITS) {
	for (const tag of unit.tags) DMARC_TAG_TO_CHECK_KEY[tag] = unit.key;
}

export function dmarcUnitByKey(key: string): DmarcCheckUnit | undefined {
	return DMARC_CHECK_UNITS.find((u) => u.key === key);
}

/**
 * The unit owning a finding id (§6.3 mapping rules). Ids outside the registry — e.g. the
 * environmental `dmarc.tool_missing` advisory — belong to no unit and must not link.
 */
export function dmarcUnitForFindingId(
	findingId: string,
): DmarcCheckUnit | undefined {
	return DMARC_CHECK_UNITS.find(
		(u) =>
			u.findingIds.includes(findingId) ||
			(u.prefixIds ?? []).some(
				(p) => findingId === p.replace(/\.$/, "") || findingId.startsWith(p),
			),
	);
}

const RESULT_RANK: Record<UnitResult, number> = {
	pass: 0,
	info: 1,
	warn: 2,
	fail: 3,
};
const RESULT_OF_SEVERITY: Record<Severity, UnitResult> = {
	ok: "pass",
	info: "info",
	warning: "warn",
	critical: "fail",
};

/** True when a §5 tests[] row (or finding) id belongs to `unit`. */
function unitOwns(unit: DmarcCheckUnit, id: string): boolean {
	return (
		unit.findingIds.includes(id) ||
		(unit.prefixIds ?? []).some(
			(p) => id === p.replace(/\.$/, "") || id.startsWith(p),
		)
	);
}

/**
 * The band chip for one unit in one run (§6.3): the WORST result among the unit's ids in this
 * run's tests[] (falling back to the findings when the run predates persisted tests[]); null =
 * none of the unit's ids fired → the slate "not measured" chip.
 */
export function dmarcUnitResult(
	unit: DmarcCheckUnit,
	tests: DmarcTestRow[],
	findings: Finding[],
): UnitResult | null {
	let worst: UnitResult | null = null;
	const consider = (r: UnitResult): void => {
		if (worst === null || RESULT_RANK[r] > RESULT_RANK[worst]) worst = r;
	};
	for (const t of tests) if (unitOwns(unit, t.id)) consider(t.result);
	if (worst === null) {
		for (const f of findings)
			if (unitOwns(unit, f.id)) consider(RESULT_OF_SEVERITY[f.severity]);
	}
	return worst;
}

/** Band sort key (§7): failing units first — fail → warn → info → not-measured → pass. */
export function dmarcBandOrder(result: UnitResult | null): number {
	if (result === "fail") return 0;
	if (result === "warn") return 1;
	if (result === "info") return 2;
	if (result === null) return 3;
	return 4;
}
