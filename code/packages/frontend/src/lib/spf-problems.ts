/**
 * The SPF problem-state catalog (pm/checks/spf.mdx §9). Each state matches on finding ids from the
 * latest run and carries the drill-down content rendered at /domains/:id/spf/:problemId. PS-11
 * (alignment) and PS-12 (flattening) are future — they need message-level data — and are absent.
 */
import type { Finding } from "@/api/types";
import {
	matchProblemStates as matchStates,
	type ProblemState,
	problemStateById as stateById,
} from "@/lib/problem-states";

export type SpfProblemState = ProblemState;

export const SPF_PROBLEM_STATES: SpfProblemState[] = [
	{
		id: "PS-01",
		title: "No SPF record at all",
		hook: "Receivers can't verify any sender, and bulk-sender rules penalize you.",
		severity: "critical",
		findingIds: ["spf.missing"],
		concept: [
			"Without a v=spf1 TXT record at the apex, receivers get result `none`: they have no owner-published list of authorized senders, so your mail rides on weaker heuristics and spoofers face no SPF obstacle at all.",
			"The Gmail/Yahoo/Microsoft bulk-sender rules require SPF or DKIM (and recommend both), so a missing record hurts legitimate deliverability directly. SPF can also never contribute to DMARC alignment until it exists.",
		],
		dataFields: [
			"record.record_found = false",
			"record.record_count = 0",
			"record.eval_result = none",
		],
		commands: [
			"dig +short TXT <domain>",
			"kdig @8.8.8.8 +short TXT <domain>",
			"checkdmarc <domain> -f json",
		],
		tools: [
			"dig / kdig / doggo (brew install bind knot doggo)",
			"checkdmarc (brew install checkdmarc)",
		],
		metrics: ["None until the record exists — publish and re-audit."],
		pathForward: [
			'Publish a TXT record at the apex: "v=spf1 include:<your-ESP> ~all" — build the include list from your known senders, not guesses.',
			"Re-run the audit to confirm the record is visible and within the lookup budget.",
			"Remember subdomains do not inherit SPF — any subdomain used as an envelope-from needs its own record.",
		],
	},
	{
		id: "PS-02",
		title: "Multiple SPF records",
		hook: "Two v=spf1 strings = permerror — receivers ignore SPF entirely.",
		severity: "critical",
		findingIds: ["spf.multiple"],
		concept: [
			"RFC 7208 §4.5: more than one v=spf1 record is a permerror — receivers discard ALL of them, so the domain is unprotected even though a correct record is among them.",
			"Classic after a provider migration: the registrar wizard's record lingers next to the one your ESP told you to add.",
		],
		dataFields: [
			"record.record_count ≥ 2",
			"record.raw_record (all observed strings)",
		],
		commands: ["dig TXT <domain> +multiline", "doggo <domain> TXT --json"],
		tools: [
			"dig / doggo",
			"your DNS provider's console (find which entry created each record)",
		],
		metrics: [
			"The scheduled-run regression diff flags if the count ever rises above 1 again.",
		],
		pathForward: [
			"List every v=spf1 TXT at the apex and identify where each came from.",
			"Merge all mechanisms into ONE record with one v=spf1 prefix and one terminating all, then delete the extras.",
			"Re-run the audit to confirm exactly one record remains and the merged record stays under 10 lookups.",
		],
	},
	{
		id: "PS-03",
		title: "Over the lookup limit (permerror)",
		hook: "More than 10 DNS lookups — SPF fails for ALL your mail.",
		severity: "critical",
		findingIds: ["spf.lookups"],
		concept: [
			"RFC 7208 §4.6.4 allows at most 10 DNS-querying mechanisms (include, a, mx, ptr, exists, redirect) counted recursively through every nested include. One past the limit and receivers return permerror — under DMARC that counts as SPF fail for every message.",
			"This is the single most common enterprise SPF failure, and it appears silently: adding one more vendor include (or a vendor growing their own include) pushes you over.",
		],
		dataFields: [
			"record.lookup_count (recursive)",
			"record.include_tree — per-node cost_lookups shows which branch is heaviest",
		],
		commands: ["checkdmarc <domain> -f json", "dig +short TXT <domain>"],
		tools: [
			"checkdmarc (counts lookups recursively)",
			"dmarcian SPF Surveyor (visual second opinion)",
			"the include tree on this page",
		],
		metrics: [
			"Lookup-count trend across scheduled runs — we warn at 8 so you see the cliff coming.",
		],
		pathForward: [
			"Delete dead or unused vendor includes first — free wins (the tree shows each branch's cost).",
			"Replace a/mx with explicit ip4:/ip6: ranges where the IPs are stable.",
			"Split mail streams onto subdomains with their own SPF records.",
			"Only as a last resort, use dynamically maintained flattening — never a static IP dump (it breaks silently when providers rotate ranges).",
		],
	},
	{
		id: "PS-04",
		title: "Dead includes / void lookups",
		hook: "A stale vendor include resolves to nothing — permerror territory.",
		severity: "critical",
		findingIds: ["spf.void", "spf.include_resolves"],
		concept: [
			"A mechanism whose DNS query returns NXDOMAIN or an empty answer is a void lookup; more than 2 lets receivers return permerror. An include: whose target publishes no SPF record at all is an immediate permerror.",
			"The usual cause is a decommissioned vendor. A repurposed vendor domain is also a takeover-style risk — someone else could publish an SPF record that authorizes their servers to send as you.",
		],
		dataFields: [
			"record.void_count (limit 2)",
			"record.include_tree — nodes with is_void = true",
		],
		commands: [
			"dig +short TXT <include-target>",
			"checkdmarc <domain> -f json",
		],
		tools: ["dig / doggo", "checkdmarc (flags dead includes)"],
		metrics: [
			"Re-probed every scheduled run; a vendor include going dark between runs is a regression finding.",
		],
		pathForward: [
			"Open the include tree and find the node(s) marked VOID.",
			"Confirm with dig that the target really publishes nothing.",
			"Delete the stale term from the record — the copy-fix button holds the record without it.",
		],
	},
	{
		id: "PS-05",
		title: "Syntax or macro errors (permerror)",
		hook: "One bad term and receivers discard the whole record.",
		severity: "critical",
		findingIds: ["spf.syntax", "spf.macro"],
		concept: [
			"A misspelled mechanism (inlcude:), an out-of-range CIDR (/33), a value on all, comma separators, or a stray/invalid %-macro — any single grammar violation is a permerror. Receivers treat the record as if it did not exist.",
			"The owner believes SPF is in place while the domain silently has none — a dangerous mismatch.",
		],
		dataFields: [
			"record.raw_record (read it character-by-character)",
			"record.mechanisms (what survived parsing)",
			"the spf.syntax / spf.macro findings quote each offending term",
		],
		commands: [
			"dig +short TXT <domain>",
			"checkdmarc <domain>   # names the offending term",
		],
		tools: [
			"checkdmarc",
			"spf-parse (npm) for per-term validity",
			"EasyDMARC's raw checker to validate a corrected record before publishing",
		],
		metrics: ["The regression diff surfaces any change to raw_record."],
		pathForward: [
			"Compare the raw record against the mechanism table on the SPF page — invalid terms are flagged in place.",
			"Fix each quoted term; valid macro letters are s l o d i p v h.",
			"Validate the corrected record before publishing, then re-run the audit.",
		],
	},
	{
		id: "PS-06",
		title: "Open door (+all / ?all / missing all / /0 range)",
		hook: "The record authorizes the entire internet — or nobody in particular.",
		severity: "critical",
		findingIds: ["spf.all", "spf.cidr_scope"],
		concept: [
			"+all (or ip4:0.0.0.0/0) authorizes every host on the internet to send as your domain — worse than useless, since some receivers score it as a spam signal in itself.",
			"?all or a missing all gives receivers no default policy for unlisted senders: functionally close to having no SPF at all.",
		],
		dataFields: [
			"record.all_qualifier",
			"record.mechanisms (the CIDR terms)",
			"record.pass_set",
		],
		commands: ["dig +short TXT <domain>"],
		tools: [
			"dig — the last term tells the story",
			"any online checker flags +all instantly",
		],
		metrics: [
			"Regression diff — -all/~all weakening to ?all/+all between runs is a high-value regression.",
		],
		pathForward: [
			"Remove +all (and any /0 range) immediately.",
			"With DMARC enforcing, end in ~all — softfail lets forwarded mail still be evaluated by DKIM/DMARC.",
			"Without DMARC, use -all — or better, deploy DMARC.",
			'Non-sending domains: publish exactly "v=spf1 -all", a Null MX (0 .), and DMARC p=reject.',
		],
	},
	{
		id: "PS-07",
		title: "Dead weight & deprecated constructs",
		hook: "ptr, terms after all, duplicates — nothing breaks yet, everything misleads.",
		severity: "warning",
		findingIds: [
			"spf.ptr",
			"spf.all_terminal",
			"spf.dup_mechanisms",
			"spf.redirect",
		],
		concept: [
			"ptr is deprecated (RFC 7208 §5.5): slow, unreliable, burns a lookup, and some receivers treat it as no-match. Terms after all never evaluate. Duplicate terms waste lookups. A redirect= next to an all is silently ignored (§6.1).",
			"None of these break SPF today — all of them mislead the next person who edits the record, and the wasted lookups shrink your head-room under the 10-lookup limit.",
		],
		dataFields: [
			"record.mechanisms (order + duplicates)",
			"record.has_redirect",
			"record.all_qualifier position",
		],
		commands: ["dig +short TXT <domain>"],
		tools: [
			"none required — this is pure record hygiene; the mechanism table shows it all",
		],
		metrics: [
			"Lookup head-room reclaimed after cleanup (the budget gauge drops).",
		],
		pathForward: [
			"Delete ptr; replace it with explicit ip4:/ip6: or the vendor's include:.",
			"Move all to the end and delete unreachable terms.",
			"Remove duplicate terms and pick one of redirect=/all (they don't combine).",
		],
	},
	{
		id: "PS-08",
		title: "Sending IP not covered",
		hook: "A host you actually send from fails SPF on every message.",
		severity: "critical",
		findingIds: ["spf.ip_coverage"],
		concept: [
			"The record parses and evaluates fine, but a configured sending IP is not inside the expanded pass-set — every message from it fails SPF, and at DMARC enforcement gets quarantined or rejected unless DKIM saves it.",
			'The classic "we added a new relay and forgot SPF". Also happens when a vendor rotates ranges out from under a static IP list.',
		],
		dataFields: [
			"record.ip_coverage[] — ip, covered, matched_by",
			"record.pass_set (the CIDRs the record authorizes, with sources)",
			"the domain's sendingIps config (Domains page)",
		],
		commands: [
			"npx mailauth spf --sender postmaster@<domain> --ip <the-uncovered-ip>",
			"dig +short TXT <domain>",
		],
		tools: [
			"mailauth (npm) — a true check_host() simulation for any IP",
			"swaks (brew) — send a live probe and read Authentication-Results at a seed mailbox",
		],
		metrics: [
			"Coverage re-checked every scheduled run; an IP falling out of coverage is a regression finding.",
		],
		pathForward: [
			"Verify the IP really is a legitimate sender (mail server config, ESP dashboard).",
			"Add the exact ip4:<ip> / ip6:<ip> line (the coverage panel's copy button holds it) — or the vendor's include: — before the all term.",
			"Re-run the audit and confirm the coverage row turns green.",
		],
	},
	{
		id: "PS-09",
		title: "Include/redirect loop",
		hook: "Record A includes B includes A — evaluation aborts with permerror.",
		severity: "critical",
		findingIds: ["spf.recursion_depth"],
		concept: [
			"An include or redirect chain that references back into itself never terminates, so receivers abort with permerror. Rare, but catastrophic — and invisible to eyeball review when the loop spans DNS zones.",
		],
		dataFields: [
			'record.include_tree — the node whose resolved_to says "cycle"',
			"the spf.recursion_depth finding names the looping domain",
		],
		commands: [
			"dig +short TXT <looping-target>   # follow each hop until the repeat appears",
		],
		tools: ["dig", "checkdmarc (its recursive parse also detects loops)"],
		metrics: ["None — fix it."],
		pathForward: [
			"Walk the include tree to the cycle edge.",
			"Replace one back-reference with the concrete ip4:/ip6: ranges so the chain becomes a tree.",
		],
	},
	{
		id: "PS-10",
		title: "Oversized record / stale type-99",
		hook: "UDP truncation risk, or a deprecated record type drifting out of sync.",
		severity: "warning",
		findingIds: ["spf.length", "spf.dns_type"],
		concept: [
			"Past ~450 bytes the whole DNS answer risks classic-UDP truncation → TCP retries or temperror at strict resolvers. Records over 255 bytes must be split into multiple quoted strings inside ONE TXT record (multiple records is a permerror).",
			"Separately, a leftover SPF type-99 RR (deprecated since RFC 7208; registrars are dropping the type) signals stale config — receivers only read TXT, so the type-99 copy silently drifts.",
		],
		dataFields: [
			"record.byte_length",
			"the spf.length / spf.dns_type findings",
		],
		commands: [
			"dig +short TXT <domain> | wc -c",
			"dig <domain> SPF +short   # any answer = stale type-99",
		],
		tools: ["dig", "drill (brew install ldns) for DNSSEC-aware size tracing"],
		metrics: ["Byte-length trend as vendors are added."],
		pathForward: [
			"Shorten the record: drop unused includes, replace a/mx with explicit ranges, split streams onto subdomains.",
			"Delete the SPF-type (99) record at your DNS console; publish TXT only.",
		],
	},
];

/** Problem states matched by the latest run's findings (pm/checks/spf.mdx §9 mapping). */
export function matchSpfProblemStates(findings: Finding[]): SpfProblemState[] {
	return matchStates(SPF_PROBLEM_STATES, findings);
}

export function spfProblemStateById(id: string): SpfProblemState | undefined {
	return stateById(SPF_PROBLEM_STATES, id);
}
