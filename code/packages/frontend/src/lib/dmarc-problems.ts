/**
 * The DMARC problem-state catalog (pm/checks/dmarc.mdx §9). Each state matches on finding ids from
 * the latest run and carries the drill-down content rendered at /domains/:id/dmarc/:problemId:
 * concept, diagnose-it-yourself commands, tools, extra health metrics, and the path forward.
 * PS-11/PS-12 are future (rua ingestion) and intentionally absent.
 */
import type { Finding } from "@/api/types"
import {
  matchProblemStates as matchStates,
  type ProblemState,
  problemStateById as stateById,
} from "@/lib/problem-states"

export type DmarcProblemState = ProblemState

export const DMARC_PROBLEM_STATES: DmarcProblemState[] = [
  {
    id: "PS-01",
    title: "No DMARC record at all",
    hook: "Anyone can spoof your exact domain, and bulk mail is penalized.",
    severity: "critical",
    findingIds: ["dmarc.missing"],
    concept: [
      "Without a DMARC record, receivers have no owner-published instruction for mail that fails SPF and DKIM alignment — spoofed mail claiming to be your exact domain is judged only by the receiver's own heuristics.",
      "Since the 2024 Gmail/Yahoo bulk-sender rules, senders without DMARC can be rate-limited or rejected outright, so this hurts legitimate deliverability too.",
    ],
    dataFields: ["record.record_found = false", "record.query_name", "record.found_at = null"],
    commands: [
      "dig +short TXT _dmarc.<domain>",
      "kdig @8.8.8.8 +short TXT _dmarc.<domain>",
      "checkdmarc <domain> -f json",
    ],
    tools: [
      "dig / kdig / doggo (brew install bind knot doggo)",
      "checkdmarc (brew install checkdmarc)",
    ],
    metrics: ["None until the record exists — publish and start monitoring."],
    pathForward: [
      'Publish a TXT record at _dmarc.<domain>: "v=DMARC1; p=none; rua=mailto:dmarc@<domain>". Zero risk — it only turns on monitoring.',
      "Re-run the audit to confirm the record is visible.",
      "After 30–90 days of clean reports, raise to p=quarantine, then p=reject.",
    ],
  },
  {
    id: "PS-02",
    title: "Multiple DMARC records",
    hook: "Receivers discard ALL of them — the domain has no effective policy.",
    severity: "critical",
    findingIds: ["dmarc.multiple"],
    concept: [
      "The spec requires receivers that find more than one v=DMARC1 record to treat DMARC as absent for the domain. All protection evaporates even though a correct record is among them.",
      "This is classic after switching DMARC vendors: the old record lingers while the new one is added.",
    ],
    dataFields: ["record.record_count ≥ 2", "record.raw_record (all observed strings)"],
    commands: ["dig TXT _dmarc.<domain> +multiline", "doggo _dmarc.<domain> TXT --json"],
    tools: ["dig / doggo", "your DNS provider's console (find which entry created each record)"],
    metrics: ["The scheduled-run regression diff flags if the count ever rises above 1 again."],
    pathForward: [
      "List every TXT record at _dmarc.<domain> and identify where each was created.",
      "Delete all but one — keep the record whose rua points at the mailbox you actually monitor.",
      "Re-run the audit to confirm exactly one record remains.",
    ],
  },
  {
    id: "PS-03",
    title: "Record invisible — wrong host or wildcard junk",
    hook: "A DMARC-looking record exists, but not where receivers look.",
    severity: "critical",
    findingIds: ["dmarc.lookup_failed"],
    concept: [
      "Receivers only query _dmarc.<domain>. A record published at the apex, at dmarc.<domain> (missing underscore), or at _dmarc._dmarc.<domain> (console auto-append) is never seen.",
      "A wildcard TXT record can also answer the _dmarc query with junk (an SPF string, a verification token), which receivers ignore — or a _dmarc CNAME can point at a dead target.",
    ],
    dataFields: [
      "record.record_found = false at record.query_name",
      "TXT probes of the apex and dmarc.<domain>",
    ],
    commands: [
      "dig +short TXT <domain> | grep -i dmarc",
      "dig +short TXT dmarc.<domain>",
      "dig +short CNAME _dmarc.<domain>",
      "dig +short TXT zz-random.<domain>   # exposes wildcards",
    ],
    tools: ["dig", "dnsx for sweeping many candidate names (brew install dnsx)"],
    metrics: ["Once fixed, the PS-01 path applies."],
    pathForward: [
      "Find where the record actually lives (commands above).",
      "Publish it at exactly _dmarc.<domain> and delete the misplaced string.",
      "If _dmarc is a CNAME, resolve the chain and confirm the target holds one valid record.",
    ],
  },
  {
    id: "PS-04",
    title: "Syntax-invalid record",
    hook: "Receivers discard the record — you have no policy while believing you do.",
    severity: "critical",
    findingIds: ["dmarc.syntax", "dmarc.no_policy", "dmarc.policy", "dmarc.syntax_p_position"],
    concept: [
      "v=DMARC1 must be the first tag and p= should immediately follow. Misspelled policies (p=monitor), commas or colons as separators, smart quotes, and duplicated tags all make the record invalid.",
      "An invalid record is treated as no record at all — a silent regression that removes protection the owner believes is in place.",
    ],
    dataFields: [
      "record.raw_record (read it character-by-character)",
      "record.parsed (what survived parsing)",
    ],
    commands: ["dig +short TXT _dmarc.<domain>", "checkdmarc <domain>   # names the offending tag"],
    tools: ["checkdmarc", "learndmarc.com for an interactive second opinion"],
    metrics: ["The regression diff surfaces any change to raw_record."],
    pathForward: [
      "Compare the raw record against the parsed-tag table on the DMARC page — invalid values are flagged in place.",
      "Rewrite the record starting exactly with v=DMARC1; p=<none|quarantine|reject>; …",
      "Use the copy-fix button — it holds the corrected full record assembled from the valid parts.",
    ],
  },
  {
    id: "PS-05",
    title: "Stuck in monitoring (p=none or t=y)",
    hook: "Reports flow, but spoofed mail is still delivered normally.",
    severity: "warning",
    findingIds: ["dmarc.p_none", "dmarc.testing"],
    concept: [
      "p=none is the right first step and the wrong permanent state: receivers collect reports for you but take no action against spoofed mail.",
      "t=y (RFC 9989's testing flag, the old pct=0) is the same trap wearing a new tag — the published policy is advisory only.",
    ],
    dataFields: [
      "record.policy = none (or parsed.t = y)",
      "record.is_enforcing = false",
      "record.rua_uris",
    ],
    commands: [
      "checkdmarc <domain> -f json",
      "parsedmarc <report.xml.gz>   # confirm reports are arriving and clean",
      "npx mailauth report message.eml   # verify each sender passes aligned",
    ],
    tools: ["checkdmarc", "parsedmarc (brew install parsedmarc)", "mailauth (npm)"],
    metrics: [
      "Days at p=none (from run history).",
      "Aligned pass-rate from rua reports (future) — the promotion gate.",
    ],
    pathForward: [
      "Confirm the SPF and DKIM categories are green and every legitimate sender passes aligned.",
      "Raise to p=quarantine. Failing mail goes to spam folders, so mistakes are recoverable.",
      "After ≥30 clean days, raise to p=reject. If legit mail ever bounces: step back one notch, fix alignment, re-monitor 2 weeks.",
    ],
  },
  {
    id: "PS-06",
    title: "Partial enforcement (pct<100)",
    hook: "A percentage of failing mail sails through — and the tag is obsolete.",
    severity: "warning",
    findingIds: ["dmarc.pct"],
    concept: [
      "pct=25 applies the policy to a 25% sample — non-deterministic protection, usually an abandoned rollout ramp.",
      "RFC 9989 removed pct entirely; modern receivers may ignore it, so the real-world behavior is unpredictable.",
    ],
    dataFields: ["record.pct", "record.policy", "record.raw_record"],
    commands: ["dig +short TXT _dmarc.<domain>", "checkdmarc <domain>   # flags obsolete pct"],
    tools: ["dig", "checkdmarc"],
    metrics: ["Same promotion gates as PS-05; when reports run clean, go straight to 100%."],
    pathForward: [
      "Confirm reports are clean at the current percentage.",
      "Remove the pct tag — the policy then applies to all mail.",
    ],
  },
  {
    id: "PS-07",
    title: "Subdomain gap (weak sp / missing np)",
    hook: "The apex is locked down while every subdomain stays spoofable.",
    severity: "warning",
    findingIds: ["dmarc.subdomain", "dmarc.np"],
    concept: [
      "p=reject with sp=none protects the exact domain but leaves anything@foo.<domain> wide open — attackers actively probe for exactly this.",
      "np= (RFC 9989) covers subdomains that don't exist in DNS at all — those can never have SPF or DKIM, so np=reject is free protection.",
    ],
    dataFields: ["record.policy", "record.subdomain_policy", "record.np_policy", "record.found_at"],
    commands: [
      "dig +short TXT _dmarc.<domain>   # read sp= and np=",
      "echo _dmarc.mail.<domain> | dnsx -txt -resp   # sweep known subdomains",
    ],
    tools: ["dig", "dnsx", "checkdmarc (warns on ineffective sp)"],
    metrics: ["Regression diff on sp/np changes; count of subdomains with their own records."],
    pathForward: [
      "Add sp=reject (or remove sp= so subdomains inherit p=).",
      "If you never send from non-existent subdomains, add np=reject.",
    ],
  },
  {
    id: "PS-08",
    title: "Strict alignment breaking legitimate mail",
    hook: "adkim=s / aspf=s makes subdomain and ESP mail fail DMARC.",
    severity: "warning",
    findingIds: ["dmarc.adkim_strict", "dmarc.aspf_strict", "dmarc.alignment"],
    concept: [
      "Strict alignment requires the DKIM d= or Return-Path domain to exactly equal the From: domain. Mail signed as mail.<domain> or sent through an ESP stops passing.",
      "The breakage only shows up when the policy is enforced — i.e. at the worst possible time. Relaxed alignment is almost always the right choice.",
    ],
    dataFields: ["record.adkim", "record.aspf"],
    commands: ["npx mailauth report message.eml   # read the alignment verdicts per mechanism"],
    tools: ["mailauth (npm)", "swaks for live test sends (brew install swaks)", "learndmarc.com"],
    metrics: ["Aligned pass-rate split by mechanism (future rua data)."],
    pathForward: [
      "Set adkim=r; aspf=r unless exact-domain matching is a hard requirement.",
      "If strict is required, make every sender use the exact From: domain before enforcing.",
    ],
  },
  {
    id: "PS-09",
    title: "Flying blind (no aggregate reporting)",
    hook: "No rua means no visibility — and no safe way to raise the policy.",
    severity: "warning",
    findingIds: ["dmarc.rua", "dmarc.rua_invalid"],
    concept: [
      "Aggregate (rua) reports are how you see who is sending as your domain and which legitimate streams fail alignment. Without them, enforcing is guesswork.",
      "Dead variants count too: a malformed URI, a mailbox domain with no MX, or a vendor mailbox you stopped paying for.",
    ],
    dataFields: ["record.rua_uris (empty or malformed)"],
    commands: [
      "dig +short MX <rua-domain>",
      "parsedmarc -c parsedmarc.ini   # watch the mailbox end-to-end",
    ],
    tools: ["dig", "parsedmarc"],
    metrics: ["Reports-received-per-week trend once ingestion is live."],
    pathForward: [
      "Add rua=mailto:dmarc@<domain> (or your analytics provider's address).",
      "Send a probe message and confirm a report arrives within ~48 hours.",
    ],
  },
  {
    id: "PS-10",
    title: "Reports going nowhere (unauthorized external destination)",
    hook: "Your rua points off-domain and the destination never consented — reports are silently dropped.",
    severity: "critical",
    findingIds: ["dmarc.external_report_auth"],
    concept: [
      "When rua/ruf point at a different organizational domain, that domain must publish <your-domain>._report._dmarc.<their-domain> = v=DMARC1. Compliant report generators silently skip you otherwise.",
      'This is the classic "we set up DMARC months ago and never got a single report".',
    ],
    dataFields: [
      "record.external_report_auth[] — report_domain, auth_name, authorized",
      "record.external_reports_authorized",
    ],
    commands: [
      "dig +short TXT <domain>._report._dmarc.<report-domain>   # expect v=DMARC1",
      "dig +short TXT '*._report._dmarc.<report-domain>'   # the wildcard big providers publish",
    ],
    tools: ["dig / doggo", "checkdmarc (verifies this natively)"],
    metrics: ["Re-probed every scheduled run; a lost authorization is flagged as a regression."],
    pathForward: [
      'Have the destination publish TXT <your-domain>._report._dmarc.<their-domain> = "v=DMARC1" (report providers document this).',
      "Or point rua= at a mailbox on your own domain instead.",
    ],
  },
  {
    id: "PS-13",
    title: "Forwarding fragility (SPF-only authentication)",
    hook: "Forwarded legit mail will bounce at p=reject unless DKIM carries the pass.",
    severity: "warning",
    findingIds: [],
    concept: [
      "Forwarders change the connecting IP, so SPF fails downstream; mailing lists rewrite content, so DKIM can fail there. A domain whose DMARC pass depends only on SPF breaks for every forwarded message once the policy enforces.",
      "Aligned DKIM on every stream is the fix — a DKIM signature survives forwarding intact.",
    ],
    dataFields: [
      "DKIM category health (see the DKIM checks)",
      "future: rua rows where SPF fails but DKIM passes aligned",
    ],
    commands: [
      "npx mailauth report forwarded-message.eml   # verify DKIM still passes after a forward",
    ],
    tools: ["mailauth", "swaks", "the DKIM check on this domain"],
    metrics: [
      "Share of DMARC passes carried by DKIM vs SPF (future rua data) — DKIM should near 100% before p=reject.",
    ],
    pathForward: [
      "Ensure every sending system DKIM-signs with a d= aligned to your domain.",
      "Test by forwarding a message through a third-party mailbox and re-verifying it.",
    ],
  },
]

/** Problem states matched by the latest run's findings (pm/checks/dmarc.mdx §9 mapping). */
export function matchProblemStates(findings: Finding[]): DmarcProblemState[] {
  return matchStates(DMARC_PROBLEM_STATES, findings)
}

export function problemStateById(id: string): DmarcProblemState | undefined {
  return stateById(DMARC_PROBLEM_STATES, id)
}
