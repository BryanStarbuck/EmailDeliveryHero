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
    id: "PS-00",
    title: "Enforced and healthy",
    hook: "One valid record, enforcing policy, subdomains covered, reports flowing.",
    severity: "ok",
    findingIds: [],
    concept: [
      "The goal state: a single valid record at p=reject (or quarantine en route), subdomains covered by sp=/np=, and aggregate reports flowing to an authorized destination.",
      "Monitoring is permanent, not a phase — new sending streams, vendors, and key rotations keep happening, and the rua reports are how you see them before they bounce.",
    ],
    dataFields: [
      "record.policy / record.subdomain_policy / record.np_policy",
      "record.is_enforcing = true",
      "record.external_reports_authorized = true",
      "tests[] all pass",
    ],
    commands: ["dig +short TXT _dmarc.<domain>", "checkdmarc <domain> -f json"],
    tools: ["dig for a sanity glance", "checkdmarc should agree (valid: true, empty warnings)"],
    metrics: [
      "The scheduled-run regression diff: policy downgrades, new duplicates, lost authorization.",
      "Future rua ingestion adds the real aligned pass-rate trend.",
    ],
    pathForward: [
      "Nothing to fix — keep the record as is.",
      "Keep rua monitoring forever and review the regression diff after each scheduled run.",
    ],
  },
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

/**
 * The ARC problem-state catalog (pm/checks/arc.mdx §10). ARC is DMARC's advisory companion: its
 * `arc.*` findings roll into the DMARC category, so the ARC-nn drill-downs render at the shared
 * /domains/:id/(runs/:runId/)dmarc/:problemId route with the same chrome as the PS-nn pages. The
 * ARC-nn id namespace is disjoint from PS-nn and from the literal `check/` segment. `findingIds`
 * stay empty here — ARC finding ids carry per-forwarder slugs (`arc.selector_dns.<slug>`), so
 * matching goes through the dedicated prefix-aware `matchArcProblemStates` below, per the §10
 * finding → problem map.
 */
export const ARC_PROBLEM_STATES: DmarcProblemState[] = [
  {
    id: "ARC-01",
    title: "ARC signer key unresolvable",
    hook: "The forwarder may be sealing, but no receiver can verify it — the chain is worthless.",
    severity: "critical",
    findingIds: [],
    concept: [
      "The ARC-Seal and ARC-Message-Signature are DKIM-style signatures. Without the public key published at <selector>._domainkey.<signer-domain>, no receiver can verify them — the chain is cryptographically worthless.",
      "Receivers then discard the ARC evidence entirely, and forwarded mail falls back to its raw DMARC failure: under p=quarantine/reject it is spam-foldered or rejected.",
    ],
    dataFields: [
      "arc.forwarders[] — label, forwardAddress, signerDomain (d=), signerSelector (s=)",
      "arc.forwarders[].selectorResolves = false",
      "arc.forwarders[].rawKeyRecord (present when the key is revoked rather than missing)",
    ],
    commands: [
      "doggo <selector>._domainkey.<signer-domain> TXT --json",
      "dig +short TXT <selector>._domainkey.<signer-domain>",
      "kdig @8.8.8.8 +short TXT <selector>._domainkey.<signer-domain>",
    ],
    tools: ["doggo / dig / kdig (brew install doggo bind knot)"],
    metrics: [
      "The scheduled-run regression diff flags a signer selector that stops resolving as a new problem.",
    ],
    pathForward: [
      'If you operate the sealer: generate a 2048-bit key (openssl genrsa -out arc.private.pem 2048) and publish the TXT record <selector>._domainkey.<signer-domain> "v=DKIM1; k=rsa; p=<base64 public key>".',
      "If it is a third-party forwarder: report the broken key to them, pasting the failing query name and the empty answer as evidence.",
      "Verify with doggo <selector>._domainkey.<signer-domain> TXT --json, wait out the TTL, then re-run the audit.",
    ],
  },
  {
    id: "ARC-02",
    title: "Weak or legacy ARC signer key",
    hook: "Verifiers increasingly refuse <1024-bit or non-rsa/ed25519 keys — the chain erodes receiver by receiver.",
    severity: "warning",
    findingIds: [],
    concept: [
      "RFC 8301 sets the minimums for DKIM-style signatures (which ARC's AMS/AS mirror): rsa-sha256 with at least a 1024-bit key (2048-bit recommended), or ed25519-sha256. SHA-1 and short RSA keys are forgeable.",
      "Receivers increasingly hard-fail weak keys, so the chain's protection quietly disappears one receiver at a time even though the seal still 'exists'.",
    ],
    dataFields: [
      "arc.forwarders[].keyType (parsed k=)",
      "arc.forwarders[].keyBits (estimated RSA modulus)",
      "arc.forwarders[].rawKeyRecord",
    ],
    commands: [
      "dig +short TXT <selector>._domainkey.<signer-domain>",
      "dig +short TXT <selector>._domainkey.<signer-domain> | tr -d '\" ' | sed 's/.*p=//' | openssl base64 -d -A | openssl rsa -pubin -inform der -noout -text | head -1",
    ],
    tools: ["dig", "openssl (decode the modulus and read its bit length)"],
    metrics: ["keyBits per forwarder across runs — it should only ever go up."],
    pathForward: [
      "Reissue the ARC signing key at 2048-bit RSA (openssl genrsa -out arc.private.pem 2048) or ed25519.",
      'Republish the public key at <selector>._domainkey.<signer-domain> ("v=DKIM1; k=rsa; p=<base64>").',
      'For a third-party signer, ask them to reissue — prefix each step with "ask <forwarder> to…".',
    ],
  },
  {
    id: "ARC-03",
    title: "Unverified forwarding path",
    hook: "Enforcing DMARC + forwarding with no verified ARC chain — silent losses on that path.",
    severity: "warning",
    findingIds: [],
    concept: [
      'The classic silent failure: the domain enforces DMARC (p=quarantine/reject) and sends through a mailing list or forwarder, but no valid ARC chain has been verified on that path. Forwarding breaks SPF alignment and often the DKIM signature, so legitimate forwarded mail fails DMARC at delivery — "some recipients never get our mail, but only via list X."',
      "Until each forwarder demonstrably seals a valid chain (cv=pass), assume mail through it is being quarantined or rejected at strict receivers.",
    ],
    dataFields: [
      "arc.applicable = true / arc.forwardingRisk = true",
      "arc.forwarders[] — the declared paths with per-row signer/verification status",
      "arc.dmarcPolicy — the enforcing policy that makes this matter",
    ],
    commands: [
      'swaks --to <list-address> --from probe@<domain> --server <mx> --h-Subject "EDH-ARC-test"   # sends REAL mail — use a list you registered',
      "grep -iA2 'ARC-Seal' <delivered-message.eml>   # look for cv=pass on the forwarded copy",
    ],
    tools: [
      "swaks (brew install swaks) — send a test message through the path",
      "any mailbox you control on the far side of the forwarder to inspect the delivered headers",
    ],
    metrics: ["Each forwarder's verification status across runs; probeSentAt once the capture probe ships."],
    pathForward: [
      "If no forwarders are registered yet, add each one (label + forwarding address + signer d=/s= if known) in the domain's ARC / forwarding settings.",
      "If you run the list (Mailman 3): enable ARC sealing — [ARC] enabled: yes; authserv_id + domain + selector + privkey in /etc/mailman3/mailman.cfg.",
      "If it is third-party (Google Groups, a listserv): ask them to enable ARC sealing and tell you the d=/s= they sign with; record those in settings so the key check runs here. Google Groups and Microsoft 365 seal by default — record their observed signer once a sample exists.",
      "Verify manually: forward a test message through the path and inspect its headers for ARC-Seal … cv=pass.",
    ],
  },
  {
    id: "ARC-04",
    title: "ARC not applicable / not yet determined",
    hook: "No enforcing DMARC or no forwarding declared — there is nothing for ARC to rescue.",
    severity: "info",
    findingIds: [],
    concept: [
      "ARC only matters when both gates are open: the domain enforces DMARC (p=quarantine/reject) AND its mail passes through forwarders or mailing lists that mutate messages. At p=none nothing is rejected, so there is nothing for ARC to override; directly-sent mail never needs ARC.",
      "The caveat: if the domain actually does send through lists it has not declared, losses are invisible — declaring the forwarders is what turns the checks on.",
    ],
    dataFields: [
      "arc.applicable / arc.forwardingRisk",
      "arc.dmarcPolicy + arc.policySource (sibling dmarc result or fallback DNS lookup)",
      "arc.notes (set when applicability could not be evaluated transiently)",
    ],
    commands: ["doggo _dmarc.<domain> TXT --json"],
    tools: ["doggo / dig"],
    metrics: ["An applicability flip (p moves to enforcing, or forwarding gets declared) is logged by the scheduler but never worsens the cell on its own."],
    pathForward: [
      "Nothing to do for ARC right now.",
      "Revisit when moving to p=quarantine/reject, or when mail starts flowing through a list/forwarder — declare it in the domain's ARC / forwarding settings.",
      'If this run shows "could not determine", retry the audit (transient DNS failure).',
    ],
  },
  {
    id: "ARC-05",
    title: "ARC chain not yet sampled",
    hook: "The chain checks need a real forwarded message — none has been captured yet.",
    severity: "info",
    findingIds: [],
    concept: [
      "ARC is not a DNS record: the chain lives in three headers (ARC-Seal / ARC-Message-Signature / ARC-Authentication-Results) added to a message in transit. Verifying chain presence, cv=, signatures, and instance ordering requires a captured forwarded message.",
      "The capture probe (future, admin-only) sends a swaks test through a declared forwarder to a mailbox we control, then parses and validates the delivered copy's ARC headers. Until then, a manual forward-and-inspect answers the same question.",
    ],
    dataFields: [
      "arc.messageSampleId = null / arc.probeSentAt = null",
      "arc.chainPresent / chainLength / cvResult / sealValid / amsValid / instancesOk / oldestPass — all null until sampled",
      "arc.forwarders[] — the declared probe targets",
    ],
    commands: [
      "grep -iA2 'ARC-' <delivered-message.eml>   # inspect a manually-forwarded copy",
      "npx mailauth report <delivered-message.eml>",
    ],
    tools: ["mailauth (npm) — parses and verifies ARC/DKIM/SPF on a saved .eml", "swaks"],
    metrics: ["probeSentAt per (domain, forwarder) once the probe ships — throttled to at most one probe per forwarder per audit."],
    pathForward: [
      'Run the admin-only "Capture sample…" probe when it ships (it sends real mail, so it is gated and throttled).',
      "Meanwhile: forward a test message through each declared path manually and inspect the delivered headers for ARC-Seal … cv=pass (the ARC-03 confirmation steps).",
    ],
  },
  {
    id: "ARC-06",
    title: "Broken or invalid ARC chain (future)",
    hook: "cv=fail, an invalid AMS, or out-of-order instances — receivers discard the whole chain.",
    severity: "critical",
    findingIds: [],
    concept: [
      "RFC 8617 §5.2: a chain is valid only if every seal verifies over the cumulative chain, the newest cv= is pass, each hop has exactly one AS/AMS/AAR, and the i= sequence is contiguous from 1. Any structural failure makes receivers discard the ARC evidence and fall back to the raw DMARC failure.",
      "An i=1 seal must carry cv=none (there is no prior chain to validate); and ARC cannot rescue mail that already failed authentication at origin — the i=1 AAR must show a pass worth preserving.",
    ],
    dataFields: [
      "arc.cvResult / sealValid / amsValid / instancesOk / oldestPass",
      "arc.instances[] — per-hop {i, d, s, ams_valid, as_cv, aar}, failing hop tinted in the explainer",
      "arc.messageSampleId — the captured .eml the verdicts came from",
    ],
    commands: [
      "npx mailauth report <sample.eml>",
      "arcverify < <sample.eml>   # OpenARC",
    ],
    tools: ["mailauth (npm)", "OpenARC (arcsign/arcverify)"],
    metrics: ["cv= across captured samples per forwarder — a pass→fail flip is a regression the scheduler flags."],
    pathForward: [
      "Identify the failing hop from the per-hop instances table and fix that sealer: clock skew, header/body mutation after sealing, or the wrong key. Place the sealer last in the pipeline.",
      "If the i=1 AAR shows the message already failed at origin, fix origin authentication first — see the DKIM and DMARC categories; ARC cannot rescue mail that never passed.",
      "Re-capture a sample through the path until cv=pass.",
    ],
  },
]

/** Problem states matched by the latest run's findings (pm/checks/dmarc.mdx §9 mapping). */
export function matchProblemStates(findings: Finding[]): DmarcProblemState[] {
  return matchStates(DMARC_PROBLEM_STATES, findings)
}

/**
 * The §10 finding → problem map (pm/checks/arc.mdx): every `arc.*` finding id the checker emits
 * maps to exactly one ARC-nn state. Ids carry per-forwarder slugs, so matching is prefix-aware,
 * and — unlike the generic warning/critical matcher — the N/A + not-sampled info findings DO
 * surface their cards (they are real results, not noise). The healthy "ARC applies" info maps to
 * no card (context row only).
 */
export function arcProblemIdFor(f: Finding): string | null {
  if (f.checkId !== "arc") return null
  if (f.id.startsWith("arc.selector_dns")) {
    // critical = NXDOMAIN / revoked p= (ARC-01); info = signer-unknown (ARC-03, no evidence
    // recorded) vs transient lookup failure (ARC-04, evidence = the query name).
    if (f.severity === "critical") return "ARC-01"
    if (f.severity === "info") return f.evidence ? "ARC-04" : "ARC-03"
    return null
  }
  if (f.id.startsWith("arc.signature_algorithm"))
    return f.severity === "warning" ? "ARC-02" : null
  if (f.id.startsWith("arc.forwarding_risk"))
    return f.severity === "warning" || f.severity === "critical" ? "ARC-03" : null
  if (f.id === "arc.applicable") {
    // "ARC applies" (the healthy info) gets no card; N/A and could-not-determine map to ARC-04.
    return f.severity !== "ok" && !f.title.includes("applies") ? "ARC-04" : null
  }
  if (f.id.startsWith("arc.chain_present")) return "ARC-05"
  if (
    f.id.startsWith("arc.seal_valid") ||
    f.id.startsWith("arc.ams_valid") ||
    f.id.startsWith("arc.instance_ordering") ||
    f.id.startsWith("arc.cv_at_i1") ||
    f.id.startsWith("arc.oldest_pass") ||
    f.id.startsWith("arc.aar_completeness") ||
    f.id.startsWith("arc.receiver_honors")
  ) {
    // Future sample-derived ids — advisory infos ride along as context on the same page.
    return "ARC-06"
  }
  return null
}

export function matchArcProblemStates(findings: Finding[]): DmarcProblemState[] {
  const matched = new Set<string>()
  for (const f of findings) {
    const id = arcProblemIdFor(f)
    if (id) matched.add(id)
  }
  return ARC_PROBLEM_STATES.filter((ps) => matched.has(ps.id))
}

/** Looks up PS-nn and ARC-nn states alike — both render at the shared /dmarc/:problemId route. */
export function problemStateById(id: string): DmarcProblemState | undefined {
  return stateById(DMARC_PROBLEM_STATES, id) ?? stateById(ARC_PROBLEM_STATES, id)
}
