/**
 * The DKIM problem-state catalog (pm/checks/dkim.mdx §9). Each state matches on finding-id
 * PREFIXES from the latest run (DKIM finding ids are suffixed `.<selector>`) and carries the
 * drill-down content rendered at /domains/:id/dkim/:problemId: concept, diagnose-it-yourself
 * commands, tools, extra health metrics, and the path forward. PS-13…PS-16 are future
 * (message/rua layers) and intentionally absent.
 */
import type { Finding } from "@/api/types"

export interface DkimProblemState {
  id: string
  title: string
  /** One-line hook shown on the problem-state card. */
  hook: string
  severity: "ok" | "info" | "warning" | "critical"
  /** Finding-id prefixes whose presence at warning/critical severity matches this state. */
  findingPrefixes: string[]
  /** 2–3 short paragraphs explaining the concept. */
  concept: string[]
  /** Which test-result fields to look at (pm/checks/dkim.mdx §5). */
  dataFields: string[]
  /** Copyable terminal commands to diagnose it yourself (<domain>/<selector> substituted). */
  commands: string[]
  tools: string[]
  /** Further health metrics to watch. */
  metrics: string[]
  /** Numbered steps to progress forward. */
  pathForward: string[]
}

export const DKIM_PROBLEM_STATES: DkimProblemState[] = [
  {
    id: "PS-01",
    title: "Selector not published (no key in DNS)",
    hook: 'Every message signed with this selector fails at every receiver — permerror "no key for signature".',
    severity: "critical",
    findingPrefixes: ["dkim.present", "dkim.cname_delegation"],
    concept: [
      "Mail signed with this selector carries a DKIM-Signature that every receiver tries — and fails — to verify, because the public key was never published at <selector>._domainkey.<domain>. That is worse than not signing at all.",
      "The classic causes: the ESP was set up to sign but the DNS record was never added at the registrar, a selector typo, or signing was rotated to a selector whose record was later deleted.",
    ],
    dataFields: [
      "selectors[].present = false",
      "selectors[].query_name",
      "selectors[].resolved_via / cname_target (when the failure is a dead delegation)",
    ],
    commands: [
      "dig +short TXT <selector>._domainkey.<domain>",
      "kdig @8.8.8.8 +short TXT <selector>._domainkey.<domain>",
      "dig +short CNAME <selector>._domainkey.<domain>",
    ],
    tools: [
      "dig / kdig / doggo (brew install bind knot doggo)",
      "your ESP dashboard — it displays the exact record it expects",
    ],
    metrics: [
      "The regression diff flags a selector that was present last run and is missing now.",
      "(future) rua reports show permerror counts per selector.",
    ],
    pathForward: [
      "Copy the exact TXT value (or CNAME target) from your provider's dashboard.",
      "Publish it at exactly <selector>._domainkey.<domain> — watch for consoles that auto-append the domain.",
      "Re-run the audit and confirm the selector card turns green.",
    ],
  },
  {
    id: "PS-02",
    title: "Record unparseable (bad base64 / syntax)",
    hook: "A record exists but verifiers can't extract a key — permerror, same as no key.",
    severity: "critical",
    findingPrefixes: ["dkim.parses"],
    concept: [
      "The record is published but corrupt: PEM -----BEGIN…----- armor pasted into DNS, smart quotes, line breaks injected mid-key, a truncated paste, or malformed tags. Verifiers return permerror (key syntax error / bad base64).",
      "The net effect is identical to publishing no key: every signed message fails.",
    ],
    dataFields: [
      "selectors[].parses = false (with present = true)",
      "selectors[].raw_record — read it character by character",
      "selectors[].txt_record_count / oversize_chunk",
    ],
    commands: [
      "dig +short TXT <selector>._domainkey.<domain>",
      "dig +short TXT <selector>._domainkey.<domain> | tr -d '\" ' | grep -o 'p=[^;]*' | cut -c3- | base64 -d | openssl pkey -pubin -inform DER -text -noout",
    ],
    tools: [
      "dig + openssl@3 (brew install bind openssl@3) — openssl's error names the corruption",
      "dkimverify (pipx install dkimpy) against a saved message for a second opinion",
    ],
    metrics: ["The regression diff surfaces any change to raw_record."],
    pathForward: [
      "Export the public key from the signing system again.",
      "Publish it as one logical string: no PEM header/footer, no quotes-in-quotes, no newlines.",
      "Re-run the audit; the openssl one-liner should now print the key type and size.",
    ],
  },
  {
    id: "PS-03",
    title: "Revoked key still configured (empty p=)",
    hook: "An empty p= means the key is revoked — fatal if mail still signs with this selector.",
    severity: "critical",
    findingPrefixes: ["dkim.revoked"],
    concept: [
      "RFC 6376 §3.6.1: an empty p= value means this public key has been revoked. That is the correct final step of a key rotation — but if the signer still uses the selector, every message hard-fails.",
      "The audit treats a revoked configured selector as critical and a revoked merely-discovered selector as informational (proper decommissioning).",
    ],
    dataFields: ["selectors[].is_revoked = true", "selectors[].source", "selectors[].raw_record"],
    commands: ["dig +short TXT <selector>._domainkey.<domain>   # expect v=DKIM1; p= (empty)"],
    tools: [
      "dig",
      'Gmail "Show original" on a fresh outbound message — read the s= the signer actually uses',
    ],
    metrics: ["None — either re-key or retire the selector."],
    pathForward: [
      "Check which selector your mail actually signs with (the s= tag in a real DKIM-Signature header).",
      "If it is this one: point the signer at a live selector, or republish a valid key.",
      "If nothing signs with it anymore: remove it from the monitored selector list.",
    ],
  },
  {
    id: "PS-04",
    title: "Weak RSA key (<2048-bit)",
    hook: "1024-bit is below today's standard; sub-1024 keys are practically factorable.",
    severity: "warning",
    findingPrefixes: ["dkim.keylength"],
    concept: [
      "In 2012, mathematician Zachary Harris factored Google's then-512-bit DKIM key for about $75 of cloud time and spoofed mail between the founders (US-CERT VU#268267). Google moved to 2048-bit within days.",
      "RFC 8301 requires at least 1024 bits and recommends 2048. Several receivers refuse sub-1024 keys outright, and 1024-bit keys are a negative trust signal. Avoid 4096 — it breaks 255-byte TXT chunking at some DNS hosts.",
    ],
    dataFields: ["selectors[].key_bits", "selectors[].key_type", "selectors[].first_seen_at"],
    commands: [
      "dig +short TXT <selector>._domainkey.<domain> | tr -d '\" ' | grep -o 'p=[^;]*' | cut -c3- | base64 -d | openssl pkey -pubin -inform DER -text -noout | head -1",
    ],
    tools: [
      "dig + openssl@3 — the first output line is the verdict (e.g. RSA Public-Key: (2048 bit))",
      "your provider's key-length setting (Google Admin lets you pick 2048)",
    ],
    metrics: [
      "The duplicate-key table — one weak key is often cloned across domains; fix all at once.",
    ],
    pathForward: [
      "Generate a 2048-bit key at the provider and publish it on a NEW selector.",
      "Switch signing to the new selector once the record is visible.",
      "Keep the old record 7–30 days for in-flight mail, then revoke it (empty p=).",
    ],
  },
  {
    id: "PS-05",
    title: "Test mode left on (t=y)",
    hook: "Receivers must treat your mail as UNSIGNED while t=y is set.",
    severity: "warning",
    findingPrefixes: ["dkim.testflag"],
    concept: [
      "t=y tells verifiers the domain is testing DKIM — RFC 6376 requires them to treat the mail as if it were unsigned for policy purposes. No DMARC credit, no reputation benefit; the signature buys nothing.",
      "Don't confuse it with t=s (strict), which forbids subdomain identities and is only informational.",
    ],
    dataFields: ["selectors[].has_test_flag", "selectors[].has_strict_flag", "selectors[].flags.t"],
    commands: ["dig +short TXT <selector>._domainkey.<domain> | grep -o 't=[^;]*'"],
    tools: ["dig", "your DNS console — removing the flag is a one-tag edit"],
    metrics: [
      "The regression diff flags has_test_flag flipping back to true (a provider reset is the usual culprit).",
    ],
    pathForward: [
      "Confirm signing works (a probe message passes at a seed mailbox).",
      "Remove the y flag from the t= tag — or drop the t= tag entirely.",
    ],
  },
  {
    id: "PS-06",
    title: "SHA-1 restriction (h=sha1)",
    hook: "RFC 8301 forbids SHA-1 — such signatures permanently fail at modern receivers.",
    severity: "critical",
    findingPrefixes: ["dkim.algorithm"],
    concept: [
      "SHA-1 is collision-broken. RFC 8301 (2018) forbids rsa-sha1 for signing and verifying; signatures restricted to it have permanently failed evaluation.",
      "A key record with h=sha1 pins the key to the dead algorithm even if the signer could do better.",
    ],
    dataFields: ["selectors[].flags.h", "selectors[].key_type"],
    commands: [
      "dig +short TXT <selector>._domainkey.<domain> | grep -o 'h=[^;]*'",
      "npx mailauth report message.eml   # (future) shows the a= algorithm actually used per message",
    ],
    tools: ["dig", "mailauth (npm) for the message-side view"],
    metrics: ["None — remove and re-sign."],
    pathForward: [
      "Remove h=sha1 from the key record (or set h=sha256).",
      "Make sure the signer uses rsa-sha256 (every modern MTA/ESP default).",
    ],
  },
  {
    id: "PS-07",
    title: "Dangling CNAME delegation",
    hook: "The CNAME stayed, the ESP target vanished — permerror plus a takeover risk.",
    severity: "critical",
    findingPrefixes: ["dkim.cname_delegation"],
    concept: [
      "Delegated selectors (SendGrid, Microsoft 365, Mailchimp, SES style) die when the ESP account is closed or migrated: the CNAME remains in your zone while its target no longer resolves — every signed message fails with permerror.",
      "A stale vendor CNAME is also a subdomain-takeover risk: whoever re-registers the target can publish their own key under your name.",
    ],
    dataFields: [
      "selectors[].resolved_via = cname",
      "selectors[].cname_target",
      "selectors[].present = false",
    ],
    commands: [
      "dig +short CNAME <selector>._domainkey.<domain>",
      "dig +short TXT $(dig +short CNAME <selector>._domainkey.<domain>)",
    ],
    tools: ["dig / doggo (follows chains)", "the ESP dashboard's current target value"],
    metrics: [
      "The regression diff flags cname_target changes — an ESP-side migration shows up here before mail breaks.",
    ],
    pathForward: [
      "Open the ESP dashboard and copy the exact CNAME target it currently lists.",
      "Re-point the CNAME — or delete it if that ESP is decommissioned.",
      "Re-run the audit and confirm the chain resolves to a key.",
    ],
  },
  {
    id: "PS-08",
    title: "DNS pathologies (multi-TXT / oversize / wildcard)",
    hook: "Undefined verifier behavior, intermittent temperrors, or wildcard junk answering every selector.",
    severity: "warning",
    findingPrefixes: ["dkim.single_record", "dkim.record_size", "dkim.underscore_label"],
    concept: [
      "Three record-shape faults break verification sideways. Multiple TXT records at one selector: RFC 6376 §3.6.2.2 says results are undefined — some receivers pick the wrong one. Oversize strings (>255 bytes, or 4096-bit keys) trip UDP truncation → intermittent temperror.",
      "A wildcard *.<domain> TXT answers every _domainkey query with junk: receivers permerror, and discovery tools 'find' selectors that don't exist.",
    ],
    dataFields: [
      "selectors[].txt_record_count (want exactly 1)",
      "selectors[].oversize_chunk",
      "wildcard_shadow (domain level)",
    ],
    commands: [
      "dig TXT <selector>._domainkey.<domain> +multiline   # count answers, see string splits",
      "dig +tcp TXT <selector>._domainkey.<domain>   # differs from UDP → truncation",
      "dig +short TXT zz-random._domainkey.<domain>   # an answer = wildcard pollution",
    ],
    tools: ["dig", "dnsx for sweeping candidate names (brew install dnsx)"],
    metrics: [
      "(future) temperror clusters at one receiver (often Microsoft) in rua data correlate with truncation.",
    ],
    pathForward: [
      "Keep exactly one TXT (or one CNAME) per selector name — delete the extras.",
      "Split long p= values into ≤255-byte quoted strings; prefer 2048-bit RSA over 4096.",
      "Scope or remove any wildcard TXT so it no longer covers *._domainkey.",
    ],
  },
  {
    id: "PS-09",
    title: "No rotation headroom / stale key",
    hook: "One selector and an old key: the next rotation is an outage, and exposure accumulates.",
    severity: "warning",
    findingPrefixes: ["dkim.multi", "dkim.rotation"],
    concept: [
      "Long-lived private keys accumulate exposure — backups, tickets, ex-employees, breached ESPs — and can silently produce valid forged signatures until retired. M3AAWG guidance: rotate at least every 6 months.",
      "With a single selector, rotation means an outage window. The dual-selector pattern (Microsoft 365's selector1/selector2) makes it a cutover instead.",
    ],
    dataFields: [
      "working_selectors",
      "selectors[].first_seen_at (age survives across runs per selector+key)",
    ],
    commands: [
      "dig +short TXT <selector>._domainkey.<domain>   # sanity-check both selectors during cutover",
    ],
    tools: [
      "the app's own run history is the age instrument",
      "dknewkey (pipx install dkimpy) or the provider console to mint the next key",
    ],
    metrics: ["Key age per selector — an info fires at ~150 days, the warning at 180."],
    pathForward: [
      "Publish the next key on a NEW selector at least 48 hours before using it.",
      "Switch signing to the new selector.",
      "Keep the old record 7–30 days for in-flight mail, then revoke it (empty p=).",
    ],
  },
  {
    id: "PS-10",
    title: "Same key shared across domains",
    hook: "One private key signs several domains — one compromise spoofs every brand.",
    severity: "warning",
    findingPrefixes: ["dkim.duplicate_key"],
    concept: [
      "Identical public keys on several domains (or selectors) mean one private key signs them all: one compromise — or one bad neighbor's reputation — hits every brand at once.",
      "It usually happens when a working key pair is copied to a new domain, or an ESP issues one key for many customers.",
    ],
    dataFields: [
      "duplicate_keys[] — key_sha256 and every domain/selector sighting",
      "selectors[].key_sha256",
    ],
    commands: [
      "dig +short TXT <selector>._domainkey.<domain> | tr -d '\" ' | grep -o 'p=[^;]*'   # diff the p= across domains",
    ],
    tools: ["the duplicate-key list on this page", "openssl for manual confirmation"],
    metrics: ["New cross-domain collisions are flagged by the regression diff."],
    pathForward: [
      "Generate a unique key pair for each domain (and each rotation generation).",
      "Roll the shared key out of every domain that uses it, one rotation at a time.",
    ],
  },
  {
    id: "PS-11",
    title: "Ed25519-only signing",
    hook: "Gmail, Microsoft, and Yahoo can't verify Ed25519 — alone, it's effectively unsigned.",
    severity: "warning",
    findingPrefixes: ["dkim.ed25519_only"],
    concept: [
      "RFC 8463's Ed25519 keys are smaller and faster — but only about half of verifiers support them. Gmail returns dkim=neutral (treats the key as nonexistent), Microsoft 365 errors, Yahoo permfails.",
      "Verifiers accept a message if ANY signature validates, so the correct deployment is dual-signing: RSA-2048 primary, Ed25519 secondary, each on its own selector.",
    ],
    dataFields: ["selectors[].key_type per selector", "working_selectors"],
    commands: ["dig +short TXT <selector>._domainkey.<domain> | grep -o 'k=[^;]*'"],
    tools: ["dig", "mailauth (npm) — shows both signatures' verdicts per message (future)"],
    metrics: ["Receiver Ed25519 support is external — revisit annually."],
    pathForward: [
      "Add an RSA-2048 key on a new selector.",
      "Configure the signer to dual-sign (RSA + Ed25519).",
    ],
  },
  {
    id: "PS-12",
    title: "No selectors known — mail likely unsigned",
    hook: "Nothing configured and discovery found nothing: probably no DKIM at all.",
    severity: "warning",
    findingPrefixes: ["dkim.unsigned"],
    concept: [
      "Selectors cannot be enumerated from DNS, and discovery probed dozens of common names without a hit. Either the domain does not sign at all — which Gmail/Yahoo (2024) and Microsoft's outlook.com enforcement (May 2025) penalize for bulk senders — or it signs with a custom selector no wordlist can know (Amazon SES's random tokens, custom names).",
      "The definitive source is a real message: the s= and d= tags of its DKIM-Signature header.",
    ],
    dataFields: [
      "selectors_configured = []",
      "discovery_ran = true with zero selectors",
      "wildcard_shadow",
    ],
    commands: [
      "dig +short MX <domain>   # the MX names the provider, the provider names the selector",
      "echo google._domainkey.<domain> | dnsx -txt -resp   # sweep your own candidate names",
    ],
    tools: [
      'Gmail "Show original" on a message you send yourself — read the DKIM-Signature s= tag',
      "your provider's admin console (DKIM status page)",
    ],
    metrics: ["None until a selector is known."],
    pathForward: [
      "Send yourself a message and open it with Gmail's Show original.",
      "If there is a DKIM-Signature: copy its s= value into the selectors editor above.",
      "If there is none: enable DKIM at your provider (Google Admin → Authenticate email; M365 Defender → DKIM; your ESP's Domain Authentication), then add the selector here.",
    ],
  },
]

/** Problem states matched by the latest run's findings (pm/checks/dkim.mdx §9 mapping). */
export function matchProblemStates(findings: Finding[]): DkimProblemState[] {
  const failing = findings
    .filter((f) => f.severity === "warning" || f.severity === "critical")
    .map((f) => f.id)
  return DKIM_PROBLEM_STATES.filter((ps) =>
    ps.findingPrefixes.some((prefix) =>
      failing.some((id) => id === prefix || id.startsWith(`${prefix}.`)),
    ),
  )
}

export function problemStateById(id: string): DkimProblemState | undefined {
  return DKIM_PROBLEM_STATES.find((ps) => ps.id === id)
}
