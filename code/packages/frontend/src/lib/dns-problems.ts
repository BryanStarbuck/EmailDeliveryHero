/**
 * The DNS & Infrastructure problem-state catalog (pm/checks/dns.mdx §9). Each state matches on
 * finding-id PREFIXES from the latest run (many infra ids carry a `.<host>` / `.<ip>` suffix) and
 * carries the drill-down content rendered at /domains/:id/dns/:problemId: concept,
 * diagnose-it-yourself commands, tools, extra health metrics, and the path forward.
 * PS-12 (split answers / resolver divergence) is future and intentionally absent.
 */
import type { Finding } from "@/api/types"

export interface DnsProblemState {
  id: string
  title: string
  /** One-line hook shown on the problem-state card. */
  hook: string
  severity: "ok" | "info" | "warning" | "critical"
  /** Id prefixes (after "infra.") whose warning/critical presence matches this state. */
  findingPrefixes: string[]
  /** 2–3 short paragraphs explaining the concept. */
  concept: string[]
  /** Which test-result fields to look at (pm/checks/dns.mdx §5). */
  dataFields: string[]
  /** Copyable terminal commands to diagnose it yourself. */
  commands: string[]
  tools: string[]
  /** Further health metrics to watch. */
  metrics: string[]
  /** Numbered steps to progress forward. */
  pathForward: string[]
}

export const DNS_PROBLEM_STATES: DnsProblemState[] = [
  {
    id: "PS-00",
    title: "Plumbing healthy end to end",
    hook: "The goal state — now the job is keeping it, because infrastructure rots quietly.",
    severity: "ok",
    // The healthy state matches by ABSENCE of warning/critical findings (pm/checks/dns.mdx §9),
    // not by prefix — matchDnsProblemStates special-cases it.
    findingPrefixes: [],
    concept: [
      "Routable redundant MX, FCrDNS closed on every IP in both address families, TLS on every MX, diverse honest nameservers, sane SOA/TTLs, a signed zone, and a locked mature registration — every hard receiver gate passes and nothing is eroding reputation.",
      "Infrastructure rots quietly: certificates expire, providers change PTRs during migrations, secondaries fall out of sync, RRSIGs slide toward expiry, and registrar changes drift the parent NS set. The scheduled-run regression diff exists to catch exactly these silent regressions.",
    ],
    dataFields: [
      "families.*.status = ok — every family chip green",
      "mx_routing / reverse_dns / dns_health / dnssec snapshots all clean",
    ],
    commands: [
      "dig MX <domain> +short   # the sanity glance",
      "checkdmarc <domain> -f json   # the cross-validation oracle should agree",
    ],
    tools: [
      "checkdmarc (brew install checkdmarc)",
      "Zonemaster (zonemaster.net) and internet.nl for the public scorecards",
    ],
    metrics: [
      "The scheduled-run regression diff — a lost PTR, an expired cert, NS drift, or RRSIG expiry are all silent regressions.",
      "The registrar expiry countdown.",
    ],
    pathForward: [
      "Keep registrar auto-renew and the transfer lock on.",
      "Keep scheduled re-runs enabled — regressions are the real enemy now.",
      "Watch RRSIG expiry and certificate renewals; verify DANE TLSA records after every cert rotation.",
    ],
  },
  {
    id: "PS-01",
    title: "Broken inbound mail routing",
    hook: "MX records are the world's route to you — and to your bounces and DMARC reports.",
    severity: "critical",
    findingPrefixes: [
      "mx_present",
      "mx_resolve",
      "mx_not_cname",
      "mx_public_ip",
      "mx_localhost",
      "mx_null",
      "mx_matches_a",
      "mx_trailing_dot",
      "mx_a_consistency",
      "mx_priority",
      "mx_redundancy",
      "mx_dup_targets",
      "mx_target_count",
    ],
    concept: [
      "An absent, dangling, CNAME'd, or private-IP MX doesn't just break inbound mail: receivers check that the From: domain has a valid MX or A record (a Gmail requirement), and a domain that can't take bounces or feedback-loop mail accumulates reputation damage invisibly.",
      'RFC 5321 §5.1 and RFC 2181 §10.3 forbid MX targets that are CNAMEs; RFC 7505\'s null MX (MX 0 ".") declares a domain no-mail and must be the only MX record when used.',
    ],
    dataFields: [
      "mx_routing.mx_found / null_mx / implicit_a_fallback",
      "mx_routing.hosts[] — host, priority, is_cname, ips, non_public[]",
      "mx_routing.redundancy — host_count, network_count",
    ],
    commands: [
      "dig MX <domain> +short",
      "dig A mx1.<domain> +short && dig AAAA mx1.<domain> +short",
      "dig CNAME mx1.<domain> +short   # must be empty",
      "kdig @8.8.8.8 MX <domain> +short   # does a public resolver agree?",
    ],
    tools: [
      "dig / kdig / doggo (brew install bind knot doggo)",
      "dnsx for bulk sweeps (brew install dnsx)",
      "intoDNS (intodns.com) for the classic delegation report",
    ],
    metrics: ["Future probe adds port-25 reachability and SMTP banner per MX host."],
    pathForward: [
      'Publish 1–3 MX records with distinct priorities, e.g. "<domain>. IN MX 10 mx1.<domain>." and "<domain>. IN MX 20 mx2.<domain>.".',
      "Make every target an FQDN with its own public A/AAAA — never a CNAME, never an internal IP.",
      "Put the second host on a different network/provider so one outage doesn't stop all inbound mail.",
      'If the domain truly sends no mail, publish the full deny set instead: MX 0 ".", "v=spf1 -all", and DMARC p=reject.',
    ],
  },
  {
    id: "PS-02",
    title: "Reverse-DNS failure",
    hook: "FCrDNS is a hard Gmail/Microsoft gate — fail it and mail is rejected, not filtered.",
    severity: "critical",
    findingPrefixes: [
      "ptr_present",
      "ptr_ipv6",
      "fcrdns",
      "ptr_single",
      "ptr_generic",
      "ptr_no_ip_literal",
      "ptr_tld_valid",
    ],
    concept: [
      "Forward-confirmed reverse DNS is the oldest infrastructure trust test: the connecting IP must have a PTR, and that PTR hostname must resolve back to the same IP. Gmail rejects failures with a permanent 550-5.7.25 (enforced since late 2025); Yahoo requires a non-generic hostname reflecting your domain; Microsoft enforces it for dedicated IPs.",
      "The killer variant: your MTA has an AAAA record, Gmail prefers the IPv6 path, and only the IPv4 PTR exists — mail the IPv4 path would deliver gets rejected over IPv6.",
      "PTR records live in the IP owner's reverse zone, not your domain's zone — the fix is a hosting-provider request, not a DNS edit at your registrar.",
    ],
    dataFields: [
      "reverse_dns.ips[] — ip, source (mx | sending_ip), ptr, forward_confirmed, generic",
    ],
    commands: [
      "dig -x <ip> +short   # expect exactly one hostname",
      "dig A <ptr-hostname> +short   # must include the IP (AAAA for v6)",
      "asn <ip>   # who owns the block = who you file the PTR ticket with",
    ],
    tools: [
      "dig (brew install bind)",
      "asn (brew install asn)",
      "swaks to observe the live rejection text (brew install swaks)",
    ],
    metrics: ["Future SMTP probe compares the MTA's HELO/EHLO name to the PTR hostname."],
    pathForward: [
      "Ask the IP owner (hosting provider/ISP) to set the PTR: <ip> → mail.<domain>.",
      "Publish the matching forward record: mail.<domain> A/AAAA <ip>, so the loop closes.",
      "Repeat for every IPv6 address — or disable outbound IPv6 on the MTA (Postfix: inet_protocols = ipv4) until its PTR exists.",
      "Replace provider-default names (ec2-…, …dyn…) with a hostname containing your domain.",
    ],
  },
  {
    id: "PS-03",
    title: "Fragile delegation",
    hook: "Flaky nameservers turn SPF/DKIM/DMARC verification into a coin flip.",
    severity: "warning",
    findingPrefixes: [
      "ns_sanity",
      "ns_lame",
      "ns_parent_child",
      "ns_all_answer",
      "ns_response_time",
      "ns_no_cname",
      "glue_records",
      "recursion_open",
      "zone_transfer",
    ],
    concept: [
      "Every SPF, DKIM, and DMARC verification a receiver performs is a live query against your nameservers. One NS, a lame NS, parent↔child disagreement, or missing glue produces temperror results that spam-folder mail in a pattern that matches the receiver's resolver — not your content — which makes it brutally hard to debug.",
      "RFC 1034 requires at least two nameservers; BCP 16 wants them on different networks. The post-Dyn-2016 best practice is two independent DNS providers fed from one zone source.",
    ],
    dataFields: [
      "dns_health.ns[] / ns_count / network_count",
      "dns_health.parent_child_match (null until the parent-zone probe ships)",
    ],
    commands: [
      "dig NS <domain> +short",
      "dig SOA <domain> @<each-ns> +norec   # AA bit present? same serial everywhere?",
      "dnstracer -s . -o <domain>",
      "dig google.com @<each-ns> +norec   # authoritative servers should refuse recursion",
    ],
    tools: [
      "dig, dnstracer (brew install bind dnstracer)",
      "Zonemaster (zonemaster.net) — the reference delegation auditor",
      "intoDNS for a quick second opinion",
    ],
    metrics: ["Per-NS response-time trend; SOA-serial drift across secondaries."],
    pathForward: [
      "Add a second DNS provider's nameservers (different network/ASN) as secondaries.",
      "Make the registrar's NS list exactly equal the zone's own NS RRset.",
      "Disable recursion and restrict AXFR (allow-transfer { none; }) on every authoritative server.",
    ],
  },
  {
    id: "PS-04",
    title: "SOA & TTL out of range",
    hook: "Bad timers keep stale auth records alive — and rock-bottom TTLs read as fast-flux.",
    severity: "warning",
    findingPrefixes: ["soa_sanity", "soa_serial", "soa_mname_ns", "soa_rname", "ttl_sanity"],
    concept: [
      "SOA timers govern how secondaries refresh and how long negative answers are cached. A huge negative TTL delays every new record you publish (a just-added DKIM selector stays NXDOMAIN for days); a tiny expire makes the whole zone vanish during a primary outage.",
      "Steady-state record TTLs under ~300 s pattern-match fast-flux spam infrastructure (CISA AA25-093A) — not a hard reject, but a reputation-model feature; TTLs over a day slow incident recovery.",
    ],
    dataFields: [
      "dns_health.soa — serial, refresh (3600–86400), retry (< refresh), expire (604800–2419200), min_ttl (300–86400)",
      "dns_health.ttls (future: parsed from dig; node:dns does not expose TTLs)",
    ],
    commands: ["dig SOA <domain> +multiline", "dig MX <domain>   # read the TTL column"],
    tools: ["dig", "intoDNS (flags out-of-range SOA values with RFC citations)"],
    metrics: [
      "TTL history across scheduled runs — a TTL that drops without a migration is a flag.",
    ],
    pathForward: [
      "Adopt the modern default set: refresh 14400, retry 3600, expire 1209600, minimum 3600.",
      "Use the YYYYMMDDnn serial convention and bump it on every zone edit.",
      "Keep mail-record TTLs at 3600 s or more; lower them only around planned migrations, then raise them back.",
    ],
  },
  {
    id: "PS-05",
    title: "Wildcard & zone bleed",
    hook: "A wildcard answers every name you didn't pin — including mail-authentication lookups.",
    severity: "warning",
    findingPrefixes: ["wildcard", "cname_at_apex", "multi_txt_spf", "txt_bloat"],
    concept: [
      "A wildcard (*.<domain>) answers every name with no explicit record (RFC 4592). Wildcard MX accepts mail for every nonexistent subdomain (backscatter, spamtrap hits); wildcard TXT can answer _dmarc.<sub> or DKIM-selector queries with junk, corrupting authentication discovery on any name you didn't pin explicitly.",
      "Apex CNAMEs and duplicate SPF strings are the same class of bug: zone content that silently changes how mail lookups resolve. A CNAME at the apex masks the SOA/NS/MX/TXT records; two v=spf1 strings are a permerror that voids SPF entirely.",
    ],
    dataFields: [
      "dns_health.wildcard — detected, probe, types[]",
      "dns_health.cname_at_apex",
      "multi_txt_spf / txt_bloat finding evidence (the observed TXT strings)",
    ],
    commands: [
      "dig A edh-probe-x7f3q.<domain> +short   # any answer = wildcard",
      "dig MX edh-probe-x7f3q.<domain> +short",
      "dig CNAME <domain> +short   # apex must be empty",
      "dig TXT <domain> +short   # exactly one v=spf1 string",
    ],
    tools: ["dig", "dnsx for probing many candidate names"],
    metrics: ["Re-probed every run — wildcards reappear with provider template resets."],
    pathForward: [
      "Remove wildcard MX outright; scope any business-required wildcard A deliberately.",
      "Pin explicit records for _dmarc, _mta-sts, _smtp._tls, and every DKIM selector above any wildcard that must stay.",
      "Merge duplicate SPF records into one v=spf1 string and delete stale verification TXT records.",
    ],
  },
  {
    id: "PS-06",
    title: "DNSSEC broken — or missing where it should be",
    hook: "Unsigned is an upgrade you're missing; signed-but-broken takes your whole zone dark.",
    severity: "critical",
    findingPrefixes: [
      "dnssec_signed",
      "dnssec_ds_present",
      "dnssec_ds_algo_match",
      "dnssec_algorithm",
      "dnssec_key_rollover",
      "dnssec_validates",
      "dnssec_rrsig_expiry",
      "dnssec_nsec3",
      "dnssec_chain_complete",
      "dnssec_soa_signed",
    ],
    concept: [
      "Two very different states share this family. Unsigned is an adoption gap: no DANE possible, lookups spoofable — advisory only. Signed-but-broken (DS↔DNSKEY mismatch, expired RRSIG, deprecated algorithm) is an outage: validating resolvers — Google, Cloudflare, Quad9, Comcast — SERVFAIL the entire zone, so mail to and from the domain fails.",
      "Algorithm guidance (RFC 8624, updated by RFC 9904): 13 (ECDSAP256SHA256) is the recommended default, 15 (Ed25519) is good, 8 (RSASHA256, ≥2048-bit) acceptable; SHA-1-based 5/7 are deprecated. DS digest should be SHA-256 (type 2), never SHA-1 (type 1).",
    ],
    dataFields: [
      "dnssec.signed / ds_present / ds_matches_dnskey",
      "dnssec.algorithms[] / ds_digest_types[]",
      "dnssec.dane_ready — the DANE prerequisite",
    ],
    commands: [
      "delv +vtrace MX <domain>   # look for '; fully validated' vs SERVFAIL",
      "drill -TD -S DNSKEY <domain>",
      "dig DS <domain> +short",
      "dnsviz probe <domain> | dnsviz grok",
    ],
    tools: ["dnsviz, delv (bind), drill (ldns), kdig +dnssec (brew install dnsviz bind ldns knot)"],
    metrics: ["Future probe reads RRSIG inception/expiration and warns under 7 days from expiry."],
    pathForward: [
      "If BROKEN (DS mismatch): re-sign or fix the DS at the registrar today — resolvers are SERVFAILing the zone right now. Pulling the DS temporarily beats staying bogus.",
      "If unsigned: enable automated signing at your DNS provider (algorithm 13), then publish the DS at the registrar (SHA-256 digest).",
      "Turn on CDS/CDNSKEY (RFC 8078) so future key rolls update the DS automatically.",
    ],
  },
  {
    id: "PS-07",
    title: "DANE gap",
    hook: "TLSA pins your MX certificate in DNS — and a stale pin is worse than none.",
    severity: "warning",
    findingPrefixes: [
      "dane_tlsa",
      "dane_all_mx",
      "dane_ttl_sane",
      "dane_mx_lookup",
      "dane_rollover",
      "dane_digest_length",
      "dane_name_alignment",
      "dane_dnssec_prereq",
      "dane_without_dnssec",
    ],
    concept: [
      'DANE publishes a TLSA record at _25._tcp.<mx-host> binding the MX certificate into DNS, closing the STARTTLS-stripping hole for senders that validate it (Postfix dane mode, Exchange Online). The "3 1 1" profile (DANE-EE, SubjectPublicKeyInfo, SHA-256) survives certificate renewals that keep the same key pair.',
      "The hard prerequisite is DNSSEC — an unsigned TLSA is ignored. And a TLSA that stops matching the live certificate makes DANE-validating senders bounce your inbound mail, which is worse than publishing nothing.",
    ],
    dataFields: [
      "dane_* finding evidence per MX host — record profile, DNSSEC prerequisite, rollover state",
      "dnssec.dane_ready — signed + DS present",
    ],
    commands: [
      "dig TLSA _25._tcp.<mx-host> +short",
      "gnutls-cli --dane --starttls-proto=smtp <mx-host> -p 25",
    ],
    tools: [
      "kdig/dig, gnutls-cli (brew install knot gnutls)",
      "dane.sys4.de — DANE validator + common-mistakes list",
    ],
    metrics: [
      "Cert-rotation watch: alert when the live SPKI hash diverges from every published TLSA.",
    ],
    pathForward: [
      "Complete DNSSEC first (PS-06) — DANE is meaningless in an unsigned zone.",
      "Publish a 3 1 1 TLSA at _25._tcp.<mx-host> for every MX, computed from the live certificate's public key.",
      "During certificate rollover publish current + next TLSA records and wait at least one TTL before swapping certs.",
    ],
  },
  {
    id: "PS-08",
    title: "Encryption-in-transit gaps",
    hook: "TLS in transit is required by Gmail, Yahoo, and Microsoft — STARTTLS, MTA-STS, TLS-RPT.",
    severity: "warning",
    findingPrefixes: ["tls_transport", "mta_sts", "tls_rpt"],
    concept: [
      "STARTTLS is the capability; MTA-STS (RFC 8461) is the downgrade-resistant policy — a _mta-sts TXT record plus a policy file served at https://mta-sts.<domain>/.well-known/mta-sts.txt with mode: enforce; TLS-RPT (RFC 8460) is the feedback channel telling you when senders couldn't negotiate TLS with you.",
      "Classic failures: the policy file changed but the TXT id= was not rotated (senders cache the old policy for max_age); mode: testing left on forever; the policy's mx: patterns drifting from the real MX set; enforce mode with an expired MX certificate (mail refused).",
    ],
    dataFields: [
      "mta_sts_* findings — record, id format, policy fetch, MX-list consistency",
      "tls_rpt_* findings — record presence, rua mailbox, syntax",
      "tls_transport findings (per-MX STARTTLS/cert once the SMTP probe ships)",
    ],
    commands: [
      "dig TXT _mta-sts.<domain> +short",
      "curl -s https://mta-sts.<domain>/.well-known/mta-sts.txt",
      "dig TXT _smtp._tls.<domain> +short",
      "openssl s_client -starttls smtp -connect <mx-host>:25 -servername <mx-host>",
      "testssl --starttls smtp <mx-host>:25",
    ],
    tools: ["curl, dig, openssl/testssl/sslscan/certigo, swaks --tls"],
    metrics: [
      "TLS-RPT report ingestion (pm/emails.mdx) turns this from configuration-audit into observed-failure data.",
    ],
    pathForward: [
      'Publish TLS-RPT first: _smtp._tls TXT "v=TLSRPTv1; rua=mailto:tls-reports@<domain>".',
      "Publish MTA-STS in mode: testing with max_age 86400 and watch the reports for 14–30 days.",
      "Switch to mode: enforce with max_age 604800, and rotate the TXT id= on every policy change.",
    ],
  },
  {
    id: "PS-09",
    title: "Registration risk",
    hook: "Filters treat the domain's registration lifecycle as reputation bedrock.",
    severity: "warning",
    findingPrefixes: [
      "domain_age",
      "domain_expiry",
      "registrar_",
      "registrant_privacy",
      "auto_renew",
      "hold_status",
      "pending_delete",
      "recent_transfer",
      "record_available",
      "parked",
      "parking_nameservers",
      "tld_risk",
      "name_similarity",
      "idn_homograph",
      "update_lock",
      "delete_lock",
      "dnssec_ds_at_registrar",
      "domain_reputation",
    ],
    concept: [
      "Newly registered domains (under ~30 days) are throttled or junked wholesale — Spamhaus, Proofpoint, and Microsoft all consume NRD feeds. No DNS record fixes that; only age and a gradual volume warm-up do.",
      "At the other end of the lifecycle: expiry within 30 days, clientHold/pendingDelete (the domain literally stops resolving), a missing transfer lock, parked nameservers, and high-abuse TLDs all mark the domain as ephemeral or hijackable.",
      "RDAP replaced WHOIS as the authoritative registration source for gTLDs in January 2025.",
    ],
    dataFields: [
      "domain_age / domain_expiry finding evidence — creation and expiry dates from RDAP",
      "hold_status / pending_delete / registrar_lock — the EPP status array",
      "name_similarity / idn_homograph — the colliding lookalike names",
    ],
    commands: [
      "rdap <domain>",
      "whois <domain>",
      "dnstwist --registered <domain>   # lookalike sweep",
    ],
    tools: ["rdap, whois, dnstwist (brew install rdap whois dnstwist)"],
    metrics: [
      "Expiry countdown as a standing dashboard nudge; scheduled runs catch EPP status changes (a sudden clientHold is an emergency).",
    ],
    pathForward: [
      "Fix any hold/expiry emergency at the registrar first — a domain on hold resolves for no one.",
      "Enable auto-renew and clientTransferProhibited; keep at least a year of registration runway.",
      "For a young domain: warm up gradually (5–10 messages/day at first, full volume by week 4–8) — this is time, not configuration.",
    ],
  },
  {
    id: "PS-10",
    title: "SMTP exposure",
    hook: "An open relay burns every other investment within hours.",
    severity: "critical",
    findingPrefixes: ["smtp_security"],
    concept: [
      "An open relay gets blacklisted first and asked questions never — Spamhaus and the DNSBLs list within hours of discovery. VRFY/EXPN enumeration, AUTH offered before TLS, and submission on port 25 are the smaller cousins.",
      "The first round emits a pending info only: the SMTP probe is off by default and runs under the smtp25 semaphore when enabled (see pm/checks/smtp_security.mdx and pm/run_checks.mdx).",
    ],
    dataFields: [
      "smtp_security findings — per-MX probe verdicts once the probe is enabled (relay accepted?, VRFY/EXPN, AUTH-over-plaintext, banner)",
    ],
    commands: [
      "nmap -p25 --script smtp-commands,smtp-open-relay <mx-host>",
      "swaks --server <mx-host> --from test@external.example --to victim@external.example --quit-after RCPT",
    ],
    tools: ["nmap, swaks (brew install nmap swaks)"],
    metrics: ["Blacklist category cross-check — open relays surface there first."],
    pathForward: [
      "Restrict relaying in the MTA (Postfix: smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination).",
      "Disable VRFY/EXPN; offer AUTH only after STARTTLS; move submission to 587/465.",
      "Re-run the audit's SMTP probe (when enabled) to confirm the transcript is clean.",
    ],
  },
  {
    id: "PS-11",
    title: "Dangling records / takeover exposure",
    hook: "A dead CNAME or expired SPF include is a reputation hijack waiting to be claimed.",
    severity: "critical",
    findingPrefixes: ["dangling_cname", "dangling_include"],
    concept: [
      "CNAMEs to unclaimed SaaS endpoints, MX targets on expired domains, and SPF include: chains through re-registerable domains all hand an attacker a hostname — or an SPF authorization — inside your domain.",
      "The 2024 SubdoMailing campaign rode exactly this (~8,800 hijacked domains): the attacker registers the dangling target, inherits the org's SPF pass and reputation, spams, and the org domain lands on the Spamhaus DBL.",
    ],
    dataFields: [
      "dangling_cname.<name> / dangling_include[.mx].<domain> finding evidence — the dead target and which record references it",
    ],
    commands: [
      "dig CNAME mail.<domain> +short   # then resolve the target",
      "dig TXT <domain> +short | grep spf1   # then resolve every include: domain",
      "rdap <target-domain>   # is the referenced domain even registered?",
    ],
    tools: ["dig, dnsx, rdap; future sweep: subfinder, amass, massdns"],
    metrics: [
      "Future: full subdomain enumeration with SaaS-fingerprint liveness on every CNAME/MX/NS/include target.",
    ],
    pathForward: [
      "Delete the stale record the moment a service is decommissioned — never leave a CNAME pointing at a deprovisioned host.",
      "Remove dead include:/redirect= terms from the SPF record (they can also permerror SPF).",
      "Monitor the registration status of every domain your SPF tree references.",
    ],
  },
]

/** Problem states matched by the latest run's findings (pm/checks/dns.mdx §9 prefix mapping). */
export function matchDnsProblemStates(findings: Finding[]): DnsProblemState[] {
  const failing = findings
    .filter((f) => f.severity === "warning" || f.severity === "critical")
    .map((f) => (f.id.startsWith("infra.") ? f.id.slice("infra.".length) : f.id))
  return DNS_PROBLEM_STATES.filter((ps) =>
    ps.findingPrefixes.some((prefix) => failing.some((id) => id.startsWith(prefix))),
  )
}

export function dnsProblemStateById(id: string): DnsProblemState | undefined {
  return DNS_PROBLEM_STATES.find((ps) => ps.id === id)
}
