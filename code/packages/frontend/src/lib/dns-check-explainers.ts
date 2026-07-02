/**
 * The check-detail explainer layer for the ten DNS & Infrastructure test families
 * (pm/checks/dns.mdx frontmatter + §6.2 item 6/8): one explainer page per family at
 * /domains/:domainId/runs/:runId/dns/check/:checkKey — what the check is, what its current state
 * means, how to fix it, plus the `#concept-<term>` sections the DNS page's underlined concept
 * terms anchor into. Content mirrors pm/checks/dns.mdx §1/§2/§9 (the family specs own the
 * per-sub-check detail).
 */
import type { DnsFamilyKey } from "@/lib/dns-families"

/** One glossary concept rendered as an anchored `#concept-<anchor>` section on the explainer. */
export interface DnsConcept {
  /** The anchor slug — the page section id is `concept-<anchor>`. */
  anchor: string
  term: string
  text: string
}

export interface DnsCheckExplainer {
  key: DnsFamilyKey
  title: string
  /** "What it is" — 2–3 short paragraphs a non-expert can read. */
  whatItIs: string[]
  /** "What it means" — how to interpret pass / warn / fail for this family. */
  whatItMeans: string[]
  /** "How to fix it" — the numbered remediation ladder for this family. */
  howToFix: string[]
  /** Anchored glossary sections (`#concept-<anchor>`) the DNS page's terms deep-link into. */
  concepts: DnsConcept[]
}

export const DNS_CHECK_EXPLAINERS: Record<DnsFamilyKey, DnsCheckExplainer> = {
  mx_routing: {
    key: "mx_routing",
    title: "MX records & mail routing",
    whatItIs: [
      "MX records are how the world routes mail to your domain — and how bounces, feedback-loop complaints, and DMARC reports route back to you. Receivers also check that a From: domain resolves (MX or A) before accepting mail from it, so a broken MX set hurts outbound reputation too.",
      "The rules come from RFC 5321 §5.1 (implicit-MX fallback, no address literals), RFC 2181 §10.3 (an MX target must never be a CNAME), and RFC 7505 (the null MX that declares a no-mail domain).",
    ],
    whatItMeans: [
      "Pass: 1–3 MX records with distinct priorities, every target an FQDN resolving to public A/AAAA, and at least two hosts on two networks.",
      "Fail (critical): the MX is absent, unresolvable, a CNAME, or points into private/loopback address space — inbound mail, bounces, and DMARC reports all silently vanish.",
      "Warn: single-host or single-network redundancy, duplicate targets, equal priorities, or an MX set drifting from your declared expectation.",
    ],
    howToFix: [
      'Publish 1–3 MX records with distinct priorities (10/20/30), e.g. "IN MX 10 mx1.<domain>.".',
      "Make every target an FQDN with its own public A (and AAAA) record — never a CNAME, never an IP literal.",
      "Put the second MX host on a different network or provider.",
      'For a genuine no-mail domain publish the deny set instead: MX 0 ".", "v=spf1 -all", DMARC p=reject.',
    ],
    concepts: [
      {
        anchor: "mx",
        term: "MX record",
        text: "A Mail eXchanger record names the host(s) that accept mail for a domain, each with a priority — lower is tried first. RFC 2181 forbids the target being a CNAME.",
      },
      {
        anchor: "null-mx",
        term: "Null MX",
        text: 'RFC 7505: a single "MX 0 ." record declares the domain accepts no mail at all. It must be the only MX record, and belongs only on no-mail domains.',
      },
      {
        anchor: "implicit-mx",
        term: "Implicit MX",
        text: "With no MX record, RFC 5321 falls back to the domain's apex A record as the mail host — fragile, and a signal the mail setup was never finished.",
      },
    ],
  },
  reverse_dns: {
    key: "reverse_dns",
    title: "Reverse DNS / PTR / FCrDNS",
    whatItIs: [
      "Forward-confirmed reverse DNS (FCrDNS) is the oldest infrastructure trust test: the connecting IP must have a PTR record, and that PTR hostname must resolve back to the same IP. Gmail rejects failures outright with a permanent 550-5.7.25; Yahoo requires the hostname to be non-generic and reflect your domain; Microsoft enforces it for dedicated IPs.",
      "The killer variant is the IPv6 gap: the MTA has an AAAA record, Gmail prefers the IPv6 path, and only the IPv4 PTR exists — mail the IPv4 path would deliver gets rejected over IPv6.",
    ],
    whatItMeans: [
      "Pass: every sending/MX IP — v4 and v6 — has exactly one PTR, FCrDNS closes both ways, and the hostname contains your domain.",
      "Fail (critical): a mail IP has no PTR or its PTR fails forward confirmation — a hard receiver gate, mail is rejected, not filtered.",
      "Warn: the PTR is a generic provider pattern (ec2-…, dyn…, pool…) — Yahoo-class reputation damage even when FCrDNS closes.",
    ],
    howToFix: [
      "Open a ticket with the IP owner (hosting provider/ISP) to delegate the PTR: <ip> → mail.<domain>.",
      "Publish the matching forward record (mail.<domain> A/AAAA <ip>) so the loop closes.",
      "Repeat for every IPv6 address — or disable outbound IPv6 on the MTA (Postfix: inet_protocols = ipv4) until its PTR exists.",
      "Replace generic provider hostnames with one containing your domain.",
    ],
    concepts: [
      {
        anchor: "ptr",
        term: "PTR record",
        text: "The reverse-DNS record mapping an IP back to a hostname. It lives in the IP owner's reverse zone — set by your hosting provider, not at your domain's registrar.",
      },
      {
        anchor: "fcrdns",
        term: "FCrDNS",
        text: "Forward-confirmed reverse DNS: IP → PTR hostname → A/AAAA → the same IP. Required by Gmail (550-5.7.25 on failure), Yahoo, and Microsoft.",
      },
      {
        anchor: "generic-ptr",
        term: "Generic PTR",
        text: "A provider-template hostname (ec2-….compute.amazonaws.com, host-1-2-3-4.pool…) that says nothing about who sends the mail — treated like dynamic-pool space by receivers.",
      },
    ],
  },
  tls_transport: {
    key: "tls_transport",
    title: "STARTTLS & MX certificate health",
    whatItIs: [
      "TLS in transit is a hard requirement at all three major receivers. STARTTLS is the SMTP capability that upgrades a port-25 session to TLS; the MX certificate behind it must be valid, publicly trusted, cover the MX hostname, and not be about to expire.",
      "First round this family emits a .pending info finding — probing port 25 needs sockets and runs under the smtp25 semaphore when enabled.",
    ],
    whatItMeans: [
      "Pass: every MX advertises STARTTLS with TLS ≥ 1.2 and a valid certificate whose SAN covers the MX hostname, 30+ days from expiry.",
      "Fail (critical): an MX offers no STARTTLS, or its certificate is expired/mismatched — receivers requiring TLS refuse or downgrade the mail.",
      "Info (.pending): the SMTP probe has not run yet — nothing is asserted either way.",
    ],
    howToFix: [
      "Enable STARTTLS on every MX host (Postfix: smtpd_tls_security_level = may, with a real certificate).",
      "Use a publicly trusted certificate that names the MX hostname in its SAN; automate renewal.",
      "Verify with: openssl s_client -starttls smtp -connect <mx>:25 -servername <mx>.",
    ],
    concepts: [
      {
        anchor: "starttls",
        term: "STARTTLS",
        text: "The SMTP command that upgrades a plaintext port-25 session to TLS. Opportunistic by default — which is why MTA-STS and DANE exist to prevent downgrade attacks.",
      },
      {
        anchor: "san",
        term: "SAN coverage",
        text: "The certificate's Subject Alternative Names must include the MX hostname the sender connected to, or verifying senders treat the session as unauthenticated.",
      },
    ],
  },
  mta_sts: {
    key: "mta_sts",
    title: "MTA-STS",
    whatItIs: [
      "MTA-STS (RFC 8461) is the downgrade-resistant TLS policy for inbound mail: a _mta-sts TXT record (v=STSv1; id=…) plus a policy file served at https://mta-sts.<domain>/.well-known/mta-sts.txt telling senders to require TLS and which MX names to expect.",
      "Classic failures: the policy file changed but the id= was never rotated (senders cache the old policy for max_age), mode: testing left on forever, and the policy's mx: patterns drifting from the real MX set.",
    ],
    whatItMeans: [
      "Pass: one _mta-sts TXT, a fetchable policy with mode: enforce and max_age ≥ 86400 (604800 typical), mx: patterns matching the live MX set.",
      "Warn: record/policy mismatch, testing mode matured past its window, id not rotated, or MTA-STS deployed without TLS-RPT.",
      "Info: no MTA-STS at all — an adoption gap, not an outage.",
    ],
    howToFix: [
      'Publish the TXT record: _mta-sts.<domain> TXT "v=STSv1; id=<timestamp>".',
      "Serve the policy at https://mta-sts.<domain>/.well-known/mta-sts.txt with mode: testing first.",
      "Add TLS-RPT, watch reports for 14–30 days, then switch to mode: enforce with max_age 604800.",
      "Rotate the id= on every policy change.",
    ],
    concepts: [
      {
        anchor: "mode-enforce",
        term: "mode: enforce",
        text: "The MTA-STS policy mode that makes senders refuse to deliver when TLS or the MX-name match fails. `testing` only reports; `none` withdraws the policy.",
      },
      {
        anchor: "max-age",
        term: "max_age",
        text: "How long (seconds) senders cache the policy. 604800 (a week) is typical — which is why the id= must rotate whenever the policy body changes.",
      },
    ],
  },
  tls_rpt: {
    key: "tls_rpt",
    title: "TLS-RPT",
    whatItIs: [
      "TLS-RPT (RFC 8460) is the feedback channel for transport security: a _smtp._tls TXT record (v=TLSRPTv1; rua=mailto:…) asking large senders to mail you a daily JSON report of TLS negotiation failures against your MXes.",
      "It is the only way to see MTA-STS/DANE failures from the sender's side — running enforce-mode policies without it is flying blind.",
    ],
    whatItMeans: [
      "Pass: exactly one _smtp._tls TXT with a valid v=TLSRPTv1 and a deliverable rua: mailbox.",
      "Warn: missing while MTA-STS or DANE is deployed, duplicate records, bad syntax, or an undeliverable report address.",
      "Info: absent with no TLS policy deployed — nothing to report on yet.",
    ],
    howToFix: [
      'Publish: _smtp._tls.<domain> TXT "v=TLSRPTv1; rua=mailto:tls-reports@<domain>".',
      "Make sure the report mailbox exists and is monitored (or ingested by this app).",
      "Keep exactly one record — duplicates void the mechanism.",
    ],
    concepts: [
      {
        anchor: "rua",
        term: "rua",
        text: "The Reporting URI for Aggregate data — the mailto: (or https:) destination senders deliver their daily TLS failure reports to.",
      },
    ],
  },
  dane_tlsa: {
    key: "dane_tlsa",
    title: "DANE / TLSA",
    whatItIs: [
      "DANE (RFC 6698/7672) pins the MX certificate in DNS: a TLSA record at _25._tcp.<mx-host> tells validating senders (Postfix dane mode, Exchange Online) exactly which key to expect, closing the STARTTLS-stripping hole.",
      'The recommended profile is "3 1 1" (DANE-EE, SubjectPublicKeyInfo, SHA-256), which survives certificate renewals that keep the key. The hard prerequisite is DNSSEC — an unsigned TLSA is ignored.',
    ],
    whatItMeans: [
      "Pass: a 3 1 1 TLSA for every MX host, matching the live certificate, in a DNSSEC-signed zone.",
      "Warn: partial coverage (some MXes without TLSA), unusable parameters, missing rollover record, or TLSA published without the DNSSEC prerequisite.",
      "Critical: a published TLSA that no longer matches the live certificate — DANE-validating senders bounce your inbound mail; worse than no TLSA.",
      "Info: no DANE at all — a hardening gap, gated on DNSSEC being in place.",
    ],
    howToFix: [
      "Complete DNSSEC first — DANE is meaningless in an unsigned zone.",
      "Compute the 3 1 1 digest from each MX's live certificate public key and publish TLSA at _25._tcp.<mx-host> for every MX.",
      "During certificate rollover publish current + next TLSA records and wait at least one TTL before swapping.",
      "Verify live: gnutls-cli --dane --starttls-proto=smtp <mx-host> -p 25.",
    ],
    concepts: [
      {
        anchor: "tlsa",
        term: "TLSA record",
        text: "The DANE record type binding a TLS certificate (or its public key) to a service name and port, e.g. _25._tcp.mx1.example.com.",
      },
      {
        anchor: "three-one-one",
        term: '"3 1 1" profile',
        text: "DANE-EE (3) + SubjectPublicKeyInfo (1) + SHA-256 (1): pin the end-entity key itself, so renewals that keep the key need no DNS change.",
      },
    ],
  },
  dnssec: {
    key: "dnssec",
    title: "DNSSEC",
    whatItIs: [
      "DNSSEC (RFC 4033-4035) cryptographically signs your zone so resolvers can verify answers weren't spoofed. It is also the hard prerequisite for DANE.",
      "Two very different failure states share this family: UNSIGNED is an adoption gap (advisory only); SIGNED-BUT-BROKEN — expired RRSIGs, a DS that matches no DNSKEY, deprecated algorithms — is an outage: validating resolvers (Google, Cloudflare, Quad9) SERVFAIL the entire zone, so mail to and from the domain fails.",
    ],
    whatItMeans: [
      "Pass: zone signed with algorithm 13 (or 15; RSA ≥ 2048 acceptable), DS at the parent with a SHA-256 digest, DNSKEY↔DS matching, RRSIGs current.",
      "Fail (critical): signed but broken — resolvers are SERVFAILing the zone right now.",
      "Info: unsigned — an upgrade you're missing, and the gate in front of DANE.",
    ],
    howToFix: [
      "If BROKEN: re-sign or fix the DS at the registrar today; temporarily pulling the DS beats staying bogus.",
      "If unsigned: enable automated signing at the DNS provider (algorithm 13 ECDSAP256SHA256), then publish the DS (SHA-256).",
      "Turn on CDS/CDNSKEY so future key rolls update the DS automatically.",
      "Verify: delv +vtrace MX <domain> — look for '; fully validated'.",
    ],
    concepts: [
      {
        anchor: "dnssec",
        term: "DNSSEC",
        text: "DNS Security Extensions: RRSIG signatures over every record set, DNSKEY keys in the zone, and a DS digest at the parent forming the chain of trust from the root.",
      },
      {
        anchor: "ds",
        term: "DS record",
        text: "The Delegation Signer digest published at the PARENT zone (via your registrar) that anchors your DNSKEY into the chain of trust. A DS matching no live key = the whole zone goes bogus.",
      },
      {
        anchor: "dnskey",
        term: "DNSKEY",
        text: "The public key(s) in your zone that sign its records. Algorithm 13 (ECDSAP256SHA256) is the recommended default; SHA-1-based 5/7 are deprecated (RFC 8624/9904).",
      },
      {
        anchor: "rrsig",
        term: "RRSIG",
        text: "The signature record over one record set, with an inception/expiration window. Expired RRSIGs are the classic 'signed once, broke later' outage.",
      },
    ],
  },
  dns_health: {
    key: "dns_health",
    title: "DNS zone & nameserver health",
    whatItIs: [
      "Every SPF, DKIM, and DMARC verification a receiver performs is a live query against your nameservers. One NS, a lame NS, parent↔child disagreement, or missing glue turns authentication into a coin flip — temperror results that spam-folder mail in a pattern matching the receiver's resolver, not your content.",
      "The zone content matters too: SOA timers in the RIPE-203/RFC 1912 ranges, sane record TTLs, no wildcard bleeding into mail lookups, no CNAME at the apex, and no dangling references an attacker could claim.",
    ],
    whatItMeans: [
      "Pass: 2–4 nameservers on ≥ 2 networks, all authoritative, parent set == child set, recursion and zone transfer closed, SOA/TTLs in range, no wildcard or apex-CNAME interference.",
      "Warn: any delegation, SOA/TTL, wildcard, or TXT-hygiene deviation — reputation-eroding and a source of intermittent auth failures.",
      "Critical: a dangling CNAME or dead SPF include — takeover exposure (the SubdoMailing pattern).",
    ],
    howToFix: [
      "Add a second DNS provider (different network/ASN) and make the registrar's NS list exactly match the zone's NS RRset.",
      "Adopt the modern SOA defaults: refresh 14400, retry 3600, expire 1209600, minimum 3600.",
      "Remove wildcard MX; pin explicit _dmarc, _mta-sts, _smtp._tls, and selector records above any wildcard that must stay.",
      "Delete dangling CNAMEs and dead SPF include: targets the moment a service is decommissioned.",
    ],
    concepts: [
      {
        anchor: "ns",
        term: "NS records",
        text: "The delegation: which servers answer authoritatively for the zone. The parent's copy (at the registrar) and the child's copy (in the zone) must match exactly.",
      },
      {
        anchor: "soa",
        term: "SOA record",
        text: "The Start of Authority: serial, refresh (3600–86400), retry (< refresh), expire (604800–2419200), and negative TTL (300–86400) — the timers that govern secondaries and negative caching.",
      },
      {
        anchor: "wildcard",
        term: "Wildcard",
        text: "*.<domain> answers every name with no explicit record (RFC 4592) — including _dmarc.<sub> and DKIM selector lookups, corrupting mail authentication discovery.",
      },
      {
        anchor: "lame-delegation",
        term: "Lame delegation",
        text: "A listed nameserver that doesn't actually answer authoritatively for the zone — some resolvers pick it, time out, and your SPF/DKIM lookups temperror.",
      },
      {
        anchor: "dangling",
        term: "Dangling record",
        text: "A CNAME/MX/NS/SPF-include pointing at a dead or re-registerable target. An attacker who claims the target inherits your name and SPF authorization (the 2024 SubdoMailing campaign).",
      },
    ],
  },
  domain_reputation: {
    key: "domain_reputation",
    title: "Domain registration reputation",
    whatItIs: [
      "Filters treat the domain's registration lifecycle as reputation bedrock. Newly registered domains are throttled or junked wholesale (Spamhaus/Proofpoint/Microsoft NRD feeds); domains near expiry, on clientHold, or parked read as ephemeral or hijackable.",
      "The data source is RDAP — WHOIS's structured successor (the ICANN gTLD WHOIS obligation ended January 2025) — cached per domain per day for registry rate limits.",
    ],
    whatItMeans: [
      "Pass: domain > 90 days old, > 90 days to expiry with auto-renew, clientTransferProhibited set, no hold/pendingDelete, not parked, low-abuse TLD.",
      "Fail (critical): clientHold, pendingDelete, or expired — the domain resolves for no one; nothing else matters until it's fixed.",
      "Warn: expiry < 90 days, missing transfer lock, age < 90 days, parked nameservers, lookalike registrations.",
      "Info: WHOIS/RDAP privacy — noted, never penalized.",
    ],
    howToFix: [
      "Fix any hold/expiry emergency at the registrar first.",
      "Enable auto-renew and clientTransferProhibited; keep at least a year of registration runway.",
      "For a young domain: warm up gradually (5–10 messages/day at first, full volume by week 4–8) — this is time, not configuration.",
    ],
    concepts: [
      {
        anchor: "rdap",
        term: "RDAP",
        text: "The Registration Data Access Protocol — WHOIS's JSON successor and the authoritative registration source for gTLDs since January 2025.",
      },
      {
        anchor: "epp-status",
        term: "EPP status codes",
        text: "The registry lifecycle flags: clientTransferProhibited is the lock you want; clientHold/serverHold and pendingDelete mean the domain does not resolve.",
      },
      {
        anchor: "nrd",
        term: "NRD",
        text: "Newly Registered Domain — feeds consumed by Spamhaus, Proofpoint, and Microsoft that throttle or junk mail from domains younger than ~30 days.",
      },
    ],
  },
  smtp_security: {
    key: "smtp_security",
    title: "SMTP server security",
    whatItIs: [
      "An open relay burns every other investment within hours — blacklists list first and ask questions never. VRFY/EXPN enumeration, AUTH offered before TLS, and submission on port 25 are the smaller cousins.",
      "The first round emits a .pending info finding only: the SMTP probe is off by default and runs under the smtp25 semaphore when enabled.",
    ],
    whatItMeans: [
      "Pass: relay refused for unauthenticated third-party recipients, VRFY/EXPN disabled, AUTH only after TLS, submission on 587/465.",
      "Fail (critical): the MX relays third-party mail — expect immediate blacklisting.",
      "Info (.pending): the probe hasn't run — nothing is asserted either way.",
    ],
    howToFix: [
      "Restrict relaying (Postfix: smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination).",
      "Disable VRFY/EXPN; offer AUTH only after STARTTLS; move submission to 587/465.",
      "Re-run the probe (when enabled) to confirm the transcript is clean.",
    ],
    concepts: [
      {
        anchor: "open-relay",
        term: "Open relay",
        text: "An MTA that accepts mail from anyone to anyone — the fastest possible route onto every blacklist. Test: a RCPT to an external victim from an external sender must be refused.",
      },
      {
        anchor: "vrfy-expn",
        term: "VRFY / EXPN",
        text: "SMTP commands that confirm or expand addresses — an enumeration gift to spammers; modern MTAs disable or fake them.",
      },
    ],
  },
}

/** The explainer for one family key, or undefined for an unknown `:checkKey`. */
export function dnsCheckExplainer(key: string): DnsCheckExplainer | undefined {
  return (DNS_CHECK_EXPLAINERS as Record<string, DnsCheckExplainer>)[key]
}
