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
      {
        anchor: "mx-priority",
        term: "MX priority",
        text: "The preference number on each MX record: lower is tried first, and equal values load-balance across those hosts. All-identical priorities defeat any primary/backup intent — use a tiered 10/20/30 convention so senders know the fallback order.",
      },
      {
        anchor: "backup-mx",
        term: "Backup MX",
        text: "A higher-preference host used only when the primary is down. A backup on the same /24 or ASN isn't real redundancy, and an unmaintained backup becomes the spammers' front door — it must enforce the same recipient validation and anti-relay rules as the primary (verified by the future backup-MX hygiene probe).",
      },
      {
        anchor: "dangling-mx",
        term: "Dangling MX",
        text: "An MX target with no A/AAAA record (a decommissioned host or a typo). Mail queues behind the sender's retry window — hours to five days of silence — and then bounces. Every sender sees it; the fix is publishing the missing address or removing the dead line.",
      },
      {
        anchor: "expected-mx",
        term: "Expected-MX allow-list",
        text: "The operator-declared list of MX hostnames this domain should publish. When the live MX set drifts from it — hosts expected-but-missing or published-but-unexpected — it is flagged as a change-detection tripwire and a possible DNS/MX-hijack signal (infra.mx_expected_drift).",
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
        anchor: "reverse-dns",
        term: "Reverse DNS",
        text: "The mirror of forward DNS: given an IP, it answers which hostname claims it, via the in-addr.arpa (IPv4) and ip6.arpa (IPv6) special-use zones. The reverse zone is owned by the IP's network owner (your hosting provider / ISP / cloud), not the domain owner — which is why fixing reverse DNS is almost always a provider control-panel action or support ticket.",
      },
      {
        anchor: "ptr",
        term: "PTR record",
        text: "The reverse-DNS record mapping an IP back to a hostname. It lives in the IP owner's reverse zone — set by your hosting provider, not at your domain's registrar. Keep exactly one PTR per IP; multiple PTRs are ambiguity a receiver can resolve either way.",
      },
      {
        anchor: "fcrdns",
        term: "FCrDNS",
        text: "Forward-confirmed reverse DNS: IP → PTR hostname → A/AAAA → the same IP. Only the real operator can close that loop, so receivers use it as an identity anchor. It breaks when the forward A/AAAA is edited or the IP is reassigned. Required by Gmail (550-5.7.25 on failure), Yahoo, and Microsoft.",
      },
      {
        anchor: "generic-ptr",
        term: "Generic PTR",
        text: "A provider-template hostname (ec2-….compute.amazonaws.com, host-1-2-3-4.pool…) that says nothing about who sends the mail — treated like dynamic-pool space by receivers. FCrDNS-valid-but-generic still scores as spam (SpamAssassin RDNS_DYNAMIC); replace it with a dedicated mail hostname.",
      },
      {
        anchor: "helo-match",
        term: "HELO ↔ PTR match",
        text: "RFC 5321 §4.1.4 requires the SMTP HELO/EHLO to be a valid FQDN identifying the client, and receivers score trust highest when the HELO name, the PTR, and the forward A/AAAA all agree. This sub-check is future here — it needs an outbound SMTP probe (or MTA-log ingestion) to observe the HELO string; see the SMTP security check.",
      },
    ],
  },
  tls_transport: {
    key: "tls_transport",
    title: "STARTTLS & MX certificates",
    whatItIs: [
      "SMTP is plaintext by default (RFC 5321). STARTTLS (RFC 3207) is the SMTP capability that upgrades a port-25 session to TLS after EHLO, so the envelope, headers, and body travel encrypted. The 2024 Gmail/Yahoo bulk-sender rules and Microsoft's 2025 requirements push senders to encrypt mail in transit.",
      "This check connects to each of your MX hosts, issues EHLO, looks for 250-STARTTLS, performs the TLS handshake, and inspects the presented certificate — its validity window, hostname (SAN/CN) match, chain trust, protocol version, cipher strength, expiry runway, downgrade resistance, SNI handling, and OCSP stapling.",
      "It measures whether TLS is offered and healthy — not whether it is enforced. A domain can pass every sub-check here and still be trivially downgradable by an active attacker unless MTA-STS enforce or DANE/TLSA is also published; enforcement is those checks' job.",
      "First round this family emits a single .pending info finding — the probe opens live SMTP+TLS handshakes, which need sockets and run under the smtp25 semaphore once the probe harness and the admin port-25 toggle ship.",
    ],
    whatItMeans: [
      "Pass: every MX advertises STARTTLS, negotiates TLS ≥ 1.2 (ideally 1.3) with a forward-secret AEAD cipher, and presents a publicly-trusted certificate whose SAN covers the MX hostname, 30+ days from expiry.",
      "Warn: the runway is short — a certificate expiring in < 14 days, an SNI/downgrade quirk, or one MX host lagging the others — which flips to hard bounces at TLS-enforcing receivers with no other warning.",
      "Fail (critical): an MX offers no STARTTLS, or its certificate is expired, hostname-mismatched, self-signed/untrusted, or the session drops to SSLv3/TLS 1.0/1.1 or a weak cipher — receivers requiring TLS defer then bounce, and everyone else delivers your mail readable on the wire.",
      "Info (.pending): the SMTP probe has not run yet — nothing is asserted either way; the DNS side (the MX set) is audited by MX routing.",
    ],
    howToFix: [
      "Enable STARTTLS on every MX host (Postfix: smtpd_tls_security_level = may + smtpd_tls_chain_files = /etc/ssl/mx.pem; Exim: tls_advertise_hosts = *), then reload.",
      "Renew before expiry and automate it: certbot certonly --standalone -d mx.<domain> --deploy-hook \"systemctl reload postfix\" so certs roll ≥ 30 days out.",
      "Use a publicly-trusted certificate that names the exact MX hostname in its SAN — do not rely on the provider's default platform cert name.",
      "Install the full chain (leaf + intermediates in fullchain.pem, not cert.pem); replace self-signed certs with a CA-issued cert.",
      "Set the protocol floor and strong ciphers (Postfix: smtpd_tls_protocols = >=TLSv1.2, smtpd_tls_mandatory_ciphers = high); drop RC4/3DES/export suites.",
      "Verify with: openssl s_client -starttls smtp -connect <mx>:25 -servername <mx> -brief.",
    ],
    // The first four anchors are the fixed pm/checks/dns.mdx §14.6 map entries (never renamed); the
    // rest are family-internal anchors this page's own copy and PS-08 link to
    // (pm/checks/tls_transport.mdx §9.2).
    concepts: [
      {
        anchor: "starttls",
        term: "STARTTLS",
        text: "The RFC 3207 SMTP command that upgrades a plaintext port-25 session to TLS after EHLO. Opportunistic by default — offered, not required — which is why MTA-STS and DANE exist to make it downgrade-proof.",
      },
      {
        anchor: "mx-certificate",
        term: "MX certificate",
        text: "The TLS certificate the MX host presents during the STARTTLS handshake. To count as healthy it must be within its validity window, publicly trusted (full chain, not self-signed), and name the MX hostname.",
      },
      {
        anchor: "san",
        term: "SAN",
        text: "Subject Alternative Names — the DNS names a certificate is valid for. RFC 6125 matching: exact entry or left-most wildcard; CN is a fallback only. If the MX hostname is not in the SAN, verifying senders (MTA-STS enforce, DANE PKIX modes) treat the session as unauthenticated.",
      },
      {
        anchor: "tls-version",
        term: "TLS version",
        text: "The negotiated protocol. TLS 1.2 is the floor, 1.3 preferred; SSLv3/TLS 1.0/1.1 are deprecated and treated as critical here.",
      },
      {
        anchor: "opportunistic-tls",
        term: "Opportunistic TLS (offered vs enforced)",
        text: "This check audits whether TLS is offered and healthy, not whether it is enforced. An active attacker can strip opportunistic STARTTLS from the banner and force cleartext unless MTA-STS enforce or DANE/TLSA makes the receiver refuse to downgrade.",
      },
      {
        anchor: "certificate-chain",
        term: "Certificate chain",
        text: "The trust path from the leaf certificate through its intermediates to a root in the public CA store. The most common failure is a missing intermediate — the handshake completes but no public CA trusts the chain, so MTA-STS and DANE-PKIX validation fail.",
      },
      {
        anchor: "expiry-runway",
        term: "Expiry runway",
        text: "How many days remain before the certificate's notAfter. This check warns at < 14 days and informs at < 30 days so renewal happens with runway — before a receiver starts bouncing.",
      },
      {
        anchor: "pfs-cipher",
        term: "PFS cipher",
        text: "A cipher suite with forward secrecy (ECDHE/DHE key exchange) and AEAD (GCM/ChaCha20). RC4, 3DES, EXPORT, and NULL suites are banned; static-RSA key exchange (no forward secrecy) is a warning.",
      },
      {
        anchor: "sni",
        term: "SNI",
        text: "Server Name Indication: on shared mail platforms the MX host must present the certificate matching the hostname sent as SNI, not a default platform certificate.",
      },
      {
        anchor: "ocsp-stapling",
        term: "OCSP stapling",
        text: "The MX stapling a signed OCSP response into the handshake so senders learn the certificate is not revoked without a separate round trip. Advisory here; a revoked certificate is critical.",
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
        anchor: "mta-sts",
        term: "MTA-STS",
        text: "MTA-STS has two moving parts: a _mta-sts TXT record (v=STSv1; id=…) and an HTTPS-served policy file. The *sender* is the enforcer — it caches your policy and refuses to downgrade. Plain STARTTLS is opportunistic, so an on-path attacker can strip it or spoof an MX; MTA-STS closes that gap.",
      },
      {
        anchor: "mode-enforce",
        term: "mode: enforce",
        text: "The MTA-STS policy mode that makes senders refuse to deliver when TLS or the MX-name match fails. `testing` only reports (report-only); `none` withdraws the policy. Migrate testing → enforce only after 14–30 days of clean TLS-RPT reports.",
      },
      {
        anchor: "policy-id",
        term: "policy id",
        text: "The id= token in the TXT record is the cache-buster: senders re-fetch the policy file only when the id changes. The stale-id trap is editing the policy body but leaving the id unchanged — senders keep serving the old cached copy until max_age expires.",
      },
      {
        anchor: "max-age",
        term: "max_age",
        text: "How long (seconds) senders cache the policy. The sane band is 604800–31557600; 604800 (a week) is typical. Too short means no protection between fetches; too long means a bad policy is pinned for weeks. The id= must rotate whenever the policy body changes.",
      },
      {
        anchor: "policy-file",
        term: "policy file",
        text: "The HTTPS-served key/value body at the exact URL https://mta-sts.<domain>/.well-known/mta-sts.txt, listing version, mode, one or more mx: patterns, and max_age. It must be served with a valid CA cert whose name matches mta-sts.<domain>, Content-Type: text/plain, and no redirect — senders will not follow a 3xx.",
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
    // The first three anchors are the fixed pm/checks/dns.mdx §14.6 category-wide destinations
    // (pm/checks/tls_rpt.mdx §9.1); the last two are page-local anchors this family's own copy
    // links to (`!10m` size suffix, and the ingested-report JSON shape).
    concepts: [
      {
        anchor: "tls-rpt",
        term: "TLS-RPT",
        text: "SMTP TLS Reporting (RFC 8460): one TXT record at _smtp._tls.<domain> that asks participating receivers (Google, Microsoft) to mail you one report per day describing every TLS session they attempted against your MX — how many succeeded, how many failed, and why. It enforces nothing itself; it is the smoke detector for MTA-STS, DANE, and STARTTLS.",
      },
      {
        anchor: "rua",
        term: "rua",
        text: "The Reporting URI for Aggregate data — one or more comma-separated mailto: (or https:) destinations senders deliver their daily TLS failure reports to, optionally with a !10m-style size cap. Same tag name as DMARC's rua but a different record: TLS-RPT has no ruf/pct/sp and needs no external-authorization record.",
      },
      {
        anchor: "reporting-mailbox",
        term: "reporting mailbox",
        text: "The mailbox (or HTTPS collector) the rua points at, where the daily reports actually land. This app can be that mailbox — the report-ingestion pipeline parses the gzip'd JSON attachments into the ingested-reports panel. If the rua domain has no MX (or the HTTPS host does not resolve) the reports bounce and you are blind again, one hop later.",
      },
      {
        anchor: "size-limit",
        term: "!10m size suffix",
        text: "RFC 8460 permits an optional maximum-size suffix on a rua URI — !<n> with an optional k/m/g/t unit, e.g. mailto:tls-reports@example.com!10m — asking reporters not to send a single report larger than that. It is advisory and parsed for display only; it never changes a URI's validity.",
      },
      {
        anchor: "report-json",
        term: "TLS report JSON",
        text: "What actually arrives: a gzip'd JSON attachment (application/tlsrpt+gzip) with organization-name, a one-day date-range, and per-policy summary counts (total-successful-session-count / total-failure-session-count) plus a failure-details[] array. Each failure entry carries a result-type (starttls-not-supported, certificate-host-mismatch, validation-failure, tlsa-invalid, sts-policy-fetch-error, …) that names the broken transport layer.",
      },
    ],
  },
  dane_tlsa: {
    key: "dane_tlsa",
    title: "DANE / TLSA",
    whatItIs: [
      "STARTTLS on its own is opportunistic — an active attacker can strip it from the SMTP banner and force cleartext. DANE (RFC 6698/7672) closes that hole by pinning the MX certificate in DNS: a DNSSEC-signed TLSA record at _25._tcp.<mx-host> tells validating senders (Gmail inbound, Exchange Online, Comcast, most German/Dutch systems) exactly which key to expect, so a stripped STARTTLS or a mismatched cert makes them defer rather than fall back to cleartext.",
      'The recommended profile is "3 1 1" (DANE-EE, SubjectPublicKeyInfo, SHA-256), which survives certificate renewals that keep the key. The hard prerequisite is DNSSEC — an unsigned TLSA is a no-op senders MUST ignore.',
      "A WRONG pin is worse than no pin: when a cert is renewed with a new key and the TLSA is not pre-staged, every DANE-validating sender hard-fails delivery to you — inbound mail queues and bounces until the record is fixed.",
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
    // The first four anchors are the fixed pm/checks/dns.mdx §14.6 map entries; the last two are
    // local anchors this family's own copy links to (pm/checks/dane_tlsa.mdx §9.1).
    concepts: [
      {
        anchor: "dane",
        term: "DANE",
        text: "DNS-Based Authentication of Named Entities: DNSSEC-anchored certificate pinning for SMTP (RFC 7672). Validated today by Gmail inbound (since late 2023), Exchange Online, Comcast, and most large German/Dutch mail systems. It is one of the two IETF answers to STARTTLS stripping — the other is MTA-STS, which uses the Web PKI + HTTPS instead of DNSSEC.",
      },
      {
        anchor: "tlsa",
        term: "TLSA record",
        text: "The DANE record type binding a TLS certificate (or its public key) to a service name and port. The owner name is _<port>._<proto>.<host> — _25._tcp.mail.example.com for SMTP — and the RDATA is four fields: usage (3 = pin the end-entity cert, 2 = pin a trust anchor; 0/1 are unusable for SMTP), selector (1 = SubjectPublicKeyInfo, 0 = full cert), matching type (1 = SHA-256, 2 = SHA-512, 0 = exact data), and the hex association data the presented cert/key must match.",
      },
      {
        anchor: "3-1-1",
        term: '"3 1 1" profile',
        text: "DANE-EE (3) + SubjectPublicKeyInfo (1) + SHA-256 (1): pin the end-entity key itself — no CA chain needed, and renewals that keep the key need no DNS change. Usage 0/1 (PKIX) MUST NOT be published for SMTP per RFC 7672; senders ignore such records entirely.",
      },
      {
        anchor: "tlsa-rollover",
        term: "TLSA rollover",
        text: 'Rollover discipline: keep ≥2 records (current + next) staged BEFORE renewing the certificate. The classic outage is "renewed the cert, forgot the TLSA" — the pinned digest stops matching and every DANE-validating sender hard-fails delivery. A short TTL (≤3600s) lets a re-pin propagate quickly.',
      },
      {
        anchor: "dnssec-prereq",
        term: "DNSSEC prerequisite",
        text: "An unsigned TLSA is a no-op senders MUST ignore. Both the MX host's zone (where the TLSA lives) and the domain's own zone (the MX lookup that leads senders there) must validate — see the DNSSEC check for signing the zone.",
      },
      {
        anchor: "partial-coverage",
        term: "Partial coverage",
        text: "Partial DANE ≈ no DANE: when only some MX hosts publish a valid TLSA, an active attacker simply steers delivery to the unprotected (often backup) MX. Every MX host, all priorities, needs a valid record.",
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
  // Interior content per pm/checks/dns_health.mdx §9.2 (block-1 copy) and §9.7 (the ten
  // #concept-<term> anchors this family owns).
  dns_health: {
    key: "dns_health",
    title: "DNS zone & nameserver health",
    whatItIs: [
      "Delegation is the substrate: the parent zone points at your nameservers, and every SPF, DKIM, and DMARC verification any receiver ever performs is a live query against them. One NS, a lame NS, parent↔child disagreement, or missing glue turns authentication into a coin flip — temperror results that spam-folder mail in a pattern matching the receiver's resolver, not your content.",
      'The SOA record is the zone\'s metronome: its serial plus refresh/retry/expire/minimum timers govern how secondaries stay in sync and how long "no such record" answers are cached. A serial that never advances (or goes backwards) can leave part of the internet serving your OLD SPF/DKIM records after a rotation.',
      "Zone content hazards silently change how mail lookups resolve: a CNAME at the apex masks the SOA/NS/MX/TXT records, a wildcard answers _dmarc.<sub> and DKIM-selector queries for names you never pinned, and a bloated or duplicated TXT set risks the exact UDP lookups receivers make while authenticating.",
      "Dangling records are the highest-severity modern DNS risk for a mail domain: a CNAME, SPF include:, MX, or delegated NS pointing at a deprovisioned or unclaimed target. Whoever claims that target controls a hostname inside your domain — the SubdoMailing-class subdomain takeover: phishing under a trusted name, a rogue TLS cert, or SPF-passing spoofed mail.",
    ],
    whatItMeans: [
      "Pass: 2–4 nameservers on ≥ 2 networks, all authoritative, parent set == child set, recursion and zone transfer closed, SOA/TTLs in range, no wildcard or apex-CNAME interference, and no dangling records — infra rots quietly, so the scheduled re-run is the value.",
      "Warn: lame NS, parent↔child drift, or a single network — some fraction of the world's resolvers intermittently gets SERVFAIL → temperror → softened DMARC enforcement and deferred legitimate mail; SOA/serial problems mean stale secondaries may keep serving old SPF/DKIM after a rotation.",
      "Critical: a dangling CNAME or dead SPF include — someone can claim the freed target and own the name (the 2024 SubdoMailing attack: thousands of reputable domains spammed through exactly this hole, then landed on the Spamhaus DBL). An apex CNAME or <2 resolving NS makes the zone's answers unreliable at the root.",
    ],
    howToFix: [
      "Dangling entries first — the takeover window is open NOW: delete the stale CNAME (or re-provision the target), remove the dead include:/redirect= token from the SPF record, repoint any dead MX; verify with `dig CNAME <name> +short` going empty.",
      "Delegation: add a second DNS provider on a different network/ASN (e.g. \"<domain>. IN NS ns1.provider-b.net.\"), make the registrar's NS list exactly match the zone's NS RRset, and remove any lame NS from the delegation.",
      "SOA: adopt the modern defaults — refresh 14400, retry 3600, expire 1209600, minimum 3600 — and bump the serial on every zone edit (YYYYMMDDnn convention).",
      "Zone content: remove the apex CNAME (use ALIAS/ANAME/flattening + real A/AAAA), remove or scope the wildcard and pin _dmarc, _mta-sts, _smtp._tls, and DKIM-selector records explicitly, merge to one v=spf1 … -all, and delete stale verification TXT records.",
    ],
    concepts: [
      {
        anchor: "ns",
        term: "NS records",
        text: "The NS RRset names which servers answer authoritatively for the zone. RFC 2182 wants at least two, on diverse networks — one provider outage must not take all mail authentication dark.",
      },
      {
        anchor: "delegation",
        term: "Delegation",
        text: "The parent zone (e.g. .com) points at your nameservers via NS records set at the registrar; the zone apex carries its own copy. The two sets must match exactly — drift means some resolvers use nameservers you no longer (or do not yet) control. A sub-delegation delegates a subdomain's subtree the same way.",
      },
      {
        anchor: "lame-delegation",
        term: "Lame delegation",
        text: "A listed nameserver that doesn't actually answer authoritatively for the zone — some resolvers pick it, get SERVFAIL/REFUSED, and your SPF/DKIM/DMARC lookups temperror, softening enforcement and deferring legitimate mail.",
      },
      {
        anchor: "glue",
        term: "Glue records",
        text: "When a nameserver's own name lives inside the zone it serves (in-bailiwick), the parent must publish its A/AAAA as glue or the delegation can never bootstrap. Missing or stale glue = an unresolvable or hijacked delegation.",
      },
      {
        anchor: "soa",
        term: "SOA record",
        text: "The Start of Authority: MNAME (primary master), RNAME (hostmaster mailbox), the serial, and the refresh (1200–86400) / retry (< refresh) / expire (≥ 604800) / minimum (≤ 86400, negative TTL) timers that govern secondaries and negative caching. The serial must advance on every edit.",
      },
      {
        anchor: "ttl",
        term: "TTL",
        text: 'How long resolvers cache a record. Mail-critical TTLs under ~300 s read as fast-flux infrastructure; over a day they make a bad record painfully slow to fix. The negative TTL (SOA minimum) controls how long "no such record" answers stick.',
      },
      {
        anchor: "wildcard",
        term: "Wildcard",
        text: "*.<domain> answers every name with no explicit record (RFC 4592) — including _dmarc.<sub> and DKIM selector lookups, corrupting mail authentication discovery and forging MX/SPF for arbitrary hostnames. A catch-all behaves the same way.",
      },
      {
        anchor: "dangling-cname",
        term: "Dangling CNAME / subdomain takeover",
        text: "A dangling record — CNAME, MX, NS, or SPF include — points at a dead or re-registerable target (an unclaimed endpoint matching a takeover fingerprint like *.herokudns.com). An attacker who claims the target inherits your name and SPF authorization (the 2024 SubdoMailing campaign).",
      },
      {
        anchor: "apex-cname",
        term: "CNAME at the apex",
        text: 'RFC 1035/2181 forbid a CNAME coexisting with other data, so a CNAME at the zone apex masks the SOA/NS/MX/TXT records — the classic "why did all my mail stop" incident. Use your provider\'s ALIAS/ANAME/flattening instead, plus real A/AAAA.',
      },
      {
        anchor: "txt-bloat",
        term: "TXT bloat & multiple SPF",
        text: "Stale verification tokens and duplicate strings swell a name's TXT set toward UDP-fragmentation / TCP-only territory on exactly the lookups receivers make while authenticating; two v=spf1 records are an RFC 7208 permerror — no SPF at all.",
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
        anchor: "client-hold",
        term: "clientHold / serverHold",
        text: "The registrar (client) or registry (server) has pulled the domain's NS delegation — it resolves for no one, so SPF/DKIM/DMARC/MX all vanish and 100% of mail hard-fails. Usually triggered by abuse reports, billing failures, or legal action; contact the registrar immediately.",
      },
      {
        anchor: "transfer-lock",
        term: "Transfer lock (clientTransferProhibited)",
        text: "The EPP status that refuses transfer requests to another registrar. Without it, anyone who phishes your registrar credentials can move the domain — and with it your SPF/DKIM/DMARC — in one step. Free at every registrar; leave it on except during an intentional transfer.",
      },
      {
        anchor: "nrd",
        term: "NRD",
        text: "Newly Registered Domain — feeds consumed by Spamhaus, Proofpoint, and Microsoft that throttle or junk mail from domains younger than ~30 days.",
      },
      {
        anchor: "parked-domain",
        term: "Parked domain",
        text: "A domain delegated to a parking service (sedoparking, bodis, afternic…) or serving a for-sale landing page. Parking nameservers can't serve your real SPF/DKIM/DMARC, and reputation systems read parked senders as inactive or speculative — a standing spam prior.",
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

/**
 * The explainer for one family key, or undefined for an unknown `:checkKey`. Route `:checkKey`
 * slugs are the KEBAB-case of the family keys (pm/checks/dns.mdx §14.1, e.g. `dns-health` ↔
 * `dns_health` — equal to the backend check directory names), so both forms resolve.
 */
export function dnsCheckExplainer(key: string): DnsCheckExplainer | undefined {
  return (DNS_CHECK_EXPLAINERS as Record<string, DnsCheckExplainer>)[key.replace(/-/g, "_")]
}
