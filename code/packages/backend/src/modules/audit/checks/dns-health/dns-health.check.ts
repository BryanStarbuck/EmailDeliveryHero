import {
  resolve4,
  resolve6,
  resolveCname,
  resolveMx,
  resolveNs,
  resolveSoa,
  resolveTxt,
} from "../dns-util"
import type { Checker, CheckOutcome, Finding } from "../types"

/**
 * DNS Zone & Nameserver Health (infra.dns_health). Audits the delegation plumbing every other
 * deliverability check depends on: nameserver count/diversity (RFC 2182), NS-as-CNAME (RFC 2181),
 * SOA sanity/serial/MNAME/RNAME (RFC 1912), apex CNAME (RFC 1035/2181), dangling CNAME / SPF
 * `include:` / MX targets (subdomain-takeover & spoofing risk), TXT bloat / multiple SPF (RFC 7208),
 * and unexpected wildcards. Everything here is first-round pure `node:dns/promises`; the probe-gated
 * sub-checks (precise lameness, authoritative parent↔child, glue, AXFR, TTL, real-ASN) emit a single
 * "not evaluated" info each rather than a false-critical. All finding `checkId`s use the stable
 * `infra.dns_health` prefix; each finding `id` is a spec sub-check id, suffixed per host/label/target.
 */

const CHECK_ID = "infra.dns_health"

/**
 * The structured zone snapshot persisted at results["infra.dns_health"] (pm/checks/dns.mdx §5) —
 * what the DNS page's Zone panel renders. `parent_child_match` and `ttls` stay null until their
 * probes (authoritative parent query / dig TTL parsing) land; snake_case mirrors the spec YAML.
 */
export interface DnsHealthResults {
  ns: { host: string; ips: string[] }[]
  ns_count: number
  network_count: number
  parent_child_match: boolean | null
  soa: {
    mname: string
    rname: string
    serial: number
    refresh: number
    retry: number
    expire: number
    min_ttl: number
  } | null
  ttls: Record<string, number> | null
  wildcard: { detected: boolean; probe: string; types: string[] }
  cname_at_apex: boolean
}

function emptySnapshot(): DnsHealthResults {
  return {
    ns: [],
    ns_count: 0,
    network_count: 0,
    parent_child_match: null,
    soa: null,
    ttls: null,
    wildcard: { detected: false, probe: "", types: [] },
    cname_at_apex: false,
  }
}

interface Fingerprint {
  provider: string
  suffix: string
}

// Bundled subdomain-takeover fingerprints (config/takeover_fingerprints.json in the store).
const TAKEOVER_FINGERPRINTS: Fingerprint[] = [
  { provider: "Heroku", suffix: ".herokudns.com" },
  { provider: "Heroku", suffix: ".herokuapp.com" },
  { provider: "AWS S3", suffix: ".s3.amazonaws.com" },
  { provider: "AWS CloudFront", suffix: ".cloudfront.net" },
  { provider: "GitHub Pages", suffix: ".github.io" },
  { provider: "Azure App Service", suffix: ".azurewebsites.net" },
  { provider: "WordPress.com", suffix: ".wordpress.com" },
  { provider: "Pantheon", suffix: ".pantheonsite.io" },
  { provider: "SendGrid", suffix: ".sendgrid.net" },
]

// Probe-gated sub-checks: emit exactly one info each (never warning/critical) per acceptance #10.
const FUTURE_SUBCHECKS = [
  {
    id: "infra.ns_lame",
    what: "per-nameserver authoritative (AA-bit) probe to detect lame servers",
    remediation:
      "When the dig/authoritative-query capability is enabled, fix any server answering non-authoritatively (REFUSED/SERVFAIL), or remove the lame NS from the delegation.",
  },
  {
    id: "infra.ns_parent_child",
    what: "authoritative parent-zone (TLD) vs apex NS comparison",
    remediation:
      "Update the registrar/parent delegation to match the in-zone NS RRset exactly (both directions).",
  },
  {
    id: "infra.ns_all_answer",
    what: "per-nameserver UDP + TCP/53 reachability probe",
    remediation: "Open TCP/53 on every nameserver; DNS requires TCP fallback (RFC 7766).",
  },
  {
    id: "infra.glue_records",
    what: "parent-supplied glue vs authoritative A/AAAA comparison for in-bailiwick NS",
    remediation: "Add/fix glue at the registrar so it matches each in-zone NS host's real A/AAAA.",
  },
  {
    id: "infra.ttl_sanity",
    what: "TTL bounds on mail-critical records (MX, SPF/TXT, DKIM, DMARC)",
    remediation:
      "Set mail-critical record TTLs to 3600s (1h); drop to 300s only during a planned migration.",
  },
  {
    id: "infra.zone_transfer",
    what: "AXFR (zone-transfer) exposure probe against each nameserver",
    remediation:
      "Restrict AXFR with allow-transfer { none; } (or TSIG-only) on every authoritative server.",
  },
  {
    id: "infra.ns_response_time",
    what: "nameserver response-latency measurement",
    remediation: "Add anycast/closer secondaries and investigate any slow nameserver.",
  },
  {
    id: "infra.recursion_open",
    what: "open-recursive-resolver probe on authoritative nameservers",
    remediation: "Disable recursion on authoritative-only nameservers.",
  },
]

function fqdnLower(name: string): string {
  return name.trim().replace(/\.$/, "").toLowerCase()
}

function unique<T>(xs: T[]): T[] {
  return [...new Set(xs)]
}

/** A coarse network-diversity key: /24 for IPv4, first three hextets (~/48) for IPv6. */
function netGroup(ip: string): string {
  if (ip.includes(":")) return ip.toLowerCase().split(":").slice(0, 3).join(":") || ip.toLowerCase()
  return ip.split(".").slice(0, 3).join(".")
}

function matchFingerprint(target: string): string | null {
  const t = fqdnLower(target)
  for (const fp of TAKEOVER_FINGERPRINTS) if (t.endsWith(fp.suffix)) return fp.provider
  return null
}

function transientInfo(id: string, detail: string, remediation: string): Finding {
  return {
    id,
    checkId: CHECK_ID,
    title: "Transient DNS lookup failure",
    severity: "info",
    detail,
    remediation,
  }
}

/** Follow a CNAME chain (8-hop cap, loop guard) to its final non-CNAME target. */
async function followCname(
  start: string,
): Promise<{ final: string; chain: string[]; status: "chain" | "transient" | "loop" }> {
  const chain: string[] = []
  const seen = new Set<string>()
  let current = fqdnLower(start)
  for (let i = 0; i < 8; i++) {
    if (seen.has(current)) return { final: current, chain, status: "loop" }
    seen.add(current)
    const c = await resolveCname(current)
    if (c.error) return { final: current, chain, status: "transient" }
    if (c.records.length === 0) return { final: current, chain, status: "chain" }
    chain.push(current)
    current = fqdnLower(c.records[0])
  }
  return { final: current, chain, status: "chain" }
}

/** Does a name resolve to anything live (address, MX, or TXT)? Distinguishes dead from transient. */
async function classifyTarget(name: string): Promise<"live" | "dead" | "transient"> {
  const [a, aaaa] = await Promise.all([resolve4(name), resolve6(name)])
  if (a.error || aaaa.error) return "transient"
  if (a.records.length > 0 || aaaa.records.length > 0) return "live"
  const [mx, txt] = await Promise.all([resolveMx(name), resolveTxt(name)])
  if (mx.error || txt.error) return "transient"
  if (mx.records.length > 0 || txt.records.length > 0) return "live"
  return "dead"
}

/** infra.ns_sanity (+ infra.ns_no_cname). Count, resolve, network-diversity, NS-as-CNAME. */
async function checkNs(domain: string, findings: Finding[], snap: DnsHealthResults): Promise<void> {
  const ns = await resolveNs(domain)
  if (ns.error) {
    findings.push(
      transientInfo(
        "infra.ns_sanity",
        `NS lookup for ${domain} failed (${ns.error}); could not assess delegation. Retry later.`,
        "Retry the audit; if it persists, verify the domain's registrar delegation and that its nameservers answer.",
      ),
    )
    return
  }
  if (ns.empty || ns.records.length === 0) {
    findings.push({
      id: "infra.ns_sanity",
      checkId: CHECK_ID,
      title: "No delegation of its own (served by parent zone)",
      severity: "info",
      detail: `${domain} has no NS records of its own; it appears to be a bare subdomain served by its parent zone. NS/SOA sub-checks are skipped.`,
      remediation: `If this should be an independent zone, delegate it at the registrar with at least two nameservers on different networks, e.g. "${domain}. IN NS ns1.provider-a.net." and "${domain}. IN NS ns1.provider-b.net.".`,
    })
    return
  }

  const hosts = unique(ns.records.map(fqdnLower))
  const nsInfos: { host: string; ips: string[]; groups: string[] }[] = []
  for (const host of hosts) {
    const cname = await resolveCname(host)
    if (!cname.error && cname.records.length > 0) {
      findings.push({
        id: `infra.ns_no_cname.${host}`,
        checkId: CHECK_ID,
        title: `Nameserver ${host} is a CNAME`,
        severity: "warning",
        detail: `NS target ${host} is a CNAME (→ ${cname.records[0]}), which RFC 2181 §10.3 forbids for NS/MX targets and breaks strict resolvers.`,
        remediation: `Repoint ${host} to a hostname that has its own A/AAAA records; NS and MX targets must not be CNAMEs.`,
        evidence: cname.records[0],
      })
    }
    const [a, aaaa] = await Promise.all([resolve4(host), resolve6(host)])
    const ips = [...a.records, ...aaaa.records]
    nsInfos.push({ host, ips, groups: unique(ips.map(netGroup)) })
  }

  snap.ns = nsInfos.map((n) => ({ host: n.host, ips: n.ips }))
  snap.ns_count = hosts.length
  snap.network_count = new Set(nsInfos.flatMap((n) => n.groups)).size

  const resolvedCount = nsInfos.filter((n) => n.ips.length > 0).length
  const evidence = nsInfos.map((n) => `${n.host}=${n.ips.join("/") || "?"}`).join(", ")

  if (hosts.length < 2 || resolvedCount === 0) {
    findings.push({
      id: "infra.ns_sanity",
      checkId: CHECK_ID,
      title: hosts.length < 2 ? "Fewer than 2 nameservers" : "No nameserver resolves to an address",
      severity: "critical",
      detail:
        hosts.length < 2
          ? `${domain} is served by only ${hosts.length} nameserver. A single NS is a single point of failure — one outage takes the domain and all its mail authentication (SPF/DKIM/DMARC) offline.`
          : `${domain} lists ${hosts.length} nameservers but none resolve to an address, so the delegation is effectively dead and authentication records may be unresolvable.`,
      remediation: `Add a second provider's nameservers on a different network/ASN, e.g. "${domain}. IN NS ns1.provider-b.net." served by a second DNS provider.`,
      evidence,
    })
    return
  }

  const groups = new Set(nsInfos.flatMap((n) => n.groups))
  if (groups.size <= 1) {
    findings.push({
      id: "infra.ns_sanity",
      checkId: CHECK_ID,
      title: "All nameservers share one network",
      severity: "warning",
      detail: `All ${resolvedCount} resolvable nameservers fall in a single /24+/48 prefix group (${[...groups].join(", ") || "unknown"}). One network/provider outage takes the whole domain — and all its mail authentication — offline (RFC 2182). True ASN diversity is a future check.`,
      remediation: `Add ns1.provider-b.net. on a different network/ASN, e.g. "${domain}. IN NS ns1.provider-b.net." served by a second DNS provider.`,
      evidence,
    })
  } else {
    findings.push({
      id: "infra.ns_sanity",
      checkId: CHECK_ID,
      title: "Nameserver set looks healthy",
      severity: "ok",
      detail: `${hosts.length} nameservers across ${groups.size} network groups (ASN-level diversity is a future check).`,
      evidence,
    })
  }
}

/** infra.soa_sanity / soa_serial / soa_mname_ns / soa_rname. */
async function checkSoa(
  domain: string,
  findings: Finding[],
  snap: DnsHealthResults,
): Promise<void> {
  const soa = await resolveSoa(domain)
  if (soa.error) {
    findings.push(
      transientInfo(
        "infra.soa_sanity",
        `SOA lookup for ${domain} failed (${soa.error}). Retry later.`,
        "Retry the audit; if it persists, verify the zone's authoritative servers answer for SOA.",
      ),
    )
    return
  }
  const r = soa.record
  if (!r) return // no SOA (bare subdomain) — already surfaced by the NS no-delegation info.

  snap.soa = {
    mname: r.nsname,
    rname: r.hostmaster,
    serial: r.serial,
    refresh: r.refresh,
    retry: r.retry,
    expire: r.expire,
    min_ttl: r.minttl,
  }

  const soaEvidence = `mname=${r.nsname} rname=${r.hostmaster} serial=${r.serial} refresh=${r.refresh} retry=${r.retry} expire=${r.expire} minimum=${r.minttl}`

  const problems: string[] = []
  if (r.expire < r.refresh) problems.push("expire < refresh")
  if (r.minttl > 86400) problems.push(`minimum ${r.minttl}s > 86400s`)
  if (r.refresh < 1200 || r.refresh > 86400)
    problems.push(`refresh ${r.refresh}s outside 1200–86400s`)
  if (r.retry >= r.refresh) problems.push(`retry ${r.retry}s >= refresh ${r.refresh}s`)
  if (r.expire < 604800) problems.push(`expire ${r.expire}s < 7 days`)
  if (problems.length > 0) {
    findings.push({
      id: "infra.soa_sanity",
      checkId: CHECK_ID,
      title: "SOA timers off RFC 1912 guidance",
      severity: "warning",
      detail: `SOA timers are unsafe: ${problems.join("; ")}. Bad timers can leave secondaries serving stale records after an SPF/DKIM rotation, causing intermittent auth failures.`,
      remediation: "Set sane SOA timers, e.g. refresh 7200 retry 3600 expire 1209600 minimum 3600.",
      evidence: soaEvidence,
    })
  } else {
    findings.push({
      id: "infra.soa_sanity",
      checkId: CHECK_ID,
      title: "SOA timers are sane",
      severity: "ok",
      detail: `refresh ${r.refresh}, retry ${r.retry}, expire ${r.expire}, minimum ${r.minttl}.`,
      evidence: soaEvidence,
    })
  }

  if (!r.serial || r.serial === 0) {
    findings.push({
      id: "infra.soa_serial",
      checkId: CHECK_ID,
      title: "SOA serial is missing or zero",
      severity: "warning",
      detail:
        "The SOA serial is zero/absent, so secondaries cannot detect zone changes and may serve stale auth records.",
      remediation:
        "Set a non-zero, advancing serial using the YYYYMMDDnn convention, e.g. 2026070101, and bump it on every zone edit so secondaries reload.",
      evidence: `serial=${r.serial}`,
    })
  } else {
    findings.push({
      id: "infra.soa_serial",
      checkId: CHECK_ID,
      title: "SOA serial present",
      severity: "ok",
      detail: `SOA serial is ${r.serial}. Cross-run monotonic checks (serial went backwards / never advances after a record change) are performed by the audit store against the previous run.`,
      evidence: `serial=${r.serial}`,
    })
  }

  // MNAME (primary master) must resolve and ideally be in the NS set.
  const mname = fqdnLower(r.nsname)
  const [ma, maaaa] = await Promise.all([resolve4(mname), resolve6(mname)])
  const mResolves = ma.records.length > 0 || maaaa.records.length > 0
  const mTransient = !!(ma.error || maaaa.error)
  const nsSet = await resolveNs(domain)
  const nsHosts = nsSet.error ? [] : nsSet.records.map(fqdnLower)
  if (!mResolves && !mTransient) {
    findings.push({
      id: "infra.soa_mname_ns",
      checkId: CHECK_ID,
      title: "SOA MNAME does not resolve",
      severity: "warning",
      detail: `SOA MNAME (primary master) ${mname} does not resolve to an address (NXDOMAIN).`,
      remediation: `Set SOA MNAME to your primary authoritative server's FQDN — a host that resolves and appears in the NS set, e.g. ${nsHosts[0] ?? "ns1.provider-a.net."}.`,
      evidence: `mname=${mname}`,
    })
  } else if (mResolves && nsHosts.length > 0 && !nsHosts.includes(mname)) {
    findings.push({
      id: "infra.soa_mname_ns",
      checkId: CHECK_ID,
      title: "SOA MNAME not in NS set",
      severity: "warning",
      detail: `SOA MNAME ${mname} resolves but is not a member of the apex NS RRset (${nsHosts.join(", ")}).`,
      remediation: `Set SOA MNAME to one of your authoritative nameservers, e.g. ${nsHosts[0]}.`,
      evidence: `mname=${mname}`,
    })
  } else if (mResolves) {
    findings.push({
      id: "infra.soa_mname_ns",
      checkId: CHECK_ID,
      title: "SOA MNAME OK",
      severity: "ok",
      detail: `SOA MNAME ${mname} resolves${nsHosts.includes(mname) ? " and is in the NS set" : ""}.`,
      evidence: `mname=${mname}`,
    })
  }

  // RNAME (hostmaster mailbox) hygiene — info-level only.
  const rname = r.hostmaster
  if (!rname || !rname.includes(".")) {
    findings.push({
      id: "infra.soa_rname",
      checkId: CHECK_ID,
      title: "SOA RNAME missing or malformed",
      severity: "info",
      detail: `SOA RNAME (hostmaster mailbox) "${rname}" is missing or malformed.`,
      remediation: `Set RNAME to a monitored mailbox, e.g. hostmaster.${domain}. (mapping to hostmaster@${domain}).`,
      evidence: `rname=${rname}`,
    })
  } else {
    const clean = fqdnLower(rname)
    const dot = clean.indexOf(".")
    const mailboxDomain = clean.slice(dot + 1)
    const [rmx, ra] = await Promise.all([resolveMx(mailboxDomain), resolve4(mailboxDomain)])
    if (!rmx.error && !ra.error && rmx.records.length === 0 && ra.records.length === 0) {
      findings.push({
        id: "infra.soa_rname",
        checkId: CHECK_ID,
        title: "SOA RNAME mailbox domain does not accept mail",
        severity: "info",
        detail: `SOA RNAME resolves to ${clean.slice(0, dot)}@${mailboxDomain}, but ${mailboxDomain} has no MX or A record, so the hostmaster mailbox is unreachable.`,
        remediation: `Set RNAME to a monitored, deliverable mailbox, e.g. hostmaster.${domain}. (mapping to hostmaster@${domain}).`,
        evidence: `rname=${rname}`,
      })
    }
  }
}

/** infra.cname_at_apex. Any CNAME at the zone apex masks SOA/NS/MX/TXT. */
async function checkApexCname(
  domain: string,
  findings: Finding[],
  snap: DnsHealthResults,
): Promise<void> {
  const c = await resolveCname(domain)
  if (c.error) {
    findings.push(
      transientInfo(
        "infra.cname_at_apex",
        `Apex CNAME lookup for ${domain} failed (${c.error}). Retry later.`,
        "Retry the audit; if it persists, verify the zone's authoritative servers answer.",
      ),
    )
    return
  }
  if (c.records.length > 0) {
    snap.cname_at_apex = true
    findings.push({
      id: "infra.cname_at_apex",
      checkId: CHECK_ID,
      title: "CNAME at the zone apex",
      severity: "critical",
      detail: `${domain} is a CNAME (→ ${c.records[0]}). A CNAME at the apex masks the apex SOA/NS/MX/TXT records (RFC 1035/2181), which silently breaks mail routing and SPF/DMARC publication.`,
      remediation: `Remove the apex CNAME on ${domain}; use your DNS provider's ALIAS/ANAME/flattening feature, or publish real A/AAAA plus MX/TXT at the apex.`,
      evidence: c.records[0],
    })
  } else {
    findings.push({
      id: "infra.cname_at_apex",
      checkId: CHECK_ID,
      title: "No apex CNAME",
      severity: "ok",
      detail: `${domain} has no CNAME at the apex.`,
    })
  }
}

/** Curated mail-relevant labels to scan for dangling CNAMEs, plus MX hosts. */
async function danglingLabels(domain: string, selectors: string[]): Promise<string[]> {
  const base = [
    "mail",
    "smtp",
    "links",
    "email",
    "click",
    "newsletter",
    "_dmarc",
    "_mta-sts",
    "mta-sts",
  ]
  const dkim = selectors.map((s) => `${s}._domainkey`)
  const labels = [...base, ...dkim].map((l) => `${l}.${domain}`)
  const mx = await resolveMx(domain)
  if (!mx.error) {
    for (const rec of mx.records) {
      const host = fqdnLower(rec.exchange)
      if (host && host !== ".") labels.push(host)
    }
  }
  return unique(labels)
}

/** infra.dangling_cname. Each CNAME must point at a live, claimed target. */
async function checkDanglingCname(
  domain: string,
  selectors: string[],
  findings: Finding[],
): Promise<void> {
  const labels = await danglingLabels(domain, selectors)
  for (const label of labels) {
    const c = await resolveCname(label)
    if (c.error || c.records.length === 0) continue // no CNAME here (or transient) — nothing to flag.
    const { final, chain } = await followCname(label)
    const fp = matchFingerprint(final)
    const status = await classifyTarget(final)
    if (status === "transient") continue
    const chainStr = [...chain, final].join(" → ")
    if (status === "dead") {
      findings.push({
        id: `infra.dangling_cname.${label}`,
        checkId: CHECK_ID,
        title: `Dangling CNAME on ${label}${fp ? ` — ${fp} takeover risk` : ""}`,
        severity: "critical",
        detail: `${label} is a CNAME to ${final}, which does not resolve (NXDOMAIN).${
          fp
            ? ` ${final} matches the ${fp} pattern — an attacker who claims this ${fp} endpoint takes over ${label} to host phishing under a trusted name or send SPF-passing mail for ${domain}.`
            : ` Whoever claims ${final} controls a hostname inside ${domain} (subdomain takeover).`
        } Chain: ${chainStr}.`,
        remediation: `Delete the stale CNAME on ${label}, or re-provision the target so ${final} resolves again. Never leave a CNAME pointing at a deprovisioned host.`,
        evidence: chainStr,
      })
    } else if (fp) {
      findings.push({
        id: `infra.dangling_cname.${label}`,
        checkId: CHECK_ID,
        title: `${label} points at a ${fp} endpoint (live)`,
        severity: "ok",
        detail: `${label} is a CNAME to ${final} (${fp}) which currently resolves. HTTP "unclaimed endpoint" signature confirmation is a future check.`,
        evidence: chainStr,
      })
    } else {
      findings.push({
        id: `infra.dangling_cname.${label}`,
        checkId: CHECK_ID,
        title: `${label} CNAME target is live`,
        severity: "ok",
        detail: `${label} → ${final} resolves.`,
        evidence: chainStr,
      })
    }
  }
}

/** infra.dangling_include. SPF include:/redirect= and MX targets must resolve to a live service. */
async function checkDanglingInclude(domain: string, findings: Finding[]): Promise<void> {
  const txt = await resolveTxt(domain)
  if (!txt.error) {
    const spf = txt.records.find((r) => r.toLowerCase().startsWith("v=spf1"))
    if (spf) {
      for (const tok of spf.split(/\s+/)) {
        const m = /^[+~\-?]?(include:|redirect=)(.+)$/i.exec(tok)
        if (!m) continue
        const mech = m[1].replace(/[:=]/, "")
        const target = fqdnLower(m[2])
        const status = await classifyTarget(target)
        if (status === "dead") {
          findings.push({
            id: `infra.dangling_include.${target}`,
            checkId: CHECK_ID,
            title: `SPF ${mech} target ${target} is dead`,
            severity: "critical",
            detail: `The SPF record's ${mech}:${target} points at a domain that no longer resolves (NXDOMAIN). Receivers evaluating SPF hit this dead lookup, which can void SPF (permerror) and lets the freed target be claimed to pass SPF for ${domain}.`,
            remediation: `Remove "${tok}" from the SPF (v=spf1) TXT record at ${domain}, or repoint it to a live sending service. Keep exactly one v=spf1 record ending in -all/~all.`,
            evidence: spf,
          })
        }
      }
    }
  }

  const mx = await resolveMx(domain)
  if (!mx.error) {
    for (const rec of mx.records) {
      const host = fqdnLower(rec.exchange)
      if (!host || host === ".") continue
      const [a, aaaa] = await Promise.all([resolve4(host), resolve6(host)])
      if (a.error || aaaa.error) continue
      if (a.records.length === 0 && aaaa.records.length === 0) {
        findings.push({
          id: `infra.dangling_include.mx.${host}`,
          checkId: CHECK_ID,
          title: `MX host ${host} does not resolve`,
          severity: "critical",
          detail: `MX ${rec.priority} ${host} for ${domain} has no A/AAAA address — mail routed here bounces, and the freed hostname can be claimed.`,
          remediation: `Repoint the MX for ${domain} to a live mail host with A/AAAA records, or remove the dead MX entry (see mx_routing).`,
          evidence: `MX ${rec.priority} ${host}`,
        })
      }
    }
  }
}

function detectTxtDuplicates(records: string[]): string[] {
  const dups: string[] = []
  const counts = new Map<string, number>()
  for (const r of records) counts.set(r.toLowerCase(), (counts.get(r.toLowerCase()) ?? 0) + 1)
  for (const [, c] of counts) if (c > 1) dups.push("exact-duplicate TXT")
  for (const p of ["google-site-verification", "ms=", "facebook-domain-verification"]) {
    const c = records.filter((r) => r.toLowerCase().startsWith(p)).length
    if (c > 1) dups.push(`${c}× "${p}"`)
  }
  return unique(dups)
}

/** infra.multi_txt_spf + infra.txt_bloat. */
async function checkTxt(domain: string, findings: Finding[]): Promise<void> {
  const txt = await resolveTxt(domain)
  if (txt.error) {
    findings.push(
      transientInfo(
        "infra.txt_bloat",
        `TXT lookup for ${domain} failed (${txt.error}). Retry later.`,
        "Retry the audit; if it persists, verify the zone's authoritative servers answer for TXT.",
      ),
    )
    return
  }
  const records = txt.records
  const spfRecs = records.filter((r) => r.toLowerCase().startsWith("v=spf1"))
  if (spfRecs.length >= 2) {
    findings.push({
      id: "infra.multi_txt_spf",
      checkId: CHECK_ID,
      title: "Multiple SPF records",
      severity: "warning",
      detail: `${domain} publishes ${spfRecs.length} v=spf1 TXT records. Per RFC 7208 §3.2 this is a permerror; receivers ignore SPF entirely, softening enforcement and letting spoofed mail through.`,
      remediation: 'Merge into a single "v=spf1 ... -all" TXT record and delete the duplicate(s).',
      evidence: spfRecs.join(" | "),
    })
  } else {
    findings.push({
      id: "infra.multi_txt_spf",
      checkId: CHECK_ID,
      title: "Single SPF record",
      severity: "ok",
      detail: `${spfRecs.length} v=spf1 record at the apex.`,
    })
  }

  const totalOctets = records.reduce((n, r) => n + r.length, 0)
  const dups = detectTxtDuplicates(records)
  const bloat: string[] = []
  if (totalOctets > 1200)
    bloat.push(
      `TXT set totals ${totalOctets} octets (approaching UDP fragmentation / forcing TCP-only responses)`,
    )
  if (dups.length > 0) bloat.push(`duplicate verification strings: ${dups.join(", ")}`)
  if (bloat.length > 0) {
    findings.push({
      id: "infra.txt_bloat",
      checkId: CHECK_ID,
      title: "TXT record bloat",
      severity: "warning",
      detail: `Apex TXT set may be problematic: ${bloat.join("; ")}.`,
      remediation:
        "Remove stale verification TXT records (old google-site-verification, MS=, facebook-domain-verification, etc.) and keep exactly one SPF record so the apex TXT set fits a single UDP response.",
      evidence: `${records.length} TXT records, ${totalOctets} octets`,
    })
  } else {
    findings.push({
      id: "infra.txt_bloat",
      checkId: CHECK_ID,
      title: "TXT set size OK",
      severity: "ok",
      detail: `${records.length} TXT records, ${totalOctets} octets at the apex.`,
    })
  }
}

/** infra.wildcard. A random nonce label that resolves implies a wildcard/catch-all. */
async function checkWildcard(
  domain: string,
  findings: Finding[],
  snap: DnsHealthResults,
): Promise<void> {
  const nonce = `nonce-${Math.random().toString(36).slice(2, 12)}${Date.now().toString(36)}`
  const label = `${nonce}.${domain}`
  const [a, aaaa, mx, txt] = await Promise.all([
    resolve4(label),
    resolve6(label),
    resolveMx(label),
    resolveTxt(label),
  ])
  const types: string[] = []
  if (a.records.length > 0) types.push("A")
  if (aaaa.records.length > 0) types.push("AAAA")
  if (mx.records.length > 0) types.push("MX")
  if (txt.records.length > 0) types.push("TXT")
  snap.wildcard = { detected: types.length > 0, probe: label, types }
  if (types.length > 0) {
    findings.push({
      id: "infra.wildcard",
      checkId: CHECK_ID,
      title: "Unexpected wildcard record",
      severity: "warning",
      detail: `A random label (${label}) resolved (${types.join(", ")}), indicating a wildcard/catch-all under ${domain}. Wildcards mask typos and can forge arbitrary mail hostnames (bogus MX/SPF for any name).`,
      remediation: `Remove the wildcard record, or scope it deliberately; ensure "*.${domain}" does not create MX/SPF/A for arbitrary hostnames.`,
      evidence: `${label} → ${types.join(", ")}`,
    })
  } else {
    findings.push({
      id: "infra.wildcard",
      checkId: CHECK_ID,
      title: "No wildcard",
      severity: "ok",
      detail: `A random label under ${domain} did not resolve — no wildcard/catch-all.`,
    })
  }
}

function emitFutureInfos(findings: Finding[]): void {
  for (const f of FUTURE_SUBCHECKS) {
    findings.push({
      id: f.id,
      checkId: CHECK_ID,
      title: `${f.id} not evaluated (future probe)`,
      severity: "info",
      detail: `${f.what} is not performed in the first round — it needs a dig/authoritative-query, TCP/AXFR, or HTTP-signature capability not enabled yet. No problem is asserted; this row is informational only.`,
      remediation: f.remediation,
    })
  }
}

export const dnsHealthCheck: Checker = {
  id: "infra.dns_health",
  label: "DNS Zone & NS Health",
  async run(ctx): Promise<CheckOutcome> {
    const findings: Finding[] = []
    const snap = emptySnapshot()
    const domain = fqdnLower(ctx.domain)
    if (!domain) return { findings }

    const selectors = ctx.dkimSelectors ?? []

    // Ordered, but independent — run each sub-check with its own graceful degradation.
    await checkNs(domain, findings, snap)
    await checkSoa(domain, findings, snap)
    await checkApexCname(domain, findings, snap)
    await checkDanglingCname(domain, selectors, findings)
    await checkDanglingInclude(domain, findings)
    await checkTxt(domain, findings)
    await checkWildcard(domain, findings, snap)
    emitFutureInfos(findings)

    return { findings, results: snap }
  },
}
