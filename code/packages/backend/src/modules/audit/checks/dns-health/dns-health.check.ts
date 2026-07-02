import { Resolver } from "node:dns/promises"
import { domainToASCII } from "node:url"
import { readAppConfig, type TakeoverFingerprint } from "@shared/config-store"
import {
  resolve4,
  resolve6,
  resolveCname,
  resolveMx,
  resolveNs,
  resolveSoa,
  resolveTxt,
} from "../dns-util"
import type { Checker, CheckOutcome, DnsHealthConfig, Finding } from "../types"

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
 * One nameserver row of the zone snapshot (pm/checks/dns_health.mdx §5 `dns_nameservers`):
 * resolved addresses, the /24+/48 diversity key, the NS-as-CNAME flag, and the (first-round,
 * inferred) lame flag. `asn`/`authoritative`/`answers_tcp` stay for future probes.
 */
export interface DnsNameserverRow {
  host: string
  ips: string[]
  /** "/24 (v4) + first-3-hextets (v6)" diversity key(s), "+"-joined; "" when unresolved. */
  net_group: string
  /** NS target is itself a CNAME (RFC 2181 §10.3 violation). */
  is_cname: boolean
  /** First-round inference: the NS resolves to no address (precise AA-bit probe is future). */
  lame: boolean
}

/** One dangling record observed this run (pm/checks/dns_health.mdx §5 `dns_health_results.dangling`). */
export interface DanglingEntry {
  /** The owner name carrying the dangling reference. */
  name: string
  /** The record type holding the reference (CNAME / SPF / MX / NS). */
  type: "CNAME" | "SPF" | "MX" | "NS"
  /** The dead / unclaimed target. */
  target: string
  kind: "cname" | "include" | "mx" | "ns"
}

/**
 * One CNAME chain observed by the dangling sweep, live ones included
 * (pm/checks/dns_health.mdx §12 `cname_chains`): powers the raw panel's chain lines and lets the
 * history strip see a chain re-point BEFORE it dangles.
 */
export interface CnameChainEntry {
  /** The owner name the chain starts at. */
  name: string
  /** The CNAME nodes visited, in order (the owner name first). */
  chain: string[]
  /** The final non-CNAME target. */
  final: string
  status: "live" | "dead" | "loop"
}

/**
 * The structured zone snapshot persisted at results["infra.dns_health"] (pm/checks/dns.mdx §5 +
 * pm/checks/dns_health.mdx §5 — the `dns_health_results` summary + `dns_nameservers` rows mapped
 * onto today's per-run store) — what the DNS page's Zone panel renders. `parent_child_match` and
 * `ttls` stay null until their probes (authoritative parent query / dig TTL parsing) land;
 * snake_case mirrors the spec YAML.
 */
export interface DnsHealthResults {
  ns: DnsNameserverRow[]
  ns_count: number
  network_count: number
  /**
   * `dns_health_results.ns_asn_diverse` (acceptance #2): FALSE when the resolvable NS all share
   * one /24+/48 prefix group (single-network proxy for single-ASN); NULL when prefix-diverse —
   * true ASN diversity waits for the future ASN feed — or when nothing resolved.
   */
  ns_asn_diverse: boolean | null
  /** `dns_health_results.lame_ns`: the lame/no-answer NS observed this run (first-round inference). */
  lame_ns: { host: string; reason: string }[]
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
  /** `dns_health_results.soa_serial` — extracted for the cross-run monotonic compare. */
  soa_serial: number | null
  ttls: Record<string, number> | null
  wildcard: { detected: boolean; probe: string; types: string[] }
  /** Spec-named mirror of `wildcard.types` (`dns_health_results.wildcard_types`, acceptance #9). */
  wildcard_types: string[]
  cname_at_apex: boolean
  /** Spec-named mirror of `cname_at_apex` (`dns_health_results.apex_is_cname`, acceptance #3). */
  apex_is_cname: boolean
  /** Dangling CNAME / SPF-include / MX / sub-delegated-NS targets found this run. */
  dangling: DanglingEntry[]
  /** Apex TXT RRset size (infra.txt_bloat). */
  txt_record_count: number
  /** How many v=spf1 TXT records the apex publishes (>1 = permerror, infra.multi_txt_spf). */
  spf_record_count: number
  /** §12: apex TXT set size in octets — the parsed-table row and the octets sparkline. */
  txt_total_octets: number
  /** §12: the labels the dangling sweep actually resolved this run (base set + DKIM selectors + MX hosts + operator extras). */
  scanned_labels: string[]
  /** §12: every CNAME chain observed this run, live ones included. */
  cname_chains: CnameChainEntry[]
  /**
   * §12: zone-file-style render strings built at check time so the explainer's raw panel renders
   * verbatim with no reconstruction drift. The apex TXT set is summarized as count/octets/spf-count
   * — never full verification-token values.
   */
  raw: { ns_lines: string[]; soa_line: string | null; apex_txt_meta: string | null }
  /** `dns_health_results.glue_ok` — NULL until the parent-glue probe (future). */
  glue_ok: boolean | null
  /** `dns_health_results.axfr_open` — NULL until the AXFR probe (future). */
  axfr_open: boolean | null
  /** `dns_health_results.worst_severity` — the worst severity this check produced this run. */
  worst_severity: "ok" | "info" | "warning" | "critical"
  /** `dns_health_results.checked_at` — ISO timestamp of this run's DNS-health pass. */
  checked_at: string
}

function emptySnapshot(): DnsHealthResults {
  return {
    ns: [],
    ns_count: 0,
    network_count: 0,
    ns_asn_diverse: null,
    lame_ns: [],
    parent_child_match: null,
    soa: null,
    soa_serial: null,
    ttls: null,
    wildcard: { detected: false, probe: "", types: [] },
    wildcard_types: [],
    cname_at_apex: false,
    apex_is_cname: false,
    dangling: [],
    txt_record_count: 0,
    spf_record_count: 0,
    txt_total_octets: 0,
    scanned_labels: [],
    cname_chains: [],
    raw: { ns_lines: [], soa_line: null, apex_txt_meta: null },
    glue_ok: null,
    axfr_open: null,
    worst_severity: "ok",
    checked_at: new Date().toISOString(),
  }
}

// Built-in subdomain-takeover fingerprints — the fallback when config.yaml is unreadable. The
// live (seeded, admin-editable) list is `config.yaml → dns_health.fingerprints` (pm/checks/
// dns_health.mdx §5 `takeover_fingerprints`), loaded once per run in run().
const FALLBACK_FINGERPRINTS: TakeoverFingerprint[] = [
  { provider: "Heroku", cname_suffix: ".herokudns.com", enabled: true },
  { provider: "Heroku", cname_suffix: ".herokuapp.com", enabled: true },
  { provider: "AWS S3", cname_suffix: ".s3.amazonaws.com", enabled: true },
  { provider: "AWS CloudFront", cname_suffix: ".cloudfront.net", enabled: true },
  { provider: "GitHub Pages", cname_suffix: ".github.io", enabled: true },
  { provider: "Azure App Service", cname_suffix: ".azurewebsites.net", enabled: true },
  { provider: "WordPress.com", cname_suffix: ".wordpress.com", enabled: true },
  { provider: "Pantheon", cname_suffix: ".pantheonsite.io", enabled: true },
  { provider: "SendGrid", cname_suffix: ".sendgrid.net", enabled: true },
]

/** The admin-editable fingerprint list from config.yaml; built-in seed on any failure. */
function loadFingerprints(): TakeoverFingerprint[] {
  try {
    const list = readAppConfig().dns_health.fingerprints.filter((f) => f.enabled)
    return list.length > 0 ? list : FALLBACK_FINGERPRINTS
  } catch {
    return FALLBACK_FINGERPRINTS
  }
}

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

function matchFingerprint(target: string, fingerprints: TakeoverFingerprint[]): string | null {
  const t = fqdnLower(target)
  for (const fp of fingerprints) if (t.endsWith(fp.cname_suffix.toLowerCase())) return fp.provider
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

/**
 * infra.ns_sanity (+ infra.ns_no_cname, first-round infra.ns_lame inference, and the operator's
 * expected-NS drift alert). Count, resolve, network-diversity, NS-as-CNAME, allow-list compare.
 */
async function checkNs(
  domain: string,
  findings: Finding[],
  snap: DnsHealthResults,
  expectedNs: string[],
): Promise<void> {
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
  const nsInfos: {
    host: string
    ips: string[]
    groups: string[]
    isCname: boolean
    dead: boolean
  }[] = []
  for (const host of hosts) {
    const cname = await resolveCname(host)
    const isCname = !cname.error && cname.records.length > 0
    if (isCname) {
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
    // Dead = a definitive empty answer (not a transient failure) — the first-round lame inference.
    const dead = !a.error && !aaaa.error && ips.length === 0
    nsInfos.push({ host, ips, groups: unique(ips.map(netGroup)), isCname, dead })
  }

  const resolvedCount = nsInfos.filter((n) => n.ips.length > 0).length

  snap.ns = nsInfos.map((n) => ({
    host: n.host,
    ips: n.ips,
    net_group: n.groups.join("+"),
    is_cname: n.isCname,
    lame: n.dead,
  }))
  snap.ns_count = hosts.length
  snap.network_count = new Set(nsInfos.flatMap((n) => n.groups)).size
  // ns_asn_diverse (acceptance #2): a single prefix group is definitively NOT diverse (false);
  // prefix-diverse stays NULL until the real-ASN feed can confirm; nothing resolved stays NULL.
  snap.ns_asn_diverse = resolvedCount === 0 ? null : snap.network_count <= 1 ? false : null
  snap.lame_ns = nsInfos
    .filter((n) => n.dead)
    .map((n) => ({ host: n.host, reason: "resolves to no A/AAAA address (inferred lame)" }))
  // §12 raw.ns_lines — zone-file-style delegation lines, rendered verbatim by the raw panel.
  snap.raw.ns_lines = nsInfos.map(
    (n) =>
      `${domain}. IN NS ${n.host}. ; ${n.ips.join(" ") || "unresolved"} · net ${
        n.groups.join("+") || "?"
      } · lame: ${n.dead ? "yes" : "no"}`,
  )

  const evidence = nsInfos.map((n) => `${n.host}=${n.ips.join("/") || "?"}`).join(", ")

  // First-round infra.ns_lame inference (pm/checks/dns_health.mdx §3): an NS listed in the
  // delegation that definitively resolves to no address is almost certainly lame — receivers whose
  // resolver picks it get SERVFAIL and score SPF/DMARC as temperror. The precise per-server AA-bit
  // probe stays a future info. Only fires when at least one sibling NS works; the all-dead case is
  // the critical infra.ns_sanity below.
  if (resolvedCount > 0) {
    for (const n of nsInfos.filter((n) => n.dead)) {
      findings.push({
        id: `infra.ns_lame.${n.host}`,
        checkId: CHECK_ID,
        title: `Nameserver ${n.host} looks lame (does not resolve)`,
        severity: "warning",
        detail: `${n.host} is listed in ${domain}'s delegation but resolves to no A/AAAA address, so resolvers that pick it get no answer — SPF/DKIM/DMARC lookups intermittently fail (temperror) depending on which NS a receiver happens to query. (Inferred; the authoritative AA-bit probe is a future check.)`,
        remediation: `Remove ${n.host} from the delegation at the registrar, or restore its A/AAAA records and zone config so it answers authoritatively for ${domain}.`,
        evidence,
      })
    }
  }

  // Operator expected-NS allow-list (pm/checks/dns_health.mdx §4): flag drift when the published
  // NS set differs from what the operator declared — an unnoticed delegation change is how
  // hijacks and provider migrations silently break mail auth.
  if (expectedNs.length > 0) {
    const expected = new Set(expectedNs.map(fqdnLower))
    const missing = [...expected].filter((h) => !hosts.includes(h))
    const unexpected = hosts.filter((h) => !expected.has(h))
    if (missing.length > 0 || unexpected.length > 0) {
      findings.push({
        id: "infra.ns_expected_drift",
        checkId: CHECK_ID,
        title: "NS set drifted from the expected allow-list",
        severity: "warning",
        detail: `${domain}'s published NS set differs from the configured expectation.${
          missing.length > 0 ? ` Missing: ${missing.join(", ")}.` : ""
        }${unexpected.length > 0 ? ` Unexpected: ${unexpected.join(", ")}.` : ""} An unnoticed delegation change can mean a provider migration went wrong — or a hijack.`,
        remediation: `Either fix the registrar delegation back to the expected set (${[...expected].join(", ")}), or update the domain's expected-NS list in its DNS-health settings if this change was intentional.`,
        evidence: `published: ${hosts.join(", ")}`,
      })
    } else {
      findings.push({
        id: "infra.ns_expected_drift",
        checkId: CHECK_ID,
        title: "NS set matches the expected allow-list",
        severity: "ok",
        detail: `All ${hosts.length} published nameservers match the configured expectation.`,
        evidence: hosts.join(", "),
      })
    }
  }

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
  snap.soa_serial = r.serial
  // §12 raw.soa_line — the zone-file-style SOA render string for the raw panel.
  snap.raw.soa_line = `${domain}. IN SOA ${fqdnLower(r.nsname)}. ${fqdnLower(r.hostmaster)}. ( ${r.serial} ${r.refresh} ${r.retry} ${r.expire} ${r.minttl} )`

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

  // infra.soa_serial (presence + cross-run monotonic compare) is emitted by checkSoaSerial after
  // every sub-check has filled the snapshot, so the "unchanged despite a record change" nudge can
  // diff the whole zone snapshot against the previous run.

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
  if (!rname?.includes(".")) {
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

/** True when any zone fact other than the serial differs between two snapshots. */
function zoneChanged(prev: Partial<DnsHealthResults>, cur: DnsHealthResults): boolean {
  const prevNs = (prev.ns ?? []).map((n) => n.host).sort()
  const curNs = cur.ns.map((n) => n.host).sort()
  if (prevNs.join(",") !== curNs.join(",")) return true
  if ((prev.cname_at_apex ?? false) !== cur.cname_at_apex) return true
  if ((prev.wildcard?.detected ?? false) !== cur.wildcard.detected) return true
  if ((prev.txt_record_count ?? cur.txt_record_count) !== cur.txt_record_count) return true
  const p = prev.soa
  const c = cur.soa
  if (!p || !c) return false
  return (
    p.mname !== c.mname ||
    p.rname !== c.rname ||
    p.refresh !== c.refresh ||
    p.retry !== c.retry ||
    p.expire !== c.expire ||
    p.min_ttl !== c.min_ttl
  )
}

/**
 * infra.soa_serial (pm/checks/dns_health.mdx §3.8, acceptance #7): presence/non-zero, plus the
 * cross-run monotonic compare against the previous audit's snapshot — a serial that went BACKWARDS
 * is a warning (secondaries will ignore the newer zone), and a serial that did not advance even
 * though other zone facts changed is an info nudge. Runs after every sub-check so the current
 * snapshot is complete.
 */
function checkSoaSerial(
  domain: string,
  findings: Finding[],
  snap: DnsHealthResults,
  prev: Partial<DnsHealthResults> | undefined,
): void {
  const serial = snap.soa?.serial
  if (snap.soa === null || serial === undefined) return // no SOA — no-delegation info already emitted.
  if (!serial) {
    findings.push({
      id: "infra.soa_serial",
      checkId: CHECK_ID,
      title: "SOA serial is missing or zero",
      severity: "warning",
      detail:
        "The SOA serial is zero/absent, so secondaries cannot detect zone changes and may serve stale auth records.",
      remediation:
        "Set a non-zero, advancing serial using the YYYYMMDDnn convention, e.g. 2026070101, and bump it on every zone edit so secondaries reload.",
      evidence: `serial=${serial}`,
    })
    return
  }
  const prevSerial = prev?.soa?.serial
  if (typeof prevSerial === "number" && prevSerial > 0 && serial < prevSerial) {
    findings.push({
      id: "infra.soa_serial",
      checkId: CHECK_ID,
      title: "SOA serial went backwards",
      severity: "warning",
      detail: `${domain}'s SOA serial regressed from ${prevSerial} (previous run) to ${serial}. Secondaries treat a lower serial as "no change" (or as a broken zone), so they keep serving the OLD records — an SPF/DKIM rotation may never propagate.`,
      remediation: `Bump the serial above ${prevSerial} on the primary (use the YYYYMMDDnn or unix-time convention) and reload every secondary so the zone converges.`,
      evidence: `previous=${prevSerial} current=${serial}`,
    })
    return
  }
  if (typeof prevSerial === "number" && serial === prevSerial && prev && zoneChanged(prev, snap)) {
    findings.push({
      id: "infra.soa_serial",
      checkId: CHECK_ID,
      title: "SOA serial did not advance despite a zone change",
      severity: "info",
      detail: `Zone records for ${domain} changed since the previous run, but the SOA serial is still ${serial}. Secondaries only reload when the serial advances, so they may keep serving the old records.`,
      remediation:
        "Bump the SOA serial on every zone edit (YYYYMMDDnn or unix-time convention) so secondaries pick up the change.",
      evidence: `serial=${serial} (unchanged)`,
    })
    return
  }
  findings.push({
    id: "infra.soa_serial",
    checkId: CHECK_ID,
    title: "SOA serial present",
    severity: "ok",
    detail:
      typeof prevSerial === "number"
        ? `SOA serial is ${serial} (previous run: ${prevSerial}) — monotonic.`
        : `SOA serial is ${serial}. Cross-run monotonic compares start with the next run.`,
    evidence: `serial=${serial}`,
  })
}

/**
 * infra.ns_parent_child — first-round drift approximation (pm/checks/dns_health.mdx §3):
 * node:dns cannot query the parent (TLD) servers, so compare the effective NS set as seen by two
 * independent public resolvers. A difference means a delegation change has not fully propagated
 * (registrar updated but zone not, or vice versa). The authoritative parent-vs-child compare stays
 * a future probe (its "not evaluated" info is still emitted). Any lookup failure = silent skip —
 * never a false positive.
 */
async function checkParentChildDrift(domain: string, findings: Finding[]): Promise<void> {
  const nsVia = async (server: string): Promise<string[] | null> => {
    try {
      const r = new Resolver({ timeout: 4000, tries: 1 })
      r.setServers([server])
      const records = await r.resolveNs(domain)
      return unique(records.map(fqdnLower)).sort()
    } catch {
      return null
    }
  }
  const [a, b] = await Promise.all([nsVia("8.8.8.8"), nsVia("1.1.1.1")])
  if (!a || !b) return // resolver unreachable/blocked — the future-probe info already covers this.
  if (a.join(",") !== b.join(",")) {
    findings.push({
      id: "infra.ns_parent_child",
      checkId: CHECK_ID,
      title: "NS set differs between public resolvers (delegation drift)",
      severity: "warning",
      detail: `Two public resolvers see different NS sets for ${domain} — 8.8.8.8: [${a.join(", ")}]; 1.1.1.1: [${b.join(", ")}]. This is the signature of a parent↔child delegation mismatch mid-propagation: some receivers resolve your auth records through nameservers you no longer (or do not yet) control. (Approximation; the authoritative parent-zone compare is a future probe.)`,
      remediation:
        "Update the registrar/parent delegation to match the in-zone NS RRset exactly (both directions), then wait out the old NS TTL.",
      evidence: `8.8.8.8=[${a.join(",")}] 1.1.1.1=[${b.join(",")}]`,
    })
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
    snap.apex_is_cname = true
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

/**
 * Curated mail-relevant labels to scan for dangling CNAMEs, plus MX hosts and the operator's
 * extra-labels list (pm/checks/dns_health.mdx §4 per-domain config).
 */
async function danglingLabels(
  domain: string,
  selectors: string[],
  extraLabels: string[],
): Promise<string[]> {
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
  // Operator-supplied extras: a bare label goes under the domain; a name already ending in the
  // domain is used as-is.
  const extras = extraLabels
    .map(fqdnLower)
    .filter(Boolean)
    .map((l) => (l === domain || l.endsWith(`.${domain}`) ? l : `${l}.${domain}`))
  // The apex itself is scanned too (spec §3.4 "for the apex and a curated set of mail-relevant
  // labels"): an apex CNAME is already critical via infra.cname_at_apex, but a DEAD apex-CNAME
  // target additionally surfaces here as a takeover-risk dangling finding.
  const labels = [domain, ...[...base, ...dkim].map((l) => `${l}.${domain}`), ...extras]
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
  extraLabels: string[],
  fingerprints: TakeoverFingerprint[],
  findings: Finding[],
  snap: DnsHealthResults,
): Promise<void> {
  const labels = await danglingLabels(domain, selectors, extraLabels)
  // §12 scanned_labels — what the sweep actually resolved this run, so the explainer can render
  // its "N labels scanned" line and scope changes across runs are explainable.
  snap.scanned_labels = labels
  for (const label of labels) {
    const c = await resolveCname(label)
    if (c.error || c.records.length === 0) continue // no CNAME here (or transient) — nothing to flag.
    const { final, chain, status: chainStatus } = await followCname(label)
    if (chainStatus === "loop") {
      snap.cname_chains.push({ name: label, chain, final, status: "loop" })
      // The 8-hop loop guard tripped (spec §3 edge cases): a CNAME loop never resolves, so every
      // lookup through this name SERVFAILs — flag it rather than silently classifying the target.
      findings.push({
        id: `infra.dangling_cname.${label}`,
        checkId: CHECK_ID,
        title: `CNAME loop on ${label}`,
        severity: "warning",
        detail: `${label} is part of a CNAME loop (${[...chain, final].join(" → ")} → …). Resolvers abort looped chains, so this name never resolves and any mail/auth record behind it is unreachable.`,
        remediation: `Break the loop: repoint the CNAME on ${label} (or on ${final}) at a real A/AAAA host, or delete the record.`,
        evidence: [...chain, final].join(" → "),
      })
      continue
    }
    const fp = matchFingerprint(final, fingerprints)
    const status = await classifyTarget(final)
    if (status === "transient") continue
    // §12 cname_chains — every chain observed, live ones included (a re-point is trend-worthy
    // before it dangles).
    snap.cname_chains.push({ name: label, chain, final, status })
    const chainStr = [...chain, final].join(" → ")
    if (status === "dead") {
      snap.dangling.push({ name: label, type: "CNAME", target: final, kind: "cname" })
      findings.push({
        id: `infra.dangling_cname.${label}`,
        checkId: CHECK_ID,
        title: `Dangling CNAME on ${label} — ${fp ? `${fp} ` : ""}takeover risk`,
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
async function checkDanglingInclude(
  domain: string,
  findings: Finding[],
  snap: DnsHealthResults,
): Promise<void> {
  const txt = await resolveTxt(domain)
  if (!txt.error) {
    const spf = txt.records.find((r) => r.toLowerCase().startsWith("v=spf1"))
    if (spf) {
      for (const tok of spf.split(/\s+/)) {
        const m = /^[+~\-?]?(include:|redirect=)(.+)$/i.exec(tok)
        // SPF `a:`/`mx:` mechanisms with an explicit domain are dead-target candidates too
        // (spec §3.5: "extract include:/redirect: domains and a/mx mechanism hosts").
        const am = m ? null : /^[+~\-?]?(a|mx):([^/]+)(?:\/.*)?$/i.exec(tok)
        if (!m && !am) continue
        const mech = m ? m[1].replace(/[:=]/, "") : (am as RegExpExecArray)[1].toLowerCase()
        const target = fqdnLower(m ? m[2] : (am as RegExpExecArray)[2])
        if (!target || target === domain) continue
        const status = await classifyTarget(target)
        if (status === "dead") {
          snap.dangling.push({
            name: domain,
            type: "SPF",
            target,
            kind: mech === "mx" ? "mx" : "include",
          })
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
        snap.dangling.push({ name: domain, type: "MX", target: host, kind: "mx" })
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

/**
 * infra.dangling_ns (pm/checks/dns_health.mdx §2): discover sub-delegations under the
 * mail-relevant labels (an NS RRset on a subdomain) and verify every delegated nameserver still
 * resolves. A sub-delegated NS that is NXDOMAIN is a lame sub-delegation an attacker can register
 * to control the whole subtree. First round resolves the NS hosts; the authoritative AA-bit probe
 * per child server is a future check.
 */
async function checkDanglingNs(
  domain: string,
  selectors: string[],
  extraLabels: string[],
  findings: Finding[],
  snap: DnsHealthResults,
): Promise<void> {
  const apexNs = new Set(snap.ns.map((n) => n.host))
  // Only subdomains of the audited zone can be sub-delegations of it; MX hosts in other zones
  // (collected by danglingLabels) are excluded.
  const labels = (await danglingLabels(domain, selectors, extraLabels)).filter(
    (l) => l !== domain && l.endsWith(`.${domain}`),
  )
  let subDelegations = 0
  for (const label of labels) {
    const ns = await resolveNs(label)
    if (ns.error || ns.records.length === 0) continue // not sub-delegated (or transient).
    const childNs = unique(ns.records.map(fqdnLower))
    // The same NS set as the apex usually means the resolver answered from the parent zone — not
    // an independent sub-delegation worth re-checking.
    if (childNs.every((h) => apexNs.has(h))) continue
    subDelegations++
    const dead: string[] = []
    for (const host of childNs) {
      const [a, aaaa] = await Promise.all([resolve4(host), resolve6(host)])
      if (!a.error && !aaaa.error && a.records.length === 0 && aaaa.records.length === 0)
        dead.push(host)
    }
    if (dead.length > 0) {
      for (const host of dead)
        snap.dangling.push({ name: label, type: "NS", target: host, kind: "ns" })
      findings.push({
        id: `infra.dangling_ns.${label}`,
        checkId: CHECK_ID,
        title: `Lame sub-delegation on ${label} — takeover risk`,
        severity: "warning",
        detail: `${label} is delegated to ${childNs.join(", ")}, but ${dead.join(", ")} no longer resolve${dead.length === 1 ? "s" : ""} (NXDOMAIN). Whoever registers or claims a dead delegated nameserver answers for the WHOLE ${label} subtree — hosting phishing or sending mail under it.`,
        remediation: `Remove the sub-delegation NS records on ${label}, or repoint them to live nameservers that answer authoritatively for it. Never leave a delegation pointing at a host that no longer exists.`,
        evidence: `${label} NS ${childNs.join(", ")}; dead: ${dead.join(", ")}`,
      })
    } else {
      findings.push({
        id: `infra.dangling_ns.${label}`,
        checkId: CHECK_ID,
        title: `Sub-delegation on ${label} is healthy`,
        severity: "ok",
        detail: `${label} is delegated to ${childNs.join(", ")}; every delegated nameserver resolves. (Per-server authoritative probing is a future check.)`,
        evidence: `${label} NS ${childNs.join(", ")}`,
      })
    }
  }
  if (subDelegations === 0) {
    findings.push({
      id: "infra.dangling_ns",
      checkId: CHECK_ID,
      title: "No sub-delegations found",
      severity: "ok",
      detail: `No independently delegated subdomains were discovered under the scanned mail-relevant labels of ${domain}, so there is no sub-delegation to go lame.`,
    })
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
async function checkTxt(
  domain: string,
  selectors: string[],
  findings: Finding[],
  snap: DnsHealthResults,
): Promise<void> {
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
  snap.txt_record_count = records.length
  snap.spf_record_count = spfRecs.length
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
  // §12 txt_total_octets + raw.apex_txt_meta — the apex TXT set summarized as count/octets/
  // spf-count (never full verification-token values) for the parsed table and octets sparkline.
  snap.txt_total_octets = totalOctets
  snap.raw.apex_txt_meta = `apex TXT (${records.length} record${records.length === 1 ? "" : "s"}, ${totalOctets} octets · ${spfRecs.length} × v=spf1)`
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

  // Mail names too (spec §2 infra.txt_bloat: "Count TXT RRs + total octets at apex and MAIL
  // NAMES"): a bloated _dmarc / DKIM-selector TXT set risks the same UDP-fragmentation /
  // TCP-only failure mode on exactly the lookups receivers make while authenticating.
  const mailNames = unique(
    ["_dmarc", "_mta-sts", ...selectors.map((s) => `${s}._domainkey`)].map((l) => `${l}.${domain}`),
  )
  for (const name of mailNames) {
    const t = await resolveTxt(name)
    if (t.error || t.records.length === 0) continue // absent/transient — owned by that record's check.
    const octets = t.records.reduce((n, r) => n + r.length, 0)
    const nameDups = detectTxtDuplicates(t.records)
    const issues: string[] = []
    if (octets > 1200)
      issues.push(`TXT set totals ${octets} octets (risks UDP fragmentation / TCP-only responses)`)
    if (nameDups.length > 0) issues.push(`duplicate records: ${nameDups.join(", ")}`)
    if (issues.length > 0) {
      findings.push({
        id: `infra.txt_bloat.${name}`,
        checkId: CHECK_ID,
        title: `TXT record bloat at ${name}`,
        severity: "warning",
        detail: `The TXT set at ${name} may be problematic: ${issues.join("; ")}. Receivers resolve this name while authenticating mail, so an oversized/duplicated answer can intermittently fail as temperror.`,
        remediation: `Remove stale or duplicate TXT records at ${name} so its TXT set fits a single UDP response (keep exactly one record per purpose).`,
        evidence: `${t.records.length} TXT records, ${octets} octets`,
      })
    }
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
  snap.wildcard_types = types
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

function emitFutureInfos(findings: Finding[], skipAxfrProbe: boolean): void {
  for (const f of FUTURE_SUBCHECKS) {
    // The operator can opt a domain out of the (future) AXFR probe (pm/checks/dns_health.mdx §4).
    const skipped = f.id === "infra.zone_transfer" && skipAxfrProbe
    findings.push({
      id: f.id,
      checkId: CHECK_ID,
      title: skipped
        ? `${f.id} not evaluated (skipped by domain settings)`
        : `${f.id} not evaluated (future probe)`,
      severity: "info",
      detail: skipped
        ? `${f.what} is disabled for this domain (skip-AXFR-probe is set in its DNS-health settings). No problem is asserted; this row is informational only.`
        : `${f.what} is not performed in the first round — it needs a dig/authoritative-query, TCP/AXFR, or HTTP-signature capability not enabled yet. No problem is asserted; this row is informational only.`,
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
    // IDN domains are normalized to their punycode A-label before any query (spec §3 edge cases).
    const domain = fqdnLower(domainToASCII(ctx.domain.trim()) || ctx.domain)
    if (!domain) return { findings }

    const selectors = ctx.dkimSelectors ?? []
    const cfg: DnsHealthConfig = {
      extraLabels: ctx.dnsHealth?.extraLabels ?? [],
      expectedNs: ctx.dnsHealth?.expectedNs ?? [],
      skipAxfrProbe: ctx.dnsHealth?.skipAxfrProbe ?? false,
    }
    // The previous run's zone snapshot — powers the cross-run SOA-serial monotonic compare.
    const prev = ctx.previousResults?.[CHECK_ID] as Partial<DnsHealthResults> | undefined

    // Ordered, but independent — run each sub-check with its own graceful degradation.
    await checkNs(domain, findings, snap, cfg.expectedNs)
    await checkParentChildDrift(domain, findings)
    await checkSoa(domain, findings, snap)
    await checkApexCname(domain, findings, snap)
    await checkDanglingCname(domain, selectors, cfg.extraLabels, loadFingerprints(), findings, snap)
    await checkDanglingInclude(domain, findings, snap)
    await checkDanglingNs(domain, selectors, cfg.extraLabels, findings, snap)
    await checkTxt(domain, selectors, findings, snap)
    await checkWildcard(domain, findings, snap)
    // Last: the serial compare diffs the completed snapshot against the previous run's.
    checkSoaSerial(domain, findings, snap, prev)
    emitFutureInfos(findings, cfg.skipAxfrProbe)

    // dns_health_results.worst_severity / checked_at (spec §5) — the summary row's verdict.
    const rank = { ok: 0, info: 1, warning: 2, critical: 3 } as const
    snap.worst_severity = findings.reduce<DnsHealthResults["worst_severity"]>(
      (worst, f) => (rank[f.severity] > rank[worst] ? f.severity : worst),
      "ok",
    )
    snap.checked_at = new Date().toISOString()

    return { findings, results: snap }
  },
}
