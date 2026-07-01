import { Resolver } from "node:dns/promises"
import { mapLimit } from "@shared/concurrency"
import type {
  BlacklistRunResults,
  BlocklistZone,
  DomainTarget,
  IpTarget,
  PositiveReputation,
  ZoneHealth,
  ZoneResult,
} from "./blacklist/blacklist-types"
import {
  buildQueryName,
  classifyAnswer,
  classifyZoneHealth,
  decodeDnswl,
  decodeMailspikeRep,
  decodeSenderScore,
  detectProblemStates,
  diffRuns,
  reverseIpv4,
  spfLiteralIps,
  worstSeverity,
} from "./blacklist/engine"
import {
  applyPortalStates,
  readLatestBlacklistRun,
  readPortalStates,
  saveBlacklistRun,
} from "./blacklist/store"
import { loadZones, PROVIDER_PORTALS } from "./blacklist/zones"
import { resolveMx, resolveTxt, resolve4 as utilResolve4 } from "./dns-util"
import type { Checker, CheckOutcome, Finding, Severity } from "./types"

/**
 * DNS blacklist (DNSBL/RHSBL) membership — the full pm/checks/blacklists.mdx implementation:
 * target discovery (§11.1), RFC 5782 zone-health preflight (§11.2), refusal-code detection (§11.3),
 * IP + domain sweeps with return-code decoding (§11.4-5), positive-reputation probes (§11.6),
 * problem-state mapping (§16), diff vs the previous run (§11.9), and per-run persistence of the
 * test_results.yaml document (§12) that the /blacklists API and UI consume.
 */

const QUERY_CONCURRENCY = 8
const QUERY_TIMEOUT_MS = 3000

/** Dedicated resolver so operators can point DNSBL traffic at a real recursive resolver
 *  (EDH_DNS_RESOLVER=ip[,ip]) — public resolvers get refused by Spamhaus/URIBL (§3, PS-9). */
function makeResolver(): { resolver: Resolver; mode: "system" | "custom"; server: string | null } {
  const resolver = new Resolver({ timeout: QUERY_TIMEOUT_MS, tries: 1 })
  const custom = process.env.EDH_DNS_RESOLVER?.trim()
  if (custom) {
    const servers = custom
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
    if (servers.length > 0) {
      resolver.setServers(servers)
      return { resolver, mode: "custom", server: servers.join(",") }
    }
  }
  return { resolver, mode: "system", server: null }
}

interface Lookup {
  records: string[]
  ms: number
}

/** resolve4 that treats NXDOMAIN/ENODATA (and any resolver failure) as an empty answer. */
async function query4(resolver: Resolver, name: string): Promise<Lookup> {
  const started = Date.now()
  try {
    const records = await resolver.resolve4(name)
    return { records, ms: Date.now() - started }
  } catch {
    return { records: [], ms: Date.now() - started }
  }
}

async function queryTxt(resolver: Resolver, name: string): Promise<string | null> {
  try {
    const records = await resolver.resolveTxt(name)
    const flat = records.map((chunks) => chunks.join("")).filter(Boolean)
    return flat.length > 0 ? flat.join(" | ") : null
  } catch {
    return null
  }
}

async function queryPtr(resolver: Resolver, ip: string): Promise<string | null> {
  try {
    const names = await resolver.reverse(ip)
    return names[0] ?? null
  } catch {
    return null
  }
}

/** Team Cymru DNS ASN lookup — origin.asn.cymru.com then AS<n>.asn.cymru.com for the org name. */
async function queryAsn(resolver: Resolver, ip: string): Promise<IpTarget["asn"]> {
  const reversed = reverseIpv4(ip)
  if (!reversed) return null
  const origin = await queryTxt(resolver, `${reversed}.origin.asn.cymru.com`)
  if (!origin) return null
  const asnField = origin.split("|")[0]?.trim().split(" ")[0]
  const asn = Number(asnField)
  if (!Number.isInteger(asn)) return null
  const detail = await queryTxt(resolver, `AS${asn}.asn.cymru.com`)
  const org = detail ? (detail.split("|").pop()?.trim() ?? null) : null
  return { number: asn, org }
}

/** §11.1 target discovery: configured sending IPs, else MX-derived, plus SPF ip4 literals. */
async function discoverIpTargets(
  resolver: Resolver,
  domain: string,
  configured: string[],
): Promise<IpTarget[]> {
  const sources = new Map<string, IpTarget["source"]>()
  for (const ip of configured) {
    if (reverseIpv4(ip)) sources.set(ip, "sending_ips")
  }
  if (sources.size === 0) {
    const mx = await resolveMx(domain)
    for (const record of mx.records) {
      const a = await utilResolve4(record.exchange)
      for (const ip of a.records) {
        if (!sources.has(ip)) sources.set(ip, "mx_resolved")
      }
    }
  }
  const txt = await resolveTxt(domain)
  const spf = txt.records.find((r) => r.toLowerCase().startsWith("v=spf1"))
  if (spf) {
    for (const ip of spfLiteralIps(spf)) {
      if (!sources.has(ip)) sources.set(ip, "spf_authorized")
    }
  }

  return mapLimit([...sources.entries()], QUERY_CONCURRENCY, async ([ip, source]) => {
    const ptr = await queryPtr(resolver, ip)
    let fcrdnsOk: boolean | null = null
    if (ptr) {
      const forward = await query4(resolver, ptr)
      fcrdnsOk = forward.records.includes(ip)
    } else {
      fcrdnsOk = false
    }
    const asn = await queryAsn(resolver, ip)
    return { ip, source, ptr, fcrdns_ok: fcrdnsOk, asn }
  })
}

/** §11.2 RFC 5782 preflight: 127.0.0.2 must be listed, 127.0.0.1 must not. */
async function probeZoneHealth(resolver: Resolver, zone: BlocklistZone): Promise<ZoneHealth> {
  const started = Date.now()
  const positive = await query4(resolver, `2.0.0.127.${zone.zone}`)
  const negative = await query4(resolver, `1.0.0.127.${zone.zone}`)
  return classifyZoneHealth({
    zone: zone.zone,
    positiveAnswers: positive.records,
    negativeAnswers: negative.records,
    probeMs: Date.now() - started,
  })
}

function queryNameFor(r: ZoneResult): string {
  if (r.kind === "ip") {
    const reversed = reverseIpv4(r.target)
    return reversed ? `${reversed}.${r.zone}` : r.zone
  }
  return `${r.target.toLowerCase()}.${r.zone}`
}

async function queryPair(
  resolver: Resolver,
  zone: BlocklistZone,
  target: string,
): Promise<ZoneResult> {
  const base: ZoneResult = {
    zone: zone.zone,
    name: zone.name,
    tier: zone.tier,
    kind: zone.kind,
    target,
    listed: false,
    return_code: null,
    sub_list: null,
    reason_txt: null,
    lookup_url: zone.lookup_url,
    delist_url: zone.delist_url,
    severity: null,
    inconclusive: false,
    refusal_code: null,
    query_ms: 0,
    problem_state: null,
    paid_delist_offered: zone.paid_delist_offered ?? false,
    auto_expires: zone.auto_expires ?? null,
  }
  const name = buildQueryName(target, zone)
  if (!name) return { ...base, inconclusive: true } // e.g. IPv6 target on an IPv4-only zone
  const answer = await query4(resolver, name)
  const decoded = classifyAnswer(zone, answer.records)
  const result: ZoneResult = {
    ...base,
    listed: decoded.listed,
    return_code: decoded.return_code,
    sub_list: decoded.sub_list,
    severity: decoded.severity,
    refusal_code: decoded.refusal_code,
    inconclusive: decoded.refusal_code !== null,
    problem_state: decoded.problem_state,
    query_ms: answer.ms,
  }
  if (result.listed) {
    result.reason_txt = await queryTxt(resolver, name)
  }
  return result
}

/** §11.6 positive-reputation probes: DNSWL, Sender Score, Mailspike reputation. */
async function probePositiveReputation(
  resolver: Resolver,
  ips: IpTarget[],
): Promise<PositiveReputation> {
  const out: PositiveReputation = {
    dnswl: { listed: false, category: null, trust: null },
    senderscore: { score: null, severity: "info" },
    mailspike_rep: { code: null, label: null },
  }
  const first = ips.find((t) => reverseIpv4(t.ip))
  if (!first) return out
  const reversed = reverseIpv4(first.ip)
  const [dnswl, score, rep] = await Promise.all([
    query4(resolver, `${reversed}.list.dnswl.org`),
    query4(resolver, `${reversed}.score.senderscore.com`),
    query4(resolver, `${reversed}.rep.mailspike.net`),
  ])
  out.dnswl = decodeDnswl(dnswl.records)
  out.senderscore = decodeSenderScore(score.records)
  out.mailspike_rep = decodeMailspikeRep(rep.records)
  return out
}

function delistRemediation(r: ZoneResult): string {
  const parts: string[] = []
  parts.push(
    `Fix the root cause first — a delist request while the cause is live gets re-listed. ${causeHint(r)}`,
  )
  const url = r.reason_txt?.match(/https?:\/\/\S+/)?.[0] ?? r.delist_url
  parts.push(
    `Then request removal at ${url} (reason code ${r.return_code ?? "n/a"}${r.sub_list ? ` = ${r.sub_list}` : ""}).`,
  )
  if (r.auto_expires)
    parts.push(`This list auto-expires (${r.auto_expires}) — waiting is a valid option.`)
  if (r.paid_delist_offered) {
    parts.push(
      "NEVER pay for delisting: paid 'express' removal is unnecessary (listings auto-expire) and the industry considers pay-to-delist abusive (RFC 6471).",
    )
  }
  parts.push("Re-run this check after the operator's processing window to confirm removal.")
  return parts.join(" ")
}

function causeHint(r: ZoneResult): string {
  switch (r.problem_state) {
    case "PS-2":
      return "This zone flags compromised hosts: find and clean the infected machine, close open relays/proxies, rotate credentials."
    case "PS-3":
      return "This is a policy listing (dynamic/consumer IP space): either send via your provider's smarthost, or get a proper static PTR and request policy exclusion."
    case "PS-4":
      return "The domain itself is listed: if 'abused-legit', secure the hacked site/open redirect first; otherwise contest with evidence."
    case "PS-5":
      return "Mail hit a spam trap: clean the recipient list (remove non-engaged/unverified addresses) and stop the offending stream."
    case "PS-6":
      return "This is collateral from your network neighbors: verify you are clean on high-trust zones, then escalate to your provider's abuse desk."
    case "PS-7":
      return "The trigger is reverse DNS: set a proper PTR (FCrDNS) for the IP before requesting removal."
    default:
      return "Investigate the cause (compromise, complaints, open relay, list hygiene) using the reason text."
  }
}

export const blacklistCheck: Checker = {
  id: "blacklist",
  label: "DNS blacklists",
  async run(ctx): Promise<CheckOutcome> {
    const startedAt = Date.now()
    const ranAt = new Date(startedAt)
    const auditId = `${ranAt.toISOString().replace(/[:.]/g, "-")}_${Math.random().toString(36).slice(2, 6)}`
    const { resolver, mode, server } = makeResolver()

    const zones = loadZones().filter((z) => z.enabled)
    const sweepZones = zones.filter((z) => !z.positive)

    const ipTargets = await discoverIpTargets(resolver, ctx.domain, ctx.sendingIps)
    const domainTargets: DomainTarget[] = [{ domain: ctx.domain, source: "primary", created: null }]

    // §11.2 preflight — dead/wildcarding zones are excluded from the sweep (PS-10).
    const zoneHealth = await mapLimit(sweepZones, QUERY_CONCURRENCY, (z) =>
      probeZoneHealth(resolver, z),
    )
    const healthByZone = new Map(zoneHealth.map((h) => [h.zone, h]))
    const usableZones = sweepZones.filter((z) => {
      const h = healthByZone.get(z.zone)
      return h && h.status !== "dead" && h.status !== "wildcarding"
    })

    // §11.4-5 the sweep: every usable (zone × matching target).
    const pairs: Array<{ zone: BlocklistZone; target: string }> = []
    for (const zone of usableZones) {
      if (zone.kind === "ip") {
        for (const t of ipTargets) pairs.push({ zone, target: t.ip })
      } else {
        for (const t of domainTargets) pairs.push({ zone, target: t.domain })
      }
    }
    const results = await mapLimit(pairs, QUERY_CONCURRENCY, (p) =>
      queryPair(resolver, p.zone, p.target),
    )

    const positive = await probePositiveReputation(resolver, ipTargets)

    const listedRows = results.filter((r) => r.listed)
    const inconclusiveRows = results.filter((r) => r.inconclusive)
    const refusalsDetected =
      results.some((r) => r.refusal_code !== null) || zoneHealth.some((h) => h.status === "blocked")
    const deadZones = zoneHealth.filter((h) => h.status === "dead" || h.status === "wildcarding")

    const problemStates = detectProblemStates({ results, zoneHealth, positive, zones: sweepZones })
    const previous = readLatestBlacklistRun(ctx.domain)
    const diff = diffRuns(previous, results)

    const run: BlacklistRunResults = {
      schema_version: 1,
      technology: "blacklists",
      domain: ctx.domain,
      audit_id: auditId,
      ran_at: ranAt.toISOString(),
      duration_ms: Date.now() - startedAt,
      resolver: { mode, server, refusals_detected: refusalsDetected },
      targets: { ips: ipTargets, domains: domainTargets },
      zone_health: zoneHealth,
      results,
      positive_reputation: positive,
      provider_portals: applyPortalStates(PROVIDER_PORTALS, readPortalStates(ctx.domain)),
      summary: {
        zones_enabled: sweepZones.length,
        pairs_queried: results.length,
        listed: listedRows.length,
        clean: results.length - listedRows.length - inconclusiveRows.length,
        inconclusive: inconclusiveRows.length,
        dead_zones_skipped: deadZones.length,
        worst_severity: worstSeverity(listedRows.map((r) => r.severity)),
        problem_states: problemStates,
      },
      diff,
    }

    try {
      saveBlacklistRun(ctx.domain, run)
    } catch {
      // Persistence failure is already logged by the yaml store; the audit result still carries the run.
    }

    // ---- findings ---------------------------------------------------------------------------
    const findings: Finding[] = []

    if (ipTargets.length === 0) {
      findings.push({
        id: "blacklist.no_ips",
        checkId: "blacklist",
        title: "No sending IPs to check",
        severity: "info",
        detail:
          "No sending IPs were configured and none could be derived from MX or SPF records; only domain blocklists were checked.",
        remediation:
          "Add the IP addresses your mail actually sends from to this domain so IP blacklist status can be verified.",
      })
    }

    for (const r of listedRows) {
      const severity: Severity = r.severity ?? "warning"
      findings.push({
        id: `blacklist.listed.${r.zone}.${r.target}`,
        checkId: "blacklist",
        title: `${r.target} is listed on ${r.name}`,
        severity,
        detail: `${r.kind === "ip" ? "Sending IP" : "Domain"} ${r.target} is on ${r.name} (${r.zone} answered ${r.return_code}${r.sub_list ? ` = ${r.sub_list}` : ""}).${r.reason_txt ? ` Reason: ${r.reason_txt}` : ""}`,
        remediation: delistRemediation(r),
        evidence: queryNameFor(r),
      })
    }

    if (refusalsDetected) {
      findings.push({
        id: "blacklist.refused",
        checkId: "blacklist",
        title: "Some blocklists refused our DNS queries",
        severity: "info",
        detail:
          "One or more zones returned in-band refusal codes (Spamhaus 127.255.255.x / URIBL_BLOCKED). Results for those zones are inconclusive — this says nothing bad about your domain.",
        remediation:
          "Point the checker at a real recursive resolver (set EDH_DNS_RESOLVER; avoid 8.8.8.8/1.1.1.1), or configure a free Spamhaus DQS key / Abusix key, then re-run.",
      })
    }

    if (deadZones.length > 0) {
      findings.push({
        id: "blacklist.zones_dead",
        checkId: "blacklist",
        title: `${deadZones.length} blocklist zone(s) dead or misbehaving — excluded`,
        severity: "info",
        detail: `RFC 5782 test probes failed for: ${deadZones.map((z) => `${z.zone} (${z.status})`).join(", ")}. Dead zones sometimes wildcard and "list the world", so they were excluded rather than reported.`,
        remediation:
          "No action needed for your domain. An operator can retire the zone in the Blocklist Zones config (blacklist_zones.yaml).",
      })
    }

    if (listedRows.length === 0) {
      findings.push({
        id: "blacklist.clean",
        checkId: "blacklist",
        title: "Not on any checked blacklist",
        severity: "ok",
        detail: `Checked ${ipTargets.length} IP(s) and ${domainTargets.length} domain(s) against ${usableZones.length} blocklist zones — none listed.`,
        evidence: ipTargets.map((t) => t.ip).join(", ") || ctx.domain,
      })
      if (problemStates.includes("PS-12")) {
        findings.push({
          id: "blacklist.positive_reputation",
          checkId: "blacklist",
          title: "No positive reputation established",
          severity: "info",
          detail: `Nothing is wrong, but nothing vouches for you either: not on DNSWL${positive.senderscore.score !== null ? `, Sender Score ${positive.senderscore.score}` : ", no Sender Score"}.`,
          remediation:
            "Register your MTA at dnswl.org (free tier) and keep sending volume steady so Sender Score materializes — positive signals buffer against gray-area filtering.",
        })
      }
    }

    return { findings, results: run }
  },
}
