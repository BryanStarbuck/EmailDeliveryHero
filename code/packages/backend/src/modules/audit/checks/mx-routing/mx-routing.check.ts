import { resolve4, resolve6, resolveCname, resolveMx } from "../dns-util"
import type { Checker, CheckOutcome, Finding, MxRoutingConfig, Severity } from "../types"

/**
 * MX & Mail Routing (RFC 5321 §5.1, RFC 7505 null MX, RFC 2181 §10.3). Resolves the domain's MX
 * RRset and audits its inbound-routing topology using only node:dns/promises: presence, dangling
 * targets, CNAME violations, public routability, priority ordering, redundancy (host count + /24,/48
 * prefix diversity), null-MX correctness, duplicate/relative targets, and implicit-A fallback.
 *
 * Reachability, SMTP banner, greylisting, backup-relay hygiene, precise RRset TTL, and real-ASN
 * diversity require a network probe / external feed and are FUTURE — each emits at most one "not yet
 * evaluated" info finding and never a warning/critical (spec §7).
 *
 * All finding checkId values use the "infra" prefix; sub-check ids follow the spec's MX sub-family
 * (infra.mx_present, infra.mx_resolve, ...). Per-domain intent arrives on CheckContext.mx
 * (pm/checks/mx_routing.mdx §4): `receivesMail` (default true — the mx_expectations schema default)
 * decides whether an absent/null MX is a problem or expected, `expectedHosts` is an optional
 * allow-list diffed against the published MX set (infra.mx_expected_drift), and `skipSmtpProbe`
 * keeps the future TCP/25 probes off for this domain.
 */

const CHECK_ID = "infra"

type IpClass = "public" | "private" | "loopback" | "linklocal" | "cgnat" | "unspecified"

function ipv4Class(ip: string): IpClass {
  const parts = ip.split(".").map((p) => Number(p))
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return "public"
  const [a, b] = parts
  if (a === 0) return "unspecified"
  if (a === 127) return "loopback"
  if (a === 10) return "private"
  if (a === 172 && b >= 16 && b <= 31) return "private"
  if (a === 192 && b === 168) return "private"
  if (a === 169 && b === 254) return "linklocal"
  if (a === 100 && b >= 64 && b <= 127) return "cgnat"
  return "public"
}

function ipv6Class(ip: string): IpClass {
  const addr = ip.toLowerCase().split("%")[0]
  if (addr === "::" || addr === "::0" || /^0(:0){7}$/.test(addr)) return "unspecified"
  if (addr === "::1") return "loopback"
  // fe80::/10 covers fe80..febf
  if (/^fe[89ab]/.test(addr)) return "linklocal"
  // fc00::/7 unique-local
  if (/^f[cd]/.test(addr)) return "private"
  return "public"
}

function ipClass(ip: string): IpClass {
  return ip.includes(":") ? ipv6Class(ip.trim()) : ipv4Class(ip.trim())
}

/** Expand a possibly-compressed IPv6 address to eight 4-hex-digit groups. */
function expandIpv6(ip: string): string {
  const addr = ip.toLowerCase().split("%")[0]
  if (!addr.includes("::")) {
    return addr
      .split(":")
      .map((g) => g.padStart(4, "0"))
      .join(":")
  }
  const [head, tail] = addr.split("::")
  const headGroups = head ? head.split(":") : []
  const tailGroups = tail ? tail.split(":") : []
  const missing = 8 - headGroups.length - tailGroups.length
  const groups = [...headGroups, ...Array(Math.max(0, missing)).fill("0"), ...tailGroups].map((g) =>
    (g === "" ? "0" : g).padStart(4, "0"),
  )
  return groups.slice(0, 8).join(":")
}

/** Network prefix used to approximate ASN/network diversity in the first round: /24 v4, /48 v6. */
function networkPrefix(ip: string): string {
  if (ip.includes(":")) return expandIpv6(ip).split(":").slice(0, 3).join(":")
  return ip.split(".").slice(0, 3).join(".")
}

/** Normalize an MX exchange for comparison: lowercase, strip a single trailing dot. */
function normHost(exchange: string): string {
  return exchange.trim().toLowerCase().replace(/\.$/, "")
}

interface HostInfo {
  host: string
  priority: number
  isCname: boolean
  cnameTarget?: string
  ips: string[]
  nonPublic: { ip: string; cls: IpClass }[]
  transient?: string
}

/**
 * The topology-level verdict — the JSON analog of one `mx_check_results` row
 * (pm/checks/mx_routing.mdx §5); column names deliberately mirror these keys.
 */
export interface MxCheckSummary {
  /** Number of MX RRs returned (null-MX records included). */
  mx_count: number
  /** RFC 7505 "." present. */
  has_null_mx: boolean
  distinct_priorities: number
  /** >= 2 resolvable hosts. */
  redundant: boolean
  /** null until an ASN feed exists (future) — first round approximates by /24,/48 prefixes. */
  asn_diverse: boolean | null
  /** No MX, but the domain's A record exists (RFC 5321 implicit MX). */
  implicit_a_fallback: boolean
  /** null in the first round — node:dns does not expose the RRset TTL (needs dig, future). */
  rrset_ttl: number | null
  /** Declared intent snapshot (pm/checks/mx_routing.mdx §4 "This domain receives mail"). */
  receives_mail: boolean
  worst_severity: Severity
  checked_at: string
}

/**
 * The structured snapshot persisted at results["infra.mx_routing"] (pm/checks/mx_routing.mdx §5:
 * `checks.infra_mx` — `summary` is the mx_check_results row, `hosts[]` are mx_records rows) — the
 * MX topology the DNS page's Mail path panel renders. snake_case mirrors the spec YAML.
 */
export interface MxRoutingResults {
  mx_found: boolean
  null_mx: boolean
  implicit_a_fallback: boolean
  /** The mx_check_results row (pm/checks/mx_routing.mdx §5). */
  summary: MxCheckSummary
  hosts: {
    host: string
    priority: number
    is_cname: boolean
    cname_target: string | null
    ips: string[]
    /** Spec-named mirror of `ips` (the mx_records.resolved_ips column). */
    resolved_ips: string[]
    /** false when any resolved address is RFC1918/loopback/link-local/CGNAT/unspecified. */
    is_public: boolean
    non_public: { ip: string; cls: IpClass }[]
    /** null until the SMTP probe round (future). */
    reachable: boolean | null
    /** 220 greeting (future). */
    banner: string | null
    /** Resolved ASN (future). */
    asn: number | null
  }[]
  redundancy: { host_count: number; network_count: number }
}

const SEVERITY_ORDER: Record<Severity, number> = { ok: 0, info: 1, warning: 2, critical: 3 }

function worstSeverity(findings: Finding[]): Severity {
  let worst: Severity = "ok"
  for (const f of findings) if (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[worst]) worst = f.severity
  return worst
}

function snapshot(
  hosts: HostInfo[],
  flags: { mx_found: boolean; null_mx: boolean; implicit_a_fallback: boolean },
  redundancy: { host_count: number; network_count: number },
  summary: { mx_count: number; distinct_priorities: number; receives_mail: boolean },
  findings: Finding[],
): MxRoutingResults {
  return {
    ...flags,
    summary: {
      mx_count: summary.mx_count,
      has_null_mx: flags.null_mx,
      distinct_priorities: summary.distinct_priorities,
      // Redundant = >= 2 resolvable hosts (pm/checks/mx_routing.mdx §5).
      redundant: hosts.filter((h) => h.ips.length > 0).length >= 2,
      asn_diverse: null,
      implicit_a_fallback: flags.implicit_a_fallback,
      rrset_ttl: null,
      receives_mail: summary.receives_mail,
      worst_severity: worstSeverity(findings),
      checked_at: new Date().toISOString(),
    },
    hosts: hosts.map((h) => ({
      host: h.host,
      priority: h.priority,
      is_cname: h.isCname,
      cname_target: h.cnameTarget ?? null,
      ips: h.ips,
      resolved_ips: h.ips,
      is_public: h.nonPublic.length === 0,
      non_public: h.nonPublic,
      reachable: null,
      banner: null,
      asn: null,
    })),
    redundancy,
  }
}

/** One info finding for a FUTURE, probe/feed-gated sub-check. Never warning/critical. */
function future(id: string, title: string, detail: string): Finding {
  return {
    id,
    checkId: CHECK_ID,
    title,
    severity: "info",
    detail,
  }
}

export const mxRoutingCheck: Checker = {
  id: "infra.mx_routing",
  label: "MX & Mail Routing",
  async run(ctx): Promise<CheckOutcome> {
    const domain = normHost(ctx.domain)
    const findings: Finding[] = []
    // Declared intent (pm/checks/mx_routing.mdx §4): schema default receivesMail=TRUE.
    const mxConfig: MxRoutingConfig = ctx.mx ?? {}
    const receivesMail = mxConfig.receivesMail ?? true
    const skipSmtpProbe = mxConfig.skipSmtpProbe ?? false

    const mx = await resolveMx(ctx.domain)
    if (mx.error) {
      // Transient resolver failure: no snapshot — the UI must not render false topology.
      return {
        findings: [
          {
            id: "infra.mx_present.lookup_failed",
            checkId: CHECK_ID,
            title: "Could not look up MX",
            severity: "info",
            detail: `DNS lookup for MX ${domain} failed transiently (${mx.error}). MX topology was not evaluated.`,
            remediation:
              "Retry the audit later. If it persists, check the domain's authoritative nameservers.",
          },
        ],
      }
    }

    // --- infra.mx_present: no MX at all --------------------------------------------------------
    // Critical only when the domain is expected to receive mail; a declared sender-only domain
    // downgrades to info (pm/checks/mx_routing.mdx §3 step 1, acceptance 1).
    if (mx.records.length === 0) {
      findings.push(
        receivesMail
          ? {
              id: "infra.mx_present",
              checkId: CHECK_ID,
              title: "No MX record",
              severity: "critical",
              detail: `${domain} publishes no MX record, so receiving mail servers have no host to deliver inbound mail to.`,
              remediation: `Publish an MX record, e.g. "${domain}. IN MX 10 mail.${domain}." (or your provider's host, e.g. "1 aspmx.l.google.com.").`,
            }
          : {
              id: "infra.mx_present",
              checkId: CHECK_ID,
              title: "No MX record (declared sender-only)",
              severity: "info",
              detail: `${domain} publishes no MX record. This domain is declared as not receiving mail, so an absent MX is acceptable — but senders will still fall back to the A record instead of failing fast.`,
              remediation: `Publish an RFC 7505 null MX so senders fail fast with a permanent error: "${domain}. IN MX 0 \\".\\"".`,
            },
      )
      // infra.mx_matches_a: implicit-A fallback (RFC 5321) when no MX exists.
      const a = await resolve4(ctx.domain)
      if (a.records.length > 0) {
        findings.push({
          id: "infra.mx_matches_a",
          checkId: CHECK_ID,
          title: "Mail will implicit-route to the A record",
          severity: "info",
          detail: `With no MX, RFC 5321 makes senders fall back to the domain's A record (${a.records.join(", ")}). This is fragile — many senders and reputation systems expect an explicit MX.`,
          remediation: `Publish an explicit MX rather than relying on implicit A fallback: "${domain}. IN MX 10 mail.${domain}.".`,
          evidence: a.records.join(", "),
        })
      }
      return {
        findings,
        results: snapshot(
          [],
          { mx_found: false, null_mx: false, implicit_a_fallback: a.records.length > 0 },
          { host_count: 0, network_count: 0 },
          { mx_count: 0, distinct_priorities: 0, receives_mail: receivesMail },
          findings,
        ),
      }
    }

    // --- infra.mx_null: RFC 7505 detection -----------------------------------------------------
    const nullRecords = mx.records.filter((r) => {
      const ex = r.exchange.trim()
      return ex === "." || ex === ""
    })
    const realRecords = mx.records.filter((r) => {
      const ex = r.exchange.trim()
      return ex !== "." && ex !== ""
    })

    if (nullRecords.length > 0 && realRecords.length === 0) {
      // Pure null MX (pm/checks/mx_routing.mdx §2 infra.mx_null, acceptance 6): a warning when the
      // domain is declared mail-receiving; a correct RFC 7505 declaration for a non-mail domain.
      const priorityOk = nullRecords.length === 1 && nullRecords[0].priority === 0
      if (!priorityOk) {
        findings.push({
          id: "infra.mx_null",
          checkId: CHECK_ID,
          title: "Malformed null MX (RFC 7505)",
          severity: "warning",
          detail: `${domain} publishes a malformed null MX (RFC 7505 requires exactly one record: MX 0 ".").`,
          remediation: `Publish exactly one null MX line: "${domain}. IN MX 0 \\".\\"" — or, if this domain must receive mail, a real host, e.g. "${domain}. IN MX 10 mail.${domain}.".`,
          evidence: nullRecords.map((r) => `${r.priority} "."`).join(" | "),
        })
      } else if (receivesMail) {
        findings.push({
          id: "infra.mx_null",
          checkId: CHECK_ID,
          title: "Null MX present (RFC 7505)",
          severity: "warning",
          detail: `${domain} publishes a null MX (MX 0 "."), declaring it accepts no mail — but this domain is expected to receive mail, so all inbound mail (bounces, replies) is being rejected.`,
          remediation: `Replace the null MX with a real host, e.g. "${domain}. IN MX 10 mail.${domain}." — or mark the domain as not receiving mail in its Mail-routing settings if it is genuinely send-only.`,
          evidence: nullRecords.map((r) => `${r.priority} "."`).join(" | "),
        })
      } else {
        findings.push({
          id: "infra.mx_null",
          checkId: CHECK_ID,
          title: "Correct null MX (RFC 7505)",
          severity: "ok",
          detail: `Null MX — ${domain} correctly declares it accepts no mail (RFC 7505). Senders fail fast with a permanent error instead of falling back to the A record.`,
          evidence: nullRecords.map((r) => `${r.priority} "."`).join(" | "),
        })
      }
      // Null MX short-circuits target resolution/reachability (no target to probe).
      pushFutureFindings(findings, domain, skipSmtpProbe)
      return {
        findings,
        results: snapshot(
          [],
          { mx_found: true, null_mx: true, implicit_a_fallback: false },
          { host_count: 0, network_count: 0 },
          {
            mx_count: nullRecords.length,
            distinct_priorities: new Set(nullRecords.map((r) => r.priority)).size,
            receives_mail: receivesMail,
          },
          findings,
        ),
      }
    }

    if (nullRecords.length > 0 && realRecords.length > 0) {
      // Mix of null and real MX is itself a misconfiguration.
      findings.push({
        id: "infra.mx_null",
        checkId: CHECK_ID,
        title: "Null MX mixed with real MX",
        severity: "warning",
        detail: `${domain} publishes both a null MX (".") and real MX host(s). A null MX must be the ONLY MX record (RFC 7505); mixing them gives receivers contradictory instructions.`,
        remediation: `Remove the "${domain}. IN MX 0 \\".\\"" line and keep only the real MX host(s), or remove the real hosts if the domain truly accepts no mail.`,
        evidence: mx.records.map((r) => `${r.priority} ${r.exchange || "."}`).join(" | "),
      })
    }

    // We have at least one real MX target.
    findings.push({
      id: "infra.mx_present",
      checkId: CHECK_ID,
      title: "MX record present",
      severity: "ok",
      detail: `${domain} publishes ${realRecords.length} MX host(s).`,
      evidence: realRecords.map((r) => `${r.priority} ${r.exchange}`).join(" | "),
    })

    // --- Resolve each distinct host once (dedupe within the run) --------------------------------
    const seen = new Map<string, HostInfo>()
    for (const rec of realRecords) {
      const host = normHost(rec.exchange)
      if (seen.has(host)) continue
      const info: HostInfo = {
        host,
        priority: rec.priority,
        isCname: false,
        ips: [],
        nonPublic: [],
      }

      const cname = await resolveCname(rec.exchange)
      if (cname.records.length > 0) {
        info.isCname = true
        info.cnameTarget = cname.records.join(", ")
      }

      const [v4, v6] = await Promise.all([resolve4(rec.exchange), resolve6(rec.exchange)])
      info.ips = [...v4.records, ...v6.records]
      if (info.ips.length === 0 && !v4.empty && !v6.empty && (v4.error || v6.error)) {
        info.transient = v4.error ?? v6.error
      }
      for (const ip of info.ips) {
        const cls = ipClass(ip)
        if (cls !== "public") info.nonPublic.push({ ip, cls })
      }
      seen.set(host, info)
    }
    const hosts = [...seen.values()]

    // --- Per-host sub-checks: CNAME, resolve, public/localhost ---------------------------------
    let anyCname = false
    let anyDangling = false
    let anyNonPublic = false
    for (const h of hosts) {
      if (h.isCname) {
        anyCname = true
        findings.push({
          id: `infra.mx_not_cname.${h.host}`,
          checkId: CHECK_ID,
          title: `MX target ${h.host} is a CNAME`,
          severity: "critical",
          detail: `MX target ${h.host} is a CNAME (→ ${h.cnameTarget}). RFC 5321 §5.1 / RFC 2181 §10.3 forbid an MX pointing at a CNAME; strict receivers refuse to follow it.`,
          remediation: `Repoint the MX at the canonical hostname's own A/AAAA record (flatten the CNAME). Publish A/AAAA for ${h.host} directly and set MX to it.`,
          evidence: `${h.host} CNAME ${h.cnameTarget}`,
        })
      }

      if (h.transient) {
        findings.push({
          id: `infra.mx_resolve.${h.host}`,
          checkId: CHECK_ID,
          title: `Could not resolve MX target ${h.host}`,
          severity: "info",
          detail: `Address lookup for MX target ${h.host} failed transiently (${h.transient}); resolvability was not determined.`,
          remediation: `Retry the audit later. If it persists, confirm A/AAAA records exist for ${h.host}.`,
        })
        continue
      }

      if (h.ips.length === 0) {
        anyDangling = true
        findings.push({
          id: `infra.mx_resolve.${h.host}`,
          checkId: CHECK_ID,
          title: `Dangling MX: ${h.host} does not resolve`,
          severity: "critical",
          detail: `MX target ${h.host} (priority ${h.priority}) returns no A/AAAA record (NXDOMAIN / empty). Mail to ${domain} queues and eventually bounces after the sender's retry window.`,
          remediation: `Publish the missing A/AAAA for ${h.host}, or remove the "${domain}. IN MX ${h.priority} ${h.host}." line if the host is decommissioned.`,
          evidence: `${h.host} → (no address)`,
        })
        continue
      }

      if (h.nonPublic.length > 0) {
        anyNonPublic = true
        const isLocalhost = h.nonPublic.some((n) => n.cls === "loopback")
        const worst = h.nonPublic.map((n) => `${n.ip} (${n.cls})`).join(", ")
        findings.push({
          id: isLocalhost ? `infra.mx_localhost.${h.host}` : `infra.mx_public_ip.${h.host}`,
          checkId: CHECK_ID,
          title: isLocalhost
            ? `MX target ${h.host} resolves to localhost`
            : `MX target ${h.host} resolves to a non-public IP`,
          severity: "critical",
          detail: `MX target ${h.host} resolves to non-routable address(es): ${worst}. Private/loopback/link-local/CGNAT space is undeliverable from the public Internet — mail cannot be delivered.`,
          remediation: `Repoint MX ${h.host} at a public, routable IP; do not expose internal relays or localhost via public MX. Update the A/AAAA for ${h.host} to a public address.`,
          evidence: worst,
        })
      }
    }

    if (hosts.length > 0 && !anyCname) {
      findings.push({
        id: "infra.mx_not_cname",
        checkId: CHECK_ID,
        title: "No MX target is a CNAME",
        severity: "ok",
        detail: "Every MX target points at an A/AAAA host, not a CNAME (RFC 5321 §5.1).",
      })
    }
    if (hosts.length > 0 && !anyDangling && !hosts.some((h) => h.transient)) {
      findings.push({
        id: "infra.mx_resolve",
        checkId: CHECK_ID,
        title: "All MX targets resolve",
        severity: "ok",
        detail: "Every MX target resolves to at least one A/AAAA address (no dangling MX).",
      })
    }
    if (hosts.length > 0 && !anyNonPublic) {
      findings.push({
        id: "infra.mx_public_ip",
        checkId: CHECK_ID,
        title: "All MX IPs are public",
        severity: "ok",
        detail: "Every resolved MX address is public/routable on the Internet.",
      })
    }

    // --- infra.mx_priority ---------------------------------------------------------------------
    const distinctPriorities = new Set(realRecords.map((r) => r.priority))
    if (realRecords.length >= 2 && distinctPriorities.size === 1) {
      findings.push({
        id: "infra.mx_priority",
        checkId: CHECK_ID,
        title: "All MX priorities are identical",
        severity: "warning",
        detail: `All ${realRecords.length} MX hosts share preference ${[...distinctPriorities][0]}, so there is no primary/backup ordering — receivers load-balance across every host equally.`,
        remediation: `Use tiered distinct values, e.g. "${domain}. IN MX 10 primary.${domain}." and "${domain}. IN MX 20 backup.${domain}.".`,
        evidence: realRecords.map((r) => `${r.priority} ${r.exchange}`).join(" | "),
      })
    } else {
      findings.push({
        id: "infra.mx_priority",
        checkId: CHECK_ID,
        title: "MX priorities express ordering",
        severity: "ok",
        detail: `MX preferences are within range (0–65535) with ${distinctPriorities.size} distinct value(s).`,
      })
    }

    // --- infra.mx_dup_targets ------------------------------------------------------------------
    const targetCounts = new Map<string, number>()
    for (const r of realRecords) {
      const h = normHost(r.exchange)
      targetCounts.set(h, (targetCounts.get(h) ?? 0) + 1)
    }
    const dups = [...targetCounts.entries()].filter(([, n]) => n > 1).map(([h]) => h)
    if (dups.length > 0) {
      findings.push({
        id: "infra.mx_dup_targets",
        checkId: CHECK_ID,
        title: "Duplicate MX targets",
        severity: "info",
        detail: `The MX RRset lists the same exchange host more than once: ${dups.join(", ")}. Duplicates add no redundancy.`,
        remediation: `Remove the duplicate MX line(s) for ${dups.join(", ")}; keep one entry per distinct host.`,
        evidence: dups.join(", "),
      })
    }

    // --- infra.mx_target_count -----------------------------------------------------------------
    if (realRecords.length > 10) {
      findings.push({
        id: "infra.mx_target_count",
        checkId: CHECK_ID,
        title: "Excessive MX targets",
        severity: "warning",
        detail: `${realRecords.length} MX records are published — an unusually large fan-out that usually signals misconfiguration or abuse.`,
        remediation: "Trim the MX RRset to the hosts you actually operate (2–4 is typical).",
        evidence: realRecords.map((r) => `${r.priority} ${r.exchange}`).join(" | "),
      })
    } else {
      findings.push({
        id: "infra.mx_target_count",
        checkId: CHECK_ID,
        title: "MX target count is sane",
        severity: "ok",
        detail: `${realRecords.length} MX host(s) published (within the expected 1–10 range).`,
      })
    }

    // --- infra.mx_trailing_dot: accidental relative name that expanded oddly --------------------
    const doubled = hosts.filter((h) => h.host.endsWith(`.${domain}.${domain}`))
    for (const h of doubled) {
      findings.push({
        id: `infra.mx_trailing_dot.${h.host}`,
        checkId: CHECK_ID,
        title: `MX target ${h.host} looks like a relative name`,
        severity: "warning",
        detail: `MX target ${h.host} appears to have the zone origin appended twice (e.g. a zone-file entry missing its trailing dot), producing "${h.host}".`,
        remediation: `Republish the MX target as a fully-qualified name WITH a trailing dot in the zone file, e.g. "${domain}. IN MX ${h.priority} mail.${domain}.".`,
        evidence: h.host,
      })
    }

    // --- infra.mx_redundancy: host count + /24,/48 prefix diversity -----------------------------
    const distinctHosts = new Set(hosts.map((h) => h.host))
    const publicPrefixes = new Set<string>()
    for (const h of hosts) {
      for (const ip of h.ips) {
        if (ipClass(ip) === "public") publicPrefixes.add(networkPrefix(ip))
      }
    }
    if (distinctHosts.size < 2) {
      findings.push({
        id: "infra.mx_redundancy",
        checkId: CHECK_ID,
        title: "Single MX host — no failover",
        severity: "warning",
        detail: `Only ${distinctHosts.size} MX host is published, so any outage of that host defers all inbound mail until the sender times out.`,
        remediation: `Add a second MX on a different provider/network: "${domain}. IN MX 20 mail2.${domain}.".`,
        evidence: [...distinctHosts].join(", "),
      })
    } else if (publicPrefixes.size <= 1) {
      findings.push({
        id: "infra.mx_redundancy",
        checkId: CHECK_ID,
        title: "MX hosts share one network",
        severity: "warning",
        detail: `The ${distinctHosts.size} MX hosts all resolve into a single /24 (v4) or /48 (v6) prefix${
          publicPrefixes.size === 1 ? ` (${[...publicPrefixes][0]})` : ""
        }, so a single network/provider outage takes down all inbound mail.`,
        remediation: `Add an MX on a genuinely separate network/provider: "${domain}. IN MX 30 mail3.otherprovider.net.". (Precise ASN-diversity is verified in a future round.)`,
        evidence: [...distinctHosts].join(", "),
      })
    } else {
      findings.push({
        id: "infra.mx_redundancy",
        checkId: CHECK_ID,
        title: "Redundant MX hosts on diverse networks",
        severity: "ok",
        detail: `${distinctHosts.size} MX hosts spread across ${publicPrefixes.size} distinct /24 or /48 prefixes (first-round network-diversity approximation).`,
        evidence: [...distinctHosts].join(", "),
      })
    }

    // --- infra.mx_a_consistency: v4/v6 both present and routable --------------------------------
    for (const h of hosts) {
      if (h.transient || h.ips.length === 0) continue
      const v4 = h.ips.filter((ip) => !ip.includes(":"))
      const v6 = h.ips.filter((ip) => ip.includes(":"))
      const v6NonPublic = v6.length > 0 && v6.every((ip) => ipClass(ip) !== "public")
      if (v6NonPublic && v4.some((ip) => ipClass(ip) === "public")) {
        findings.push({
          id: `infra.mx_a_consistency.${h.host}`,
          checkId: CHECK_ID,
          title: `MX target ${h.host} advertises a broken AAAA`,
          severity: "warning",
          detail: `${h.host} has a working IPv4 address but its advertised AAAA record(s) (${v6.join(", ")}) are not publicly routable, so IPv6-only senders will fail.`,
          remediation: `Fix or remove the AAAA for ${h.host} so both families point at working, public listeners (or drop the AAAA entirely if you do not run IPv6 SMTP).`,
          evidence: v6.join(", "),
        })
      } else if (v4.length > 0 && v6.length > 0) {
        findings.push({
          id: `infra.mx_a_consistency.${h.host}`,
          checkId: CHECK_ID,
          title: `MX target ${h.host} has consistent A/AAAA`,
          severity: "ok",
          detail: `${h.host} resolves on both IPv4 and IPv6 with routable addresses.`,
        })
      }
    }

    // --- FUTURE (probe / external feed) sub-checks: info only -----------------------------------
    pushFutureFindings(findings, domain)

    return {
      findings,
      results: snapshot(
        hosts,
        { mx_found: true, null_mx: nullRecords.length > 0, implicit_a_fallback: false },
        { host_count: distinctHosts.size, network_count: publicPrefixes.size },
      ),
    }
  },
}

/**
 * Emit the one-info-each "not yet evaluated" findings for the FUTURE, network-probe / external-feed
 * sub-checks (spec §7). These never escalate to warning/critical.
 */
function pushFutureFindings(findings: Finding[], _domain: string): void {
  findings.push(
    future(
      "infra.mx_reachable",
      "SMTP reachability not yet evaluated",
      "TCP/25 connect + 220-banner probing is deferred to the network-probe round (outbound port 25 is blocked on many hosts). Each MX will be tested for a 220 SMTP greeting there.",
    ),
    future(
      "infra.mx_banner",
      "SMTP banner not yet evaluated",
      "The 220 greeting hostname will be validated as a proper FQDN (not localhost.localdomain or a bare IP) once SMTP probing is enabled.",
    ),
    future(
      "infra.mx_greylash",
      "Greylisting behavior not yet evaluated",
      "First-contact 4xx tempfail (greylisting) detection requires an SMTP probe and is advisory-only; it will estimate expected first-delivery delay in the probe round.",
    ),
    future(
      "infra.backup_mx_hygiene",
      "Backup-MX hygiene not yet evaluated",
      "Open-relay / recipient-validation testing of higher-preference (backup) MX hosts requires an SMTP relay probe, pending the network-probe round.",
    ),
    future(
      "infra.mx_ttl",
      "MX RRset TTL not evaluated in first round",
      "node:dns does not expose the RRset TTL. The exact MX TTL will be captured by parsing `dig +noall +answer MX` in a future round; aim for ~3600s (1h) and only drop to 300s during a planned migration.",
    ),
  )
}
