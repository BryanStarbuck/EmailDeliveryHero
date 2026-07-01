import { join } from "node:path"
import { resolveStateDir } from "@shared/state-dir"
import { readYaml } from "@shared/yaml-store"
import type { BlocklistZone, ProviderPortal } from "./blacklist-types"

/**
 * The blocklist zone catalog — pm/checks/blacklists.mdx §9 (compiled 2026-07). Tier drives default
 * severity/weight; the dead-zone registry is hard-blocked (dead zones sometimes wildcard and "list
 * the world"). Operators can override/extend via <stateDir>/blacklist_zones.yaml (same row shape,
 * merged by `zone`; a row with enabled:false disables a default zone) — no code change needed.
 */

const critical = "critical" as const
const warning = "warning" as const
const info = "info" as const

export const DEFAULT_ZONES: BlocklistZone[] = [
  // ---- Tier HIGH — IP zones ----------------------------------------------------------------
  {
    zone: "zen.spamhaus.org",
    name: "Spamhaus ZEN",
    kind: "ip",
    tier: "high",
    weight: 1,
    lookup_url: "https://check.spamhaus.org",
    delist_url: "https://check.spamhaus.org",
    enabled: true,
    severity: critical,
    codes: {
      "127.0.0.2": {
        label: "SBL (manual spam listing)",
        severity: critical,
        problem_state: "PS-1",
      },
      "127.0.0.3": { label: "CSS (snowshoe spam)", severity: critical, problem_state: "PS-1" },
      "127.0.0.4": { label: "XBL (compromised host)", severity: critical, problem_state: "PS-2" },
      "127.0.0.5": { label: "XBL (compromised host)", severity: critical, problem_state: "PS-2" },
      "127.0.0.6": { label: "XBL (compromised host)", severity: critical, problem_state: "PS-2" },
      "127.0.0.7": { label: "XBL (compromised host)", severity: critical, problem_state: "PS-2" },
      "127.0.0.10": {
        label: "PBL (ISP policy: dynamic range)",
        severity: warning,
        problem_state: "PS-3",
      },
      "127.0.0.11": {
        label: "PBL (Spamhaus policy: dynamic range)",
        severity: warning,
        problem_state: "PS-3",
      },
    },
  },
  {
    zone: "b.barracudacentral.org",
    name: "Barracuda BRBL",
    kind: "ip",
    tier: "high",
    weight: 1,
    lookup_url: "https://www.barracudacentral.org/lookups",
    delist_url: "https://www.barracudacentral.org/rbl/removal-request",
    enabled: true,
    severity: critical,
    requires_registration: true,
    notes: "Register your resolver IPs at barracudacentral.org before queries resolve.",
  },
  {
    zone: "bl.spamcop.net",
    name: "SpamCop SCBL",
    kind: "ip",
    tier: "high",
    weight: 0.7,
    lookup_url: "https://www.spamcop.net/bl.shtml",
    delist_url: "https://www.spamcop.net/bl.shtml",
    enabled: true,
    severity: warning,
    auto_expires: "~24h after reports stop",
    codes: {
      "127.0.0.2": { label: "SCBL (spam-trap reports)", severity: warning, problem_state: "PS-5" },
    },
  },
  {
    zone: "psbl.surriel.com",
    name: "PSBL",
    kind: "ip",
    tier: "high",
    weight: 0.7,
    lookup_url: "https://psbl.org",
    delist_url: "https://psbl.org/remove",
    enabled: true,
    severity: warning,
    auto_expires: "2–4 weeks; instant self-removal",
    codes: {
      "127.0.0.2": { label: "PSBL (passive spam trap)", severity: warning, problem_state: "PS-5" },
    },
  },
  {
    zone: "dnsbl.dronebl.org",
    name: "DroneBL",
    kind: "ip",
    tier: "high",
    weight: 0.9,
    lookup_url: "https://dronebl.org/lookup",
    delist_url: "https://dronebl.org/lookup",
    enabled: true,
    severity: critical,
    codes: {
      "127.0.0.3": { label: "IRC drone", severity: critical, problem_state: "PS-2" },
      "127.0.0.8": { label: "SOCKS proxy", severity: critical, problem_state: "PS-2" },
      "127.0.0.9": { label: "HTTP proxy", severity: critical, problem_state: "PS-2" },
      "127.0.0.10": { label: "proxy", severity: critical, problem_state: "PS-2" },
      "127.0.0.13": { label: "DDoS drone", severity: critical, problem_state: "PS-2" },
      "127.0.0.14": { label: "breached host", severity: critical, problem_state: "PS-2" },
      "127.0.0.16": { label: "autorooted host", severity: critical, problem_state: "PS-2" },
    },
  },
  // ---- Tier HIGH — domain zones (RHSBL) ----------------------------------------------------
  {
    zone: "dbl.spamhaus.org",
    name: "Spamhaus DBL",
    kind: "domain",
    tier: "high",
    weight: 1,
    lookup_url: "https://check.spamhaus.org",
    delist_url: "https://check.spamhaus.org",
    enabled: true,
    severity: critical,
    codes: {
      "127.0.1.2": { label: "spam domain", severity: critical, problem_state: "PS-4" },
      "127.0.1.4": { label: "phishing domain", severity: critical, problem_state: "PS-4" },
      "127.0.1.5": { label: "malware domain", severity: critical, problem_state: "PS-4" },
      "127.0.1.6": { label: "botnet C&C domain", severity: critical, problem_state: "PS-4" },
      "127.0.1.102": { label: "abused-legit: spam", severity: warning, problem_state: "PS-4" },
      "127.0.1.103": {
        label: "abused-legit: redirector",
        severity: warning,
        problem_state: "PS-4",
      },
      "127.0.1.104": { label: "abused-legit: phish", severity: warning, problem_state: "PS-4" },
      "127.0.1.105": { label: "abused-legit: malware", severity: warning, problem_state: "PS-4" },
      "127.0.1.106": { label: "abused-legit: botnet", severity: warning, problem_state: "PS-4" },
      "127.0.1.255": { label: "IP queried at DBL (query bug — never a listing)", severity: info },
    },
  },
  {
    zone: "multi.surbl.org",
    name: "SURBL multi",
    kind: "domain",
    tier: "high",
    weight: 1,
    lookup_url: "https://www.surbl.org/surbl-analysis",
    delist_url: "https://www.surbl.org/surbl-analysis",
    enabled: true,
    severity: critical,
    bitmask: {
      "8": { label: "PH (phishing)", severity: critical, problem_state: "PS-4" },
      "16": { label: "MW (malware)", severity: critical, problem_state: "PS-4" },
      "64": { label: "ABUSE", severity: warning, problem_state: "PS-4" },
      "128": { label: "CR (cracked site)", severity: warning, problem_state: "PS-4" },
    },
  },
  {
    zone: "multi.uribl.com",
    name: "URIBL",
    kind: "domain",
    tier: "high",
    weight: 0.9,
    lookup_url: "https://admin.uribl.com/?section=lookup",
    delist_url: "https://admin.uribl.com/?section=lookup",
    enabled: true,
    severity: warning,
    bitmask: {
      // Bit 1 (127.0.0.1) is URIBL_BLOCKED — query refused, handled as a refusal, never a listing.
      "2": { label: "black", severity: critical, problem_state: "PS-4" },
      "4": { label: "grey", severity: warning, problem_state: "PS-4" },
      "8": { label: "red", severity: warning, problem_state: "PS-4" },
    },
  },
  // ---- Tier MEDIUM --------------------------------------------------------------------------
  {
    zone: "all.spamrats.com",
    name: "SpamRATS",
    kind: "ip",
    tier: "medium",
    weight: 0.6,
    lookup_url: "https://www.spamrats.com/lookup.php",
    delist_url: "https://www.spamrats.com/removal.php",
    enabled: true,
    severity: warning,
    codes: {
      "127.0.0.36": {
        label: "RATS-Dyna (dynamic-looking PTR)",
        severity: warning,
        problem_state: "PS-7",
      },
      "127.0.0.37": { label: "RATS-NoPtr (missing PTR)", severity: warning, problem_state: "PS-7" },
      "127.0.0.38": { label: "RATS-Spam", severity: warning, problem_state: "PS-5" },
      "127.0.0.43": { label: "RATS-Auth (auth attacks)", severity: warning, problem_state: "PS-2" },
    },
  },
  {
    zone: "bl.mailspike.net",
    name: "Mailspike BL",
    kind: "ip",
    tier: "medium",
    weight: 0.6,
    lookup_url: "https://mailspike.io/ip_verify",
    delist_url: "https://mailspike.io/ip_verify",
    enabled: true,
    severity: warning,
    codes: {
      "127.0.0.2": { label: "Mailspike blacklist", severity: warning, problem_state: "PS-5" },
    },
  },
  {
    zone: "z.mailspike.net",
    name: "Mailspike zero-hour",
    kind: "ip",
    tier: "medium",
    weight: 0.5,
    lookup_url: "https://mailspike.io/ip_verify",
    delist_url: "https://mailspike.io/ip_verify",
    enabled: true,
    severity: warning,
    auto_expires: "hours (zero-hour outbreak list)",
  },
  {
    zone: "ubl.lashback.com",
    name: "Lashback UBL",
    kind: "ip",
    tier: "medium",
    weight: 0.5,
    lookup_url: "https://blacklist.lashback.com",
    delist_url: "https://blacklist.lashback.com",
    enabled: true,
    severity: warning,
    codes: {
      "127.0.0.2": { label: "unsubscribe-abuse trap", severity: warning, problem_state: "PS-5" },
    },
  },
  {
    zone: "db.wpbl.info",
    name: "WPBL",
    kind: "ip",
    tier: "medium",
    weight: 0.5,
    lookup_url: "http://wpbl.info",
    delist_url: "http://wpbl.info",
    enabled: true,
    severity: warning,
    auto_expires: "~10 days after spam stops",
    codes: {
      "127.0.0.2": {
        label: "WPBL (private trap network)",
        severity: warning,
        problem_state: "PS-5",
      },
    },
  },
  {
    zone: "bl.0spam.org",
    name: "0spam",
    kind: "ip",
    tier: "medium",
    weight: 0.4,
    lookup_url: "https://0spam.org",
    delist_url: "https://0spam.org",
    enabled: true,
    severity: warning,
  },
  {
    zone: "all.s5h.net",
    name: "s5h.net",
    kind: "ip",
    tier: "medium",
    weight: 0.4,
    lookup_url: "https://usan.s5h.net/query/",
    delist_url: "https://usan.s5h.net/query/",
    enabled: true,
    severity: warning,
  },
  {
    zone: "bl.blocklist.de",
    name: "Blocklist.de",
    kind: "ip",
    tier: "medium",
    weight: 0.4,
    lookup_url: "https://www.blocklist.de/en/search.html",
    delist_url: "https://www.blocklist.de/en/delist.html",
    enabled: true,
    severity: warning,
    auto_expires: "48h–1 month after attacks stop",
    notes: "Lists brute-force attack sources (ssh/imap/smtp) — a hit suggests a compromised host.",
  },
  {
    zone: "truncate.gbudb.net",
    name: "GBUdb Truncate",
    kind: "ip",
    tier: "medium",
    weight: 0.4,
    lookup_url: "http://www.gbudb.com/truncate/",
    delist_url: "http://www.gbudb.com/truncate/",
    enabled: true,
    severity: warning,
    auto_expires: "auto — drops when good traffic is seen",
  },
  {
    zone: "hostkarma.junkemailfilter.com",
    name: "Hostkarma",
    kind: "ip",
    tier: "medium",
    weight: 0.4,
    lookup_url: "https://ipadmin.junkemailfilter.com/remove.php",
    delist_url: "https://ipadmin.junkemailfilter.com/remove.php",
    enabled: true,
    severity: warning,
    codes: {
      "127.0.0.1": { label: "whitelisted (good)", severity: "ok" },
      "127.0.0.2": { label: "blacklisted", severity: warning },
      "127.0.0.3": { label: "yellow (mixed)", severity: info },
      "127.0.0.4": { label: "brown (dynamic)", severity: info, problem_state: "PS-3" },
      "127.0.0.5": { label: "NOBL (no blacklisting)", severity: "ok" },
    },
  },
  {
    zone: "dnsbl.spfbl.net",
    name: "SPFBL",
    kind: "ip",
    tier: "medium",
    weight: 0.4,
    lookup_url: "https://spfbl.net/en/dnsbl/",
    delist_url: "https://spfbl.net/en/dnsbl/",
    enabled: true,
    severity: warning,
    paid_delist_offered: true,
    notes: "May charge for expedited delisting — advise waiting for the free path instead.",
  },
  {
    zone: "bl.nordspam.com",
    name: "NordSpam",
    kind: "ip",
    tier: "medium",
    weight: 0.3,
    lookup_url: "https://www.nordspam.com",
    delist_url: "https://www.nordspam.com",
    enabled: true,
    severity: warning,
    notes:
      "Delist by emailing delist@nordspam.com from the affected domain with evidence of the fix.",
  },
  {
    zone: "dbl.nordspam.com",
    name: "NordSpam DBL",
    kind: "domain",
    tier: "medium",
    weight: 0.3,
    lookup_url: "https://www.nordspam.com",
    delist_url: "https://www.nordspam.com",
    enabled: true,
    severity: warning,
  },
  {
    zone: "bogons.cymru.com",
    name: "Team Cymru Bogons",
    kind: "ip",
    tier: "medium",
    weight: 0.2,
    lookup_url: "https://www.team-cymru.com/bogon-networks",
    delist_url: "https://www.team-cymru.com/bogon-networks",
    enabled: true,
    severity: info,
    notes: "A hit means unallocated/leaked IP space — a routing/config bug, not spam.",
  },
  // ---- Positive reputation (being listed is GOOD) -------------------------------------------
  {
    zone: "list.dnswl.org",
    name: "DNSWL (whitelist)",
    kind: "ip",
    tier: "medium",
    weight: 0,
    lookup_url: "https://www.dnswl.org",
    delist_url: "https://www.dnswl.org",
    enabled: true,
    severity: info,
    positive: true,
  },
  // ---- Tier LOW / advisory — never panic the user --------------------------------------------
  {
    zone: "dnsbl-1.uceprotect.net",
    name: "UCEPROTECT L1",
    kind: "ip",
    tier: "low",
    weight: 0.2,
    lookup_url: "https://www.uceprotect.net/en/rblcheck.php",
    delist_url: "https://www.uceprotect.net/en/rblcheck.php",
    enabled: true,
    severity: warning,
    paid_delist_offered: true,
    auto_expires: "7 days after spam stops — NEVER pay for express delisting (RFC 6471)",
  },
  {
    zone: "dnsbl-2.uceprotect.net",
    name: "UCEPROTECT L2 (allocation)",
    kind: "ip",
    tier: "low",
    weight: 0.1,
    lookup_url: "https://www.uceprotect.net/en/rblcheck.php",
    delist_url: "https://www.uceprotect.net/en/rblcheck.php",
    enabled: true,
    severity: info,
    paid_delist_offered: true,
    notes: "Collateral: your provider's allocation is listed. Gmail/Microsoft/Yahoo do not use it.",
  },
  {
    zone: "dnsbl-3.uceprotect.net",
    name: "UCEPROTECT L3 (whole ASN)",
    kind: "ip",
    tier: "low",
    weight: 0.05,
    lookup_url: "https://www.uceprotect.net/en/rblcheck.php",
    delist_url: "https://www.uceprotect.net/en/rblcheck.php",
    enabled: true,
    severity: info,
    paid_delist_offered: true,
    notes: "ASN-wide collateral — pure noise for most senders.",
  },
  {
    zone: "ips.backscatterer.org",
    name: "Backscatterer",
    kind: "ip",
    tier: "low",
    weight: 0.1,
    lookup_url: "https://www.backscatterer.org/?target=test",
    delist_url: "https://www.backscatterer.org/?target=test",
    enabled: true,
    severity: info,
    paid_delist_offered: true,
    auto_expires: "4 weeks after last event",
    notes:
      "Only matters when a receiver runs it in SAFE mode; caused by bounce-after-accept backscatter.",
  },
  {
    zone: "bl.spameatingmonkey.net",
    name: "SEM-BLACK",
    kind: "ip",
    tier: "low",
    weight: 0.2,
    lookup_url: "https://spameatingmonkey.com/lookup",
    delist_url: "https://spameatingmonkey.com/lookup",
    enabled: true,
    severity: warning,
    auto_expires: "trap listings expire 15 days idle",
  },
  {
    zone: "netbl.spameatingmonkey.net",
    name: "SEM netblock",
    kind: "ip",
    tier: "low",
    weight: 0.1,
    lookup_url: "https://spameatingmonkey.com/lookup",
    delist_url: "https://spameatingmonkey.com/lookup",
    enabled: true,
    severity: info,
    notes: "Range listing — collateral from network neighbors.",
  },
  {
    zone: "uribl.spameatingmonkey.net",
    name: "SEM-URI",
    kind: "domain",
    tier: "low",
    weight: 0.2,
    lookup_url: "https://spameatingmonkey.com/lookup",
    delist_url: "https://spameatingmonkey.com/lookup",
    enabled: true,
    severity: warning,
  },
  {
    zone: "fresh.spameatingmonkey.net",
    name: "SEM-FRESH (new domains)",
    kind: "domain",
    tier: "low",
    weight: 0.1,
    lookup_url: "https://spameatingmonkey.com/lookup",
    delist_url: "https://spameatingmonkey.com/lookup",
    enabled: true,
    severity: info,
    notes: "Domain-age heuristic, not an accusation — new domains age out automatically.",
  },
]

/**
 * The dead-zone registry (pm/checks/blacklists.mdx §9.5). Hard-blocked: the engine refuses to query
 * these even if an operator override adds them. Suffix match so all 18 SORBS sub-zones are covered.
 */
export const DEAD_ZONE_SUFFIXES: string[] = [
  "sorbs.net", // Proofpoint decommissioned SORBS 2024-06-05
  "ix.dnsbl.manitu.net", // NiX Spam, died 2025-01-16
  "ubl.unsubscore.com",
  "combined.abuse.ch",
  "drone.abuse.ch",
  "spam.abuse.ch",
  "dnsbl.inps.de",
  "all.rbl.webiron.net",
  "bsb.spamlookup.net",
  "rbl.megarbl.net",
  "bl.emailbasura.org",
  "bl.spamcannibal.org", // wildcarded on death
  "dnsbl.cyberlogic.net",
  "exitnodes.tor.dnsbl.sectoor.de",
  "dnsbl.ahbl.org", // intentionally wildcarded on death
  "rbl.orbitrbl.com",
  "l2.apews.org", // zombie — stale data, no delisting
  "dnsbl.njabl.org",
  "dul.ru",
  "no-more-funn.moensted.dk",
  "dnsbl.burnt-tech.com",
  "anonwhois.org",
  "relays.osirusoft.com",
  "list.dsbl.org",
  "relays.ordb.org",
  "cbl.abuseat.org", // not dead — absorbed into Spamhaus XBL; never check separately (double-count)
]

export function isDeadZone(zone: string): boolean {
  const z = zone.toLowerCase()
  return DEAD_ZONE_SUFFIXES.some((suffix) => z === suffix || z.endsWith(`.${suffix}`))
}

/**
 * Provider reputation portals (§9.7) — the "invisible blacklists" with no DNS zone. Served as a
 * link-out checklist; per-domain user_state is stored by the blacklists store.
 */
export const PROVIDER_PORTALS: Array<Omit<ProviderPortal, "user_state">> = [
  {
    provider: "google_postmaster",
    name: "Google Postmaster Tools",
    check_url: "https://postmaster.google.com",
    delist_url: "https://support.google.com/mail/contact/gmail_bulk_sender_escalation",
  },
  {
    provider: "microsoft_snds",
    name: "Microsoft SNDS (Outlook/Hotmail)",
    check_url: "https://sendersupport.olc.protection.outlook.com/snds/",
    delist_url: "https://sendersupport.olc.protection.outlook.com/pm/",
  },
  {
    provider: "microsoft_365",
    name: "Microsoft 365 delist portal",
    check_url: "https://sender.office.com",
    delist_url: "https://sender.office.com",
  },
  {
    provider: "yahoo_sender_hub",
    name: "Yahoo/AOL Sender Hub",
    check_url: "https://senders.yahooinc.com",
    delist_url: "https://senders.yahooinc.com/contact/",
  },
  {
    provider: "cloudmark_csi",
    name: "Cloudmark CSI (carrier filters)",
    check_url: "https://csi.cloudmark.com/en/reset/",
    delist_url: "https://csi.cloudmark.com/en/reset/",
  },
  {
    provider: "proofpoint_pdr",
    name: "Proofpoint IP reputation",
    check_url: "https://ipcheck.proofpoint.com",
    delist_url: "https://ipcheck.proofpoint.com",
  },
  {
    provider: "cisco_talos",
    name: "Cisco Talos reputation",
    check_url: "https://talosintelligence.com/reputation_center",
    delist_url: "https://talosintelligence.com/reputation_center",
  },
  {
    provider: "comcast_postmaster",
    name: "Comcast/Xfinity postmaster",
    check_url: "https://postmaster.comcast.net",
    delist_url: "https://postmaster.xfinity.com/block-removal-request.html",
  },
  {
    provider: "validity_senderscore",
    name: "Validity Sender Score",
    check_url: "https://senderscore.org",
    delist_url: "https://senderscore.org",
  },
]

/** Path of the operator override file (admin "Blocklist Zones" panel writes here). */
export function zonesOverridePath(): string {
  return join(resolveStateDir(), "blacklist_zones.yaml")
}

/**
 * The effective zone catalog: defaults merged with <stateDir>/blacklist_zones.yaml overrides
 * (matched by `zone`; unknown zones are appended), with dead zones hard-excluded last.
 */
export function loadZones(): BlocklistZone[] {
  const overrides = readYaml<Partial<BlocklistZone>[]>(zonesOverridePath(), [])
  const byZone = new Map<string, BlocklistZone>(DEFAULT_ZONES.map((z) => [z.zone, { ...z }]))
  for (const raw of overrides) {
    if (!raw || typeof raw.zone !== "string") continue
    const existing = byZone.get(raw.zone)
    if (existing) byZone.set(raw.zone, { ...existing, ...raw })
    else if (raw.name && raw.kind && raw.lookup_url && raw.delist_url) {
      const defaults = {
        tier: "low" as const,
        weight: 0.2,
        enabled: true,
        severity: "warning" as const,
      }
      byZone.set(raw.zone, { ...defaults, ...(raw as BlocklistZone) })
    }
  }
  return [...byZone.values()].filter((z) => !isDeadZone(z.zone))
}
