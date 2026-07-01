import type { Severity } from "../types"

/**
 * Shared shapes for the Blacklists (DNSBL/RHSBL) checker — the TypeScript mirror of the
 * `test_results.yaml` schema in pm/checks/blacklists.mdx §12. Field names are snake_case on purpose:
 * the persisted YAML, the `results.blacklist` audit payload, and the /blacklists REST responses all
 * carry this exact shape so the frontend never re-maps keys.
 */

export type ZoneTier = "high" | "medium" | "low"
export type ZoneKind = "ip" | "domain"
export type ZoneHealthStatus = "ok" | "dead" | "wildcarding" | "blocked" | "slow"
export type TargetSource = "sending_ips" | "mx_resolved" | "spf_authorized" | "primary"

/** Problem states PS-0..PS-13 from pm/checks/blacklists.mdx §16. */
export type ProblemStateId =
  | "PS-0"
  | "PS-1"
  | "PS-2"
  | "PS-3"
  | "PS-4"
  | "PS-5"
  | "PS-6"
  | "PS-7"
  | "PS-8"
  | "PS-9"
  | "PS-10"
  | "PS-11"
  | "PS-12"
  | "PS-13"

/** Meaning of one decoded return code (or bitmask bit). */
export interface CodeMeaning {
  label: string
  severity: Severity
  /** Which problem state this sub-list maps to (drives the deep-dive link). */
  problem_state?: ProblemStateId
}

/** One catalog row — pm/checks/blacklists.mdx §9. */
export interface BlocklistZone {
  zone: string
  name: string
  kind: ZoneKind
  tier: ZoneTier
  /** 0..1 — scales severity in the roll-up (§3 "Severity mapping"). */
  weight: number
  lookup_url: string
  delist_url: string
  enabled: boolean
  /** Default severity for a listing when no return-code entry overrides it. */
  severity: Severity
  /** Exact return-code map, e.g. { "127.0.0.4": { label: "XBL", severity: "critical" } }. */
  codes?: Record<string, CodeMeaning>
  /** Bitmask decode of the answer's last octet (SURBL/URIBL style). */
  bitmask?: Record<string, CodeMeaning>
  requires_registration?: boolean
  is_paid?: boolean
  /** Operator sells "express" delisting — triggers the PS-13 never-pay advisory. */
  paid_delist_offered?: boolean
  /** Human auto-expiry window, e.g. "~24h after reports stop". */
  auto_expires?: string
  /** Listing on this zone is a GOOD signal (DNSWL). */
  positive?: boolean
  notes?: string
}

export interface IpTarget {
  ip: string
  source: TargetSource
  ptr: string | null
  fcrdns_ok: boolean | null
  asn: { number: number | null; org: string | null } | null
}

export interface DomainTarget {
  domain: string
  source: TargetSource
  /** whois creation date — null in the first (DNS-only) round. */
  created: string | null
}

export interface ZoneHealth {
  zone: string
  status: ZoneHealthStatus
  positive_probe: string
  negative_probe: string
  probe_ms: number
}

/** One (zone × target) query outcome. */
export interface ZoneResult {
  zone: string
  name: string
  tier: ZoneTier
  kind: ZoneKind
  target: string
  listed: boolean
  return_code: string | null
  sub_list: string | null
  reason_txt: string | null
  lookup_url: string
  delist_url: string
  severity: Severity | null
  inconclusive: boolean
  /** In-band refusal answer (Spamhaus 127.255.255.x, URIBL_BLOCKED 127.0.0.1) when refused. */
  refusal_code: string | null
  query_ms: number
  problem_state: ProblemStateId | null
  paid_delist_offered: boolean
  auto_expires: string | null
}

export interface PositiveReputation {
  dnswl: { listed: boolean; category: string | null; trust: number | null }
  senderscore: { score: number | null; severity: Severity }
  mailspike_rep: { code: string | null; label: string | null }
}

export type PortalUserState = "unverified" | "verified_clean" | "problem_reported"

export interface ProviderPortal {
  provider: string
  name: string
  check_url: string
  delist_url: string
  user_state: PortalUserState
}

export interface BlacklistDiff {
  new_listings: Array<{ zone: string; target: string; sub_list: string | null }>
  cleared: Array<{ zone: string; target: string; sub_list: string | null }>
  escalated: Array<{ zone: string; target: string; from: string; to: string }>
  first_run: boolean
}

export interface BlacklistSummary {
  zones_enabled: number
  pairs_queried: number
  listed: number
  clean: number
  inconclusive: number
  dead_zones_skipped: number
  worst_severity: Severity
  problem_states: ProblemStateId[]
}

/** The whole per-run document — persisted as test_results.yaml and served as results.blacklist. */
export interface BlacklistRunResults {
  schema_version: 1
  technology: "blacklists"
  domain: string
  audit_id: string
  ran_at: string
  duration_ms: number
  resolver: { mode: "system" | "custom"; server: string | null; refusals_detected: boolean }
  targets: { ips: IpTarget[]; domains: DomainTarget[] }
  zone_health: ZoneHealth[]
  results: ZoneResult[]
  positive_reputation: PositiveReputation
  provider_portals: ProviderPortal[]
  summary: BlacklistSummary
  diff: BlacklistDiff
}

/** Compact per-run row for the history strip (sparkline). */
export interface BlacklistHistoryEntry {
  audit_id: string
  ran_at: string
  listed: number
  clean: number
  inconclusive: number
  worst_severity: Severity
}
