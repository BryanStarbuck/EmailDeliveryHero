/** Shared API types — mirror the backend DTOs (packages/backend/src/modules/*). */

export type Severity = "ok" | "info" | "warning" | "critical"

export interface MonitoredDomain {
  id: string
  name: string
  label: string
  dkimSelectors: string[]
  sendingIps: string[]
  /** Whether this domain is included in recurring scheduled checks (ANDed with the global switch). */
  scheduleEnabled: boolean
  addedBy: string
  createdAt: string
  updatedAt: string
}

export interface Finding {
  id: string
  checkId: string
  title: string
  severity: Severity
  detail: string
  remediation?: string
  evidence?: string
}

/** One external rua/ruf destination and its `_report._dmarc` authorization state. */
export interface DmarcExternalAuth {
  report_kind: "rua" | "ruf"
  report_uri: string
  report_domain: string
  auth_name: string
  authorized: boolean
}

/** The parsed DMARC observation (`results.dmarc`, pm/checks/dmarc.mdx §5). */
export interface DmarcResults {
  query_name: string
  record_found: boolean
  record_count: number
  found_at: string | null
  raw_record: string | null
  parsed: Record<string, string> | null
  policy: "none" | "quarantine" | "reject" | null
  subdomain_policy: "none" | "quarantine" | "reject" | null
  np_policy: string | null
  pct: number | null
  adkim: string
  aspf: string
  rua_uris: string[]
  ruf_uris: string[]
  fo: string | null
  ri: number | null
  is_enforcing: boolean
  external_reports_authorized: boolean | null
  external_report_auth: DmarcExternalAuth[]
}

/** One parsed apex-level SPF term (mechanism or redirect/exp modifier). */
export interface SpfMechanism {
  qualifier: "+" | "-" | "~" | "?"
  type: string
  value: string | null
  /** Whether evaluating this term costs one of the 10 allowed DNS lookups. */
  lookup: boolean
  raw: string
}

/** One node of the recursively expanded include/redirect graph. */
export interface SpfTreeNode {
  term: string
  depth: number
  cost_lookups: number
  is_void: boolean
  resolved_to: string[]
  children: SpfTreeNode[]
}

export interface SpfIpCoverage {
  ip: string
  covered: boolean
  matched_by: string | null
}

/** The parsed SPF observation (`results.spf`, pm/checks/spf.mdx §5). */
export interface SpfResults {
  query_name: string
  record_found: boolean
  record_count: number
  raw_record: string | null
  mechanisms: SpfMechanism[]
  lookup_count: number
  void_count: number
  all_qualifier: "-all" | "~all" | "?all" | "+all" | null
  has_redirect: boolean
  byte_length: number
  /** valid | permerror | temperror | none. */
  eval_result: string
  include_tree: SpfTreeNode | null
  pass_set: { cidr: string; source: string }[]
  ip_coverage: SpfIpCoverage[]
}

/** One probed DKIM selector (`results.dkim.selectors[]`, pm/checks/dkim.mdx §5). */
export interface DkimSelectorResult {
  selector: string
  query_name: string
  source: "configured" | "discovered"
  resolved_via: "txt" | "cname" | "none"
  cname_target: string | null
  present: boolean
  parses: boolean
  raw_record: string | null
  dkim_version: string | null
  key_type: string | null
  key_bits: number | null
  key_sha256: string | null
  has_test_flag: boolean
  has_strict_flag: boolean
  is_revoked: boolean
  txt_record_count: number
  oversize_chunk: boolean
  flags: Record<string, string>
  first_seen_at: string | null
}

/** The parsed DKIM observation (`results.dkim`, pm/checks/dkim.mdx §5). */
export interface DkimResults {
  selectors_configured: string[]
  discovery_ran: boolean
  working_selectors: number
  wildcard_shadow: boolean
  duplicate_keys: { key_sha256: string; seen_on: string[] }[]
  selectors: DkimSelectorResult[]
}

// ---- DNS & Infrastructure snapshots (pm/checks/dns.mdx §5 — snake_case mirrors the YAML) -------

/** The MX topology snapshot (`results["infra.mx_routing"]`). */
export interface MxRoutingResults {
  mx_found: boolean
  null_mx: boolean
  implicit_a_fallback: boolean
  hosts: {
    host: string
    priority: number
    is_cname: boolean
    cname_target: string | null
    ips: string[]
    non_public: { ip: string; cls: string }[]
  }[]
  redundancy: { host_count: number; network_count: number }
}

/** One PTR/FCrDNS row of the reverse-DNS map (`results["infra.reverse_dns"]`). */
export interface ReverseDnsIpResult {
  ip: string
  source: "mx" | "sending_ip"
  ptr: string | null
  forward_confirmed: boolean
  generic: boolean
}

export interface ReverseDnsResults {
  ips: ReverseDnsIpResult[]
}

/** The zone snapshot (`results["infra.dns_health"]`); null fields = probe not run yet. */
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

/** The DNSSEC state (`results["infra.dnssec"]`); null = could not be determined this run. */
export interface DnssecResults {
  signed: boolean
  ds_present: boolean | null
  ds_digest_types: number[]
  algorithms: number[]
  ds_matches_dnskey: boolean | null
  dane_ready: boolean
}

export interface AuditResult {
  /** Unique id of this run (pm/dashboard.mdx §1). Optional: pre-history persisted data lacks it. */
  runId?: string
  domainId: string
  domain: string
  /** ISO date-times the run started/stopped (pm/dashboard.mdx §1). Optional on old data. */
  startedAt?: string
  finishedAt?: string
  ranAt: string
  score: number
  status: Severity
  findings: Finding[]
  counts: Record<Severity, number>
  /** Structured per-check payloads keyed by checker id (e.g. results.dmarc, results.spf). */
  results?: {
    dmarc?: DmarcResults
    spf?: SpfResults
    dkim?: DkimResults
    blacklist?: BlacklistRunResults
    "infra.mx_routing"?: MxRoutingResults
    "infra.reverse_dns"?: ReverseDnsResults
    "infra.dns_health"?: DnsHealthResults
    "infra.dnssec"?: DnssecResults
  } & Record<string, unknown>
}

// ---- Blacklists (pm/checks/blacklists.mdx §12 — snake_case mirrors the persisted YAML) ---------

export type ZoneTier = "high" | "medium" | "low"
export type ZoneKind = "ip" | "domain"
export type ZoneHealthStatus = "ok" | "dead" | "wildcarding" | "blocked" | "slow"
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
export type PortalUserState = "unverified" | "verified_clean" | "problem_reported"

export interface BlacklistIpTarget {
  ip: string
  source: "sending_ips" | "mx_resolved" | "spf_authorized" | "email_report" | "primary"
  ptr: string | null
  fcrdns_ok: boolean | null
  asn: { number: number | null; org: string | null } | null
}

export interface BlacklistDomainTarget {
  domain: string
  source: string
  created: string | null
}

export interface BlacklistZoneHealth {
  zone: string
  status: ZoneHealthStatus
  positive_probe: string
  negative_probe: string
  probe_ms: number
}

export interface BlacklistZoneResult {
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
  refusal_code: string | null
  query_ms: number
  problem_state: ProblemStateId | null
  paid_delist_offered: boolean
  auto_expires: string | null
}

export interface BlacklistPositiveReputation {
  dnswl: { listed: boolean; category: string | null; trust: number | null }
  senderscore: { score: number | null; severity: Severity }
  mailspike_rep: { code: string | null; label: string | null }
}

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

/** The whole per-run document (test_results.yaml / results.blacklist / GET /blacklists/results). */
export interface BlacklistRunResults {
  schema_version: 1
  technology: "blacklists"
  domain: string
  audit_id: string
  ran_at: string
  duration_ms: number
  resolver: { mode: "system" | "custom"; server: string | null; refusals_detected: boolean }
  targets: { ips: BlacklistIpTarget[]; domains: BlacklistDomainTarget[] }
  zone_health: BlacklistZoneHealth[]
  results: BlacklistZoneResult[]
  positive_reputation: BlacklistPositiveReputation
  provider_portals: ProviderPortal[]
  summary: BlacklistSummary
  diff: BlacklistDiff
}

export interface BlacklistHistoryEntry {
  audit_id: string
  ran_at: string
  listed: number
  clean: number
  inconclusive: number
  worst_severity: Severity
}

/** One effective catalog row from GET /blacklists/zones (pm/checks/blacklists.mdx §18). */
export interface BlocklistZoneRow {
  zone: string
  name: string
  kind: ZoneKind
  tier: ZoneTier
  weight: number
  lookup_url: string
  delist_url: string
  enabled: boolean
  severity: Severity
  requires_registration?: boolean
  is_paid?: boolean
  paid_delist_offered?: boolean
  auto_expires?: string
  positive?: boolean
  notes?: string
}

/** The effective registry view — checked-in blacklists.yaml ⊕ operator overrides (§17.1 panel 5). */
export interface BlacklistRegistryInfo {
  compiled: string
  lists_total: number
  zones: BlocklistZoneRow[]
  dead_zones: Array<{ zone: string; name: string; died?: string | number; reason?: string }>
  aggregators: Array<{ name: string; url: string; description: string }>
}
