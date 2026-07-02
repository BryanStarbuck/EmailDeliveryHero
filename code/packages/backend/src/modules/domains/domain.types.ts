import type {
  ArcConfig,
  BimiDomainConfig,
  DnsHealthConfig,
  DomainReputationConfig,
  ListUnsubDomainConfig,
} from "../audit/checks/types"

/** A monitored email-sending domain. Persisted as YAML under the state dir (no database). */
export interface MonitoredDomain {
  id: string
  /** The domain name, e.g. "whitehatengineering.com". */
  name: string
  /** Friendly label / notes shown under the domain in the table; "" if none. */
  label: string
  /** DKIM selectors to probe (provider-specific), e.g. ["google"]. */
  dkimSelectors: string[]
  /** Sending IPs to test against DNS blacklists (optional; MX IPs are used when empty). */
  sendingIps: string[]
  /**
   * Whether this domain is included in recurring scheduled checks. ANDed with the global scheduled
   * switch: a domain is on the schedule only if the global switch is ON and this is true
   * (pm/domains.mdx §6). Manual runs ignore it.
   */
  scheduleEnabled: boolean
  /**
   * ARC / forwarding configuration (pm/checks/arc.mdx §4): whether the domain sends through
   * forwarders/mailing lists, and the declared forwarders (the `arc_forwarders` reference table
   * mapped onto the YAML store). Absent = no forwarding declared.
   */
  arc?: ArcConfig
  /**
   * BIMI configuration (pm/checks/bimi.mdx §4): optional extra BIMI selectors beyond `default`
   * and an optional sample message whose `BIMI-Selector:` header is compared against the
   * published `_bimi` records. Absent = only the `default` selector is audited.
   */
  bimi?: BimiDomainConfig
  /**
   * List-management configuration (pm/checks/list_unsubscribe.mdx §3/§4): the isBulkSender
   * severity escalator (> 5,000 msgs/day → missing one-click is critical) and the opt-in
   * probeUnsubEndpoint toggle (default off) for the live one-click POST probe. Absent = not a
   * declared bulk sender, probe off.
   */
  listUnsub?: ListUnsubDomainConfig
  /**
   * DNS-health expectations (pm/checks/dns_health.mdx §4/§5 — the `dns_health_expectations`
   * table mapped onto the YAML store): extra subdomain labels for the dangling-CNAME scan, an
   * optional expected-NS allow-list (drift alerts), and the skip-AXFR-probe toggle. Absent = the
   * built-in mail-relevant label set and no NS expectation.
   */
  dnsHealth?: DnsHealthConfig
  /**
   * Domain-Registration-Reputation config (pm/checks/domain_reputation.mdx §4, admin-only): the
   * org brand string(s) for `infra.name_similarity`, expiry/age warning thresholds (default 30
   * days each), the "registrant is intentionally public" silencer, and the (future) active
   * cousin-domain scan toggle. Absent = defaults, no brands configured.
   */
  domainReputation?: DomainReputationConfig
  /** Who added it (email from the auth token). */
  addedBy: string
  createdAt: string
  updatedAt: string
}
