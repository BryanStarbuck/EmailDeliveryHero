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
  /** Who added it (email from the auth token). */
  addedBy: string
  createdAt: string
  updatedAt: string
}
