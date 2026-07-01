/** A monitored email-sending domain. Persisted as JSON under the state dir (no database). */
export interface MonitoredDomain {
  id: string
  /** The domain name, e.g. "whitehatengineering.com". */
  name: string
  /** DKIM selectors to probe (provider-specific), e.g. ["google"]. */
  dkimSelectors: string[]
  /** Sending IPs to test against DNS blacklists (optional; MX IPs are used when empty). */
  sendingIps: string[]
  /** Who added it (email from the auth token). */
  addedBy: string
  createdAt: string
  updatedAt: string
}
