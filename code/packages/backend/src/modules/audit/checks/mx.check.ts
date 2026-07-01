import type { Checker, Finding } from "./types"
import { resolveMx, resolve4, reverse } from "./dns-util"

/**
 * MX + PTR sanity. Confirms the domain has MX records (so it can receive mail — required for DMARC
 * reports and bounce handling) and does a light reverse-DNS (PTR) sanity check on the primary MX
 * host's IP. Missing PTR / generic-looking rDNS is a classic spam-filter trigger for the SENDING
 * side, so we surface it here as guidance.
 */
export const mxCheck: Checker = {
  id: "mx",
  label: "MX & reverse DNS",
  async run(ctx): Promise<Finding[]> {
    const { records, empty, error } = await resolveMx(ctx.domain)
    if (error) {
      return [
        {
          id: "mx.lookup_failed",
          checkId: "mx",
          title: "Could not look up MX",
          severity: "warning",
          detail: `DNS lookup for MX ${ctx.domain} failed (${error}).`,
          remediation: "Retry the audit; if it persists, verify the domain's nameservers.",
        },
      ]
    }
    if (empty || records.length === 0) {
      return [
        {
          id: "mx.missing",
          checkId: "mx",
          title: "No MX records",
          severity: "warning",
          detail: `${ctx.domain} has no MX records, so it cannot receive mail — including DMARC failure reports and bounce messages.`,
          remediation: "Publish MX records pointing at your mail provider (e.g. Google Workspace's ASPMX hosts).",
        },
      ]
    }

    const findings: Finding[] = []
    const primary = [...records].sort((a, b) => a.priority - b.priority)[0]
    findings.push({
      id: "mx.ok",
      checkId: "mx",
      title: `MX records present (${records.length})`,
      severity: "ok",
      detail: `Primary MX is ${primary.exchange} (priority ${primary.priority}).`,
      evidence: records.map((r) => `${r.priority} ${r.exchange}`).join(", "),
    })

    // Light PTR sanity on the primary MX host's first A record.
    const a = await resolve4(primary.exchange)
    const ip = a.records[0]
    if (ip) {
      const ptr = await reverse(ip)
      if (ptr.empty || ptr.records.length === 0) {
        findings.push({
          id: "mx.no_ptr",
          checkId: "mx",
          title: "Primary MX host has no PTR record",
          severity: "info",
          detail: `${primary.exchange} (${ip}) has no reverse-DNS (PTR) record. Many receivers penalize senders without valid rDNS.`,
          remediation: "Ask your mail host to set a PTR record for the sending IP that resolves back to the mail host name.",
        })
      }
    }
    return findings
  },
}
