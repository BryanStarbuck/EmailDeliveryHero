import { resolve4, resolveMx, reverseIpv4 } from "./dns-util"
import type { Checker, Finding } from "./types"

/**
 * DNS blacklist (DNSBL) membership. For each sending IP, reverses the octets and queries a set of
 * well-known blocklist zones (e.g. 4.3.2.1.zen.spamhaus.org). A DNS answer means the IP is LISTED —
 * the strongest possible deliverability problem, because listed IPs are outright rejected by many
 * receivers. Each blocklist gets a targeted delisting remediation.
 *
 * When the domain configures no explicit sending IPs, we derive candidate IPs from the domain's MX
 * A records so the check still runs with zero configuration.
 */

interface Blocklist {
  zone: string
  name: string
  delistUrl: string
}

const BLOCKLISTS: Blocklist[] = [
  { zone: "zen.spamhaus.org", name: "Spamhaus ZEN", delistUrl: "https://check.spamhaus.org/" },
  {
    zone: "b.barracudacentral.org",
    name: "Barracuda",
    delistUrl: "https://www.barracudacentral.org/rbl/removal-request",
  },
  { zone: "bl.spamcop.net", name: "SpamCop", delistUrl: "https://www.spamcop.net/bl.shtml" },
]

async function candidateIps(domain: string, configured: string[]): Promise<string[]> {
  if (configured.length > 0) return configured
  const mx = await resolveMx(domain)
  const ips: string[] = []
  for (const record of mx.records) {
    const a = await resolve4(record.exchange)
    ips.push(...a.records)
  }
  return [...new Set(ips)]
}

export const blacklistCheck: Checker = {
  id: "blacklist",
  label: "DNS blacklists",
  async run(ctx): Promise<Finding[]> {
    const ips = await candidateIps(ctx.domain, ctx.sendingIps)
    if (ips.length === 0) {
      return [
        {
          id: "blacklist.no_ips",
          checkId: "blacklist",
          title: "No sending IPs to check",
          severity: "info",
          detail:
            "No sending IPs were configured and none could be derived from MX records, so DNS blacklists were not checked.",
          remediation:
            "Add the IP addresses your mail actually sends from to this domain so blacklist status can be verified.",
        },
      ]
    }

    const findings: Finding[] = []
    let anyListed = false
    for (const ip of ips) {
      const reversed = reverseIpv4(ip)
      if (!reversed) continue // IPv6 blacklist queries are out of scope for the first round.
      for (const bl of BLOCKLISTS) {
        const query = `${reversed}.${bl.zone}`
        const res = await resolve4(query)
        if (res.records.length > 0) {
          anyListed = true
          findings.push({
            id: `blacklist.listed.${bl.zone}.${ip}`,
            checkId: "blacklist",
            title: `${ip} is listed on ${bl.name}`,
            severity: "critical",
            detail: `Sending IP ${ip} is on the ${bl.name} blocklist (${bl.zone} returned ${res.records.join(", ")}). Mail from this IP is being rejected or heavily filtered by receivers that consult this list.`,
            remediation: `Investigate the cause (compromised host, spam complaints, open relay), then request delisting at ${bl.delistUrl}. Confirm SPF/DKIM/DMARC are all passing before re-listing risk returns.`,
            evidence: query,
          })
        }
      }
    }

    if (!anyListed) {
      findings.push({
        id: "blacklist.clean",
        checkId: "blacklist",
        title: "Not on any checked blacklist",
        severity: "ok",
        detail: `Checked ${ips.length} IP(s) against ${BLOCKLISTS.length} blocklists — none listed.`,
        evidence: ips.join(", "),
      })
    }
    return findings
  },
}
