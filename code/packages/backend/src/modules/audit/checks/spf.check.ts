import { resolveTxt } from "./dns-util"
import type { Checker, Finding } from "./types"

/**
 * SPF (Sender Policy Framework). Looks up the domain's TXT records for a single `v=spf1` record and
 * inspects its terminating "all" mechanism. Multiple SPF records, or a missing one, are the two most
 * common causes of soft spam-foldering.
 */
export const spfCheck: Checker = {
  id: "spf",
  label: "SPF record",
  async run(ctx): Promise<Finding[]> {
    const { records, error } = await resolveTxt(ctx.domain)
    if (error) {
      return [
        {
          id: "spf.lookup_failed",
          checkId: "spf",
          title: "Could not look up SPF",
          severity: "warning",
          detail: `DNS lookup for TXT ${ctx.domain} failed (${error}).`,
          remediation:
            "Retry the audit. If it persists, check the domain's authoritative nameservers.",
        },
      ]
    }

    const spf = records.filter((r) => r.toLowerCase().startsWith("v=spf1"))
    if (spf.length === 0) {
      return [
        {
          id: "spf.missing",
          checkId: "spf",
          title: "No SPF record",
          severity: "critical",
          detail: `${ctx.domain} has no v=spf1 TXT record. Receivers cannot verify which servers may send for this domain, so mail is likely to be spam-foldered or rejected.`,
          remediation:
            'Publish a TXT record at the root domain, e.g. "v=spf1 include:_spf.google.com ~all" (adjust the include: to your sending provider). Use "-all" once you are confident every legitimate source is listed.',
        },
      ]
    }

    if (spf.length > 1) {
      return [
        {
          id: "spf.multiple",
          checkId: "spf",
          title: "Multiple SPF records",
          severity: "critical",
          detail: `${ctx.domain} publishes ${spf.length} v=spf1 records. Per RFC 7208 this is a permerror and receivers will ignore SPF entirely.`,
          remediation:
            "Merge the SPF records into a single TXT record with one v=spf1 and one terminating all mechanism.",
          evidence: spf.join(" | "),
        },
      ]
    }

    const record = spf[0]
    const all = /([~\-+?])all\b/.exec(record.toLowerCase())
    const findings: Finding[] = []
    if (!all) {
      findings.push({
        id: "spf.no_all",
        checkId: "spf",
        title: "SPF has no 'all' mechanism",
        severity: "warning",
        detail:
          "The SPF record does not end in an 'all' mechanism, so receivers have no default policy for unlisted senders.",
        remediation: 'Append "~all" (softfail) or "-all" (hardfail) to the end of the SPF record.',
        evidence: record,
      })
    } else if (all[1] === "+") {
      findings.push({
        id: "spf.pass_all",
        checkId: "spf",
        title: "SPF ends in '+all' (allows anyone)",
        severity: "critical",
        detail:
          "'+all' authorizes ANY server to send for this domain — effectively no SPF protection at all.",
        remediation: 'Change "+all" to "~all" (softfail) or "-all" (hardfail).',
        evidence: record,
      })
    } else {
      findings.push({
        id: "spf.ok",
        checkId: "spf",
        title: "SPF record present",
        severity: "ok",
        detail: `Found a single valid SPF record ending in "${all[1]}all".`,
        evidence: record,
      })
    }
    return findings
  },
}
