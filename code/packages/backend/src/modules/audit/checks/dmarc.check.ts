import { resolveTxt } from "./dns-util"
import type { Checker, Finding } from "./types"

/**
 * DMARC. Looks up the `_dmarc.<domain>` TXT record and inspects the policy (`p=`). A missing DMARC
 * record, or `p=none`, means receivers get no instruction on what to do with mail that fails SPF and
 * DKIM — the single biggest lever for both deliverability and anti-spoofing.
 */
export const dmarcCheck: Checker = {
  id: "dmarc",
  label: "DMARC record",
  async run(ctx): Promise<Finding[]> {
    const name = `_dmarc.${ctx.domain}`
    const { records, error } = await resolveTxt(name)
    if (error) {
      return [
        {
          id: "dmarc.lookup_failed",
          checkId: "dmarc",
          title: "Could not look up DMARC",
          severity: "warning",
          detail: `DNS lookup for TXT ${name} failed (${error}).`,
          remediation:
            "Retry the audit; if it persists, verify the domain's nameservers respond for _dmarc.",
        },
      ]
    }

    const dmarc = records.filter((r) => r.toLowerCase().startsWith("v=dmarc1"))
    if (dmarc.length === 0) {
      return [
        {
          id: "dmarc.missing",
          checkId: "dmarc",
          title: "No DMARC record",
          severity: "critical",
          detail: `${name} has no v=DMARC1 record. Without DMARC, spoofed mail from your domain is not rejected and major providers increasingly penalize deliverability.`,
          remediation:
            "Publish a TXT record at _dmarc." +
            ctx.domain +
            ' — start with "v=DMARC1; p=none; rua=mailto:dmarc@' +
            ctx.domain +
            '" to collect reports, then move to p=quarantine and finally p=reject.',
        },
      ]
    }

    if (dmarc.length > 1) {
      return [
        {
          id: "dmarc.multiple",
          checkId: "dmarc",
          title: "Multiple DMARC records",
          severity: "warning",
          detail:
            "More than one DMARC record is published; receivers will treat this as no DMARC policy.",
          remediation: "Keep exactly one v=DMARC1 TXT record at _dmarc.",
          evidence: dmarc.join(" | "),
        },
      ]
    }

    const record = dmarc[0]
    const policy = /\bp\s*=\s*(none|quarantine|reject)\b/i.exec(record)?.[1]?.toLowerCase()
    if (policy === "none") {
      return [
        {
          id: "dmarc.p_none",
          checkId: "dmarc",
          title: "DMARC policy is p=none",
          severity: "warning",
          detail:
            "p=none only monitors — it does not tell receivers to quarantine or reject failing mail, so spoofing is not blocked.",
          remediation:
            "Once your aggregate (rua) reports look clean, tighten the policy to p=quarantine, then p=reject.",
          evidence: record,
        },
      ]
    }
    if (!policy) {
      return [
        {
          id: "dmarc.no_policy",
          checkId: "dmarc",
          title: "DMARC record has no p= tag",
          severity: "warning",
          detail: "The DMARC record is missing a policy (p=) tag, so it has no effect.",
          remediation: 'Add a policy tag, e.g. "; p=quarantine".',
          evidence: record,
        },
      ]
    }
    return [
      {
        id: "dmarc.ok",
        checkId: "dmarc",
        title: `DMARC enforced (p=${policy})`,
        severity: "ok",
        detail: `A DMARC policy of p=${policy} is published.`,
        evidence: record,
      },
    ]
  },
}
