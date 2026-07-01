import type { Checker, Finding } from "./types"
import { resolveTxt } from "./dns-util"

/**
 * DKIM. For each configured selector, looks up `<selector>._domainkey.<domain>` and confirms a
 * public key (v=DKIM1; p=…) is published. Because selectors are provider-specific and cannot be
 * discovered from DNS alone, the domain record supplies the selectors to probe (e.g. "google" for
 * Google Workspace). With no selectors configured we emit an informational nudge rather than a
 * failure.
 */
export const dkimCheck: Checker = {
  id: "dkim",
  label: "DKIM keys",
  async run(ctx): Promise<Finding[]> {
    if (ctx.dkimSelectors.length === 0) {
      return [
        {
          id: "dkim.no_selectors",
          checkId: "dkim",
          title: "No DKIM selectors configured",
          severity: "info",
          detail: "DKIM selectors are provider-specific and cannot be auto-discovered. No selectors were provided for this domain, so DKIM was not verified.",
          remediation:
            'Add your sending provider\'s selector(s) to the domain (e.g. "google" for Google Workspace, "s1"/"s2" for many ESPs) so DKIM can be checked.',
        },
      ]
    }

    const findings: Finding[] = []
    for (const selector of ctx.dkimSelectors) {
      const name = `${selector}._domainkey.${ctx.domain}`
      const { records, error } = await resolveTxt(name)
      if (error) {
        findings.push({
          id: `dkim.lookup_failed.${selector}`,
          checkId: "dkim",
          title: `Could not look up DKIM selector "${selector}"`,
          severity: "warning",
          detail: `DNS lookup for TXT ${name} failed (${error}).`,
          remediation: "Retry the audit; if it persists, verify the selector name with your email provider.",
        })
        continue
      }
      const key = records.find((r) => /(^|;)\s*v\s*=\s*dkim1/i.test(r) || /\bp\s*=\s*[A-Za-z0-9+/]/.test(r))
      if (!key) {
        findings.push({
          id: `dkim.missing.${selector}`,
          checkId: "dkim",
          title: `DKIM selector "${selector}" not found`,
          severity: "critical",
          detail: `No DKIM public key is published at ${name}. Mail signed with this selector will fail DKIM, hurting deliverability.`,
          remediation: `Publish the DKIM TXT record your provider gives you at ${name}, or correct the selector name.`,
        })
        continue
      }
      const empty = /\bp\s*=\s*(;|$)/.test(key)
      if (empty) {
        findings.push({
          id: `dkim.revoked.${selector}`,
          checkId: "dkim",
          title: `DKIM selector "${selector}" has an empty key (revoked)`,
          severity: "critical",
          detail: "The DKIM record has an empty p= value, which signals a revoked key. Signatures will fail.",
          remediation: `Republish a valid public key at ${name}.`,
          evidence: key,
        })
        continue
      }
      findings.push({
        id: `dkim.ok.${selector}`,
        checkId: "dkim",
        title: `DKIM selector "${selector}" present`,
        severity: "ok",
        detail: `A DKIM public key is published at ${name}.`,
        evidence: key.slice(0, 80) + (key.length > 80 ? "…" : ""),
      })
    }
    return findings
  },
}
