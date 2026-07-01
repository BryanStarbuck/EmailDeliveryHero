import { useAuditResults } from "@/api/audit"
import { FindingsList } from "@/components/FindingsList"

/**
 * Blacklist-focused view: pulls just the blacklist-check findings out of every domain's latest
 * audit so the user can see, in one place, which sending IPs are listed and how to get delisted.
 */
export function BlacklistsPage() {
  const { data: results } = useAuditResults()

  const perDomain = (results ?? [])
    .map((r) => ({
      domain: r.domain,
      findings: r.findings.filter((f) => f.checkId === "blacklist"),
    }))
    .filter((d) => d.findings.length > 0)

  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="mb-1 text-2xl font-bold">Blacklists</h1>
      <p className="mb-6 text-sm text-[var(--edh-muted)]">
        DNS blacklist (DNSBL) status for your sending IPs, with delisting steps.
      </p>

      {perDomain.length === 0 ? (
        <p className="rounded-lg border border-dashed border-[var(--edh-border)] p-8 text-center text-[var(--edh-muted)]">
          No blacklist results yet — run an audit from the Audits page.
        </p>
      ) : (
        <div className="space-y-6">
          {perDomain.map((d) => (
            <section key={d.domain}>
              <h2 className="mb-2 font-semibold">{d.domain}</h2>
              <FindingsList findings={d.findings} />
            </section>
          ))}
        </div>
      )}
    </div>
  )
}
