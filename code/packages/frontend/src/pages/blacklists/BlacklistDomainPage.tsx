import { useQueryClient } from "@tanstack/react-query"
import { Link, useParams } from "@tanstack/react-router"
import { ChevronDown, ChevronRight, ExternalLink, RefreshCw } from "lucide-react"
import { useMemo, useState } from "react"
import { useRunAudit } from "@/api/audit"
import { useBlacklistHistory, useBlacklistRun, useSetPortalState } from "@/api/blacklists"
import { useDomains } from "@/api/domains"
import type { BlacklistRunResults, BlacklistZoneResult, PortalUserState } from "@/api/types"
import { SeverityBadge } from "@/components/Badges"
import { cn } from "@/lib/utils"
import { problemState } from "@/lib/problemStates"

/**
 * The full Blacklists technology page (pm/checks/blacklists.mdx §13.2, layout §14): verdict band →
 * problems table (row-chevron opens the debug drawer with the exact query/answer/TXT/resolver/PTR
 * values) → fix panel → provider-portal checklist → the collapsed all-zones pass/fail matrix →
 * history strip. Severity decides vertical position; evidence hides one level down; ↗ leaves the
 * app, › goes deeper inside it.
 */

const RANK = { ok: 0, info: 1, warning: 2, critical: 3 } as const
const BAND: Record<string, string> = {
  critical: "bg-red-800 text-white",
  warning: "bg-amber-500 text-black",
  ok: "bg-green-800 text-white",
  info: "bg-green-800 text-white",
}

function TierChip({ tier }: { tier: string }) {
  return (
    <span className="rounded border border-current px-1 text-[10px] uppercase opacity-60">{tier}</span>
  )
}

function DebugDrawer({ run, row }: { run: BlacklistRunResults; row: BlacklistZoneResult }) {
  const ipTarget = run.targets.ips.find((t) => t.ip === row.target)
  const query =
    row.kind === "ip"
      ? `${row.target.split(".").reverse().join(".")}.${row.zone}`
      : `${row.target}.${row.zone}`
  const rows: Array<[string, string | null]> = [
    ["Query", query],
    ["Answer", row.return_code ?? (row.refusal_code ? `refused: ${row.refusal_code}` : "NXDOMAIN (clean)")],
    ["Sub-list", row.sub_list],
    ["TXT", row.reason_txt],
    ["Resolver", run.resolver.server ?? "system default"],
    ["Latency", `${row.query_ms} ms`],
    ["PTR", ipTarget ? (ipTarget.ptr ?? "none") : null],
    ["FCrDNS", ipTarget ? (ipTarget.fcrdns_ok === null ? "unknown" : ipTarget.fcrdns_ok ? "ok" : "FAILS") : null],
    ["ASN", ipTarget?.asn ? `AS${ipTarget.asn.number} — ${ipTarget.asn.org ?? "?"}` : null],
    ["Auto-expires", row.auto_expires],
  ]
  const ps = row.problem_state ? problemState(row.problem_state) : null
  return (
    <div className="rounded-md bg-slate-50 p-3">
      <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1 text-xs">
        {rows
          .filter(([, v]) => v !== null && v !== undefined)
          .map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-slate-500">{k}</dt>
              <dd
                className="break-all font-mono text-slate-800"
                onClick={() => navigator.clipboard?.writeText(String(v))}
                title="Click to copy"
              >
                {v}
              </dd>
            </div>
          ))}
      </dl>
      {ps && (
        <Link
          to="/blacklists/$domain/state/$psId"
          params={{ domain: run.domain, psId: ps.id }}
          className="mt-2 inline-flex items-center gap-1 text-sm font-medium text-[var(--edh-primary)]"
        >
          Explain &amp; fix this ({ps.id}: {ps.name}) <ChevronRight className="h-4 w-4" />
        </Link>
      )}
    </div>
  )
}

function ProblemsTable({ run }: { run: BlacklistRunResults }) {
  const [open, setOpen] = useState<string | null>(null)
  const problems = useMemo(
    () =>
      [...run.results.filter((r) => r.listed)].sort(
        (a, b) => RANK[b.severity ?? "info"] - RANK[a.severity ?? "info"] || a.zone.localeCompare(b.zone),
      ),
    [run.results],
  )
  const newKeys = new Set(run.diff.new_listings.map((n) => `${n.zone}|${n.target}`))
  if (problems.length === 0) return null

  return (
    <section className="mt-6">
      <h2 className="mb-2 font-semibold">Problems ({problems.length})</h2>
      <div className="overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
        {problems.map((r) => {
          const key = `${r.zone}|${r.target}`
          const expanded = open === key
          return (
            <div key={key} className="border-b border-[var(--edh-border)] last:border-b-0">
              <button
                type="button"
                onClick={() => setOpen(expanded ? null : key)}
                className="flex w-full items-center gap-3 px-3 py-3 text-left hover:bg-slate-50"
              >
                <SeverityBadge severity={r.severity ?? "warning"} />
                <span className="flex min-w-0 flex-1 items-center gap-2">
                  <span className="font-medium">{r.name}</span>
                  <TierChip tier={r.tier} />
                  <span className="truncate font-mono text-xs text-slate-600">{r.target}</span>
                  {r.sub_list && <span className="truncate text-xs text-slate-500">{r.sub_list}</span>}
                  {newKeys.has(key) && (
                    <span className="rounded bg-red-100 px-1.5 text-xs font-semibold text-red-800">NEW</span>
                  )}
                </span>
                <a
                  href={r.delist_url}
                  target="_blank"
                  rel="noreferrer"
                  onClick={(e) => e.stopPropagation()}
                  className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-medium hover:bg-slate-100"
                >
                  Delist <ExternalLink className="h-3 w-3" />
                </a>
                {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
              </button>
              {expanded && (
                <div className="px-3 pb-3">
                  <DebugDrawer run={run} row={r} />
                </div>
              )}
            </div>
          )
        })}
      </div>
    </section>
  )
}

function FixPanel({ run }: { run: BlacklistRunResults }) {
  const problems = run.results.filter((r) => r.listed)
  if (problems.length === 0) {
    // All-clean state: the fix panel becomes the prevention checklist (§15.3).
    return (
      <section className="mt-6 rounded-lg border border-[var(--edh-border)] bg-white p-4">
        <h2 className="mb-2 font-semibold">Stay clean</h2>
        <ol className="list-decimal space-y-1 pl-5 text-sm text-slate-700">
          <li>Keep FCrDNS valid on every sending IP and SPF/DKIM/DMARC green.</li>
          <li>
            Register at DNSWL (free positive signal)
            {run.positive_reputation.dnswl.listed ? " — done ✓" : ""}.
          </li>
          <li>Enroll in Google Postmaster Tools and Microsoft SNDS/JMRP (checklist below).</li>
          <li>Keep the scheduled re-check on so a new listing alerts within hours.</li>
          <li>Warm up new IPs/domains gradually with steady volume.</li>
        </ol>
      </section>
    )
  }
  const sorted = [...problems].sort(
    (a, b) => RANK[b.severity ?? "info"] - RANK[a.severity ?? "info"],
  )
  return (
    <section className="mt-6 rounded-lg border border-[var(--edh-border)] bg-white p-4">
      <h2 className="mb-2 font-semibold">How to fix — highest impact first</h2>
      <ol className="list-decimal space-y-2 pl-5 text-sm text-slate-700">
        {sorted.map((r) => (
          <li key={`${r.zone}|${r.target}`}>
            <span className="font-medium">
              {r.name} ({r.target})
            </span>
            : fix the root cause first, then request removal at{" "}
            <a href={r.delist_url} target="_blank" rel="noreferrer" className="text-[var(--edh-primary)] underline">
              {r.delist_url}
            </a>
            {r.auto_expires && <> — or wait it out (auto-expires {r.auto_expires})</>}
            {r.paid_delist_offered && (
              <span className="font-semibold text-red-700"> Never pay for "express" delisting (RFC 6471).</span>
            )}
            {r.tier === "low" && <span className="text-slate-500"> Low real-world impact at Gmail/Outlook/Yahoo.</span>}
          </li>
        ))}
      </ol>
    </section>
  )
}

const PORTAL_PILL: Record<PortalUserState, { label: string; cls: string; next: PortalUserState }> = {
  unverified: { label: "Unverified", cls: "bg-gray-100 text-gray-600", next: "verified_clean" },
  verified_clean: { label: "Clean", cls: "bg-emerald-100 text-emerald-800", next: "problem_reported" },
  problem_reported: { label: "Problem", cls: "bg-red-100 text-red-800", next: "unverified" },
}

function PortalsChecklist({ run }: { run: BlacklistRunResults }) {
  const setState = useSetPortalState(run.domain)
  return (
    <section className="mt-6 rounded-lg border border-[var(--edh-border)] bg-white p-4">
      <h2 className="mb-1 font-semibold">Provider reputation portals</h2>
      <p className="mb-3 text-xs text-[var(--edh-muted)]">
        The "invisible blacklists" — clean public zones ≠ clean at Gmail/Microsoft. Check each portal
        and mark its state (click the pill to cycle).
      </p>
      <ul className="space-y-1">
        {run.provider_portals.map((p) => {
          const pill = PORTAL_PILL[p.user_state]
          return (
            <li key={p.provider} className="flex items-center gap-3 text-sm">
              <span className="min-w-0 flex-1 truncate">{p.name}</span>
              <a
                href={p.check_url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-xs text-[var(--edh-primary)]"
              >
                Check <ExternalLink className="h-3 w-3" />
              </a>
              <button
                type="button"
                onClick={() => setState.mutate({ provider: p.provider, state: pill.next })}
                className={cn("rounded-full px-2 py-0.5 text-xs font-medium", pill.cls)}
                title="Click to cycle: Unverified → Clean → Problem"
              >
                {pill.label}
              </button>
            </li>
          )
        })}
      </ul>
    </section>
  )
}

function ZonesMatrix({ run }: { run: BlacklistRunResults }) {
  const allClean = run.summary.listed === 0
  const [show, setShow] = useState(allClean)
  const byZone = useMemo(() => {
    const map = new Map<string, BlacklistZoneResult[]>()
    for (const r of run.results) {
      const list = map.get(r.zone) ?? []
      list.push(r)
      map.set(r.zone, list)
    }
    const tierOrder = { high: 0, medium: 1, low: 2 } as const
    return [...map.entries()].sort(
      (a, b) => tierOrder[a[1][0].tier] - tierOrder[b[1][0].tier] || a[0].localeCompare(b[0]),
    )
  }, [run.results])

  return (
    <section className="mt-6">
      <button
        type="button"
        onClick={() => setShow(!show)}
        className="flex items-center gap-1 text-sm font-medium text-[var(--edh-primary)]"
      >
        {show ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        {show ? "Hide" : "Show"} all {byZone.length} zones (passed too)
      </button>
      {show && (
        <div className="mt-2 overflow-x-auto rounded-lg border border-[var(--edh-border)] bg-white">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--edh-border)] text-left text-xs uppercase text-slate-500">
                <th className="px-3 py-2">Zone</th>
                <th className="px-3 py-2">Tier</th>
                <th className="px-3 py-2">Targets</th>
              </tr>
            </thead>
            <tbody>
              {byZone.map(([zone, rows]) => (
                <tr key={zone} className="border-b border-[var(--edh-border)] last:border-b-0">
                  <td className="px-3 py-1.5 font-mono text-xs">{zone}</td>
                  <td className="px-3 py-1.5">
                    <TierChip tier={rows[0].tier} />
                  </td>
                  <td className="px-3 py-1.5">
                    <span className="flex flex-wrap gap-2">
                      {rows.map((r) => (
                        <span
                          key={r.target}
                          title={
                            r.inconclusive
                              ? `inconclusive${r.refusal_code ? ` (refused: ${r.refusal_code})` : ""}`
                              : r.listed
                                ? `listed: ${r.return_code}${r.sub_list ? ` = ${r.sub_list}` : ""}`
                                : "clean (NXDOMAIN)"
                          }
                          className={cn(
                            "inline-flex items-center gap-1 rounded px-1.5 font-mono text-xs",
                            r.inconclusive
                              ? "bg-gray-100 text-gray-500"
                              : r.listed
                                ? "bg-red-100 text-red-800"
                                : "bg-emerald-50 text-emerald-700",
                          )}
                        >
                          {r.inconclusive ? "?" : r.listed ? "✕" : "✓"} {r.target}
                        </span>
                      ))}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function HistoryStrip({ domain }: { domain: string }) {
  const { data: history } = useBlacklistHistory(domain)
  if (!history || history.length < 2) return null
  const max = Math.max(1, ...history.map((h) => h.listed))
  return (
    <section className="mt-6">
      <h2 className="mb-2 text-sm font-semibold text-slate-600">Listed count — last {history.length} runs</h2>
      <div className="flex h-12 items-end gap-1">
        {history.map((h) => (
          <div
            key={h.audit_id}
            title={`${new Date(h.ran_at).toLocaleString()}: ${h.listed} listed`}
            className={cn("w-3 rounded-t", h.listed > 0 ? "bg-red-600" : "bg-emerald-500")}
            style={{ height: `${Math.max(8, (h.listed / max) * 100)}%` }}
          />
        ))}
      </div>
    </section>
  )
}

export function BlacklistDomainPage() {
  const { domain } = useParams({ from: "/blacklists/$domain" as never }) as { domain: string }
  const { data: run, isLoading, isError } = useBlacklistRun(domain)
  const { data: domains } = useDomains()
  const runAudit = useRunAudit()
  const qc = useQueryClient()

  const domainRecord = domains?.find((d) => d.name === domain)
  const recheck = async () => {
    if (!domainRecord) return
    await runAudit.mutateAsync(domainRecord.id)
    await qc.invalidateQueries({ queryKey: ["blacklists"] })
  }

  if (isLoading) return <p className="text-sm text-[var(--edh-muted)]">Loading…</p>
  if (isError || !run) {
    return (
      <div className="mx-auto max-w-4xl">
        <h1 className="mb-2 text-2xl font-bold">Blacklists — {domain}</h1>
        <p className="rounded-lg border border-dashed border-[var(--edh-border)] p-8 text-center text-[var(--edh-muted)]">
          Never run for this domain.
          {domainRecord && (
            <button
              type="button"
              onClick={recheck}
              className="ml-2 rounded-md bg-[var(--edh-primary)] px-3 py-1 text-sm font-medium text-white"
            >
              Run blacklist check
            </button>
          )}
        </p>
      </div>
    )
  }

  const band = BAND[run.summary.worst_severity] ?? BAND.ok
  const allHighInconclusive =
    run.results.filter((r) => r.tier === "high").length > 0 &&
    run.results.filter((r) => r.tier === "high").every((r) => r.inconclusive)

  return (
    <div className="mx-auto max-w-[1100px]">
      <Link to="/blacklists" className="text-sm text-[var(--edh-primary)]">
        ← All domains
      </Link>

      {/* 1. Verdict band — the answer to "am I in trouble?" in the first 100px (§14). */}
      <div className={cn("mt-2 rounded-xl p-5", band)}>
        <div className="flex items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-bold">Blacklists — {run.domain}</h1>
            <p className="mt-1 text-sm">
              <span className="font-semibold">{run.summary.listed} listed</span> · {run.summary.clean} clean ·{" "}
              {run.summary.inconclusive} unknown across {run.summary.zones_enabled} zones
              <span className="ml-2 opacity-75">{new Date(run.ran_at).toLocaleString()}</span>
            </p>
            {(run.diff.new_listings.length > 0 || run.diff.cleared.length > 0) && (
              <p className="mt-1 text-sm font-semibold">
                {run.diff.new_listings.length > 0 && <>▲ {run.diff.new_listings.length} new </>}
                {run.diff.cleared.length > 0 && <>▼ {run.diff.cleared.length} resolved</>}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={recheck}
            disabled={runAudit.isPending || !domainRecord}
            className="inline-flex shrink-0 items-center gap-2 rounded-md bg-white/20 px-3 py-2 text-sm font-medium backdrop-blur hover:bg-white/30 disabled:opacity-50"
          >
            <RefreshCw className={cn("h-4 w-4", runAudit.isPending && "animate-spin")} />
            Re-check now
          </button>
        </div>
      </div>

      {(run.resolver.refusals_detected || allHighInconclusive) && (
        <div className="mt-3 rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900">
          Some blocklists refused our DNS queries — results are partially inconclusive. This says
          nothing bad about your domain.{" "}
          <Link
            to="/blacklists/$domain/state/$psId"
            params={{ domain: run.domain, psId: "PS-9" }}
            className="font-medium underline"
          >
            Why, and how to fix it →
          </Link>
        </div>
      )}

      {/* 2. Problems table → 3. Fix panel → 4. Portals → 5. Matrix → 6. History (§14 order). */}
      <ProblemsTable run={run} />
      <FixPanel run={run} />
      <PortalsChecklist run={run} />
      <ZonesMatrix run={run} />
      <HistoryStrip domain={run.domain} />
    </div>
  )
}
