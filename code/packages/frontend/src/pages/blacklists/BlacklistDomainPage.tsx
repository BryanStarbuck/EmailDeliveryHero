import { useQueryClient } from "@tanstack/react-query"
import { Link, Navigate, useNavigate, useParams } from "@tanstack/react-router"
import { ChevronDown, ChevronLeft, ChevronRight, ExternalLink, RefreshCw } from "lucide-react"
import { useMemo, useState } from "react"
import { useAuditRun, useAuditRuns, useRunAudit } from "@/api/audit"
import { useBlacklistRun, useSetPortalState } from "@/api/blacklists"
import { useDomains } from "@/api/domains"
import type {
  AuditResult,
  BlacklistRunResults,
  BlacklistZoneResult,
  PortalUserState,
} from "@/api/types"
import { problemState } from "@/lib/problemStates"
import { cn } from "@/lib/utils"

/**
 * The run-scoped Blacklists technology page (pm/checks/blacklists.mdx §13.2, layout §14).
 * Routes: /domains/$id/runs/$runId/blacklists (one run), newest alias /domains/$id/blacklists,
 * and the left-bar shorthand /blacklists/$domain which redirects into the alias (§17).
 * Fixed §14 vertical order: run header (back ‹, prev/next run stepping, Re-run) → verdict band →
 * listings matrix (zones × targets, HIGH tier always visible) → sub-test results table (every pass
 * and fail, sorted fail → warn → info → pass, row accordion = debug drawer with the verbatim
 * tool_runs command) → fix panel → provider portals → history sparkline (points navigate to runs).
 */

const RANK = { ok: 0, info: 1, warning: 2, critical: 3 } as const
const BAND: Record<string, string> = {
  critical: "bg-red-800 text-white",
  warning: "bg-amber-500 text-black",
  ok: "bg-green-800 text-white",
  info: "bg-green-800 text-white",
}

/** Stable per-zone sub-test id — mirrors the backend's tests[].id derivation (§12). */
function subTestId(zone: string): string {
  return `dnsbl.${zone.toLowerCase().replace(/[^a-z0-9]+/g, "_")}`
}

function rowKey(r: BlacklistZoneResult): string {
  return `${r.zone}|${r.kind}|${r.target}`
}

function rowDomId(r: BlacklistZoneResult): string {
  return `subtest-${rowKey(r).replace(/[^a-zA-Z0-9_-]/g, "_")}`
}

function queryNameOf(r: BlacklistZoneResult): string {
  return r.kind === "ip"
    ? `${r.target.split(".").reverse().join(".")}.${r.zone}`
    : `${r.target}.${r.zone}`
}

/** fail → warn → info → pass ordering for the sub-test table (§14, never alphabetical). */
function testRank(r: BlacklistZoneResult): number {
  if (r.listed) {
    if (r.severity === "critical") return 0
    if (r.severity === "warning") return 1
    return 2
  }
  if (r.inconclusive) return 2
  return 3
}

const TEST_ICON = ["✗", "⚠", "ⓘ", "✓"] as const
const TEST_ICON_CLS = [
  "text-red-700",
  "text-amber-600",
  "text-slate-500",
  "text-emerald-700",
] as const

function DebugDrawer({
  run,
  row,
  linkParams,
}: {
  run: BlacklistRunResults
  row: BlacklistZoneResult
  linkParams: { domain: string }
}) {
  const ipTarget = run.targets.ips.find((t) => t.ip === row.target)
  const query = queryNameOf(row)
  // The verbatim §12 tool_runs[].command that produced this row (the sweep phase includes the
  // row's query name in its replayable call expression).
  const command = run.tool_runs?.find((t) => t.command.includes(query))?.command ?? null
  const rows: Array<[string, string | null]> = [
    ["Query", query],
    [
      "Answer",
      row.return_code ?? (row.refusal_code ? `refused: ${row.refusal_code}` : "NXDOMAIN (clean)"),
    ],
    ["Sub-list", row.sub_list],
    ["TXT", row.reason_txt],
    ["Resolver", run.resolver.server ?? "system default"],
    ["Latency", `${row.query_ms} ms`],
    ["PTR", ipTarget ? (ipTarget.ptr ?? "none") : null],
    [
      "FCrDNS",
      ipTarget
        ? ipTarget.fcrdns_ok === null
          ? "unknown"
          : ipTarget.fcrdns_ok
            ? "ok"
            : "FAILS"
        : null,
    ],
    ["ASN", ipTarget?.asn ? `AS${ipTarget.asn.number} — ${ipTarget.asn.org ?? "?"}` : null],
    [
      "Target source",
      ipTarget
        ? ipTarget.source === "email_report"
          ? "via DMARC reports (§19 — observed sending as this domain)"
          : ipTarget.source
        : null,
    ],
    ["Auto-expires", row.auto_expires],
    ["Command", command],
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
              <dd className="break-all font-mono text-slate-800">
                <button
                  type="button"
                  className="text-left"
                  onClick={() => navigator.clipboard?.writeText(String(v))}
                  title="Click to copy"
                >
                  {k === "Command" && v && v.length > 160 ? `${v.slice(0, 160)}…` : v}
                </button>
              </dd>
            </div>
          ))}
      </dl>
      {row.listed && (
        <p className="mt-2 text-xs text-slate-700">
          <span className="font-semibold">Delisting steps:</span> ① fix the root cause first (a
          delist request with the cause live gets re-listed) ② request removal at{" "}
          <a
            href={row.delist_url}
            target="_blank"
            rel="noreferrer"
            className="text-[var(--edh-primary)] underline"
          >
            {row.delist_url}
          </a>
          {row.auto_expires && <> — or wait it out (auto-expires {row.auto_expires})</>}
          {row.paid_delist_offered && (
            <span className="font-semibold text-red-700">
              {" "}
              Never pay for "express" delisting (RFC 6471).
            </span>
          )}
        </p>
      )}
      {ps && (
        <Link
          to="/blacklists/$domain/state/$psId"
          params={{ domain: linkParams.domain, psId: ps.id }}
          className="mt-2 inline-flex items-center gap-1 text-sm font-medium text-[var(--edh-primary)]"
        >
          Explain &amp; fix this ({ps.id}: {ps.name}) <ChevronRight className="h-4 w-4" />
        </Link>
      )}
    </div>
  )
}

/**
 * §14.3 the listings matrix — zones (rows) × targets (columns). HIGH tier always visible,
 * MEDIUM/LOW behind "Show all N zones ▸" (expanded by default only when all clean). A cell click
 * jumps to (and expands) that pair's sub-test row.
 */
function ListingsMatrix({
  run,
  onCell,
}: {
  run: BlacklistRunResults
  onCell: (r: BlacklistZoneResult) => void
}) {
  const allClean = run.summary.listed === 0
  const [showAll, setShowAll] = useState(allClean)
  const ipCols = run.targets.ips
  const domainCols = run.targets.domains
  const byPair = useMemo(() => {
    const map = new Map<string, BlacklistZoneResult>()
    for (const r of run.results) map.set(`${r.zone}|${r.target}`, r)
    return map
  }, [run.results])
  const zones = useMemo(() => {
    const tierOrder = { high: 0, medium: 1, low: 2 } as const
    const seen = new Map<string, (typeof run.results)[number]>()
    for (const r of run.results) if (!seen.has(r.zone)) seen.set(r.zone, r)
    return [...seen.values()].sort(
      (a, b) => tierOrder[a.tier] - tierOrder[b.tier] || a.zone.localeCompare(b.zone),
    )
  }, [run.results])
  const visible = showAll ? zones : zones.filter((z) => z.tier === "high")

  const cell = (zone: string, target: string) => {
    const r = byPair.get(`${zone}|${target}`)
    if (!r) return <span className="text-slate-300">—</span>
    const label = r.inconclusive ? "?" : r.listed ? `✕ ${r.return_code ?? ""}` : "✓"
    return (
      <button
        type="button"
        onClick={() => onCell(r)}
        title={
          r.inconclusive
            ? `inconclusive${r.refusal_code ? ` (refused: ${r.refusal_code})` : ""}`
            : r.listed
              ? `listed: ${r.return_code}${r.sub_list ? ` = ${r.sub_list}` : ""}`
              : "clean (NXDOMAIN)"
        }
        className={cn(
          "rounded px-1.5 font-mono text-xs",
          r.inconclusive
            ? "bg-gray-100 text-gray-500"
            : r.listed
              ? "bg-red-100 font-semibold text-red-800"
              : "text-emerald-700",
        )}
      >
        {label}
      </button>
    )
  }

  return (
    <section className="mt-6">
      <h2 className="mb-2 font-semibold">
        Listings matrix{" "}
        <span className="text-xs font-normal text-[var(--edh-muted)]">zones × targets</span>
      </h2>
      <div className="overflow-x-auto rounded-lg border border-[var(--edh-border)] bg-white">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--edh-border)] text-left text-xs text-slate-500">
              <th className="sticky left-0 bg-white px-3 py-2 font-medium">Zone</th>
              {ipCols.map((t) => (
                <th key={t.ip} className="px-3 py-2 font-mono font-normal">
                  {t.ip}
                  {t.source === "email_report" && (
                    <span className="ml-1 rounded bg-sky-100 px-1 text-[10px] font-sans text-sky-800">
                      via DMARC reports
                    </span>
                  )}
                </th>
              ))}
              {domainCols.map((t) => (
                <th key={t.domain} className="px-3 py-2 font-mono font-normal">
                  {t.domain}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map((z) => (
              <tr key={z.zone} className="border-b border-[var(--edh-border)] last:border-b-0">
                <td className="sticky left-0 bg-white px-3 py-1.5 font-mono text-xs">
                  {z.zone}{" "}
                  <span className="rounded border border-slate-200 px-1 font-sans text-[10px] uppercase text-slate-400">
                    {z.tier}
                  </span>
                </td>
                {ipCols.map((t) => (
                  <td key={t.ip} className="px-3 py-1.5">
                    {cell(z.zone, t.ip)}
                  </td>
                ))}
                {domainCols.map((t) => (
                  <td key={t.domain} className="px-3 py-1.5">
                    {cell(z.zone, t.domain)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-1 flex items-center justify-between text-xs text-[var(--edh-muted)]">
        {zones.length > visible.length || showAll ? (
          <button
            type="button"
            onClick={() => setShowAll(!showAll)}
            className="font-medium text-[var(--edh-primary)]"
          >
            {showAll ? "Show HIGH tier only" : `Show all ${zones.length} zones ▸`}
          </button>
        ) : (
          <span />
        )}
        <span>✓ clean · ✕ listed · ? timeout/refused</span>
      </div>
    </section>
  )
}

/** §14.4 the sub-test results table — one row per zone check, every pass and fail of the run. */
function SubTestTable({
  run,
  open,
  setOpen,
  linkParams,
}: {
  run: BlacklistRunResults
  open: string | null
  setOpen: (key: string | null) => void
  linkParams: { domain: string }
}) {
  const sorted = useMemo(
    () =>
      [...run.results].sort(
        (a, b) =>
          testRank(a) - testRank(b) ||
          RANK[b.severity ?? "info"] - RANK[a.severity ?? "info"] ||
          a.zone.localeCompare(b.zone),
      ),
    [run.results],
  )
  const failed = sorted.filter((r) => r.listed).length
  const newKeys = new Set(run.diff.new_listings.map((n) => `${n.zone}|${n.target}`))

  return (
    <section className="mt-6">
      <h2 className="mb-2 font-semibold">
        Sub-test results{" "}
        <span className="text-xs font-normal text-[var(--edh-muted)]">
          {failed} listed · {sorted.length - failed} other checks
        </span>
      </h2>
      <div className="overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
        {sorted.map((r) => {
          const key = rowKey(r)
          const expanded = open === key
          const rank = testRank(r)
          return (
            <div
              key={key}
              id={rowDomId(r)}
              className="border-b border-[var(--edh-border)] last:border-b-0"
            >
              <button
                type="button"
                onClick={() => setOpen(expanded ? null : key)}
                className="flex w-full items-center gap-3 px-3 py-2.5 text-left hover:bg-slate-50"
              >
                <span className={cn("w-4 shrink-0 text-center font-bold", TEST_ICON_CLS[rank])}>
                  {TEST_ICON[rank]}
                </span>
                <span className="flex min-w-0 flex-1 items-center gap-2">
                  <span className="shrink-0 font-mono text-xs text-slate-500">
                    {subTestId(r.zone)}
                  </span>
                  <span className="truncate font-mono text-xs text-slate-600">{r.target}</span>
                  <span className="truncate text-xs">
                    {r.inconclusive
                      ? r.refusal_code
                        ? `refused ${r.refusal_code}`
                        : "inconclusive"
                      : r.listed
                        ? `${r.return_code ?? "listed"}${r.sub_list ? ` "${r.sub_list}"` : ""}`
                        : "NXDOMAIN"}
                  </span>
                  {newKeys.has(`${r.zone}|${r.target}`) && (
                    <span className="rounded bg-red-100 px-1.5 text-xs font-semibold text-red-800">
                      NEW
                    </span>
                  )}
                </span>
                {r.listed && (
                  <a
                    href={r.delist_url}
                    target="_blank"
                    rel="noreferrer"
                    onClick={(e) => e.stopPropagation()}
                    className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-medium hover:bg-slate-100"
                  >
                    Delist <ExternalLink className="h-3 w-3" />
                  </a>
                )}
                {expanded ? (
                  <ChevronDown className="h-4 w-4 shrink-0" />
                ) : (
                  <ChevronRight className="h-4 w-4 shrink-0" />
                )}
              </button>
              {expanded && (
                <div className="px-3 pb-3">
                  <DebugDrawer run={run} row={r} linkParams={linkParams} />
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
            <a
              href={r.delist_url}
              target="_blank"
              rel="noreferrer"
              className="text-[var(--edh-primary)] underline"
            >
              {r.delist_url}
            </a>
            {r.auto_expires && <> — or wait it out (auto-expires {r.auto_expires})</>}
            {r.paid_delist_offered && (
              <span className="font-semibold text-red-700">
                {" "}
                Never pay for "express" delisting (RFC 6471).
              </span>
            )}
            {r.tier === "low" && (
              <span className="text-slate-500"> Low real-world impact at Gmail/Outlook/Yahoo.</span>
            )}
          </li>
        ))}
      </ol>
    </section>
  )
}

const PORTAL_PILL: Record<PortalUserState, { label: string; cls: string; next: PortalUserState }> =
  {
    unverified: { label: "Unverified", cls: "bg-gray-100 text-gray-600", next: "verified_clean" },
    verified_clean: {
      label: "Clean",
      cls: "bg-emerald-100 text-emerald-800",
      next: "problem_reported",
    },
    problem_reported: { label: "Problem", cls: "bg-red-100 text-red-800", next: "unverified" },
  }

function PortalsChecklist({ run }: { run: BlacklistRunResults }) {
  const setState = useSetPortalState(run.domain)
  return (
    <section className="mt-6 rounded-lg border border-[var(--edh-border)] bg-white p-4">
      <h2 className="mb-1 font-semibold">Provider reputation portals</h2>
      <p className="mb-3 text-xs text-[var(--edh-muted)]">
        The "invisible blacklists" — clean public zones ≠ clean at Gmail/Microsoft. Check each
        portal and mark its state (click the pill to cycle).
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

/** §14.8 history strip — clicking a point navigates to that run's page. */
function HistoryStrip({ domainId, runs }: { domainId: string; runs: AuditResult[] }) {
  if (runs.length < 2) return null
  const chronological = [...runs]
    .filter((r) => r.runId)
    .reverse()
    .slice(-30)
  const max = Math.max(1, ...chronological.map((r) => r.results?.blacklist?.summary.listed ?? 0))
  return (
    <section className="mt-6">
      <h2 className="mb-2 text-sm font-semibold text-slate-600">
        Listed count — last {chronological.length} runs (click a point to open that run)
      </h2>
      <div className="flex h-12 items-end gap-1">
        {chronological.map((r) => {
          const listed = r.results?.blacklist?.summary.listed ?? 0
          return (
            <Link
              key={r.runId ?? r.ranAt}
              to="/domains/$id/runs/$runId/blacklists"
              params={{ id: domainId, runId: r.runId ?? "" }}
              title={`${new Date(r.ranAt).toLocaleString()}: ${listed} listed`}
              className={cn("w-3 rounded-t", listed > 0 ? "bg-red-600" : "bg-emerald-500")}
              style={{ height: `${Math.max(8, (listed / max) * 100)}%` }}
            />
          )
        })}
      </div>
    </section>
  )
}

/** Route component: resolves the shorthand/alias/run-scoped params, then renders the run view. */
export function BlacklistDomainPage() {
  const params = useParams({ strict: false }) as { domain?: string; id?: string; runId?: string }
  const { data: domains } = useDomains()

  if (domains === undefined) {
    return <p className="text-sm text-[var(--edh-muted)]">Loading…</p>
  }

  // §17: /blacklists/:domain is a redirect shorthand into the newest-run alias.
  if (params.domain) {
    const record = domains.find((d) => d.name === params.domain)
    if (record) return <Navigate to="/domains/$id/blacklists" params={{ id: record.id }} replace />
    // Domain not (or no longer) monitored — render by name so persisted runs stay reachable.
    return <BlacklistRunView domainName={params.domain} domainId={null} runId={undefined} />
  }
  const record = domains.find((d) => d.id === params.id)
  return (
    <BlacklistRunView
      domainName={record?.name ?? null}
      domainId={params.id ?? null}
      runId={params.runId}
    />
  )
}

function BlacklistRunView({
  domainName,
  domainId,
  runId,
}: {
  domainName: string | null
  domainId: string | null
  runId: string | undefined
}) {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const runAudit = useRunAudit()
  const [open, setOpen] = useState<string | null>(null)

  // Newest-run alias reads the store's latest doc; a run-scoped view reads that run's report.
  const latest = useBlacklistRun(domainName ?? "", !runId)
  const { data: auditRun, isLoading: runLoading } = useAuditRun(runId)
  const { data: allRuns } = useAuditRuns()

  // This domain's runs that carry a Blacklists section, newest first — prev/next stepping (§13.2).
  const domainRuns = useMemo(
    () =>
      (allRuns ?? []).filter(
        (r) =>
          (domainId ? r.domainId === domainId : r.domain === domainName) && r.results?.blacklist,
      ),
    [allRuns, domainId, domainName],
  )
  const currentIndex = runId ? domainRuns.findIndex((r) => r.runId === runId) : 0
  const newestRun = domainRuns[0]
  const olderRun = currentIndex >= 0 ? domainRuns[currentIndex + 1] : undefined
  const newerRun = currentIndex > 0 ? domainRuns[currentIndex - 1] : undefined
  const isHistorical = Boolean(runId && newestRun?.runId && runId !== newestRun.runId)

  const run: BlacklistRunResults | undefined = runId ? auditRun?.results?.blacklist : latest.data
  const isLoading = runId ? runLoading : latest.isLoading

  const name = domainName ?? run?.domain ?? "…"
  const recheck = async () => {
    if (!domainId) return
    // §13.2: [Re-run ⟳] starts a NEW run (never mutates the viewed one) and navigates to it.
    await runAudit.mutateAsync(domainId)
    await qc.invalidateQueries({ queryKey: ["blacklists"] })
    await qc.invalidateQueries({ queryKey: ["audit"] })
    navigate({ to: "/domains/$id/blacklists", params: { id: domainId } })
  }

  // Back chevron ‹ — to this run's report (§14.1), or the newest run report on the alias route.
  const backLink = domainId ? (
    runId ? (
      <Link
        to="/domains/$id/runs/$runId"
        params={{ id: domainId, runId }}
        className="text-sm text-[var(--edh-primary)]"
      >
        ‹ Back to run report
      </Link>
    ) : (
      <Link
        to="/domains/$id"
        params={{ id: domainId }}
        className="text-sm text-[var(--edh-primary)]"
      >
        ‹ Back to run report
      </Link>
    )
  ) : (
    <Link to="/blacklists" className="text-sm text-[var(--edh-primary)]">
      ‹ Back to Blacklists
    </Link>
  )

  const openAndScroll = (r: BlacklistZoneResult) => {
    setOpen(rowKey(r))
    document.getElementById(rowDomId(r))?.scrollIntoView({ behavior: "smooth", block: "center" })
  }

  if (isLoading) return <p className="text-sm text-[var(--edh-muted)]">Loading…</p>

  if (runId && !run) {
    return (
      <div className="mx-auto max-w-4xl">
        <h1 className="mb-2 text-2xl font-bold">Blacklists — {name}</h1>
        <p className="rounded-lg border border-dashed border-[var(--edh-border)] p-8 text-center text-[var(--edh-muted)]">
          Run not found — it may have been pruned or carries no Blacklists section.
          {domainId && (
            <Link
              to="/domains/$id/blacklists"
              params={{ id: domainId }}
              className="ml-2 font-medium text-[var(--edh-primary)] underline"
            >
              Open the newest run →
            </Link>
          )}
        </p>
      </div>
    )
  }

  if (!run) {
    return (
      <div className="mx-auto max-w-4xl">
        <h1 className="mb-2 text-2xl font-bold">Blacklists — {name}</h1>
        <p className="rounded-lg border border-dashed border-[var(--edh-border)] p-8 text-center text-[var(--edh-muted)]">
          No runs yet — run a check to query the blocklist zones.
          {domainId && (
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

  const status = run.status ?? run.summary.worst_severity
  const band = BAND[status] ?? BAND.ok
  const highRows = run.results.filter((r) => r.tier === "high")
  const allHighInconclusive = highRows.length > 0 && highRows.every((r) => r.inconclusive)
  const worstListing = [...run.results.filter((r) => r.listed)].sort(
    (a, b) => RANK[b.severity ?? "info"] - RANK[a.severity ?? "info"],
  )[0]

  return (
    <div className="mx-auto max-w-[1100px]">
      {/* 1. Run header (§14.1) — back ‹ to this run's report, run timestamp, prev/next, Re-run. */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        {backLink}
        {domainId && (
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={!olderRun?.runId}
              onClick={() =>
                olderRun?.runId &&
                navigate({
                  to: "/domains/$id/runs/$runId/blacklists",
                  params: { id: domainId, runId: olderRun.runId },
                })
              }
              className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-medium disabled:opacity-40"
            >
              <ChevronLeft className="h-3 w-3" /> prev
            </button>
            <button
              type="button"
              disabled={!isHistorical || !newerRun?.runId}
              onClick={() =>
                newerRun?.runId &&
                navigate({
                  to: "/domains/$id/runs/$runId/blacklists",
                  params: { id: domainId, runId: newerRun.runId },
                })
              }
              className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-medium disabled:opacity-40"
            >
              next <ChevronRight className="h-3 w-3" />
            </button>
            <button
              type="button"
              onClick={recheck}
              disabled={runAudit.isPending}
              className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-1 text-xs font-medium text-white disabled:opacity-50"
            >
              <RefreshCw className={cn("h-3 w-3", runAudit.isPending && "animate-spin")} />
              Re-run
            </button>
          </div>
        )}
      </div>

      {isHistorical && newestRun && (
        <div className="mt-2 rounded-md bg-slate-200 px-3 py-1.5 text-xs text-slate-700">
          historical run — newest is {new Date(newestRun.ranAt).toLocaleString()}{" "}
          {domainId && (
            <Link
              to="/domains/$id/blacklists"
              params={{ id: domainId }}
              className="font-medium underline"
            >
              →
            </Link>
          )}
        </div>
      )}

      {/* 2. Verdict band — the answer to "am I in trouble?" in the first 100px (§14.2). */}
      <div className={cn("mt-2 rounded-xl p-5", band)}>
        <div className="flex items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-bold">Blacklists — {run.domain}</h1>
            <p className="mt-1 text-sm">
              <span className="font-semibold">{run.summary.listed} listed</span> ·{" "}
              {run.summary.clean} clean · {run.summary.inconclusive} unknown across{" "}
              {run.summary.zones_enabled} zones
              <span className="ml-2 opacity-75">run {new Date(run.ran_at).toLocaleString()}</span>
            </p>
            {worstListing && (
              <p className="mt-1 text-sm">
                {worstListing.name} lists {worstListing.target}
                {worstListing.sub_list ? ` — ${worstListing.sub_list}` : ""}. Fix the cause first.
              </p>
            )}
            {(run.diff.new_listings.length > 0 || run.diff.cleared.length > 0) && (
              <p className="mt-1 text-sm font-semibold">
                {run.diff.new_listings.length > 0 && <>▲ {run.diff.new_listings.length} new </>}
                {run.diff.cleared.length > 0 && <>▼ {run.diff.cleared.length} resolved</>}
              </p>
            )}
          </div>
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

      {/* 3. Matrix → 4. Sub-tests → 6. Fix panel → 7. Portals → 8. History (§14 fixed order). */}
      <ListingsMatrix run={run} onCell={openAndScroll} />
      <SubTestTable run={run} open={open} setOpen={setOpen} linkParams={{ domain: run.domain }} />
      <FixPanel run={run} />
      <PortalsChecklist run={run} />
      {domainId && <HistoryStrip domainId={domainId} runs={domainRuns} />}
    </div>
  )
}
