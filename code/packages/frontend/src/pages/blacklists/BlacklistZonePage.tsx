import { Link, useNavigate, useParams } from "@tanstack/react-router"
import { ExternalLink, RefreshCw } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"
import { useBlacklistRecheck, useBlacklistRegistry, useRunBlacklistsCheck } from "@/api/blacklists"
import type { BlacklistLiveRecheck, BlacklistZoneResult, BlocklistZoneRow } from "@/api/types"
import { SeverityBadge } from "@/components/Badges"
import { problemState } from "@/lib/problemStates"
import { cn } from "@/lib/utils"
import { useScopedBlacklistRun } from "./useScopedBlacklistRun"

/**
 * The zone explainer page (pm/checks/blacklists.mdx §20.3 / AC 23):
 * /domains/$id/runs/$runId/blacklists/zone/$zoneId with newest-run alias
 * /domains/$id/blacklists/zone/$zoneId. Renders entirely from the registry entry
 * (GET /api/blacklists/zones) plus that ONE run's blacklists section, in the locked §20.2
 * five-point template: what it is / current status / what it means / what to do / run it now.
 * Includes the raw+parsed evidence, the full return-code decoder table with this run's observed
 * code highlighted, the per-zone history strip across the last 30 runs, the references block,
 * and the zone-scoped [Run this check now] (§21.2). A zone with no results this run renders by
 * explaining WHY (dead / not registered / paid / disabled).
 */

const CHANGE_CHIP: Record<string, { label: string; cls: string }> = {
  now_listed: { label: "▲ now listed", cls: "bg-red-100 text-red-800" },
  now_clean: { label: "▼ now clean", cls: "bg-emerald-100 text-emerald-800" },
  unchanged: { label: "unchanged", cls: "bg-slate-100 text-slate-600" },
  inconclusive: { label: "? inconclusive", cls: "bg-gray-100 text-gray-500" },
  untracked: { label: "new pair", cls: "bg-sky-100 text-sky-800" },
}

function LiveOverlay({ live }: { live: BlacklistLiveRecheck }) {
  const hhmm = new Date(live.checked_at).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  })
  return (
    <div className="mt-3 rounded-lg border border-sky-200 bg-sky-50 p-3">
      <p className="text-xs font-semibold text-sky-900">
        live recheck {hhmm} — ephemeral, the stored run is untouched
      </p>
      <ul className="mt-1 space-y-0.5 text-xs">
        {live.results.map((r) => {
          const chip = CHANGE_CHIP[r.change] ?? CHANGE_CHIP.unchanged
          return (
            <li key={`${r.zone}|${r.target}`} className="flex items-center gap-2">
              <span className="font-mono">{r.target}</span>
              <span className="font-mono text-slate-500">
                {r.inconclusive
                  ? (r.refusal_code ?? "inconclusive")
                  : r.listed
                    ? (r.return_code ?? "listed")
                    : "NXDOMAIN"}
              </span>
              <span className={cn("rounded px-1.5 font-medium", chip.cls)}>{chip.label}</span>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

export function BlacklistZonePage() {
  const { zoneId } = useParams({ strict: false }) as { zoneId?: string }
  const navigate = useNavigate()
  const scope = useScopedBlacklistRun()
  const { data: registry, isLoading: registryLoading } = useBlacklistRegistry()
  const recheck = useBlacklistRecheck()
  const runCheck = useRunBlacklistsCheck()
  const [live, setLive] = useState<BlacklistLiveRecheck | null>(null)

  // §20.8 loading state — skeletons sized to the final layout, never a blank screen.
  if (registryLoading || scope.isLoading || !scope.domainsLoaded) {
    return (
      <div className="mx-auto max-w-3xl space-y-4">
        {[0, 1, 2].map((i) => (
          <div key={i} className="h-28 animate-pulse rounded-lg bg-slate-100" />
        ))}
      </div>
    )
  }

  const zone = zoneId?.toLowerCase() ?? ""
  const entries: BlocklistZoneRow[] = (registry?.zones ?? []).filter(
    (z) => z.zone.toLowerCase() === zone,
  )
  const entry = entries[0]
  const dead = registry?.dead_zones.find((d) => zone === d.zone || zone.endsWith(`.${d.zone}`))
  const backTo = scope.domainId ? (
    scope.runId ? (
      <Link
        to="/domains/$id/runs/$runId/blacklists"
        params={{ id: scope.domainId, runId: scope.runId }}
        className="text-sm text-[var(--edh-primary)]"
      >
        ‹ Back to this run's Blacklists page
      </Link>
    ) : (
      <Link
        to="/domains/$id/blacklists"
        params={{ id: scope.domainId }}
        className="text-sm text-[var(--edh-primary)]"
      >
        ‹ Back to the Blacklists page
      </Link>
    )
  ) : (
    <Link to="/blacklists" className="text-sm text-[var(--edh-primary)]">
      ‹ Back to Blacklists
    </Link>
  )

  // §20.8 unknown-zone state — name the bad param and link back; never a blank screen.
  if (!entry && !dead) {
    return (
      <div className="mx-auto max-w-3xl">
        {backTo}
        <h1 className="mt-2 text-2xl font-bold">Unknown blocklist zone</h1>
        <p className="mt-2 rounded-lg border border-dashed border-[var(--edh-border)] p-6 text-sm text-[var(--edh-muted)]">
          No zone named <span className="font-mono">{zoneId}</span> exists in the effective
          registry. See the Blocklist Zones panel for every zone we know.
        </p>
      </div>
    )
  }

  const run = scope.run
  const zoneResults: BlacklistZoneResult[] = (run?.results ?? []).filter(
    (r) => r.zone.toLowerCase() === zone,
  )
  const health = run?.zone_health.find((h) => h.zone.toLowerCase() === zone)
  const observedCodes = new Set(
    zoneResults.map((r) => r.return_code).filter((c): c is string => c !== null),
  )
  const listed = zoneResults.filter((r) => r.listed)
  const worst = [...listed].sort((a, b) => {
    const rank = { ok: 0, info: 1, warning: 2, critical: 3 } as const
    return rank[b.severity ?? "info"] - rank[a.severity ?? "info"]
  })[0]

  // Why the zone produced no rows this run (§20.3: dead / not registered / paid / disabled).
  const skippedReason = dead
    ? `This zone is DEAD (${dead.name}${dead.died ? `, died ${dead.died}` : ""}) — ${dead.reason ?? "it is on the do-not-check registry"}. It is never queried; a "listing" from it would be noise.`
    : entry && !entry.enabled
      ? "This zone is disabled in the Blocklist Zones panel, so this run did not query it."
      : entry?.is_paid
        ? "This zone requires a paid subscription/licensed resolver; without configured credentials it is skipped, never errored."
        : entry?.requires_registration
          ? "This zone requires (free) resolver registration before queries resolve; until registered it is skipped and reported inconclusive."
          : health?.status === "dead" || health?.status === "wildcarding"
            ? `The RFC 5782 liveness probe classified this zone "${health.status}" this run, so its results were excluded rather than false-reported.`
            : null

  const runZoneNow = async () => {
    if (!scope.domainName) return
    try {
      const res = await recheck.mutateAsync({ domain: scope.domainName, zones: [zone] })
      setLive(res)
    } catch (err) {
      toast.error(
        `Live recheck failed: ${err instanceof Error ? err.message : String(err)} — retry?`,
      )
    }
  }
  const runFullCheck = async () => {
    if (!scope.domainId) return
    try {
      const result = await runCheck.mutateAsync(scope.domainId)
      toast.success("Blacklists check finished — opening the new run")
      navigate({
        to: "/domains/$id/runs/$runId/blacklists/zone/$zoneId",
        params: { id: scope.domainId, runId: result.runId ?? "", zoneId: zone },
      })
    } catch (err) {
      toast.error(`Check failed: ${err instanceof Error ? err.message : String(err)} — retry?`)
    }
  }

  const decoderRows = Object.entries(entry?.codes ?? {})
  const bitmaskRows = Object.entries(entry?.bitmask ?? {})

  return (
    <div className="mx-auto max-w-3xl">
      {backTo}

      {/* §20.2 point 1 — what it is */}
      <div className="mt-2 flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-bold">{entry?.name ?? dead?.name ?? zone}</h1>
        <span className="font-mono text-sm text-slate-500">{zone}</span>
        {entry && (
          <span className="rounded border border-slate-200 px-1.5 text-xs uppercase text-slate-500">
            {entry.tier} tier · {entries.map((e) => e.kind).join(" + ")} zone
          </span>
        )}
      </div>
      {entry?.notes && <p className="mt-1 text-sm text-[var(--edh-muted)]">{entry.notes}</p>}

      {/* §20.2 point 2 — current status against the viewed run */}
      <section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
        <h2 className="mb-1 font-semibold">Status in this run</h2>
        {!run ? (
          <p className="text-sm text-[var(--edh-muted)]">
            No run to compare against — run a blacklist check first.
          </p>
        ) : zoneResults.length === 0 ? (
          <p className="text-sm text-slate-700">
            {skippedReason ?? "This zone produced no results this run."}
          </p>
        ) : (
          <>
            <p className="text-sm text-slate-700">
              {listed.length === 0 ? (
                <>Every target is clean on this zone in the viewed run.</>
              ) : (
                <>
                  <span className="font-semibold text-red-700">
                    {listed.length} target(s) listed
                  </span>
                  {worst?.sub_list && <> — worst: {worst.sub_list}</>}.
                </>
              )}
              {health && (
                <span className="ml-2 text-xs text-slate-500">
                  liveness: {health.status} ({health.probe_ms} ms)
                </span>
              )}
            </p>
            {/* §20.6 raw + parsed evidence, field by field */}
            <table className="mt-2 w-full text-xs">
              <thead>
                <tr className="border-b border-[var(--edh-border)] text-left text-slate-500">
                  <th className="py-1 pr-2 font-medium">Target</th>
                  <th className="py-1 pr-2 font-medium">Raw answer</th>
                  <th className="py-1 pr-2 font-medium">Parsed</th>
                  <th className="py-1 font-medium">TXT reason</th>
                </tr>
              </thead>
              <tbody>
                {zoneResults.map((r) => (
                  <tr key={r.target} className="border-b border-[var(--edh-border)] last:border-0">
                    <td className="py-1 pr-2 font-mono">{r.target}</td>
                    <td className="py-1 pr-2 font-mono">
                      {r.return_code ?? r.refusal_code ?? "NXDOMAIN"}
                    </td>
                    <td className="py-1 pr-2">
                      {r.inconclusive
                        ? "query refused — inconclusive, never a listing"
                        : r.listed
                          ? `listed${r.sub_list ? ` = ${r.sub_list}` : ""}`
                          : "not listed"}
                    </td>
                    <td className="py-1 font-mono">{r.reason_txt ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
        {live && <LiveOverlay live={live} />}
      </section>

      {/* §20.2 point 3 — what it means: the decoder table, observed code highlighted */}
      {(decoderRows.length > 0 || bitmaskRows.length > 0) && (
        <section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
          <h2 className="mb-2 font-semibold">Return-code decoder</h2>
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[var(--edh-border)] text-left text-slate-500">
                <th className="py-1 pr-2 font-medium">{decoderRows.length > 0 ? "Code" : "Bit"}</th>
                <th className="py-1 pr-2 font-medium">Meaning</th>
                <th className="py-1 font-medium">Severity</th>
              </tr>
            </thead>
            <tbody>
              {(decoderRows.length > 0 ? decoderRows : bitmaskRows).map(([code, meaning]) => (
                <tr
                  key={code}
                  className={cn(
                    "border-b border-[var(--edh-border)] last:border-0",
                    observedCodes.has(code) && "bg-amber-50 font-semibold",
                  )}
                >
                  <td className="py-1 pr-2 font-mono">
                    {code}
                    {observedCodes.has(code) && (
                      <span className="ml-1 rounded bg-amber-200 px-1 text-[10px]">this run</span>
                    )}
                  </td>
                  <td className="py-1 pr-2">
                    {meaning.label}
                    {meaning.problem_state && (
                      <span className="ml-1 text-slate-500">
                        ({meaning.problem_state}: {problemState(meaning.problem_state)?.name})
                      </span>
                    )}
                  </td>
                  <td className="py-1">
                    <SeverityBadge severity={meaning.severity} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {/* §20.2 point 4 — what to do */}
      <section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
        <h2 className="mb-1 font-semibold">What to do</h2>
        <ol className="list-decimal space-y-1 pl-5 text-sm text-slate-700">
          <li>Fix the root cause first — a delist request with the cause live gets re-listed.</li>
          <li>
            Request removal via the operator's own portal
            {entry?.auto_expires && <> — or wait it out (auto-expires {entry.auto_expires})</>}.
          </li>
          {entry?.paid_delist_offered && (
            <li className="font-semibold text-red-700">
              Never pay for "express" delisting — these listings auto-expire and pay-to-delist is
              considered abusive (RFC 6471).
            </li>
          )}
          <li>Re-run this check after the operator's processing window to confirm removal.</li>
        </ol>
      </section>

      {/* §20.7 references */}
      {entry && (
        <section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
          <h2 className="mb-1 font-semibold">References</h2>
          <ul className="space-y-1 text-sm">
            <li>
              <a
                href={entry.lookup_url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-[var(--edh-primary)] underline"
              >
                Operator lookup page <ExternalLink className="h-3 w-3" />
              </a>
            </li>
            <li>
              <a
                href={entry.delist_url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-[var(--edh-primary)] underline"
              >
                Delisting portal <ExternalLink className="h-3 w-3" />
              </a>
            </li>
            <li className="text-xs text-[var(--edh-muted)]">
              RFC 5782 (DNS blocklist query mechanics) · multirbl.valli.org zone directory
            </li>
          </ul>
        </section>
      )}

      {/* Per-zone history strip across the last 30 runs */}
      {scope.domainRuns.length > 1 && (
        <section className="mt-4">
          <h2 className="mb-2 text-sm font-semibold text-slate-600">
            This zone over the last {Math.min(scope.domainRuns.length, 30)} runs
          </h2>
          <div className="flex h-10 items-end gap-1">
            {[...scope.domainRuns]
              .reverse()
              .slice(-30)
              .map((r) => {
                const rows = (r.results?.blacklist?.results ?? []).filter(
                  (row) => row.zone.toLowerCase() === zone,
                )
                const hit = rows.some((row) => row.listed)
                const skipped = rows.length === 0
                return (
                  <Link
                    key={r.runId ?? r.ranAt}
                    to="/domains/$id/runs/$runId/blacklists/zone/$zoneId"
                    params={{
                      id: scope.domainId ?? "",
                      runId: r.runId ?? "",
                      zoneId: zone,
                    }}
                    title={`${new Date(r.ranAt).toLocaleString()}: ${skipped ? "not queried" : hit ? "listed" : "clean"}${r.scope ? " (blacklists-only run)" : ""}`}
                    className={cn(
                      "w-3 rounded-t",
                      skipped ? "bg-slate-200" : hit ? "bg-red-600" : "bg-emerald-500",
                      r.scope && "ring-1 ring-sky-400",
                    )}
                    style={{ height: hit ? "100%" : "40%" }}
                  />
                )
              })}
          </div>
        </section>
      )}

      {/* §20.2 point 5 / §21.2 — run it now, scoped to this one zone */}
      <div className="mt-5 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={runZoneNow}
          disabled={recheck.isPending || !scope.domainName || !!dead}
          className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50"
        >
          <RefreshCw className={cn("h-3.5 w-3.5", recheck.isPending && "animate-spin")} />
          {recheck.isPending ? "Re-querying this zone…" : "Run this check now (this zone)"}
        </button>
        <button
          type="button"
          onClick={runFullCheck}
          disabled={runCheck.isPending || !scope.domainId}
          className="inline-flex items-center gap-2 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm font-medium disabled:opacity-50"
          title={
            runCheck.isPending ? "A blacklists run for this domain is already in flight" : undefined
          }
        >
          <RefreshCw className={cn("h-3.5 w-3.5", runCheck.isPending && "animate-spin")} />
          Run full blacklist check
        </button>
        {dead && (
          <span className="text-xs text-[var(--edh-muted)]">
            dead zones are never queried — this does not affect your standing
          </span>
        )}
      </div>
    </div>
  )
}
