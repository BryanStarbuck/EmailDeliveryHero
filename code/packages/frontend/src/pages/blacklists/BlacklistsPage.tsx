import { Link } from "@tanstack/react-router"
import { Ban, ChevronRight, TrendingDown, TrendingUp } from "lucide-react"
import { useBlacklistRuns } from "@/api/blacklists"
import type { BlacklistRunResults } from "@/api/types"
import { cn } from "@/lib/utils"

/**
 * The Blacklists summary surface (pm/checks/blacklists.mdx §13.1): one card per domain answering
 * "am I listed anywhere that matters, and is that new?" — counts, the single worst listing, the
 * diff chip, and a chevron to the full technology page. Nothing else lives on the card.
 */

const CARD_COLOR: Record<string, string> = {
  critical: "bg-red-800 text-white",
  warning: "bg-amber-500 text-black",
  ok: "bg-green-800 text-white",
  info: "bg-green-800 text-white",
}

function worstListing(run: BlacklistRunResults) {
  const listed = run.results.filter((r) => r.listed)
  if (listed.length === 0) return null
  const rank = { ok: 0, info: 1, warning: 2, critical: 3 } as const
  return [...listed].sort((a, b) => rank[b.severity ?? "info"] - rank[a.severity ?? "info"])[0]
}

function SummaryCard({ run }: { run: BlacklistRunResults }) {
  const worst = worstListing(run)
  const color = CARD_COLOR[run.summary.worst_severity] ?? CARD_COLOR.ok
  const hasNew = run.diff.new_listings.length > 0
  const hasResolved = run.diff.cleared.length > 0

  return (
    <Link
      to="/blacklists/$domain"
      params={{ domain: run.domain }}
      className={cn(
        "block rounded-xl p-4 shadow-sm transition-transform hover:scale-[1.01]",
        color,
      )}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 font-semibold">
          <Ban className="h-4 w-4" />
          {run.domain}
        </div>
        <ChevronRight className="h-5 w-5 opacity-80" />
      </div>
      <p className="mt-2 text-sm">
        <span className="font-semibold">{run.summary.listed} listed</span>
        {" · "}
        {run.summary.clean} clean
        {" · "}
        {run.summary.inconclusive} unknown
        <span className="ml-2 text-xs opacity-75">
          as of{" "}
          {new Date(run.ran_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
        </span>
      </p>
      {worst ? (
        <p className="mt-1 truncate text-sm opacity-90">
          Worst: {worst.name} — {worst.target}
          {worst.sub_list ? ` (${worst.sub_list})` : ""}
        </p>
      ) : (
        <p className="mt-1 text-sm opacity-90">
          No listings across {run.summary.zones_enabled} zones
        </p>
      )}
      {hasNew && (
        <p className="mt-1 flex items-center gap-1 text-sm font-semibold">
          <TrendingUp className="h-4 w-4" /> NEW since the previous run
        </p>
      )}
      {!hasNew && hasResolved && (
        <p className="mt-1 flex items-center gap-1 text-sm font-semibold">
          <TrendingDown className="h-4 w-4" /> resolved since the previous run
        </p>
      )}
    </Link>
  )
}

export function BlacklistsPage() {
  const { data: runs, isLoading } = useBlacklistRuns()

  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="mb-1 text-2xl font-bold">Blacklists</h1>
      <p className="mb-6 text-sm text-[var(--edh-muted)]">
        DNSBL / domain-blocklist status for every monitored domain — click a card for the full
        per-zone detail, debug values, and delisting steps.
      </p>
      {isLoading ? (
        <p className="text-sm text-[var(--edh-muted)]">Loading…</p>
      ) : !runs || runs.length === 0 ? (
        <p className="rounded-lg border border-dashed border-[var(--edh-border)] p-8 text-center text-[var(--edh-muted)]">
          No blacklist results yet — run an audit from the Dashboard or Audits page.
        </p>
      ) : (
        <div className="space-y-4">
          {runs.map((run) => (
            <SummaryCard key={run.domain} run={run} />
          ))}
        </div>
      )}
    </div>
  )
}
