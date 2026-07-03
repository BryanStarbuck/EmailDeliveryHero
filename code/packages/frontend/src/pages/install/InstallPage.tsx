import { useNavigate, useSearch } from "@tanstack/react-router"
import { Check, Copy, Loader2, RefreshCw, TerminalSquare, X } from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { toast } from "sonner"
import {
  fetchJobStatus,
  type InstallJobStatus,
  type ToolCategory,
  type ToolManager,
  type ToolStatus,
  useStartInstall,
  usePreflight,
} from "@/api/install"

/**
 * The Install page (pm/install_brew.mdx §4; shared with the npm side, pm/install_npm.mdx §6).
 * Rows of missing tools with a left checkbox, Install bars at top and bottom, live per-row output,
 * and — when reached from a diverted run (?intent) — a footer that resumes the run afterward (§8).
 */

type RowPhase = "idle" | "queued" | "installing" | "done" | "failed"

const CATEGORY_LABEL: Record<ToolCategory, string> = {
  dns: "DNS & Domain",
  spf: "SPF",
  dkim: "DKIM",
  dmarc: "DMARC & Reports",
  blacklist: "Blacklists",
  spam: "Spam & Content",
  tls: "TLS & Transport",
  general: "General",
}
const CATEGORY_ORDER: ToolCategory[] = [
  "dns",
  "spf",
  "dkim",
  "dmarc",
  "blacklist",
  "tls",
  "spam",
  "general",
]

/** intent → the preflight scope string (pm/install_brew.mdx §8.1). */
function intentScope(intent: string | undefined): string {
  if (!intent || intent === "none") return "run-all"
  if (intent.startsWith("run-domain")) return "run-domain"
  if (intent.startsWith("run-check")) {
    // run-check:<checkId>:<domainId> → scope run-check:<checkId>
    const parts = intent.split(":")
    return parts.length >= 2 ? `run-check:${parts[1]}` : "run-all"
  }
  return "run-all"
}

export function InstallPage() {
  const search = useSearch({ strict: false }) as {
    manager?: string
    from?: string
    intent?: string
  }
  const manager = (search.manager === "npm" ? "npm" : search.manager === "brew" ? "brew" : "all") as ToolManager
  const from = search.from
  const intent = search.intent
  const navigate = useNavigate()

  const scope = intent ? intentScope(intent) : undefined
  const preflight = usePreflight(manager, scope)
  const startInstall = useStartInstall()

  // Rows = missing (pre-checked) + optional (unchecked). Installed rows are omitted from the list.
  const rows = useMemo<ToolStatus[]>(() => {
    if (!preflight.data) return []
    return [...preflight.data.missing, ...preflight.data.optional]
  }, [preflight.data])

  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [phase, setPhase] = useState<Record<string, RowPhase>>({})
  const [tail, setTail] = useState<Record<string, string[]>>({})
  const [running, setRunning] = useState(false)
  const esRef = useRef<EventSource | null>(null)

  // Seed selection when the preflight first loads: missing (default tier) checked, optional not.
  useEffect(() => {
    if (!preflight.data) return
    const next = new Set<string>()
    for (const t of preflight.data.missing) if (t.autoInstallable) next.add(t.id)
    setSelected(next)
  }, [preflight.data])

  const selectedList = useMemo(
    () => rows.filter((r) => selected.has(r.id) && r.autoInstallable),
    [rows, selected],
  )

  const toggle = useCallback((id: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const copyCmd = useCallback((cmd: string) => {
    navigator.clipboard?.writeText(cmd)
    toast.success("Command copied")
  }, [])

  const reDetect = useCallback(() => {
    preflight.refetch()
    setPhase({})
    setTail({})
  }, [preflight])

  /** Poll job status until done, driving per-row phases; the SSE stream fills in live lines. */
  const pollUntilDone = useCallback(
    async (jobId: string): Promise<InstallJobStatus> => {
      for (;;) {
        const status = await fetchJobStatus(jobId)
        setPhase((prev) => ({ ...prev, ...status.phases }))
        if (status.done) return status
        await new Promise((r) => setTimeout(r, 1000))
      }
    },
    [],
  )

  /** Return to `from` and replay `intent` via a one-shot ?resume param (pm/install_brew.mdx §8.3). */
  const continueToOrigin = useCallback(() => {
    const dest = from && from.startsWith("/") ? from : "/"
    const sep = dest.includes("?") ? "&" : "?"
    const url = intent && intent !== "none" ? `${dest}${sep}resume=${encodeURIComponent(intent)}` : dest
    navigate({ to: url })
  }, [from, intent, navigate])

  const runInstall = useCallback(async () => {
    const ids = selectedList.map((r) => r.id)
    if (ids.length === 0) return
    setRunning(true)
    setPhase(Object.fromEntries(ids.map((id) => [id, "installing" as RowPhase])))
    setTail({})
    try {
      const { jobId } = await startInstall.mutateAsync(ids)
      // Best-effort live tail; polling is the source of truth for completion.
      try {
        const es = new EventSource(`/api/install/run/${jobId}/stream`, { withCredentials: true })
        esRef.current = es
        es.onmessage = (e) => {
          try {
            const ev = JSON.parse(e.data) as { id: string; phase: RowPhase; line?: string }
            if (ev.line) {
              setTail((prev) => {
                const lines = [...(prev[ev.id] ?? []), ev.line as string].slice(-12)
                return { ...prev, [ev.id]: lines }
              })
            }
            if (ev.phase === "done" || ev.phase === "failed") {
              setPhase((prev) => ({ ...prev, [ev.id]: ev.phase }))
            }
          } catch {}
        }
        es.onerror = () => es.close()
      } catch {}
      const status = await pollUntilDone(jobId)
      esRef.current?.close()
      const okCount = status.results.filter((r) => r.ok).length
      const failed = status.results.filter((r) => !r.ok)
      if (failed.length > 0)
        toast.error(`${failed.length} install${failed.length > 1 ? "s" : ""} failed — see the red rows.`)
      else toast.success(`Installed ${okCount} tool${okCount === 1 ? "" : "s"}.`)
      await preflight.refetch()
      // Continue: once every selected install has settled and detection refreshed, resume the run.
      if (intent && intent !== "none") continueToOrigin()
    } catch (err) {
      toast.error(`Install failed: ${(err as Error).message}`)
    } finally {
      setRunning(false)
    }
  }, [selectedList, startInstall, pollUntilDone, preflight, intent, continueToOrigin])

  useEffect(() => () => esRef.current?.close(), [])

  const grouped = useMemo(() => {
    const by: Partial<Record<ToolCategory, ToolStatus[]>> = {}
    for (const r of rows) (by[r.category] ??= []).push(r)
    for (const c of Object.keys(by) as ToolCategory[])
      by[c]?.sort((a, b) => (a.tier === b.tier ? 0 : a.tier === "default" ? -1 : 1))
    return by
  }, [rows])

  if (preflight.isLoading)
    return (
      <div className="mx-auto flex max-w-4xl items-center gap-2 p-8 text-[var(--edh-muted)]">
        <Loader2 className="h-4 w-4 animate-spin" /> Detecting installed tools…
      </div>
    )

  const bar = (
    <div className="flex items-center justify-between rounded-lg border border-[var(--edh-border)] bg-slate-50 px-4 py-3">
      <span className="text-sm text-[var(--edh-muted)]">
        {running
          ? `Installing ${Object.values(phase).filter((p) => p === "done" || p === "failed").length} of ${selectedList.length}…`
          : `Install ${selectedList.length} selected tool${selectedList.length === 1 ? "" : "s"}`}
      </span>
      <button
        type="button"
        onClick={runInstall}
        disabled={running || selectedList.length === 0}
        className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
      >
        {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <TerminalSquare className="h-4 w-4" />}
        {running ? "Installing…" : "Install"}
      </button>
    </div>
  )

  return (
    <div className="mx-auto max-w-4xl p-2">
      <header className="mb-4 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-black">Install tools</h1>
          <p className="mt-1 text-sm text-[var(--edh-muted)]">
            {rows.length === 0
              ? "Everything needed is already installed."
              : `${preflight.data?.missing.length ?? 0} needed · ${selected.size} selected`}
          </p>
        </div>
        <button
          type="button"
          onClick={reDetect}
          disabled={running}
          className="inline-flex items-center gap-2 rounded-md border border-[var(--edh-border)] px-3 py-2 text-sm text-black disabled:opacity-50"
        >
          <RefreshCw className="h-4 w-4" /> Re-detect
        </button>
      </header>

      {preflight.data?.brewPresent === false && <HomebrewBanner />}

      {rows.length === 0 ? (
        <div className="rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center text-slate-600">
          Your toolbox is complete for this run.
          {intent && intent !== "none" && (
            <div className="mt-4">
              <button
                type="button"
                onClick={continueToOrigin}
                className="rounded-md bg-[var(--edh-primary)] px-4 py-2 text-sm font-medium text-white"
              >
                Continue →
              </button>
            </div>
          )}
        </div>
      ) : (
        <>
          <div className="mb-4">{bar}</div>
          <div className="space-y-6">
            {CATEGORY_ORDER.filter((c) => grouped[c]?.length).map((c) => (
              <section key={c}>
                <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-black">
                  {CATEGORY_LABEL[c]}
                </h2>
                <div className="space-y-2">
                  {grouped[c]?.map((row) => (
                    <ToolRow
                      key={row.id}
                      row={row}
                      checked={selected.has(row.id)}
                      phase={phase[row.id] ?? "idle"}
                      tail={tail[row.id] ?? []}
                      onToggle={() => toggle(row.id)}
                      onCopy={() => copyCmd(row.installCmd)}
                    />
                  ))}
                </div>
              </section>
            ))}
          </div>
          <div className="mt-4">{bar}</div>
        </>
      )}

      {intent && intent !== "none" && rows.length > 0 && (
        <footer className="mt-6 flex items-center justify-between border-t border-[var(--edh-border)] pt-4">
          <button
            type="button"
            onClick={continueToOrigin}
            disabled={running}
            className="text-sm text-black underline disabled:opacity-50"
          >
            Skip — run anyway
          </button>
          <button
            type="button"
            onClick={() => navigate({ to: from && from.startsWith("/") ? from : "/" })}
            disabled={running}
            className="text-sm text-[var(--edh-muted)] disabled:opacity-50"
          >
            Cancel run
          </button>
        </footer>
      )}
    </div>
  )
}

function ToolRow({
  row,
  checked,
  phase,
  tail,
  onToggle,
  onCopy,
}: {
  row: ToolStatus
  checked: boolean
  phase: RowPhase
  tail: string[]
  onToggle: () => void
  onCopy: () => void
}) {
  const managerChip = row.install === "corepack" || row.install === "pnpm-add" || row.install === "pnpm-install"
    ? "pnpm"
    : row.manager === "special"
      ? row.install
      : row.manager
  return (
    <div className="rounded-lg border border-[var(--edh-border)] p-4">
      <div className="flex items-start gap-3">
        {row.autoInstallable ? (
          <input
            type="checkbox"
            checked={checked}
            onChange={onToggle}
            aria-label={`Install ${row.label}`}
            className="mt-1 h-4 w-4 accent-[var(--edh-primary)]"
          />
        ) : (
          <button
            type="button"
            onClick={onCopy}
            title="Copy install command"
            className="mt-0.5 inline-flex items-center gap-1 rounded border border-[var(--edh-border)] px-1.5 py-0.5 text-xs text-black"
          >
            <Copy className="h-3 w-3" /> Copy
          </button>
        )}
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-2">
            <span className="font-medium text-black">{row.label}</span>
            <span className="flex shrink-0 items-center gap-1.5">
              <Chip>{row.category.toUpperCase()}</Chip>
              <Chip>{managerChip}</Chip>
            </span>
          </div>
          <p className="mt-0.5 text-sm text-slate-600">{row.summary}</p>
          <div className="mt-1 flex items-center gap-2">
            <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs text-slate-700">
              {row.installCmd}
            </code>
            <StatusDot phase={phase} />
          </div>
          {row.notes && <p className="mt-1 text-xs text-amber-700">⚠ {row.notes}</p>}
          {tail.length > 0 && (
            <pre className="mt-2 max-h-40 overflow-auto rounded bg-slate-900 p-2 font-mono text-[11px] leading-tight text-slate-200">
              {tail.join("\n")}
            </pre>
          )}
        </div>
      </div>
    </div>
  )
}

function Chip({ children }: { children: React.ReactNode }) {
  return (
    <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-slate-600">
      {children}
    </span>
  )
}

function StatusDot({ phase }: { phase: RowPhase }) {
  if (phase === "queued")
    return <span className="text-xs text-slate-400">● queued</span>
  if (phase === "installing")
    return (
      <span className="inline-flex items-center gap-1 text-xs text-amber-600">
        <Loader2 className="h-3 w-3 animate-spin" /> installing
      </span>
    )
  if (phase === "done")
    return (
      <span className="inline-flex items-center gap-1 text-xs text-emerald-600">
        <Check className="h-3 w-3" /> installed
      </span>
    )
  if (phase === "failed")
    return (
      <span className="inline-flex items-center gap-1 text-xs text-red-600">
        <X className="h-3 w-3" /> failed
      </span>
    )
  return <span className="text-xs text-slate-400">● missing</span>
}

function HomebrewBanner() {
  const cmd =
    '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
  return (
    <div className="mb-4 rounded-lg border border-amber-300 bg-amber-50 p-4">
      <p className="text-sm font-medium text-amber-900">Homebrew not detected</p>
      <p className="mt-1 text-sm text-amber-800">
        Install Homebrew, then press Re-detect — every brew row becomes one-click. We never run this
        for you (it pipes the internet into a shell); copy and run it yourself:
      </p>
      <div className="mt-2 flex items-center gap-2">
        <code className="flex-1 overflow-auto rounded bg-white px-2 py-1 font-mono text-xs text-slate-700">
          {cmd}
        </code>
        <button
          type="button"
          onClick={() => {
            navigator.clipboard?.writeText(cmd)
            toast.success("Command copied")
          }}
          className="inline-flex items-center gap-1 rounded border border-amber-300 px-2 py-1 text-xs text-amber-900"
        >
          <Copy className="h-3 w-3" /> Copy
        </button>
      </div>
    </div>
  )
}
