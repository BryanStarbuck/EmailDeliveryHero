import { Link, useNavigate, useParams } from "@tanstack/react-router"
import {
  ArrowLeft,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Info,
  KeyRound,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
  Wrench,
  X,
} from "lucide-react"
import { useEffect, useState } from "react"
import { useAuditResults, useAuditRuns, useDkimDiscovery } from "@/api/audit"
import { useDomains, useUpdateDomain } from "@/api/domains"
import type { DkimResults, DkimSelectorResult, DkimToolRun, Finding, Severity } from "@/api/types"
import { CopyFixButton } from "@/components/CopyFixButton"
import { StatusCell } from "@/components/StatusCell"
import { NEVER_CELL, rollupCategories } from "@/lib/categories"
import { matchProblemStates } from "@/lib/dkim-problems"
import { cn } from "@/lib/utils"
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext"

const ORDER: Record<Severity, number> = { critical: 0, warning: 1, info: 2, ok: 3 }

/**
 * The DKIM category RUN page (pm/checks/dkim.mdx §6.2/§7) — "view one category run": everything
 * about the DKIM results of ONE specific run for one domain. Run-scoped route
 * /domains/:id/runs/:runId/dkim plus the newest-run alias /domains/:id/dkim. Renders, in triage
 * order: the header (back to this run's report, status, run timestamp, ‹ prev / next › run
 * navigation, Re-run), the key-health hero, one card per selector (resolution chain, raw record,
 * key badges), the fail-first test-results table with observed DNS values and copyable fixes, the
 * tool-runs evidence accordion, the selectors editor with discovery import, and problem-state
 * cards linking to the per-problem drill-down pages.
 */
export function DkimPage() {
  const { id = "", runId } = useParams({ strict: false }) as { id?: string; runId?: string }
  const { data: domains } = useDomains()
  const { data: results } = useAuditResults()
  const { data: runs } = useAuditRuns()
  const runDomains = useScanRunner()
  const scanning = useScanProgress().some((s) => s.domainId === id)
  const navigate = useNavigate()

  const domain = (domains ?? []).find((d) => d.id === id)
  // This domain's run history, newest startedAt first — drives ‹ prev / next › (§6.2 item 3).
  const domainRuns = (runs ?? []).filter((r) => r.domainId === id)
  const newest = (results ?? []).find((r) => r.domainId === id) ?? domainRuns[0]
  // Run-scoped: render exactly the run in the URL; the alias renders the newest run.
  const result = runId ? domainRuns.find((r) => r.runId === runId) : newest
  const runNotFound = Boolean(runId) && runs !== undefined && !result

  const currentRunId = result?.runId
  const idx = currentRunId ? domainRuns.findIndex((r) => r.runId === currentRunId) : -1
  const prevRun = idx >= 0 ? domainRuns[idx + 1] : undefined // chronologically older
  const nextRun = idx > 0 ? domainRuns[idx - 1] : undefined // chronologically newer
  const isStale =
    Boolean(runId) && Boolean(result) && domainRuns.length > 0 && domainRuns[0]?.runId !== runId

  const goToRun = (run?: { runId?: string }) => {
    if (!run?.runId) return
    navigate({ to: "/domains/$id/runs/$runId/dkim", params: { id, runId: run.runId } })
  }

  // Keyboard ← / → step through the domain's runs, staying on the DKIM page (§7 header rules).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement | null)?.tagName
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return
      if (e.key === "ArrowLeft" && prevRun?.runId) {
        navigate({ to: "/domains/$id/runs/$runId/dkim", params: { id, runId: prevRun.runId } })
      } else if (e.key === "ArrowRight" && nextRun?.runId) {
        navigate({ to: "/domains/$id/runs/$runId/dkim", params: { id, runId: nextRun.runId } })
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [navigate, id, prevRun?.runId, nextRun?.runId])

  const findings = (result?.findings ?? []).filter((f) => f.checkId === "dkim")
  const dkim = result?.results?.dkim
  const cell = rollupCategories(result?.findings, result?.results).dkim ?? NEVER_CELL
  const problems = matchProblemStates(findings)
  const runStarted = result?.startedAt ?? result?.ranAt

  // Re-run starts a fresh run for just this domain, then lands on the new run's DKIM page (the
  // newest-run alias resolves to it once the scan completes — §6.2 item 1).
  const onRunAgain = () => {
    void runDomains([{ id, name: domain?.name ?? id }]).then(() => {
      navigate({ to: "/domains/$id/dkim", params: { id } })
    })
  }

  // Loading (pm/checks/dkim.mdx §6.2): skeleton header + selector cards + table rows, no layout
  // shift — never the "No runs yet" empty state while the queries are still in flight.
  if (domains === undefined || results === undefined || runs === undefined) {
    return <DkimPageSkeleton />
  }

  if (runNotFound) {
    return (
      <div className="mx-auto max-w-5xl">
        <h1 className="text-2xl font-bold">DKIM</h1>
        <div className="mt-6 rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center">
          <p className="text-slate-600">This run no longer exists.</p>
          <Link
            to="/domains/$id/dkim"
            params={{ id }}
            className="mt-2 inline-flex items-center gap-1 text-[var(--edh-primary)] underline"
          >
            Open the newest DKIM run for {domain?.name ?? id}
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-5xl">
      <div className="mb-4 flex items-center justify-between">
        <button
          type="button"
          onClick={() =>
            runId
              ? navigate({ to: "/domains/$id/runs/$runId", params: { id, runId } })
              : navigate({ to: "/domains/$id", params: { id } })
          }
          className="inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
        >
          <ArrowLeft className="h-4 w-4" /> Back to run report
        </button>
        <div className="flex items-center gap-2">
          {result && (
            <span className="inline-flex items-center rounded-md border border-[var(--edh-border)] text-sm">
              <button
                type="button"
                onClick={() => goToRun(prevRun)}
                disabled={!prevRun?.runId}
                aria-label="Previous run"
                title="Previous run (older)"
                className="inline-flex items-center gap-1 px-2 py-1.5 text-[var(--edh-muted)] hover:text-slate-700 disabled:opacity-40"
              >
                <ChevronLeft className="h-4 w-4" /> prev
              </button>
              <span className="h-4 w-px bg-[var(--edh-border)]" />
              <button
                type="button"
                onClick={() => goToRun(nextRun)}
                disabled={!nextRun?.runId}
                aria-label="Next run"
                title="Next run (newer)"
                className="inline-flex items-center gap-1 px-2 py-1.5 text-[var(--edh-muted)] hover:text-slate-700 disabled:opacity-40"
              >
                next <ChevronRight className="h-4 w-4" />
              </button>
            </span>
          )}
          <button
            type="button"
            onClick={onRunAgain}
            disabled={scanning}
            className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
          >
            <RefreshCw className={scanning ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
            Re-run
          </button>
        </div>
      </div>

      <h1 className="text-2xl font-bold">DKIM</h1>
      <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-[var(--edh-muted)]">
        <span className="font-medium text-slate-900">{domain?.name ?? id}</span>
        <span className="w-32">
          <StatusCell status={cell} />
        </span>
        {runStarted && <span>· run {new Date(runStarted).toLocaleString()}</span>}
      </div>

      {isStale && (
        <div className="mt-3 flex items-center justify-between gap-2 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-800">
          <span className="flex items-center gap-2">
            <TriangleAlert className="h-4 w-4 shrink-0" />
            Viewing the run of {runStarted ? new Date(runStarted).toLocaleString() : runId} — a
            newer run exists
          </span>
          <Link
            to="/domains/$id/dkim"
            params={{ id }}
            className="shrink-0 font-medium underline hover:text-amber-900"
          >
            newest ›
          </Link>
        </div>
      )}

      {!result ? (
        <div className="mt-6 rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center">
          <p className="text-slate-600">No runs yet.</p>
          <button
            type="button"
            onClick={onRunAgain}
            className="mt-2 inline-flex items-center gap-2 text-[var(--edh-primary)] underline"
          >
            Run checks
          </button>
        </div>
      ) : (
        <>
          <KeyHealthHero dkim={dkim} findings={findings} />

          {dkim && dkim.selectors.length > 0 && (
            <div className="mt-4 grid gap-4 lg:grid-cols-2">
              {dkim.selectors.map((sel) => (
                <SelectorCard
                  key={sel.selector}
                  sel={sel}
                  domainId={id}
                  configured={domain?.dkimSelectors ?? []}
                />
              ))}
            </div>
          )}

          <TestResultsTable findings={findings} />

          <ToolRunsAccordion toolRuns={dkim?.tool_runs ?? []} />

          <SelectorsEditor
            domainId={id}
            domainName={domain?.name ?? id}
            selectors={domain?.dkimSelectors ?? []}
            scanning={scanning}
          />

          {problems.length > 0 && (
            <section className="mt-6">
              <h2 className="mb-2 font-semibold">Problem states</h2>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {problems.map((ps) => (
                  <ProblemCard key={ps.id} ps={ps} id={id} runId={runId} />
                ))}
              </div>
            </section>
          )}
        </>
      )}
    </div>
  )
}

/**
 * One problem-state card (§7 lowest band): id + title + one-line hook + Learn-more chevron. Links
 * run-scoped (/domains/:id/runs/:runId/dkim/:problemId) when a runId is in the URL, else via the
 * newest-run alias.
 */
function ProblemCard({
  ps,
  id,
  runId,
}: {
  ps: { id: string; title: string; hook: string }
  id: string
  runId?: string
}) {
  const className =
    "group rounded-lg border border-[var(--edh-border)] bg-white p-4 hover:border-[var(--edh-primary)]"
  const body = (
    <>
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase text-[var(--edh-muted)]">{ps.id}</span>
        <ChevronRight className="h-4 w-4 text-[var(--edh-muted)] group-hover:text-[var(--edh-primary)]" />
      </div>
      <div className="mt-1 font-medium">{ps.title}</div>
      <p className="mt-1 text-sm text-slate-600">{ps.hook}</p>
    </>
  )
  return runId ? (
    <Link
      to="/domains/$id/runs/$runId/dkim/$problemId"
      params={{ id, runId, problemId: ps.id }}
      className={className}
    >
      {body}
    </Link>
  ) : (
    <Link to="/domains/$id/dkim/$problemId" params={{ id, problemId: ps.id }} className={className}>
      {body}
    </Link>
  )
}

/**
 * The tool-runs evidence accordion (pm/checks/dkim.mdx §6.2 item 5 / §7): collapsed by default,
 * one row per `dkim.tool_runs[]` entry — tool, exact copyable command, duration, exit code —
 * expanding to the captured parsed output. Failed invocations render amber with the error string
 * (which carries the `brew install` hint on ENOENT).
 */
function ToolRunsAccordion({ toolRuns }: { toolRuns: DkimToolRun[] }) {
  const [open, setOpen] = useState(false)
  if (toolRuns.length === 0) return null

  const byTool = new Map<string, number>()
  for (const t of toolRuns) byTool.set(t.tool, (byTool.get(t.tool) ?? 0) + 1)
  const summary = [...byTool.entries()].map(([tool, n]) => `${tool} ×${n}`).join(" · ")
  const failed = toolRuns.filter((t) => t.error !== null).length

  // Stable row keys: started_at+command, de-duplicated for repeat invocations.
  const seen = new Map<string, number>()
  const rows = toolRuns.map((run) => {
    const base = `${run.started_at}|${run.command}`
    const n = seen.get(base) ?? 0
    seen.set(base, n + 1)
    return { run, key: n === 0 ? base : `${base}|${n}` }
  })

  return (
    <section className="mt-4 overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-slate-50"
      >
        {open ? (
          <ChevronDown className="h-4 w-4 shrink-0 text-[var(--edh-muted)]" />
        ) : (
          <ChevronRight className="h-4 w-4 shrink-0 text-[var(--edh-muted)]" />
        )}
        <span className="font-semibold">Tool runs ({toolRuns.length})</span>
        <span className="text-xs text-[var(--edh-muted)]">{summary}</span>
        <span className="ml-auto text-xs text-[var(--edh-muted)]">
          {failed === 0 ? "all exit 0" : `${failed} failed`}
        </span>
      </button>
      {open && (
        <ul>
          {rows.map(({ run, key }) => (
            <ToolRunRow key={key} run={run} />
          ))}
        </ul>
      )}
    </section>
  )
}

function ToolRunRow({ run }: { run: DkimToolRun }) {
  const [open, setOpen] = useState(false)
  const failed = run.error !== null
  return (
    <li
      className={cn(
        "border-t border-[var(--edh-border)]",
        failed && "bg-amber-50", // ENOENT / timeout / bad-output rows render amber (§7)
      )}
    >
      <div className="flex items-center gap-2 px-3 py-2 text-sm">
        <button
          type="button"
          onClick={() => setOpen(!open)}
          aria-expanded={open}
          className="flex min-w-0 flex-1 items-center gap-2 text-left"
        >
          <ChevronDown
            className={cn(
              "h-3.5 w-3.5 shrink-0 text-[var(--edh-muted)] transition-transform",
              !open && "-rotate-90",
            )}
          />
          <span className="w-16 shrink-0 font-medium">{run.tool}</span>
          <code className="truncate font-mono text-xs text-slate-700">$ {run.command}</code>
        </button>
        <span className="shrink-0 text-xs tabular-nums text-[var(--edh-muted)]">
          {run.duration_ms}ms
        </span>
        <span
          className={cn(
            "shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium",
            run.exit_code === 0 ? "bg-slate-100 text-slate-600" : "bg-amber-100 text-amber-800",
          )}
        >
          exit {run.exit_code ?? "—"}
        </span>
        <CopyFixButton text={run.command} label="Copy" />
      </div>
      {failed && (
        <p className="break-all px-3 pb-2 pl-9 font-mono text-xs text-amber-800">{run.error}</p>
      )}
      {open && (
        <pre className="mx-3 mb-2 ml-9 max-h-64 overflow-auto rounded bg-slate-50 p-2 font-mono text-xs text-slate-700">
          {JSON.stringify(run.parsed, null, 2) ?? "null"}
        </pre>
      )}
    </li>
  )
}

/**
 * The domain-level verdict band (pm/checks/dkim.mdx §7 hero): working-selector count, weakest key,
 * and the single primary recommendation from the §8 precedence ladder.
 */
function KeyHealthHero({ dkim, findings }: { dkim?: DkimResults; findings: Finding[] }) {
  const failing = findings.filter((f) => f.severity === "critical" || f.severity === "warning")
  const has = (prefix: string) =>
    failing.some((f) => f.id === prefix || f.id.startsWith(`${prefix}.`))

  const working = dkim?.working_selectors ?? 0
  const probed = dkim?.selectors.length ?? 0
  const rsaBits = (dkim?.selectors ?? [])
    .filter((s) => s.key_type === "rsa" && s.key_bits !== null)
    .map((s) => s.key_bits as number)
  const weakest = rsaBits.length > 0 ? Math.min(...rsaBits) : null

  let verdict: string
  let next: string
  if (!dkim || (probed === 0 && !dkim.discovery_ran)) {
    verdict = "DKIM has not been probed yet."
    next = "Run the audit."
  } else if (dkim.selectors_configured.length === 0 && dkim.discovery_ran && probed === 0) {
    verdict = "No selectors configured and discovery found nothing — mail is likely unsigned."
    next =
      'Read the s= tag from a real message (Gmail "Show original") and add it in the selectors editor below.'
  } else if (dkim.selectors_configured.length === 0 && probed > 0) {
    verdict = `Discovery found ${probed} selector${probed === 1 ? "" : "s"} that ${probed === 1 ? "is" : "are"} not in the monitored list.`
    next = "Import the discovered selector(s) below so every future run audits them."
  } else if (has("dkim.present") || has("dkim.cname_delegation")) {
    verdict =
      "A configured selector has no key in DNS — mail signed with it fails at every receiver."
    next = "Publish the exact TXT/CNAME from your provider (see the failing test below)."
  } else if (has("dkim.parses") || has("dkim.revoked")) {
    verdict = "A published record is unusable (unparseable or revoked) — signatures fail."
    next = "Republish the key exactly as exported, or point the signer at a live selector."
  } else if (has("dkim.algorithm")) {
    verdict = "A key is restricted to SHA-1 — such signatures permanently fail."
    next = "Remove h=sha1 and re-sign with rsa-sha256."
  } else if (has("dkim.keylength")) {
    verdict = `Weakest RSA key is ${weakest}-bit — below the 2048-bit standard.`
    next = "Rotate to 2048-bit RSA on a new selector, then retire the weak one."
  } else if (has("dkim.testflag")) {
    verdict = "A selector is in t=y test mode — receivers treat your mail as unsigned."
    next = "Remove the test flag."
  } else if (has("dkim.ed25519_only")) {
    verdict = "Only Ed25519 keys are published — Gmail/Microsoft/Yahoo cannot verify them."
    next = "Add an RSA-2048 selector and dual-sign."
  } else if (has("dkim.single_record") || has("dkim.record_size") || has("dkim.underscore_label")) {
    verdict = "The DNS record shape is off (extra records, oversize strings, or a wildcard)."
    next = "Clean the DNS: one record per selector, ≤255-byte strings, no wildcard over _domainkey."
  } else if (has("dkim.multi") || has("dkim.rotation")) {
    verdict =
      working === 1
        ? "One working selector — the next key rotation is an outage instead of a cutover."
        : "A key is past the 6-month rotation window."
    next = "Stage a second selector / rotate per M3AAWG (new key ≥48h ahead → switch → revoke)."
  } else if (has("dkim.duplicate_key")) {
    verdict = "The same key is published on more than one domain — shared blast radius."
    next = "Mint a unique key pair per domain."
  } else {
    verdict = `${working} working selector${working === 1 ? "" : "s"}${weakest ? ` · weakest key ${weakest}-bit` : ""} — healthy.`
    next = "Keep monitoring; rotation reminders fire as keys approach 6 months."
  }

  return (
    <div className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
      <div className="flex items-center gap-2 text-sm font-medium text-slate-900">
        <KeyRound className="h-4 w-4 text-[var(--edh-primary)]" />
        {probed > 0
          ? `${working} of ${probed} selector${probed === 1 ? "" : "s"} working${weakest ? ` · weakest key ${weakest}-bit` : ""}`
          : "No selectors probed"}
      </div>
      <p className="mt-2 text-sm text-slate-700">{verdict}</p>
      <p className="mt-1 text-sm font-medium text-[var(--edh-primary)]">Next step: {next}</p>
    </div>
  )
}

/** Key-strength badge colors per pm/checks/dkim.mdx §7 (2048 green / 1024 amber / revoked red). */
function keyBadge(sel: DkimSelectorResult): { label: string; className: string } {
  if (!sel.present) return { label: "missing", className: "bg-red-100 text-red-700" }
  if (sel.is_revoked) return { label: "revoked", className: "bg-red-100 text-red-700" }
  if (!sel.parses) return { label: "unparseable", className: "bg-red-100 text-red-700" }
  if (sel.key_type === "ed25519")
    return { label: "ed25519", className: "bg-slate-200 text-slate-700" }
  if (sel.key_bits === null) return { label: "rsa", className: "bg-slate-200 text-slate-700" }
  if (sel.key_bits >= 2048)
    return { label: `RSA ${sel.key_bits}`, className: "bg-emerald-100 text-emerald-700" }
  if (sel.key_bits >= 1024)
    return { label: `RSA ${sel.key_bits}`, className: "bg-amber-100 text-amber-700" }
  return { label: `RSA ${sel.key_bits}`, className: "bg-red-100 text-red-700" }
}

/** One card per probed selector: verdict badge, resolution chain, raw record, vitals line. */
function SelectorCard({
  sel,
  domainId,
  configured,
}: {
  sel: DkimSelectorResult
  domainId: string
  configured: string[]
}) {
  const [expanded, setExpanded] = useState(false)
  const update = useUpdateDomain()
  const badge = keyBadge(sel)
  const discovered = sel.source === "discovered" && !configured.includes(sel.selector)
  const raw = sel.raw_record ?? ""
  const ageDays = sel.first_seen_at
    ? Math.floor((Date.now() - Date.parse(sel.first_seen_at)) / 86_400_000)
    : null

  const onImport = () =>
    update.mutate({ id: domainId, input: { dkimSelectors: [...configured, sel.selector] } })

  return (
    <section
      className={cn(
        "rounded-lg border bg-white p-4",
        discovered ? "border-dashed border-slate-400" : "border-[var(--edh-border)]",
      )}
    >
      <div className="flex items-center gap-2">
        <h2 className="font-mono text-sm font-semibold">{sel.selector}</h2>
        <span className={cn("rounded px-1.5 py-0.5 text-[11px] font-medium", badge.className)}>
          {badge.label}
        </span>
        {sel.has_test_flag && (
          <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[11px] font-medium text-amber-700">
            t=y
          </span>
        )}
        <span className="ml-auto text-[10px] uppercase text-[var(--edh-muted)]">{sel.source}</span>
      </div>

      <p className="mt-1 break-all font-mono text-xs text-slate-500">
        {sel.query_name}
        {sel.resolved_via === "cname" && sel.cname_target && (
          <>
            {" "}
            →{" "}
            <span className={sel.present ? "" : "text-red-600 line-through"}>
              {sel.cname_target}
            </span>
            {!sel.present && <span className="text-red-600"> (dead)</span>}
          </>
        )}
      </p>

      {raw ? (
        <div className="mt-2">
          <p
            className={cn(
              "break-all rounded-md bg-slate-50 p-2 font-mono text-xs text-slate-700",
              !expanded && "line-clamp-2",
            )}
          >
            {raw}
          </p>
          <div className="mt-1 flex items-center gap-2">
            {raw.length > 160 && (
              <button
                type="button"
                onClick={() => setExpanded(!expanded)}
                className="text-xs text-[var(--edh-muted)] underline hover:text-slate-700"
              >
                {expanded ? "collapse" : "expand"}
              </button>
            )}
            <CopyFixButton text={raw} label="Copy record" />
          </div>
        </div>
      ) : (
        <p className="mt-2 text-sm text-red-600">No record published.</p>
      )}

      <p className="mt-2 text-xs text-[var(--edh-muted)]">
        {[
          ageDays !== null ? `key age ${ageDays}d` : null,
          sel.has_test_flag ? "t=y test mode" : "no t=y",
          `${sel.txt_record_count} TXT record${sel.txt_record_count === 1 ? "" : "s"}`,
          sel.oversize_chunk ? "oversize string" : null,
        ]
          .filter(Boolean)
          .join(" · ")}
      </p>

      {discovered && (
        <button
          type="button"
          onClick={onImport}
          disabled={update.isPending}
          className="mt-2 inline-flex items-center gap-1 rounded-md border border-[var(--edh-primary)] px-2 py-1 text-xs font-medium text-[var(--edh-primary)] hover:bg-[var(--edh-primary)]/5 disabled:opacity-50"
        >
          <Plus className="h-3.5 w-3.5" /> Add to monitored
        </button>
      )}
    </section>
  )
}

/**
 * The per-domain config input (pm/checks/dkim.mdx §6.2 item 6): selector chips with remove, an add
 * field, and the "Run discovery now" action — a live probe of the §4 MX-guided common-selector
 * wordlist whose hits are offered for one-click import. Edits affect FUTURE runs only; the run on
 * screen is immutable history.
 */
function SelectorsEditor({
  domainId,
  domainName,
  selectors,
  scanning,
}: {
  domainId: string
  domainName: string
  selectors: string[]
  scanning: boolean
}) {
  const [draft, setDraft] = useState("")
  const update = useUpdateDomain()
  const discovery = useDkimDiscovery()

  const save = (next: string[]) => update.mutate({ id: domainId, input: { dkimSelectors: next } })
  const add = () => {
    const s = draft.trim().toLowerCase()
    if (!s || selectors.includes(s)) return
    save([...selectors, s])
    setDraft("")
  }

  const outcome = discovery.data
  const newHits = (outcome?.hits ?? []).filter((h) => !selectors.includes(h.selector))

  return (
    <section className="mt-6 rounded-lg border border-[var(--edh-border)] bg-white p-4">
      <div className="flex items-center justify-between">
        <h2 className="font-semibold">Selectors</h2>
        <button
          type="button"
          onClick={() => discovery.mutate(domainId)}
          disabled={scanning || discovery.isPending}
          className="inline-flex items-center gap-1 text-sm text-[var(--edh-primary)] underline disabled:opacity-50"
          title="Probes 40+ common selector names (MX-guided first) and offers one-click import of hits"
        >
          {discovery.isPending && <RefreshCw className="h-3.5 w-3.5 animate-spin" />}
          Run discovery now
        </button>
      </div>
      {selectors.length === 0 && (
        <p className="mt-2 rounded-md bg-sky-50 p-2 text-sm text-sky-800">
          No selectors configured — discovery probes common selectors on every run; add yours for
          precise auditing of {domainName}.
        </p>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        {selectors.map((s) => (
          <span
            key={s}
            className="inline-flex items-center gap-1 rounded-full border border-[var(--edh-border)] bg-slate-50 px-2.5 py-1 font-mono text-xs"
          >
            {s}
            <button
              type="button"
              onClick={() => save(selectors.filter((x) => x !== s))}
              aria-label={`Remove selector ${s}`}
              className="text-[var(--edh-muted)] hover:text-red-600"
            >
              <X className="h-3 w-3" />
            </button>
          </span>
        ))}
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && add()}
          placeholder="add selector…"
          className="w-32 rounded-md border border-[var(--edh-border)] px-2 py-1 font-mono text-xs focus:outline-none focus:ring-1 focus:ring-[var(--edh-primary)]"
        />
        <button
          type="button"
          onClick={add}
          disabled={!draft.trim() || update.isPending}
          className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs hover:bg-slate-50 disabled:opacity-50"
        >
          <Plus className="h-3.5 w-3.5" /> Add
        </button>
      </div>

      {/* Discovery results (§6.2 item 6): hits offered for one-click import. */}
      {discovery.isError && (
        <p className="mt-3 rounded-md bg-amber-50 p-2 text-sm text-amber-800">
          Discovery failed — check that the backend is reachable, then try again.
        </p>
      )}
      {outcome?.wildcard_shadow && (
        <p className="mt-3 rounded-md bg-amber-50 p-2 text-sm text-amber-800">
          A wildcard TXT record answers every selector name for {domainName} — discovery results are
          unreliable and were suppressed. Remove or scope the wildcard, then retry.
        </p>
      )}
      {outcome && !outcome.wildcard_shadow && outcome.hits.length === 0 && (
        <p className="mt-3 text-sm text-[var(--edh-muted)]">
          No published keys found at {outcome.probed} common selector names. If mail signs with a
          custom selector, read the s= tag from a real message (Gmail "Show original") and add it
          above.
        </p>
      )}
      {outcome && !outcome.wildcard_shadow && outcome.hits.length > 0 && (
        <div className="mt-3 rounded-md border border-dashed border-slate-300 p-2">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium uppercase text-[var(--edh-muted)]">
              Discovered selector{outcome.hits.length === 1 ? "" : "s"}
            </p>
            {newHits.length > 1 && (
              <button
                type="button"
                onClick={() => save([...selectors, ...newHits.map((h) => h.selector)])}
                disabled={update.isPending}
                className="text-xs text-[var(--edh-primary)] underline disabled:opacity-50"
              >
                Import all
              </button>
            )}
          </div>
          <ul className="mt-2 flex flex-wrap gap-2">
            {outcome.hits.map((hit) => {
              const already = selectors.includes(hit.selector)
              const keyLabel = hit.is_revoked
                ? "revoked"
                : hit.key_type === "rsa" && hit.key_bits
                  ? `RSA ${hit.key_bits}`
                  : (hit.key_type ?? "key")
              return (
                <li
                  key={hit.selector}
                  className="inline-flex items-center gap-1.5 rounded-full border border-[var(--edh-border)] bg-slate-50 px-2.5 py-1 text-xs"
                >
                  <span className="font-mono">{hit.selector}</span>
                  <span className={hit.is_revoked ? "text-red-600" : "text-[var(--edh-muted)]"}>
                    {keyLabel}
                  </span>
                  {already ? (
                    <span className="text-[var(--edh-muted)]">monitored</span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => save([...selectors, hit.selector])}
                      disabled={update.isPending}
                      className="inline-flex items-center gap-0.5 font-medium text-[var(--edh-primary)] hover:underline disabled:opacity-50"
                    >
                      <Plus className="h-3 w-3" /> Add
                    </button>
                  )}
                </li>
              )
            })}
          </ul>
        </div>
      )}
    </section>
  )
}

/**
 * The §6.2 loading state: skeleton header + hero + two selector cards + table rows, mirroring the
 * loaded layout so there is no layout shift when the data lands.
 */
function DkimPageSkeleton() {
  return (
    <div
      className="mx-auto max-w-5xl animate-pulse"
      role="status"
      aria-busy="true"
      aria-label="Loading DKIM run"
    >
      <div className="mb-4 flex items-center justify-between">
        <div className="h-4 w-32 rounded bg-slate-200" />
        <div className="h-9 w-48 rounded-md bg-slate-200" />
      </div>
      <div className="h-8 w-24 rounded bg-slate-200" />
      <div className="mt-2 h-4 w-72 rounded bg-slate-200" />
      <div className="mt-4 h-24 rounded-lg border border-[var(--edh-border)] bg-slate-100" />
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div className="h-36 rounded-lg border border-[var(--edh-border)] bg-slate-100" />
        <div className="h-36 rounded-lg border border-[var(--edh-border)] bg-slate-100" />
      </div>
      <div className="mt-4 overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
        {["a", "b", "c", "d"].map((k) => (
          <div key={k} className="border-t border-[var(--edh-border)] px-3 py-3 first:border-t-0">
            <div className="h-4 w-3/4 rounded bg-slate-100" />
          </div>
        ))}
      </div>
    </div>
  )
}

/** Fail-first table of every DKIM test, expandable to observed evidence + the copyable fix. */
function TestResultsTable({ findings }: { findings: Finding[] }) {
  const sorted = [...findings].sort((a, b) => ORDER[a.severity] - ORDER[b.severity])
  const counts = {
    pass: findings.filter((f) => f.severity === "ok").length,
    fail: findings.filter((f) => f.severity === "critical").length,
    warn: findings.filter((f) => f.severity === "warning").length,
    info: findings.filter((f) => f.severity === "info").length,
  }
  return (
    <section className="mt-4">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="font-semibold">Test results</h2>
        <span className="text-xs text-[var(--edh-muted)]">
          {counts.pass} passed · {counts.fail} failed · {counts.warn} warnings · {counts.info} info
        </span>
      </div>
      <div className="overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
        {sorted.length === 0 ? (
          <p className="p-4 text-sm text-slate-600">No DKIM tests in the latest run.</p>
        ) : (
          <ul>
            {sorted.map((f) => (
              <TestRow key={f.id + f.title} finding={f} />
            ))}
          </ul>
        )}
      </div>
    </section>
  )
}

function TestRow({ finding: f }: { finding: Finding }) {
  const [open, setOpen] = useState(f.severity === "critical")
  const icon =
    f.severity === "ok" ? (
      <ShieldCheck className="h-4 w-4 text-emerald-600" />
    ) : f.severity === "info" ? (
      <Info className="h-4 w-4 text-sky-600" />
    ) : (
      <ShieldAlert
        className={cn("h-4 w-4", f.severity === "critical" ? "text-red-600" : "text-amber-500")}
      />
    )
  return (
    <li className="border-t border-[var(--edh-border)] first:border-t-0">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-slate-50"
      >
        {icon}
        <span className="font-mono text-xs uppercase text-[var(--edh-muted)]">{f.id}</span>
        <span className="font-medium">{f.title}</span>
        <ChevronDown
          className={cn(
            "ml-auto h-4 w-4 shrink-0 text-[var(--edh-muted)] transition-transform",
            open && "rotate-180",
          )}
        />
      </button>
      {open && (
        <div className="px-3 pb-3 pl-9">
          <p className="text-sm text-slate-600">{f.detail}</p>
          {f.evidence && (
            <p className="mt-1 break-all rounded bg-slate-50 p-2 font-mono text-xs text-slate-600">
              observed: {f.evidence}
            </p>
          )}
          {f.remediation && f.severity !== "ok" && (
            <div className="mt-2 flex items-start justify-between gap-2 rounded-md bg-slate-50 p-2 text-sm text-slate-700">
              <span className="flex items-start gap-2">
                <Wrench className="mt-0.5 h-4 w-4 shrink-0 text-[var(--edh-primary)]" />
                <span>
                  <span className="font-medium">Fix: </span>
                  {f.remediation}
                </span>
              </span>
              <CopyFixButton text={f.evidence ?? f.remediation} />
            </div>
          )}
        </div>
      )}
    </li>
  )
}
