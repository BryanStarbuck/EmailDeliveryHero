import { Link, useNavigate, useParams } from "@tanstack/react-router"
import {
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  Info,
  KeyRound,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Wrench,
  X,
} from "lucide-react"
import { useState } from "react"
import { useAuditResults } from "@/api/audit"
import { useDomains, useUpdateDomain } from "@/api/domains"
import type { DkimResults, DkimSelectorResult, Finding, Severity } from "@/api/types"
import { CopyFixButton } from "@/components/CopyFixButton"
import { StatusCell } from "@/components/StatusCell"
import { NEVER_CELL, rollupCategories } from "@/lib/categories"
import { matchProblemStates } from "@/lib/dkim-problems"
import { cn } from "@/lib/utils"
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext"

const ORDER: Record<Severity, number> = { critical: 0, warning: 1, info: 2, ok: 3 }

/**
 * The full-page DKIM view (pm/checks/dkim.mdx §6.2/§7) — everything about one domain's DKIM: the
 * key-health hero, one card per selector (resolution chain, raw record, key badges), the fail-first
 * test-results table with observed DNS values and copyable fixes, the selectors editor with
 * discovery import, and problem-state cards linking to the per-problem drill-down pages.
 */
export function DkimPage() {
  const { id = "" } = useParams({ strict: false }) as { id?: string }
  const { data: domains } = useDomains()
  const { data: results } = useAuditResults()
  const runDomains = useScanRunner()
  const scanning = useScanProgress().some((s) => s.domainId === id)
  const navigate = useNavigate()

  const domain = (domains ?? []).find((d) => d.id === id)
  const result = (results ?? []).find((r) => r.domainId === id)
  const findings = (result?.findings ?? []).filter((f) => f.checkId === "dkim")
  const dkim = result?.results?.dkim
  const cell = rollupCategories(result?.findings).dkim ?? NEVER_CELL
  const problems = matchProblemStates(findings)

  const onRunAgain = () => runDomains([{ id, name: domain?.name ?? id }])

  return (
    <div className="mx-auto max-w-5xl">
      <div className="mb-4 flex items-center justify-between">
        <button
          type="button"
          onClick={() => navigate({ to: "/domains/$id", params: { id } })}
          className="inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
        >
          <ArrowLeft className="h-4 w-4" /> Back to {domain?.name ?? id}
        </button>
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

      <h1 className="text-2xl font-bold">DKIM</h1>
      <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-[var(--edh-muted)]">
        <span className="font-medium text-slate-900">{domain?.name ?? id}</span>
        <span className="w-32">
          <StatusCell status={cell} />
        </span>
        {result && <span>· ran {new Date(result.ranAt).toLocaleString()}</span>}
      </div>

      {!result ? (
        <div className="mt-6 rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center">
          <p className="text-slate-600">No audit yet.</p>
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

          <SelectorsEditor
            domainId={id}
            domainName={domain?.name ?? id}
            selectors={domain?.dkimSelectors ?? []}
            scanning={scanning}
            onRunDiscovery={onRunAgain}
          />

          {problems.length > 0 && (
            <section className="mt-6">
              <h2 className="mb-2 font-semibold">Problem states</h2>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {problems.map((ps) => (
                  <Link
                    key={ps.id}
                    to="/domains/$id/dkim/$problemId"
                    params={{ id, problemId: ps.id }}
                    className="group rounded-lg border border-[var(--edh-border)] bg-white p-4 hover:border-[var(--edh-primary)]"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold uppercase text-[var(--edh-muted)]">
                        {ps.id}
                      </span>
                      <ChevronRight className="h-4 w-4 text-[var(--edh-muted)] group-hover:text-[var(--edh-primary)]" />
                    </div>
                    <div className="mt-1 font-medium">{ps.title}</div>
                    <p className="mt-1 text-sm text-slate-600">{ps.hook}</p>
                  </Link>
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
 * The per-domain config input (pm/checks/dkim.mdx §6.2 item 5): selector chips with remove, an add
 * field, and a run-discovery action (discovery runs automatically when the list is empty).
 */
function SelectorsEditor({
  domainId,
  domainName,
  selectors,
  scanning,
  onRunDiscovery,
}: {
  domainId: string
  domainName: string
  selectors: string[]
  scanning: boolean
  onRunDiscovery: () => void
}) {
  const [draft, setDraft] = useState("")
  const update = useUpdateDomain()

  const save = (next: string[]) => update.mutate({ id: domainId, input: { dkimSelectors: next } })
  const add = () => {
    const s = draft.trim().toLowerCase()
    if (!s || selectors.includes(s)) return
    save([...selectors, s])
    setDraft("")
  }

  return (
    <section className="mt-6 rounded-lg border border-[var(--edh-border)] bg-white p-4">
      <div className="flex items-center justify-between">
        <h2 className="font-semibold">Selectors</h2>
        <button
          type="button"
          onClick={onRunDiscovery}
          disabled={scanning}
          className="text-sm text-[var(--edh-primary)] underline disabled:opacity-50"
          title="Discovery probes 40+ common selector names when no selectors are configured"
        >
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
    </section>
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
