import { ChevronDown, Info, ShieldAlert, ShieldCheck, Wrench } from "lucide-react"
import { useState } from "react"
import type { Finding, Severity } from "@/api/types"
import { CopyFixButton } from "@/components/CopyFixButton"
import { cn } from "@/lib/utils"

const ORDER: Record<Severity, number> = { critical: 0, warning: 1, info: 2, ok: 3 }

/**
 * The fail-first per-technology test-results table (pm/checks/*.mdx §6/§7): one row per finding,
 * pass and fail alike, expandable to the observed evidence and the copyable fix. Shared by the
 * DMARC and SPF full pages.
 */
export function TestResultsTable({
  findings,
  emptyText = "No tests in the latest run.",
  expectedById,
  titleLinkFor,
}: {
  findings: Finding[]
  emptyText?: string
  /**
   * Optional expected-DNS-value per finding id (pm/checks/dmarc.mdx §6.2 item 4 — the expanded
   * row shows observed AND expected, e.g. `<auth_name> TXT "v=DMARC1"`).
   */
  expectedById?: Map<string, string>
  /**
   * Optional deep link per finding id (pm/checks/dmarc.mdx §6.2 item 5): when it returns a
   * navigate callback, the test name renders as a link to the owning sub-test explainer page;
   * ids with no owning unit (e.g. `dmarc.tool_missing`) return undefined and stay plain text.
   */
  titleLinkFor?: (findingId: string) => (() => void) | undefined
}) {
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
          <p className="p-4 text-sm text-slate-600">{emptyText}</p>
        ) : (
          <ul>
            {sorted.map((f) => (
              <TestRow
                key={f.id + f.title}
                finding={f}
                expected={expectedById?.get(f.id)}
                titleLink={titleLinkFor?.(f.id)}
              />
            ))}
          </ul>
        )}
      </div>
    </section>
  )
}

function TestRow({
  finding: f,
  expected,
  titleLink,
}: {
  finding: Finding
  expected?: string
  titleLink?: () => void
}) {
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
        {titleLink ? (
          <span
            role="link"
            tabIndex={0}
            onClick={(e) => {
              e.stopPropagation()
              titleLink()
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.stopPropagation()
                titleLink()
              }
            }}
            className="font-medium text-[var(--edh-primary)] underline-offset-2 hover:underline"
          >
            {f.title}
          </span>
        ) : (
          <span className="font-medium">{f.title}</span>
        )}
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
          {expected && (
            <p className="mt-1 break-all rounded bg-slate-50 p-2 font-mono text-xs text-slate-600">
              expected: {expected}
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
