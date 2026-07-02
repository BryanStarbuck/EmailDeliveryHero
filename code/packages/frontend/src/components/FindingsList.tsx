import { Wrench } from "lucide-react"
import type { Finding } from "@/api/types"
import { NewProblemBadge, SeverityBadge } from "./Badges"
import { CopyFixButton } from "./CopyFixButton"

/**
 * Render a domain's audit findings using the common finding-presentation pattern (pm/ui.mdx §1.4).
 * Problems (warning/critical) sort to the top; each shows its detail, the DNS evidence, and — the
 * whole point of the app — the concrete remediation with a Copy-fix button so the user pastes the
 * exact record without retyping.
 */
const ORDER = { critical: 0, warning: 1, info: 2, ok: 3 } as const

const URL_RE = /(https?:\/\/[^\s)"'<>\]]+)/g

/**
 * Remediation text with any URL rendered as a clickable deep-link (pm/ui.mdx §5) — e.g. a blacklist
 * critical's specific removal/delisting page — so the user can jump straight to the fix.
 */
export function RemediationText({ text }: { text: string }) {
  const parts = text.split(URL_RE)
  return (
    <>
      {parts.map((part, i) => {
        const key = `${i}:${part.slice(0, 24)}`
        if (i % 2 === 0) return <span key={key}>{part}</span>
        // Trailing sentence punctuation belongs to the prose, not the URL.
        const trimmed = part.replace(/[.,;]+$/, "")
        const rest = part.slice(trimmed.length)
        return (
          <span key={key}>
            <a
              href={trimmed}
              target="_blank"
              rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="break-all text-[var(--edh-primary)] underline"
            >
              {trimmed}
            </a>
            {rest}
          </span>
        )
      })}
    </>
  )
}

export function FindingsList({ findings }: { findings: Finding[] }) {
  const sorted = [...findings].sort((a, b) => ORDER[a.severity] - ORDER[b.severity])
  return (
    <ul className="space-y-3">
      {sorted.map((f) => (
        <li
          key={f.id}
          className="rounded-lg border border-[var(--edh-border)] bg-white p-4 shadow-sm"
        >
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={f.severity} />
                {f.isNew && <NewProblemBadge />}
                <span className="font-medium">{f.title}</span>
                <span className="text-xs uppercase text-[var(--edh-muted)]">{f.checkId}</span>
              </div>
              <p className="mt-1 text-sm text-slate-600">{f.detail}</p>
              {f.evidence && (
                <p className="mt-1 break-all font-mono text-xs text-slate-500">{f.evidence}</p>
              )}
              {f.remediation && (
                <div className="mt-2 flex items-start justify-between gap-2 rounded-md bg-slate-50 p-2 text-sm text-slate-700">
                  <span className="flex items-start gap-2">
                    <Wrench className="mt-0.5 h-4 w-4 shrink-0 text-[var(--edh-primary)]" />
                    <span>
                      <span className="font-medium">Fix: </span>
                      <RemediationText text={f.remediation} />
                    </span>
                  </span>
                  {f.severity !== "ok" && <CopyFixButton text={f.evidence ?? f.remediation} />}
                </div>
              )}
            </div>
          </div>
        </li>
      ))}
    </ul>
  )
}
