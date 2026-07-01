import { Wrench } from "lucide-react"
import type { Finding } from "@/api/types"
import { SeverityBadge } from "./Badges"

/**
 * Render a domain's audit findings. Problems (warning/critical) sort to the top; each shows its
 * detail, the DNS evidence, and — the whole point of the app — the concrete remediation.
 */
const ORDER = { critical: 0, warning: 1, info: 2, ok: 3 } as const

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
                <span className="font-medium">{f.title}</span>
                <span className="text-xs uppercase text-[var(--edh-muted)]">{f.checkId}</span>
              </div>
              <p className="mt-1 text-sm text-slate-600">{f.detail}</p>
              {f.evidence && (
                <p className="mt-1 break-all font-mono text-xs text-slate-500">{f.evidence}</p>
              )}
              {f.remediation && (
                <div className="mt-2 flex items-start gap-2 rounded-md bg-slate-50 p-2 text-sm text-slate-700">
                  <Wrench className="mt-0.5 h-4 w-4 shrink-0 text-[var(--edh-primary)]" />
                  <span>
                    <span className="font-medium">Fix: </span>
                    {f.remediation}
                  </span>
                </div>
              )}
            </div>
          </div>
        </li>
      ))}
    </ul>
  )
}
