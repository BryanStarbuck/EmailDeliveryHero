import { useNavigate } from "@tanstack/react-router"
import { ArrowUpRight, ChevronRight, Pencil, Play, Plus, Trash2, X } from "lucide-react"
import { useEffect, useState } from "react"
import { toast } from "sonner"
import { useAuditResults, useRunAudit } from "@/api/audit"
import {
  type CreateDomainInput,
  useCreateDomain,
  useDeleteDomain,
  useDomains,
  useUpdateDomain,
} from "@/api/domains"
import type { MonitoredDomain } from "@/api/types"
import { StatusCell } from "@/components/StatusCell"
import { CATEGORIES, NEVER_CELL, rollupCategories } from "@/lib/categories"

/**
 * The Domains CRUD surface (pm/ui.mdx §6). A table of monitored domains, each row showing its six
 * latest category cells and per-row actions (run audit now, edit, remove, open detail), plus an
 * Add/Edit dialog. The audit engine reads this list.
 */
export function DomainsPage() {
  const { data: domains } = useDomains()
  const { data: results } = useAuditResults()
  const del = useDeleteDomain()
  const run = useRunAudit()
  const navigate = useNavigate()

  const [dialog, setDialog] = useState<
    { mode: "add" } | { mode: "edit"; domain: MonitoredDomain } | null
  >(null)

  const byId = new Map((results ?? []).map((r) => [r.domainId, r]))
  const list = domains ?? []

  const onRemove = (d: MonitoredDomain) => {
    if (!window.confirm(`Remove ${d.name}? This also removes its audit history.`)) return
    del.mutate(d.id, {
      onSuccess: () => toast.success(`Removed ${d.name}`),
      onError: (err) => toast.error(errMsg(err, "Could not remove domain")),
    })
  }

  const onRunNow = (d: MonitoredDomain) =>
    run.mutate(d.id, {
      onSuccess: () => toast.success(`Audited ${d.name}`),
      onError: () => toast.error(`Audit failed for ${d.name}`),
    })

  return (
    <div className="mx-auto max-w-6xl">
      <header className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Domains</h1>
          <p className="text-sm text-[var(--edh-muted)]">
            The email-sending domains you monitor for deliverability.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setDialog({ mode: "add" })}
          className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-2 text-sm font-medium text-white"
        >
          <Plus className="h-4 w-4" /> Add domain
        </button>
      </header>

      <div className="overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 text-left text-xs uppercase text-[var(--edh-muted)]">
            <tr>
              <th className="px-4 py-2">Domain</th>
              {CATEGORIES.map((c) => (
                <th key={c.key} className="px-2 py-2 text-center">
                  {c.header}
                </th>
              ))}
              <th className="px-4 py-2 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {list.map((d) => {
              const cells = rollupCategories(byId.get(d.id)?.findings)
              const running = run.isPending && run.variables === d.id
              return (
                <tr key={d.id} className="border-t border-[var(--edh-border)]">
                  <td className="px-4 py-3 font-medium">
                    <button
                      type="button"
                      onClick={() => navigate({ to: "/domains/$id", params: { id: d.id } })}
                      className="hover:underline"
                    >
                      {d.name}
                    </button>
                  </td>
                  {CATEGORIES.map((c) => (
                    <td key={c.key} className="px-2 py-2">
                      <StatusCell status={cells[c.key] ?? NEVER_CELL} />
                    </td>
                  ))}
                  <td className="px-4 py-2">
                    <div className="flex items-center justify-end gap-1 text-slate-500">
                      <IconBtn label="Run audit now" onClick={() => onRunNow(d)} disabled={running}>
                        <Play className={running ? "h-4 w-4 animate-pulse" : "h-4 w-4"} />
                      </IconBtn>
                      <IconBtn label="Edit" onClick={() => setDialog({ mode: "edit", domain: d })}>
                        <Pencil className="h-4 w-4" />
                      </IconBtn>
                      <IconBtn label="Remove" onClick={() => onRemove(d)}>
                        <Trash2 className="h-4 w-4 text-red-600" />
                      </IconBtn>
                      <IconBtn
                        label="Open run detail"
                        onClick={() => navigate({ to: "/domains/$id", params: { id: d.id } })}
                      >
                        <ArrowUpRight className="h-4 w-4" />
                      </IconBtn>
                    </div>
                  </td>
                </tr>
              )
            })}
            {list.length === 0 && (
              <tr>
                <td
                  colSpan={CATEGORIES.length + 2}
                  className="px-4 py-8 text-center text-[var(--edh-muted)]"
                >
                  No domains yet — click “Add domain”.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {dialog && (
        <DomainDialog
          domain={dialog.mode === "edit" ? dialog.domain : undefined}
          onClose={() => setDialog(null)}
        />
      )}
    </div>
  )
}

function IconBtn({
  label,
  onClick,
  disabled,
  children,
}: {
  label: string
  onClick: () => void
  disabled?: boolean
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      disabled={disabled}
      className="rounded p-1.5 hover:bg-slate-100 disabled:opacity-40"
    >
      {children}
    </button>
  )
}

/** Add (no domain) or Edit (domain given) dialog. Add posts a new record; Edit patches selectors/IPs. */
function DomainDialog({ domain, onClose }: { domain?: MonitoredDomain; onClose: () => void }) {
  const create = useCreateDomain()
  const update = useUpdateDomain()
  const editing = Boolean(domain)

  const [name, setName] = useState(domain?.name ?? "")
  const [selectors, setSelectors] = useState((domain?.dkimSelectors ?? []).join(", "))
  const [ips, setIps] = useState((domain?.sendingIps ?? []).join(", "))
  // The two optional fields live behind an "Advanced" disclosure. Collapsed by default when adding
  // (only the domain is required); expanded when editing, since selectors/IPs are the point of editing.
  const [showAdvanced, setShowAdvanced] = useState(editing)

  // Close on Escape (the modal backdrop is non-interactive for a11y; use Escape or the X button).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose()
    }
    document.addEventListener("keydown", onKey)
    return () => document.removeEventListener("keydown", onKey)
  }, [onClose])

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (editing && domain) {
      update.mutate(
        {
          id: domain.id,
          input: { dkimSelectors: splitList(selectors), sendingIps: splitList(ips) },
        },
        {
          onSuccess: () => {
            toast.success(`Updated ${domain.name}`)
            onClose()
          },
          onError: (err) => toast.error(errMsg(err, "Could not update domain")),
        },
      )
      return
    }
    const input: CreateDomainInput = {
      name: name.trim(),
      dkimSelectors: splitList(selectors),
      sendingIps: splitList(ips),
    }
    create.mutate(input, {
      onSuccess: () => {
        toast.success(`Now monitoring ${input.name}`)
        onClose()
      },
      onError: (err) => toast.error(errMsg(err, "Could not add domain")),
    })
  }

  const pending = create.isPending || update.isPending

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4">
      <div className="w-full max-w-lg rounded-lg border border-[var(--edh-border)] bg-white p-5 shadow-xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">
            {editing ? `Edit ${domain?.name}` : "Add domain"}
          </h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="rounded p-1 hover:bg-slate-100"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <form onSubmit={onSubmit} className="grid gap-3">
          <label className="text-sm">
            <span className="mb-1 block font-medium">Domain</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              disabled={editing}
              placeholder="whitehatengineering.com"
              className="w-full rounded-md border border-[var(--edh-border)] px-3 py-2 disabled:bg-slate-50"
            />
          </label>
          <button
            type="button"
            onClick={() => setShowAdvanced((v) => !v)}
            aria-expanded={showAdvanced}
            className="-mx-1 flex items-center gap-1 rounded px-1 py-1 text-left text-sm font-medium text-[var(--edh-muted)] hover:bg-slate-50"
          >
            <ChevronRight
              className={`h-4 w-4 transition-transform ${showAdvanced ? "rotate-90" : ""}`}
            />
            Advanced (optional)
          </button>
          {showAdvanced && (
            <div className="grid gap-3">
              <label className="text-sm">
                <span className="mb-1 block font-medium">DKIM selectors (comma-separated)</span>
                <input
                  value={selectors}
                  onChange={(e) => setSelectors(e.target.value)}
                  placeholder="google, s1"
                  className="w-full rounded-md border border-[var(--edh-border)] px-3 py-2"
                />
              </label>
              <label className="text-sm">
                <span className="mb-1 block font-medium">Sending IPs (comma-separated)</span>
                <input
                  value={ips}
                  onChange={(e) => setIps(e.target.value)}
                  placeholder="203.0.113.10"
                  className="w-full rounded-md border border-[var(--edh-border)] px-3 py-2"
                />
              </label>
            </div>
          )}
          <div className="mt-1 flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md border border-[var(--edh-border)] px-4 py-2 text-sm hover:bg-slate-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={pending}
              className="rounded-md bg-[var(--edh-primary)] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
            >
              {pending ? "Saving…" : editing ? "Save changes" : "Add domain"}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function splitList(raw: string): string[] {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
}

function errMsg(err: unknown, fallback: string): string {
  const e = err as { response?: { data?: { message?: string | string[] } } }
  const m = e?.response?.data?.message
  if (Array.isArray(m)) return m.join(", ")
  return m ?? fallback
}
