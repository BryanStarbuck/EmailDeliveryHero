import { useNavigate, useSearch } from "@tanstack/react-router"
import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  type SortingState,
  useReactTable,
} from "@tanstack/react-table"
import {
  ArrowUpDown,
  ArrowUpRight,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  Trash2,
  X,
} from "lucide-react"
import { useEffect, useMemo, useState } from "react"
import { toast } from "sonner"
import { useAuditResults } from "@/api/audit"
import {
  type CreateDomainInput,
  useCreateDomain,
  useDeleteDomain,
  useDomains,
  useUpdateDomain,
} from "@/api/domains"
import type { ArcForwarderConfig, MonitoredDomain } from "@/api/types"
import { StatusCell } from "@/components/StatusCell"
import { CATEGORIES, type CategoryKey, type CellStatus, rollupCategories } from "@/lib/categories"
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext"

/** One table row: the monitored domain plus its six latest category cells (pm/domains.mdx §3.1). */
interface DomainRow {
  domain: MonitoredDomain
  cells: Record<CategoryKey, CellStatus>
  running: boolean
}

/** Per-column header/cell classes (Domain left, category + Scheduled centered, Actions right). */
const TH_CLASS: Record<string, string> = {
  name: "px-4 py-2 text-left",
  scheduleEnabled: "px-2 py-2 text-center",
  actions: "px-4 py-2 text-right",
}
const TD_CLASS: Record<string, string> = {
  name: "px-4 py-3",
  scheduleEnabled: "px-2 py-2 text-center",
  actions: "px-4 py-2",
}

/**
 * The Domains CRUD surface (pm/domains.mdx). A TanStack Table of monitored domains — one row per
 * domain — each row showing its six latest LOCKED category cells (same colors as the Dashboard),
 * its per-domain scheduled-checks toggle (ANDed with the global switch, §6), and per-row actions
 * (run audit now, edit, remove behind a confirm dialog, open run history). Plus the header's
 * Run all + Add domain buttons and the Add/Edit dialog with an Advanced (optional) disclosure.
 */
export function DomainsPage() {
  const { data: domains } = useDomains()
  const { data: results } = useAuditResults()
  const del = useDeleteDomain()
  const update = useUpdateDomain()
  const runDomains = useScanRunner()
  const activeScans = useScanProgress()
  const navigate = useNavigate()

  const [dialog, setDialog] = useState<
    { mode: "add" } | { mode: "edit"; domain: MonitoredDomain } | null
  >(null)
  const [confirmRemove, setConfirmRemove] = useState<MonitoredDomain | null>(null)
  // Default sort: alphabetically by domain (pm/domains.mdx §3.1); headers toggle it.
  const [sorting, setSorting] = useState<SortingState>([{ id: "name", desc: false }])

  // `?edit=<domainId>` (the dashboard row-menu's "Edit domain", pm/dashboard.mdx §4.3) opens that
  // domain's editor; `?new` (pm/domains.mdx §1 — the /domains/new Add form) opens the Add dialog.
  // Both clear the param once handled so refresh/back don't re-open the dialog.
  const search = useSearch({ strict: false }) as { edit?: string; new?: boolean }
  useEffect(() => {
    if (search.new) {
      setDialog({ mode: "add" })
      navigate({ to: "/domains", search: {}, replace: true })
      return
    }
    if (!search.edit || !domains) return
    const domain = domains.find((d) => d.id === search.edit)
    if (domain) setDialog({ mode: "edit", domain })
    navigate({ to: "/domains", search: {}, replace: true })
  }, [search.new, search.edit, domains, navigate])

  const list = domains ?? []
  const scanning = activeScans.length > 0

  const rows: DomainRow[] = useMemo(() => {
    const byId = new Map((results ?? []).map((r) => [r.domainId, r]))
    return list.map((d) => ({
      domain: d,
      cells: rollupCategories(byId.get(d.id)?.findings),
      running: activeScans.some((s) => s.domainId === d.id),
    }))
  }, [list, results, activeScans])

  const onConfirmRemove = (d: MonitoredDomain) =>
    del.mutate(d.id, {
      onSuccess: () => {
        toast.success(`Removed ${d.name}`)
        setConfirmRemove(null)
      },
      onError: (err) => toast.error(errMsg(err, "Could not remove domain")),
    })

  // One card in the scan dock; the shared runner toasts and refreshes cells when it finishes.
  const onRunNow = (d: MonitoredDomain) => runDomains([{ id: d.id, name: d.name }])

  // Per-domain recurring-checks toggle (pm/domains.mdx §6); optimistic PATCH, invalidates the list.
  const onToggleSchedule = (d: MonitoredDomain) =>
    update.mutate(
      { id: d.id, input: { scheduleEnabled: !d.scheduleEnabled } },
      { onError: (err) => toast.error(errMsg(err, "Could not update schedule")) },
    )

  const openDetail = (d: MonitoredDomain) => navigate({ to: "/domains/$id", params: { id: d.id } })

  // Nine columns (pm/domains.mdx §3.2): Domain, the six LOCKED categories, Scheduled, Actions.
  const columns: ColumnDef<DomainRow>[] = [
    {
      id: "name",
      accessorFn: (r) => r.domain.name,
      header: "Domain",
      cell: ({ row }) => (
        <div className="flex flex-col">
          <span className="font-medium">{row.original.domain.name}</span>
          {row.original.domain.label && (
            <span className="text-xs font-normal text-[var(--edh-muted)]">
              {row.original.domain.label}
            </span>
          )}
        </div>
      ),
    },
    ...CATEGORIES.map<ColumnDef<DomainRow>>((c) => ({
      id: c.key,
      accessorFn: (r: DomainRow) => r.cells[c.key],
      header: c.header,
      enableSorting: false,
      cell: ({ row }) => <StatusCell status={row.original.cells[c.key]} />,
    })),
    {
      id: "scheduleEnabled",
      accessorFn: (r) => r.domain.scheduleEnabled,
      header: "Scheduled",
      cell: ({ row }) => (
        <ScheduleToggle
          enabled={row.original.domain.scheduleEnabled}
          onToggle={() => onToggleSchedule(row.original.domain)}
        />
      ),
    },
    {
      id: "actions",
      header: "Actions",
      enableSorting: false,
      cell: ({ row }) => {
        const d = row.original.domain
        return (
          <div className="flex items-center justify-end gap-1 text-slate-500">
            <IconBtn
              label="Run audit now"
              onClick={() => onRunNow(d)}
              disabled={row.original.running}
            >
              <Play className={row.original.running ? "h-4 w-4 animate-pulse" : "h-4 w-4"} />
            </IconBtn>
            <IconBtn label="Edit" onClick={() => setDialog({ mode: "edit", domain: d })}>
              <Pencil className="h-4 w-4" />
            </IconBtn>
            <IconBtn label="Remove" onClick={() => setConfirmRemove(d)}>
              <Trash2 className="h-4 w-4 text-red-600" />
            </IconBtn>
            <IconBtn label="Open run history" onClick={() => openDetail(d)}>
              <ArrowUpRight className="h-4 w-4" />
            </IconBtn>
          </div>
        )
      },
    },
  ]

  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
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
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => runDomains(list.map((d) => ({ id: d.id, name: d.name })))}
            disabled={scanning || list.length === 0}
            title="Run a fresh audit for every domain"
            className="inline-flex items-center gap-2 rounded-md border border-[var(--edh-border)] px-3 py-2 text-sm font-medium hover:bg-slate-50 disabled:opacity-50"
          >
            <RefreshCw className={scanning ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
            {scanning ? "Running…" : "Run all"}
          </button>
          <button
            type="button"
            onClick={() => setDialog({ mode: "add" })}
            className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-2 text-sm font-medium text-white"
          >
            <Plus className="h-4 w-4" /> Add domain
          </button>
        </div>
      </header>

      {/* The table scrolls independently below the header; its header row is sticky (§2). */}
      <div className="max-h-[calc(100vh-12rem)] overflow-auto rounded-lg border border-[var(--edh-border)] bg-white">
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10 bg-slate-50 text-xs uppercase text-[var(--edh-muted)]">
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((h) => (
                  <th key={h.id} className={TH_CLASS[h.column.id] ?? "px-2 py-2 text-center"}>
                    {h.column.getCanSort() ? (
                      <button
                        type="button"
                        onClick={h.column.getToggleSortingHandler()}
                        className="inline-flex items-center gap-1 uppercase hover:text-slate-700"
                      >
                        {flexRender(h.column.columnDef.header, h.getContext())}
                        {h.column.getIsSorted() === "asc" ? (
                          <ChevronUp className="h-3 w-3" />
                        ) : h.column.getIsSorted() === "desc" ? (
                          <ChevronDown className="h-3 w-3" />
                        ) : (
                          <ArrowUpDown className="h-3 w-3 opacity-40" />
                        )}
                      </button>
                    ) : (
                      flexRender(h.column.columnDef.header, h.getContext())
                    )}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row) => (
              // The whole row (outside the toggle/action cells, which stop propagation)
              // click-navigates to the run detail (pm/domains.mdx §3.1).
              <tr
                key={row.id}
                onClick={() => openDetail(row.original.domain)}
                className="cursor-pointer border-t border-[var(--edh-border)] hover:bg-slate-50"
              >
                {row.getVisibleCells().map((cell) => (
                  <td
                    key={cell.id}
                    className={TD_CLASS[cell.column.id] ?? "px-2 py-2"}
                    onClick={
                      cell.column.id === "scheduleEnabled" || cell.column.id === "actions"
                        ? (e) => e.stopPropagation()
                        : undefined
                    }
                  >
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td
                  colSpan={columns.length}
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
          existingNames={list.map((d) => d.name)}
          onClose={() => setDialog(null)}
        />
      )}
      {confirmRemove && (
        <ConfirmRemoveDialog
          domain={confirmRemove}
          pending={del.isPending}
          onCancel={() => setConfirmRemove(null)}
          onConfirm={() => onConfirmRemove(confirmRemove)}
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
      onClick={(e) => {
        // The whole row click-navigates to the detail view; actions must not also navigate.
        e.stopPropagation()
        onClick()
      }}
      disabled={disabled}
      className="rounded p-1.5 hover:bg-slate-100 disabled:opacity-40"
    >
      {children}
    </button>
  )
}

/** Inline on/off switch for a domain's recurring-checks membership (pm/domains.mdx §6). */
function ScheduleToggle({ enabled, onToggle }: { enabled: boolean; onToggle: () => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={enabled}
      aria-label={enabled ? "Scheduled checks on" : "Scheduled checks off"}
      title={enabled ? "On the recurring schedule" : "Off the recurring schedule"}
      onClick={(e) => {
        e.stopPropagation()
        onToggle()
      }}
      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
        enabled ? "bg-[var(--edh-primary)]" : "bg-slate-300"
      }`}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
          enabled ? "translate-x-4" : "translate-x-1"
        }`}
      />
    </button>
  )
}

/**
 * The remove confirm (pm/domains.mdx §3.4): removing a domain also removes its audit history, so
 * it always sits behind an explicit confirm dialog.
 */
function ConfirmRemoveDialog({
  domain,
  pending,
  onCancel,
  onConfirm,
}: {
  domain: MonitoredDomain
  pending: boolean
  onCancel: () => void
  onConfirm: () => void
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel()
    }
    document.addEventListener("keydown", onKey)
    return () => document.removeEventListener("keydown", onKey)
  }, [onCancel])

  return (
    <div
      role="alertdialog"
      aria-modal="true"
      aria-label={`Remove ${domain.name}`}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4"
    >
      <div className="w-full max-w-md rounded-lg border border-[var(--edh-border)] bg-white p-5 shadow-xl">
        <h2 className="text-lg font-semibold">Remove {domain.name}?</h2>
        <p className="mt-2 text-sm text-[var(--edh-muted)]">This also removes its audit history.</p>
        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-md border border-[var(--edh-border)] px-4 py-2 text-sm hover:bg-slate-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={pending}
            className="rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
          >
            {pending ? "Removing…" : "Remove domain"}
          </button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------------------------
// Add / Edit dialog with client-side validation mirroring the server DTOs (pm/domains.mdx §4.1).
// ---------------------------------------------------------------------------------------------

// Same shapes the backend enforces (modules/domains/dto/domain.dto.ts).
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i
const SELECTOR_RE = /^[a-z0-9-]{1,63}$/i
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

function isIp(value: string): boolean {
  if (IPV4_RE.test(value)) return true
  // Pragmatic IPv6: hex groups separated by ":", at most one "::". The server's IsIP is exact.
  if (!value.includes(":")) return false
  const halves = value.split("::")
  if (halves.length > 2) return false
  const groups = halves.flatMap((h) => (h ? h.split(":") : []))
  if (groups.length > 8) return false
  if (halves.length === 1 && groups.length !== 8) return false
  return groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))
}

/** Domain syntax + uniqueness (pm/domains.mdx §4.1): reject IPs, URLs, emails, and duplicates. */
function validateDomainName(raw: string, existing: string[]): string | null {
  const name = raw.trim().toLowerCase()
  if (!name) return null // required — the Save button stays disabled instead
  if (name.includes("@")) return "Enter a bare domain, not an email address"
  if (name.includes("://") || name.includes("/")) return "Enter a bare domain, not a URL"
  if (isIp(name)) return "Enter a domain name, not an IP address"
  if (!DOMAIN_RE.test(name)) return "Must be a valid domain, e.g. example.com"
  if (existing.includes(name)) return "This domain is already monitored"
  return null
}

function validateSelectors(raw: string): string | null {
  const bad = splitList(raw).find((s) => !SELECTOR_RE.test(s))
  return bad ? `“${bad}” is not a valid DKIM selector (letters, digits, hyphens)` : null
}

function validateIps(raw: string): string | null {
  const bad = splitList(raw).find((s) => !isIp(s))
  return bad ? `“${bad}” is not a valid IPv4 or IPv6 address` : null
}

function FieldError({ message }: { message: string | null }) {
  if (!message) return null
  return <span className="mt-1 block text-xs text-red-600">{message}</span>
}

/** Add (no domain) or Edit (domain given) dialog. Add posts a new record; Edit patches fields. */
function DomainDialog({
  domain,
  existingNames,
  onClose,
}: {
  domain?: MonitoredDomain
  existingNames: string[]
  onClose: () => void
}) {
  const create = useCreateDomain()
  const update = useUpdateDomain()
  const editing = Boolean(domain)

  const [name, setName] = useState(domain?.name ?? "")
  const [label, setLabel] = useState(domain?.label ?? "")
  const [selectors, setSelectors] = useState((domain?.dkimSelectors ?? []).join(", "))
  const [ips, setIps] = useState((domain?.sendingIps ?? []).join(", "))
  const [scheduleEnabled, setScheduleEnabled] = useState(domain?.scheduleEnabled ?? true)
  // ARC / forwarding config (pm/checks/arc.mdx §4 per-domain config inputs): the usesForwarding
  // toggle plus the repeatable forwarders/mailing-lists list. Drives arc.applicable /
  // arc.forwarding_risk / arc.selector_dns today and the capture probe later.
  const [usesForwarding, setUsesForwarding] = useState(domain?.arc?.usesForwarding ?? false)
  const [forwarders, setForwarders] = useState<ArcForwarderConfig[]>(domain?.arc?.forwarders ?? [])
  // BIMI config (pm/checks/bimi.mdx §4 per-domain config inputs): optional selectors beyond
  // `default` plus an optional sample message whose BIMI-Selector: header names the selector the
  // domain's mail streams reference. Drives content.bimi_selector.
  const [bimiSelectors, setBimiSelectors] = useState((domain?.bimi?.selectors ?? []).join(", "))
  const [bimiSample, setBimiSample] = useState(domain?.bimi?.sampleMessage ?? "")
  // DNS health (pm/checks/dns_health.mdx §4 per-domain config inputs): extra dangling-scan labels,
  // an optional expected-NS allow-list (drift alerts), and the skip-AXFR-probe toggle.
  const [dnsExtraLabels, setDnsExtraLabels] = useState(
    (domain?.dnsHealth?.extraLabels ?? []).join(", "),
  )
  const [dnsExpectedNs, setDnsExpectedNs] = useState(
    (domain?.dnsHealth?.expectedNs ?? []).join(", "),
  )
  const [dnsSkipAxfr, setDnsSkipAxfr] = useState(domain?.dnsHealth?.skipAxfrProbe ?? false)
  // The optional fields live behind an "Advanced (optional)" disclosure (pm/domains.mdx §4.1).
  // Collapsed by default when adding (only the domain is required); expanded when editing, since
  // those fields are the point of the edit.
  const [showAdvanced, setShowAdvanced] = useState(editing)

  // Client-side validation mirrors the server DTOs; field errors render inline and the Save button
  // is disabled until the form is valid (pm/domains.mdx §4.1).
  const nameError = editing ? null : validateDomainName(name, existingNames)
  const selectorError = validateSelectors(selectors)
  const ipError = validateIps(ips)
  const valid = !nameError && !selectorError && !ipError && (editing || name.trim().length > 0)

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
    if (!valid) return
    const arc = { usesForwarding, forwarders: cleanForwarders(forwarders) }
    const bimi = { selectors: splitList(bimiSelectors), sampleMessage: bimiSample.trim() }
    const dnsHealth = {
      extraLabels: splitList(dnsExtraLabels),
      expectedNs: splitList(dnsExpectedNs),
      skipAxfrProbe: dnsSkipAxfr,
    }
    if (editing && domain) {
      update.mutate(
        {
          id: domain.id,
          input: {
            label: label.trim(),
            dkimSelectors: splitList(selectors),
            sendingIps: splitList(ips),
            scheduleEnabled,
            arc,
            bimi,
            dnsHealth,
          },
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
      name: name.trim().toLowerCase(),
      label: label.trim(),
      dkimSelectors: splitList(selectors),
      sendingIps: splitList(ips),
      scheduleEnabled,
      // Only send an arc block when the operator actually declared forwarding (pm/checks/arc.mdx §4).
      ...(arc.usesForwarding || arc.forwarders.length > 0 ? { arc } : {}),
      // Only send a bimi block when the operator actually configured something (pm/checks/bimi.mdx §4).
      ...(bimi.selectors.length > 0 || bimi.sampleMessage !== "" ? { bimi } : {}),
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
              aria-invalid={Boolean(nameError)}
              placeholder="whitehatengineering.com"
              className={`w-full rounded-md border px-3 py-2 disabled:bg-slate-50 ${
                nameError ? "border-red-400" : "border-[var(--edh-border)]"
              }`}
            />
            <FieldError message={nameError} />
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
                <span className="mb-1 block font-medium">Label / notes</span>
                <input
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  maxLength={200}
                  placeholder="Primary marketing domain"
                  className="w-full rounded-md border border-[var(--edh-border)] px-3 py-2"
                />
              </label>
              <label className="text-sm">
                <span className="mb-1 block font-medium">DKIM selectors (comma-separated)</span>
                <input
                  value={selectors}
                  onChange={(e) => setSelectors(e.target.value)}
                  aria-invalid={Boolean(selectorError)}
                  placeholder="google, s1"
                  className={`w-full rounded-md border px-3 py-2 ${
                    selectorError ? "border-red-400" : "border-[var(--edh-border)]"
                  }`}
                />
                <FieldError message={selectorError} />
              </label>
              <label className="text-sm">
                <span className="mb-1 block font-medium">Sending IPs (comma-separated)</span>
                <input
                  value={ips}
                  onChange={(e) => setIps(e.target.value)}
                  aria-invalid={Boolean(ipError)}
                  placeholder="203.0.113.10"
                  className={`w-full rounded-md border px-3 py-2 ${
                    ipError ? "border-red-400" : "border-[var(--edh-border)]"
                  }`}
                />
                <FieldError message={ipError} />
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={scheduleEnabled}
                  onChange={(e) => setScheduleEnabled(e.target.checked)}
                  className="h-4 w-4 rounded border-[var(--edh-border)]"
                />
                <span className="font-medium">Include in recurring scheduled checks</span>
              </label>
              {/* ARC / forwarding (pm/checks/arc.mdx §4): usesForwarding toggle + forwarder list.
                  Drives arc.applicable / arc.forwarding_risk / arc.selector_dns and the future
                  capture probe. */}
              <fieldset className="rounded-md border border-[var(--edh-border)] p-3">
                <legend className="px-1 text-sm font-medium">ARC / forwarding</legend>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={usesForwarding}
                    onChange={(e) => setUsesForwarding(e.target.checked)}
                    className="h-4 w-4 rounded border-[var(--edh-border)]"
                  />
                  <span className="font-medium">
                    Sends through forwarders / mailing lists (DMARC-breaking hops)
                  </span>
                </label>
                {usesForwarding && (
                  <div className="mt-3 grid gap-3">
                    {forwarders.map((f, i) => (
                      <div
                        // biome-ignore lint/suspicious/noArrayIndexKey: rows are positional editor slots
                        key={i}
                        className="grid gap-2 rounded-md bg-slate-50 p-2"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-medium uppercase text-[var(--edh-muted)]">
                            Forwarder {i + 1}
                          </span>
                          <button
                            type="button"
                            aria-label={`Remove forwarder ${i + 1}`}
                            onClick={() => setForwarders((list) => list.filter((_, j) => j !== i))}
                            className="rounded p-1 text-slate-500 hover:bg-slate-100"
                          >
                            <Trash2 className="h-4 w-4 text-red-600" />
                          </button>
                        </div>
                        <div className="grid grid-cols-2 gap-2">
                          <input
                            value={f.label}
                            onChange={(e) =>
                              patchForwarder(setForwarders, i, { label: e.target.value })
                            }
                            placeholder="Label (acme-users Google Group)"
                            aria-label="Forwarder label"
                            className="rounded-md border border-[var(--edh-border)] px-2 py-1.5 text-sm"
                          />
                          <input
                            value={f.forwardAddress}
                            onChange={(e) =>
                              patchForwarder(setForwarders, i, { forwardAddress: e.target.value })
                            }
                            placeholder="Forwarding address"
                            aria-label="Forwarding address"
                            className="rounded-md border border-[var(--edh-border)] px-2 py-1.5 text-sm"
                          />
                          <input
                            value={f.signerDomain ?? ""}
                            onChange={(e) =>
                              patchForwarder(setForwarders, i, { signerDomain: e.target.value })
                            }
                            placeholder="ARC signing domain (d=, optional)"
                            aria-label="ARC signing domain"
                            className="rounded-md border border-[var(--edh-border)] px-2 py-1.5 text-sm"
                          />
                          <input
                            value={f.signerSelector ?? ""}
                            onChange={(e) =>
                              patchForwarder(setForwarders, i, { signerSelector: e.target.value })
                            }
                            placeholder="ARC selector (s=, optional)"
                            aria-label="ARC signing selector"
                            className="rounded-md border border-[var(--edh-border)] px-2 py-1.5 text-sm"
                          />
                          <input
                            value={f.probeMailbox ?? ""}
                            onChange={(e) =>
                              patchForwarder(setForwarders, i, { probeMailbox: e.target.value })
                            }
                            placeholder="Probe mailbox (optional)"
                            aria-label="Probe mailbox"
                            className="col-span-2 rounded-md border border-[var(--edh-border)] px-2 py-1.5 text-sm"
                          />
                        </div>
                      </div>
                    ))}
                    <button
                      type="button"
                      onClick={() =>
                        setForwarders((list) => [...list, { label: "", forwardAddress: "" }])
                      }
                      className="inline-flex w-fit items-center gap-1 rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm hover:bg-slate-50"
                    >
                      <Plus className="h-4 w-4" /> Add forwarder / mailing list
                    </button>
                  </div>
                )}
              </fieldset>
              {/* BIMI (pm/checks/bimi.mdx §4): optional selectors beyond `default` plus an optional
                  sample message whose BIMI-Selector: header names the selector the domain's mail
                  streams reference. Drives content.bimi_selector. */}
              <fieldset className="rounded-md border border-[var(--edh-border)] p-3">
                <legend className="px-1 text-sm font-medium">BIMI</legend>
                <label className="block text-sm">
                  <span className="mb-1 block font-medium">
                    BIMI selectors beyond “default” (comma-separated)
                  </span>
                  <input
                    value={bimiSelectors}
                    onChange={(e) => setBimiSelectors(e.target.value)}
                    placeholder="v1, marketing"
                    className="w-full rounded-md border border-[var(--edh-border)] px-3 py-2"
                  />
                </label>
                <label className="mt-3 block text-sm">
                  <span className="mb-1 block font-medium">
                    Sample message (headers) — reads its BIMI-Selector: header
                  </span>
                  <textarea
                    value={bimiSample}
                    onChange={(e) => setBimiSample(e.target.value)}
                    rows={3}
                    placeholder={
                      "Paste raw message headers, e.g.\nBIMI-Selector: v=BIMI1; s=marketing"
                    }
                    className="w-full rounded-md border border-[var(--edh-border)] px-3 py-2 font-mono text-xs"
                  />
                </label>
              </fieldset>
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
              disabled={pending || !valid}
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

/** Patch one field of one forwarder row in the dialog's editor state. */
function patchForwarder(
  set: React.Dispatch<React.SetStateAction<ArcForwarderConfig[]>>,
  index: number,
  patch: Partial<ArcForwarderConfig>,
): void {
  set((list) => list.map((f, i) => (i === index ? { ...f, ...patch } : f)))
}

/** Drop empty editor rows and strip blank optional fields before submitting (pm/checks/arc.mdx §4). */
function cleanForwarders(list: ArcForwarderConfig[]): ArcForwarderConfig[] {
  return list
    .map((f) => ({
      label: f.label.trim(),
      forwardAddress: f.forwardAddress.trim(),
      ...(f.signerDomain?.trim() ? { signerDomain: f.signerDomain.trim().toLowerCase() } : {}),
      ...(f.signerSelector?.trim() ? { signerSelector: f.signerSelector.trim() } : {}),
      ...(f.probeMailbox?.trim() ? { probeMailbox: f.probeMailbox.trim() } : {}),
    }))
    .filter((f) => f.label !== "" && f.forwardAddress !== "")
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
