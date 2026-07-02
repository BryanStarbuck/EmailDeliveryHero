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
      // Structured results give DKIM/DMARC their spec'd cell labels (selectors · bits / p=<policy>).
      cells: rollupCategories(byId.get(d.id)?.findings, byId.get(d.id)?.results),
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
              // The whole row click-navigates to the run detail (pm/domains.mdx §3.1); the
              // toggle/action controls stop propagation so they never also navigate.
              <tr
                key={row.id}
                onClick={() => openDetail(row.original.domain)}
                className="cursor-pointer border-t border-[var(--edh-border)] hover:bg-slate-50"
              >
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className={TD_CLASS[cell.column.id] ?? "px-2 py-2"}>
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

/**
 * Expiry/age warning-threshold validation (pm/checks/domain_reputation.mdx §4) mirroring the
 * server DTO: blank = use the 30-day default; otherwise an integer between 1 and 365.
 */
function validateThresholdDays(raw: string, label: string): string | null {
  const value = raw.trim()
  if (value === "") return null
  const n = Number(value)
  if (!Number.isInteger(n) || n < 1 || n > 365)
    return `${label} must be a whole number of days (1–365)`
  return null
}

/**
 * Aligned link-domain allow-list validation (pm/checks/link_url_reputation.mdx §4) mirroring the
 * server LinkUrlConfigDto: every comma-separated entry must be a bare, valid domain.
 */
function validateAlignedLinkDomains(raw: string): string | null {
  const bad = splitList(raw).find((d) => !DOMAIN_RE.test(d.toLowerCase()))
  return bad ? `“${bad}” is not a valid domain (enter bare domains, e.g. clicks.example.net)` : null
}

/**
 * Expected-MX allow-list validation (pm/checks/mx_routing.mdx §4) mirroring the server
 * MxRoutingConfigDto: every comma-separated entry must be a valid hostname (a trailing dot is
 * tolerated and stripped before submit).
 */
function validateExpectedMxHosts(raw: string): string | null {
  const bad = splitList(raw).find((h) => !DOMAIN_RE.test(h.toLowerCase().replace(/\.$/, "")))
  return bad ? `“${bad}” is not a valid MX hostname (e.g. aspmx.l.google.com)` : null
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
  // Mail routing (pm/checks/mx_routing.mdx §4 per-domain config inputs): the "this domain receives
  // mail" intent toggle (drives whether an empty/null MX is critical vs expected), the optional
  // expected-MX allow-list (infra.mx_expected_drift), and the skip-SMTP-probe switch for hosts
  // whose egress blocks port 25.
  const [mxReceivesMail, setMxReceivesMail] = useState(domain?.mx?.receivesMail ?? true)
  const [mxExpectedHosts, setMxExpectedHosts] = useState(
    (domain?.mx?.expectedHosts ?? []).join(", "),
  )
  const [mxSkipSmtpProbe, setMxSkipSmtpProbe] = useState(domain?.mx?.skipSmtpProbe ?? false)
  // Domain registration (pm/checks/domain_reputation.mdx §4 per-domain config inputs, admin-only):
  // brand strings for infra.name_similarity, the expiry/age warning thresholds (default 30 days
  // each), the "registrant is intentionally public" silencer for infra.registrant_privacy, and
  // the (future, default-off) active cousin-domain scan toggle.
  const [repBrands, setRepBrands] = useState((domain?.domainReputation?.brands ?? []).join(", "))
  const [repExpiryDays, setRepExpiryDays] = useState(
    domain?.domainReputation?.expiryWarnDays?.toString() ?? "",
  )
  const [repAgeDays, setRepAgeDays] = useState(
    domain?.domainReputation?.ageWarnDays?.toString() ?? "",
  )
  const [repPublicIntentional, setRepPublicIntentional] = useState(
    domain?.domainReputation?.registrantPublicIntentional ?? false,
  )
  const [repCousinScan, setRepCousinScan] = useState(domain?.domainReputation?.cousinScan ?? false)
  // Link / URL reputation (pm/checks/link_url_reputation.mdx §4 per-domain config inputs): the
  // own/related/allow-listed link domains counted as aligned by content.url_domain_alignment —
  // tracking/click/CDN domains the org controls that differ from the sending domain.
  const [urlAllowedDomains, setUrlAllowedDomains] = useState(
    (domain?.linkUrl?.allowedDomains ?? []).join(", "),
  )
  // The optional fields live behind an "Advanced (optional)" disclosure (pm/domains.mdx §4.1).
  // Collapsed by default when adding (only the domain is required); expanded when editing, since
  // those fields are the point of the edit.
  const [showAdvanced, setShowAdvanced] = useState(editing)

  // Client-side validation mirrors the server DTOs; field errors render inline and the Save button
  // is disabled until the form is valid (pm/domains.mdx §4.1).
  const nameError = editing ? null : validateDomainName(name, existingNames)
  const selectorError = validateSelectors(selectors)
  const ipError = validateIps(ips)
  const expiryDaysError = validateThresholdDays(repExpiryDays, "Expiry warning threshold")
  const ageDaysError = validateThresholdDays(repAgeDays, "Age warning threshold")
  const urlAllowedError = validateAlignedLinkDomains(urlAllowedDomains)
  const mxHostsError = validateExpectedMxHosts(mxExpectedHosts)
  const valid =
    !nameError &&
    !selectorError &&
    !ipError &&
    !expiryDaysError &&
    !ageDaysError &&
    !urlAllowedError &&
    !mxHostsError &&
    (editing || name.trim().length > 0)

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
    // Registration-reputation config (pm/checks/domain_reputation.mdx §4); the server collapses an
    // all-default block back to "absent" so domains.yaml stays clean.
    const domainReputation = {
      brands: splitList(repBrands),
      ...(repExpiryDays.trim() !== "" ? { expiryWarnDays: Number(repExpiryDays) } : {}),
      ...(repAgeDays.trim() !== "" ? { ageWarnDays: Number(repAgeDays) } : {}),
      registrantPublicIntentional: repPublicIntentional,
      cousinScan: repCousinScan,
    }
    const domainReputationConfigured =
      domainReputation.brands.length > 0 ||
      domainReputation.expiryWarnDays !== undefined ||
      domainReputation.ageWarnDays !== undefined ||
      repPublicIntentional ||
      repCousinScan
    // Link / URL-reputation config (pm/checks/link_url_reputation.mdx §4); the server collapses an
    // empty allow-list back to "absent" so domains.yaml stays clean.
    const linkUrl = {
      allowedDomains: splitList(urlAllowedDomains).map((d) => d.toLowerCase()),
    }
    // Mail-routing expectations (pm/checks/mx_routing.mdx §4); the server collapses an
    // all-default block (receives mail, no allow-list, probe on) back to "absent".
    const mx = {
      receivesMail: mxReceivesMail,
      expectedHosts: splitList(mxExpectedHosts).map((h) => h.toLowerCase().replace(/\.$/, "")),
      skipSmtpProbe: mxSkipSmtpProbe,
    }
    const mxConfigured = !mxReceivesMail || mx.expectedHosts.length > 0 || mxSkipSmtpProbe
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
            mx,
            domainReputation,
            linkUrl,
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
      // Only send a dnsHealth block when the operator actually configured something
      // (pm/checks/dns_health.mdx §4).
      ...(dnsHealth.extraLabels.length > 0 ||
      dnsHealth.expectedNs.length > 0 ||
      dnsHealth.skipAxfrProbe
        ? { dnsHealth }
        : {}),
      // Only send a domainReputation block when the operator actually configured something
      // (pm/checks/domain_reputation.mdx §4).
      ...(domainReputationConfigured ? { domainReputation } : {}),
      // Only send a linkUrl block when the operator actually configured aligned link domains
      // (pm/checks/link_url_reputation.mdx §4).
      ...(linkUrl.allowedDomains.length > 0 ? { linkUrl } : {}),
      // Only send an mx block when the operator changed something off the defaults
      // (pm/checks/mx_routing.mdx §4).
      ...(mxConfigured ? { mx } : {}),
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
              {/* DNS health (pm/checks/dns_health.mdx §4): extra dangling-scan labels, an optional
                  expected-NS allow-list (drift alerts), and the skip-AXFR-probe toggle. */}
              <fieldset className="rounded-md border border-[var(--edh-border)] p-3">
                <legend className="px-1 text-sm font-medium">DNS health</legend>
                <label className="block text-sm">
                  <span className="mb-1 block font-medium">
                    Extra labels to scan for dangling records (comma-separated)
                  </span>
                  <input
                    value={dnsExtraLabels}
                    onChange={(e) => setDnsExtraLabels(e.target.value)}
                    placeholder="staging, old-blog"
                    className="w-full rounded-md border border-[var(--edh-border)] px-3 py-2"
                  />
                </label>
                <label className="mt-3 block text-sm">
                  <span className="mb-1 block font-medium">
                    Expected nameservers (comma-separated, alerts on drift)
                  </span>
                  <input
                    value={dnsExpectedNs}
                    onChange={(e) => setDnsExpectedNs(e.target.value)}
                    placeholder="ns1.example-dns.com, ns2.example-dns.com"
                    className="w-full rounded-md border border-[var(--edh-border)] px-3 py-2"
                  />
                </label>
                <label className="mt-3 flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={dnsSkipAxfr}
                    onChange={(e) => setDnsSkipAxfr(e.target.checked)}
                    className="h-4 w-4 rounded border-[var(--edh-border)]"
                  />
                  <span className="font-medium">Skip the AXFR zone-transfer probe</span>
                </label>
              </fieldset>
              {/* Mail routing (pm/checks/mx_routing.mdx §4 per-domain config inputs): the
                  receives-mail intent toggle (empty/null MX critical vs expected), the expected-MX
                  allow-list (drift detection), and the skip-SMTP-probe switch for hosts whose
                  egress blocks port 25. */}
              <fieldset className="rounded-md border border-[var(--edh-border)] p-3">
                <legend className="px-1 text-sm font-medium">Mail routing</legend>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={mxReceivesMail}
                    onChange={(e) => setMxReceivesMail(e.target.checked)}
                    className="h-4 w-4 rounded border-[var(--edh-border)]"
                  />
                  <span className="font-medium">
                    This domain receives mail (a missing or null MX is then critical)
                  </span>
                </label>
                {!mxReceivesMail && (
                  <p className="mt-1 pl-6 text-xs text-[var(--edh-muted)]">
                    Send-only domain: an absent MX is accepted and an RFC 7505 null MX (
                    <code className="font-mono">MX 0 "."</code>) is reported as correct.
                  </p>
                )}
                <label className="mt-3 block text-sm">
                  <span className="mb-1 block font-medium">
                    Expected MX hosts (comma-separated, alerts on drift)
                  </span>
                  <input
                    value={mxExpectedHosts}
                    onChange={(e) => setMxExpectedHosts(e.target.value)}
                    aria-invalid={Boolean(mxHostsError)}
                    placeholder="aspmx.l.google.com, alt1.aspmx.l.google.com"
                    className={`w-full rounded-md border px-3 py-2 ${
                      mxHostsError ? "border-red-400" : "border-[var(--edh-border)]"
                    }`}
                  />
                  <FieldError message={mxHostsError} />
                </label>
                <label className="mt-3 flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={mxSkipSmtpProbe}
                    onChange={(e) => setMxSkipSmtpProbe(e.target.checked)}
                    className="h-4 w-4 rounded border-[var(--edh-border)]"
                  />
                  <span className="font-medium">
                    Skip the SMTP reachability probe (port-25 egress blocked here)
                  </span>
                </label>
              </fieldset>
              {/* Domain registration (pm/checks/domain_reputation.mdx §4 per-domain config inputs):
                  brand strings for infra.name_similarity, expiry/age warning thresholds, the
                  registrant-intentionally-public silencer, and the future cousin-scan toggle. */}
              <fieldset className="rounded-md border border-[var(--edh-border)] p-3">
                <legend className="px-1 text-sm font-medium">Domain registration</legend>
                <label className="block text-sm">
                  <span className="mb-1 block font-medium">
                    Brand string(s) for lookalike detection (comma-separated)
                  </span>
                  <input
                    value={repBrands}
                    onChange={(e) => setRepBrands(e.target.value)}
                    placeholder="example.com, examplebrand"
                    className="w-full rounded-md border border-[var(--edh-border)] px-3 py-2"
                  />
                </label>
                <div className="mt-3 grid grid-cols-2 gap-2">
                  <label className="block text-sm">
                    <span className="mb-1 block font-medium">Expiry warning (days)</span>
                    <input
                      value={repExpiryDays}
                      onChange={(e) => setRepExpiryDays(e.target.value)}
                      inputMode="numeric"
                      aria-invalid={Boolean(expiryDaysError)}
                      placeholder="30"
                      className={`w-full rounded-md border px-3 py-2 ${
                        expiryDaysError ? "border-red-400" : "border-[var(--edh-border)]"
                      }`}
                    />
                    <FieldError message={expiryDaysError} />
                  </label>
                  <label className="block text-sm">
                    <span className="mb-1 block font-medium">Age warning (days)</span>
                    <input
                      value={repAgeDays}
                      onChange={(e) => setRepAgeDays(e.target.value)}
                      inputMode="numeric"
                      aria-invalid={Boolean(ageDaysError)}
                      placeholder="30"
                      className={`w-full rounded-md border px-3 py-2 ${
                        ageDaysError ? "border-red-400" : "border-[var(--edh-border)]"
                      }`}
                    />
                    <FieldError message={ageDaysError} />
                  </label>
                </div>
                <label className="mt-3 flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={repPublicIntentional}
                    onChange={(e) => setRepPublicIntentional(e.target.checked)}
                    className="h-4 w-4 rounded border-[var(--edh-border)]"
                  />
                  <span className="font-medium">
                    Registrant contact is intentionally public (silences the privacy note)
                  </span>
                </label>
                <label className="mt-2 flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={repCousinScan}
                    onChange={(e) => setRepCousinScan(e.target.checked)}
                    className="h-4 w-4 rounded border-[var(--edh-border)]"
                  />
                  <span className="font-medium">
                    Enable active cousin-domain scan (future — RDAP cost)
                  </span>
                </label>
              </fieldset>
              {/* Link / URL reputation (pm/checks/link_url_reputation.mdx §4 per-domain config
                  inputs): the own/related/allow-listed link domains counted as aligned by
                  content.url_domain_alignment. */}
              <fieldset className="rounded-md border border-[var(--edh-border)] p-3">
                <legend className="px-1 text-sm font-medium">Link / URL reputation</legend>
                <label className="block text-sm">
                  <span className="mb-1 block font-medium">
                    Allowed link domains counted as on-brand (comma-separated)
                  </span>
                  <input
                    value={urlAllowedDomains}
                    onChange={(e) => setUrlAllowedDomains(e.target.value)}
                    aria-invalid={Boolean(urlAllowedError)}
                    placeholder="clicks.example.net, cdn.examplebrand.com"
                    className={`w-full rounded-md border px-3 py-2 ${
                      urlAllowedError ? "border-red-400" : "border-[var(--edh-border)]"
                    }`}
                  />
                  <FieldError message={urlAllowedError} />
                  <span className="mt-1 block text-xs text-[var(--edh-muted)]">
                    Tracking/click/CDN domains your org controls; links to them are not flagged
                    off-brand by the body-link alignment check.
                  </span>
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
