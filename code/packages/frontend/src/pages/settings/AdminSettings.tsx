import { useAuth } from "@auth/react"
import { Link } from "@tanstack/react-router"
import { Loader2, Minus, Plus, ShieldAlert } from "lucide-react"
import { useEffect, useRef, useState } from "react"
import { toast } from "sonner"
import {
  type SettingsView,
  type UpdateAdminSettingsInput,
  useImportArchive,
  useResetApp,
  useSettings,
  useUpdateAdminSettings,
} from "@/api/settings"

/**
 * Settings › Admin (pm/settings.mdx §7 "Admin", route /settings/admin) — the aggregation of every
 * admin-only control: enabled check categories, DNSBL zones, default DKIM selectors, score
 * thresholds + severity weights + the SPF lookup limit (§2), the shared webhook/SMTP channels
 * (§4), history retention + Import + the destructive Resets (§5), resolver settings (§6), and the
 * allowed Workspace domains (§7). The left bar hides this item without role:admin, and the
 * backend rejects the writes with 403 regardless of UI state — the frontend gate is UX only.
 */

const CATEGORIES: { id: string; label: string }[] = [
  { id: "spf", label: "SPF" },
  { id: "dkim", label: "DKIM" },
  { id: "dmarc", label: "DMARC" },
  { id: "dnsbl", label: "Blacklists" },
  { id: "dns_infra", label: "DNS & Infrastructure" },
  { id: "spam_content", label: "Spam & Content" },
]

interface Draft {
  enabled: string[]
  zones: string[]
  defaultSelectors: string
  green: number
  amber: number
  critical: number
  warning: number
  info: number
  maxLookups: number
  contentThreshold: number
  contentSafeTarget: number
  contentNetworkTests: boolean
  webhookEnabled: boolean
  webhookUrl: string
  smtpHost: string
  smtpPort: number
  smtpFrom: string
  retentionDays: number
  preferCli: boolean
  resolvers: string
  timeoutMs: number
  allowedDomains: string
}

function toDraft(view: SettingsView): Draft {
  const { checks, notifications, storage, tools, access } = view.config
  return {
    enabled: [...checks.enabled],
    zones: [...checks.dnsbl.zones],
    defaultSelectors: checks.dkim.defaultSelectors.join(", "),
    green: checks.thresholds.green,
    amber: checks.thresholds.amber,
    critical: checks.weights.critical,
    warning: checks.weights.warning,
    info: checks.weights.info,
    maxLookups: checks.spf.maxLookups,
    contentThreshold: checks.content?.threshold ?? 5.0,
    contentSafeTarget: checks.content?.safeTarget ?? 2.0,
    contentNetworkTests: checks.content?.networkTests ?? false,
    webhookEnabled: notifications.webhook.enabled,
    webhookUrl: notifications.webhook.url,
    smtpHost: notifications.smtp.host,
    smtpPort: notifications.smtp.port,
    smtpFrom: notifications.smtp.from,
    retentionDays: storage.retentionDays,
    preferCli: tools.preferCli,
    resolvers: tools.resolvers.join(", "),
    timeoutMs: tools.timeoutMs,
    allowedDomains: access.allowedDomains.join(", "),
  }
}

const splitList = (value: string): string[] =>
  [...new Set(value.split(",").map((s) => s.trim()).filter(Boolean))]

function fromDraft(d: Draft): UpdateAdminSettingsInput {
  return {
    checks: {
      enabled: d.enabled,
      spf: { maxLookups: d.maxLookups },
      dkim: { defaultSelectors: splitList(d.defaultSelectors) },
      dnsbl: { zones: d.zones.map((z) => z.trim()).filter(Boolean) },
      content: {
        threshold: d.contentThreshold,
        safeTarget: d.contentSafeTarget,
        networkTests: d.contentNetworkTests,
      },
      thresholds: { green: d.green, amber: d.amber },
      weights: { critical: d.critical, warning: d.warning, info: d.info },
    },
    notifications: {
      webhook: { enabled: d.webhookEnabled, url: d.webhookUrl.trim() },
      smtp: { host: d.smtpHost.trim(), port: d.smtpPort, from: d.smtpFrom.trim() },
    },
    storage: { retentionDays: d.retentionDays },
    tools: { preferCli: d.preferCli, resolvers: splitList(d.resolvers), timeoutMs: d.timeoutMs },
    access: { allowedDomains: splitList(d.allowedDomains) },
  }
}

export function AdminSettings() {
  const { has } = useAuth()
  const { data } = useSettings()
  const save = useUpdateAdminSettings()
  const importArchive = useImportArchive()
  const reset = useResetApp()
  const fileInput = useRef<HTMLInputElement>(null)

  const [draft, setDraft] = useState<Draft | null>(null)
  useEffect(() => {
    if (data && draft === null) setDraft(toDraft(data))
  }, [data, draft])

  const isAdmin = (() => {
    try {
      return has({ role: "admin" })
    } catch {
      return false
    }
  })()

  // The left bar already hides this item; someone deep-linking here gets the honest story.
  if (!isAdmin) {
    return (
      <section className="rounded-lg border border-[var(--edh-border)] bg-white p-5">
        <h2 className="mb-3 flex items-center gap-2 font-semibold">
          <ShieldAlert className="h-4 w-4" /> Admin
        </h2>
        <p className="text-sm text-slate-600">
          This section requires the <code>role:admin</code> claim. You can view every setting
          read-only from the{" "}
          <Link to="/settings" className="text-[var(--edh-primary)] underline">
            Account
          </Link>{" "}
          section; the backend refuses admin-only writes with 403 either way.
        </p>
      </section>
    )
  }

  if (!draft) {
    return (
      <div className="space-y-3">
        {["a", "b", "c"].map((k) => (
          <div key={k} className="h-24 animate-pulse rounded-lg bg-slate-100" />
        ))}
      </div>
    )
  }

  const set = (patch: Partial<Draft>) => setDraft((d) => (d ? { ...d, ...patch } : d))

  const onSave = async () => {
    try {
      const view = await save.mutateAsync(fromDraft(draft))
      setDraft(toDraft(view))
      toast.success("Admin settings saved")
    } catch (err) {
      const status = (err as { response?: { status?: number } }).response?.status
      toast.error(status === 403 ? "Refused: role:admin required" : "Could not save admin settings")
    }
  }

  const onImportFile = async (file: File) => {
    try {
      const bytes = new Uint8Array(await file.arrayBuffer())
      let binary = ""
      for (const b of bytes) binary += String.fromCharCode(b)
      const result = await importArchive.mutateAsync(btoa(binary))
      toast.success(`Import restored: ${result.imported.join(", ")}`)
      setDraft(null) // reseed from the restored config
    } catch {
      toast.error("Import failed — is it a valid EmailDeliveryHero export?")
    }
  }

  const onReset = async (scope: "audit_history" | "app") => {
    const message =
      scope === "app"
        ? "Reset the ENTIRE app back to defaults (domains, config, and all audit history)?"
        : "Delete all audit run history (domains and config are kept)?"
    if (!window.confirm(message)) return
    try {
      await reset.mutateAsync(scope)
      toast.success(scope === "app" ? "App reset to defaults" : "Audit history cleared")
      setDraft(null)
    } catch {
      toast.error("Reset failed")
    }
  }

  return (
    <div className="space-y-4">
      {/* §2 Checks configuration */}
      <Panel title="Checks configuration">
        <h3 className="mb-1 text-sm font-medium">Enabled check categories</h3>
        <div className="flex flex-wrap gap-x-4 gap-y-1">
          {CATEGORIES.map((c) => {
            const on = draft.enabled.includes(c.id)
            return (
              <label key={c.id} className="flex items-center gap-2 py-0.5 text-sm">
                <input
                  type="checkbox"
                  checked={on}
                  onChange={() =>
                    set({
                      enabled: on
                        ? draft.enabled.filter((e) => e !== c.id)
                        : [...draft.enabled, c.id],
                    })
                  }
                />
                {c.label}
              </label>
            )
          })}
        </div>

        <h3 className="mb-1 mt-4 text-sm font-medium">DNSBL zones to query</h3>
        {draft.zones.map((zone, i) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: rows are positional edits
          <div key={i} className="flex items-center gap-2 py-1">
            <input
              value={zone}
              onChange={(e) =>
                set({ zones: draft.zones.map((z, j) => (j === i ? e.target.value : z)) })
              }
              aria-label={`DNSBL zone ${i + 1}`}
              className="w-72 rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm"
            />
            <button
              type="button"
              onClick={() => set({ zones: draft.zones.filter((_, j) => j !== i) })}
              aria-label={`Remove zone ${zone}`}
              title="Remove this zone"
              className="rounded p-1 text-[var(--edh-muted)] hover:bg-slate-100 hover:text-slate-700"
            >
              <Minus className="h-4 w-4" />
            </button>
          </div>
        ))}
        <button
          type="button"
          onClick={() => set({ zones: [...draft.zones, ""] })}
          className="mt-1 inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
        >
          <Plus className="h-4 w-4" /> Add zone
        </button>

        <LabeledInput
          label="Default DKIM selectors (comma-separated)"
          value={draft.defaultSelectors}
          onChange={(v) => set({ defaultSelectors: v })}
          wide
        />
        <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-3">
          <NumberInput label="Green ≥" value={draft.green} onChange={(v) => set({ green: v })} />
          <NumberInput label="Amber ≥" value={draft.amber} onChange={(v) => set({ amber: v })} />
          <NumberInput
            label="SPF lookup limit"
            value={draft.maxLookups}
            onChange={(v) => set({ maxLookups: v })}
          />
          <NumberInput
            label="Weight: critical"
            value={draft.critical}
            onChange={(v) => set({ critical: v })}
          />
          <NumberInput
            label="Weight: warning"
            value={draft.warning}
            onChange={(v) => set({ warning: v })}
          />
          <NumberInput label="Weight: info" value={draft.info} onChange={(v) => set({ info: v })} />
        </div>

        {/* Content scoring (pm/checks/content_scoring.mdx §4): threshold override, inbox-safe
            target, and the network-tests opt-in. Binary path override is env (EDH_TOOL_SPAMASSASSIN). */}
        <h3 className="mb-1 mt-4 text-sm font-medium">Content scoring (SpamAssassin)</h3>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          <NumberInput
            label="Spam threshold (default 5.0)"
            value={draft.contentThreshold}
            onChange={(v) => set({ contentThreshold: v })}
          />
          <NumberInput
            label="Inbox-safe target (default 2.0)"
            value={draft.contentSafeTarget}
            onChange={(v) => set({ contentSafeTarget: v })}
          />
        </div>
        <label className="mt-2 flex items-center gap-2 py-1 text-sm">
          <input
            type="checkbox"
            checked={draft.contentNetworkTests}
            onChange={(e) => set({ contentNetworkTests: e.target.checked })}
          />
          Enable network content tests (URIBL/Razor/Pyzor/DCC — off keeps scoring deterministic)
        </label>
      </Panel>

      {/* §3 Scheduling is all-users — point at its tab rather than duplicating it here. */}
      <Panel title="Scheduling">
        <p className="text-sm text-[var(--edh-muted)]">
          Scheduling is an <strong>all-users</strong> setting (pm/settings.mdx §3.1) — configure it
          on the{" "}
          <Link
            to="/settings/$section"
            params={{ section: "scheduling" }}
            className="text-[var(--edh-primary)] underline"
          >
            Scheduling
          </Link>{" "}
          tab.
        </p>
      </Panel>

      {/* §4 shared channels */}
      <Panel title="Notification channels (shared)">
        <label className="flex items-center gap-2 py-1 text-sm">
          <input
            type="checkbox"
            checked={draft.webhookEnabled}
            onChange={(e) => set({ webhookEnabled: e.target.checked })}
          />
          Webhook enabled
        </label>
        <LabeledInput
          label="Webhook / Slack URL"
          value={draft.webhookUrl}
          onChange={(v) => set({ webhookUrl: v })}
          placeholder="https://hooks.slack.com/services/…"
          wide
        />
        <div className="mt-2 grid grid-cols-2 gap-3 sm:grid-cols-3">
          <LabeledInput
            label="SMTP host"
            value={draft.smtpHost}
            onChange={(v) => set({ smtpHost: v })}
          />
          <NumberInput
            label="SMTP port"
            value={draft.smtpPort}
            onChange={(v) => set({ smtpPort: v })}
          />
          <LabeledInput
            label="From address"
            value={draft.smtpFrom}
            onChange={(v) => set({ smtpFrom: v })}
          />
        </div>
      </Panel>

      {/* §6 tools */}
      <Panel title="Tools & environment">
        <label className="flex items-center gap-2 py-1 text-sm">
          <input
            type="checkbox"
            checked={draft.preferCli}
            onChange={(e) => set({ preferCli: e.target.checked })}
          />
          Prefer CLI tools (use dig instead of node:dns when available)
        </label>
        <div className="mt-2 grid grid-cols-2 gap-3">
          <LabeledInput
            label="DNS resolvers (comma-separated IPs; empty = system)"
            value={draft.resolvers}
            onChange={(v) => set({ resolvers: v })}
          />
          <NumberInput
            label="Query timeout (ms)"
            value={draft.timeoutMs}
            onChange={(v) => set({ timeoutMs: v })}
          />
        </div>
      </Panel>

      {/* §7 access */}
      <Panel title="Access">
        <LabeledInput
          label="Allowed Workspace domains (comma-separated)"
          value={draft.allowedDomains}
          onChange={(v) => set({ allowedDomains: v })}
          wide
        />
        <p className="mt-2 text-xs text-[var(--edh-muted)]">
          Enforcement happens on the OpenAuthFederated side (pm/authentication.mdx §2) — this value
          is displayed to users and applied to the OAF allowlist, never as a code change here.
        </p>
      </Panel>

      {/* §5 storage: retention + import + resets */}
      <Panel title="Storage & data">
        <div className="grid grid-cols-2 gap-3">
          <NumberInput
            label="History retention (days)"
            value={draft.retentionDays}
            onChange={(v) => set({ retentionDays: v })}
          />
        </div>
        <div className="mt-4 flex flex-wrap gap-2 border-t border-[var(--edh-border)] pt-3">
          <input
            ref={fileInput}
            type="file"
            accept=".zip"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0]
              if (file) onImportFile(file)
              e.target.value = ""
            }}
          />
          <button
            type="button"
            onClick={() => fileInput.current?.click()}
            disabled={importArchive.isPending}
            className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-50"
          >
            {importArchive.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            Import from export…
          </button>
          <button
            type="button"
            onClick={() => onReset("audit_history")}
            disabled={reset.isPending}
            className="rounded-md border border-amber-300 px-3 py-1.5 text-sm text-amber-800 hover:bg-amber-50 disabled:opacity-50"
          >
            Reset audit history
          </button>
          <button
            type="button"
            onClick={() => onReset("app")}
            disabled={reset.isPending}
            className="rounded-md border border-red-300 px-3 py-1.5 text-sm text-red-700 hover:bg-red-50 disabled:opacity-50"
          >
            Reset app
          </button>
        </div>
      </Panel>

      <footer className="flex justify-end gap-2">
        <button
          type="button"
          onClick={() => data && setDraft(toDraft(data))}
          className="rounded-md border border-[var(--edh-border)] px-4 py-2 text-sm text-slate-700 hover:bg-slate-50"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={onSave}
          disabled={save.isPending}
          className="rounded-md bg-[var(--edh-primary)] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
        >
          {save.isPending ? "Saving…" : "Save"}
        </button>
      </footer>
    </div>
  )
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-[var(--edh-border)] bg-white p-5">
      <h2 className="mb-3 font-semibold">
        {title} <span className="ml-1 align-middle text-xs text-[var(--edh-muted)]">🔒 admin-only</span>
      </h2>
      {children}
    </section>
  )
}

function LabeledInput({
  label,
  value,
  onChange,
  placeholder,
  wide,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  wide?: boolean
}) {
  return (
    <label className={`mt-2 block text-sm ${wide ? "w-full" : ""}`}>
      <span className="mb-1 block text-xs text-[var(--edh-muted)]">{label}</span>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm"
      />
    </label>
  )
}

function NumberInput({
  label,
  value,
  onChange,
}: {
  label: string
  value: number
  onChange: (v: number) => void
}) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block text-xs text-[var(--edh-muted)]">{label}</span>
      <input
        type="number"
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm"
      />
    </label>
  )
}
