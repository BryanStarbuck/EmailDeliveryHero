import { useAuth, useUser } from "@auth/react"
import { Link } from "@tanstack/react-router"
import { FolderOpen, Loader2, Play, Trash2 } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"
import { useRunAudit } from "@/api/audit"
import { useCreateDomain, useDeleteDomain, useDomains } from "@/api/domains"
import {
  type Density,
  downloadExport,
  type NotificationMode,
  type NotificationSeverity,
  type Theme,
  useDetectTools,
  useOpenStateDir,
  useSettings,
  useTestNotification,
  useUpdateMySettings,
} from "@/api/settings"

/**
 * Settings › the general (all-users) groups (pm/settings.mdx): Account & access (§7), Appearance
 * (§8), Notifications — my own preferences (§4), Monitored domains (§1, the compact mirror of the
 * Domains area), Checks configuration shown read-only (§2 is admin-only to EDIT, visible to all),
 * Storage & data (§5) and Tools & environment (§6). Admin-only edits live on /settings/admin;
 * everything here is usable by every user, including the logged-out `default` user.
 */

const CATEGORY_LABEL: Record<string, string> = {
  spf: "SPF",
  dkim: "DKIM",
  dmarc: "DMARC",
  dnsbl: "Blacklists",
  dns_infra: "DNS & Infrastructure",
  spam_content: "Spam & Content",
}

export function GeneralSettings() {
  return (
    <div className="space-y-4">
      <AccountPanel />
      <AppearancePanel />
      <NotificationsPanel />
      <MonitoredDomainsPanel />
      <ChecksReadOnlyPanel />
      <StoragePanel />
      <ToolsPanel />
    </div>
  )
}

/* ------------------------------- §7 Account & access ------------------------------- */

function AccountPanel() {
  const { isSignedIn, signOut, has } = useAuth()
  const { user } = useUser()
  const { data } = useSettings()

  const email = user?.primaryEmailAddress ?? "—"
  const name = [user?.firstName, user?.lastName].filter(Boolean).join(" ") || "—"
  const isAdmin = (() => {
    try {
      return has({ role: "admin" })
    } catch {
      return false
    }
  })()

  return (
    <Panel title="Account & access">
      {isSignedIn ? (
        <>
          <Row label="Name" value={name} />
          <Row label="Email" value={email} />
          <Row label="Role" value={isAdmin ? "admin" : "member"} />
        </>
      ) : (
        <>
          <Row label="Current user" value="default" />
          <p className="mt-3 text-sm text-slate-600">
            You are using the app as the <code>default</code> user — settings persist under that
            account until you sign in. Signing in is optional and never required.
          </p>
        </>
      )}
      <Row
        label="Allowed Workspace domains"
        value={data ? data.config.access.allowedDomains.join(", ") : "…"}
      />
      <Row label="Session policy" value="OpenAuthFederated session · cookie prefix oaf_edh" />
      <p className="mt-3 text-sm text-[var(--edh-muted)]">
        Identity is asserted by OpenAuthFederated (Google Workspace SSO) — there is no password to
        manage here, and the sign-in allowlist is enforced on the OpenAuthFederated side. Admins
        edit it from the <Link to="/settings/$section" params={{ section: "admin" }} className="text-[var(--edh-primary)] underline">Admin</Link> section.
      </p>
      <div className="mt-3">
        {isSignedIn ? (
          <button
            type="button"
            onClick={() => signOut()}
            className="rounded-md border border-[var(--edh-border)] px-3 py-2 text-sm text-slate-700 hover:bg-slate-50"
          >
            Sign out
          </button>
        ) : (
          <Link
            to="/sign-in"
            className="inline-block rounded-md bg-[var(--edh-primary)] px-3 py-2 text-sm font-medium text-white"
          >
            Sign in
          </Link>
        )}
      </div>
    </Panel>
  )
}

/* ---------------------------------- §8 Appearance ---------------------------------- */

function AppearancePanel() {
  const { data } = useSettings()
  const update = useUpdateMySettings()

  const onChange = (patch: { theme?: Theme; density?: Density }) => {
    update.mutate(
      { appearance: patch },
      { onError: () => toast.error("Could not save the appearance setting") },
    )
  }

  return (
    <Panel title="Appearance">
      <FieldRow label="Theme">
        <select
          value={data?.me.appearance.theme ?? "system"}
          onChange={(e) => onChange({ theme: e.target.value as Theme })}
          disabled={!data}
          aria-label="Theme"
          className="rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm"
        >
          <option value="system">System</option>
          <option value="light">Light</option>
          <option value="dark">Dark</option>
        </select>
      </FieldRow>
      <FieldRow label="Density">
        <select
          value={data?.me.appearance.density ?? "comfortable"}
          onChange={(e) => onChange({ density: e.target.value as Density })}
          disabled={!data}
          aria-label="Table density"
          className="rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm"
        >
          <option value="comfortable">Comfortable</option>
          <option value="compact">Compact</option>
        </select>
      </FieldRow>
      <p className="mt-2 text-xs text-[var(--edh-muted)]">
        Per-user and cosmetic only — appearance never affects audits or other users.
      </p>
    </Panel>
  )
}

/* --------------------------- §4 Notifications (my prefs) --------------------------- */

function NotificationsPanel() {
  const { data } = useSettings()
  const update = useUpdateMySettings()
  const test = useTestNotification()

  const prefs = data?.me.notifications

  const onChange = (patch: Partial<NonNullable<typeof prefs>>) => {
    update.mutate(
      { notifications: patch },
      { onError: () => toast.error("Could not save the notification preference") },
    )
  }

  const onTest = async () => {
    try {
      const result = await test.mutateAsync()
      if (result.desktop.attempted && "Notification" in window) {
        // The backend confirms the channels; the browser raises the desktop notification itself.
        const permission = await Notification.requestPermission()
        if (permission === "granted") {
          new Notification("EmailDeliveryHero", { body: "Test notification — everything works." })
        }
      }
      const lines = [
        `Desktop: ${result.desktop.detail}`,
        `Email: ${result.email.detail}`,
        `Webhook: ${result.webhook.detail}`,
      ]
      toast.success("Test notification fired", { description: lines.join(" ") })
    } catch {
      toast.error("Could not send the test notification")
    }
  }

  return (
    <Panel title="Notifications">
      <p className="mb-3 text-sm text-[var(--edh-muted)]">
        How you learn about <em>new</em> problems found by scheduled runs. These are your own
        preferences; the shared webhook and SMTP channels are admin-only.
      </p>
      <label className="flex items-center gap-2 py-1 text-sm">
        <input
          type="checkbox"
          checked={prefs?.desktop ?? true}
          disabled={!prefs}
          onChange={(e) => onChange({ desktop: e.target.checked })}
        />
        Desktop notification when a new problem appears
      </label>
      <label className="flex items-center gap-2 py-1 text-sm">
        <input
          type="checkbox"
          checked={prefs?.email ?? false}
          disabled={!prefs}
          onChange={(e) => onChange({ email: e.target.checked })}
        />
        Email me on new problems (via the configured SMTP relay)
      </label>
      <FieldRow label="Minimum severity">
        <select
          value={prefs?.minSeverity ?? "warning"}
          disabled={!prefs}
          onChange={(e) => onChange({ minSeverity: e.target.value as NotificationSeverity })}
          aria-label="Minimum severity to notify at"
          className="rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm"
        >
          <option value="info">info</option>
          <option value="warning">warning</option>
          <option value="critical">critical</option>
        </select>
      </FieldRow>
      <FieldRow label="Delivery">
        <select
          value={prefs?.mode ?? "immediate"}
          disabled={!prefs}
          onChange={(e) => onChange({ mode: e.target.value as NotificationMode })}
          aria-label="Immediate or daily digest"
          className="rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm"
        >
          <option value="immediate">Immediate (per run)</option>
          <option value="daily">Daily digest</option>
        </select>
      </FieldRow>
      <button
        type="button"
        onClick={onTest}
        disabled={test.isPending}
        className="mt-3 inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-50"
      >
        {test.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
        Send test notification
      </button>
    </Panel>
  )
}

/* ------------------------------ §1 Monitored domains ------------------------------ */

function MonitoredDomainsPanel() {
  const { data: domains } = useDomains()
  const { data: settings } = useSettings()
  const createDomain = useCreateDomain()
  const deleteDomain = useDeleteDomain()
  const runAudit = useRunAudit()
  const [newDomain, setNewDomain] = useState("")

  const onAdd = async () => {
    const name = newDomain.trim().toLowerCase()
    if (!name) return
    try {
      await createDomain.mutateAsync({ name })
      setNewDomain("")
      toast.success(`${name} is now monitored`)
    } catch {
      toast.error(`Could not add ${name}`)
    }
  }

  return (
    <Panel title="Monitored domains">
      <p className="mb-3 text-sm text-[var(--edh-muted)]">
        A compact view of the domains under audit — the full editor (sending IPs, DKIM selectors,
        per-domain schedule) lives in{" "}
        <Link to="/domains" className="text-[var(--edh-primary)] underline">
          Domains
        </Link>
        . Both write the same <code>domains.yaml</code>.
      </p>
      {(domains ?? []).length === 0 ? (
        <p className="py-2 text-sm text-[var(--edh-muted)]">No monitored domains yet.</p>
      ) : (
        <ul>
          {(domains ?? []).map((d) => (
            <li
              key={d.id}
              className="flex items-center justify-between gap-2 border-b border-[var(--edh-border)] py-2 text-sm last:border-0"
            >
              <span className="min-w-0">
                <span className="font-medium">{d.name}</span>
                <span className="ml-2 text-xs text-[var(--edh-muted)]">
                  {d.dkimSelectors.length > 0
                    ? `selectors: ${d.dkimSelectors.join(", ")}`
                    : "selectors: global default"}
                  {d.sendingIps.length > 0 && ` · IPs: ${d.sendingIps.join(", ")}`}
                </span>
              </span>
              <span className="flex shrink-0 items-center gap-1">
                <button
                  type="button"
                  onClick={() =>
                    runAudit.mutate(d.id, {
                      onSuccess: () => toast.success(`Audit started for ${d.name}`),
                      onError: () => toast.error(`Could not audit ${d.name}`),
                    })
                  }
                  title="Audit now"
                  aria-label={`Audit ${d.name} now`}
                  className="rounded p-1 text-[var(--edh-muted)] hover:bg-slate-100 hover:text-slate-700"
                >
                  <Play className="h-4 w-4" />
                </button>
                <Link
                  to="/domains"
                  search={{ edit: d.id }}
                  title="Edit domain"
                  aria-label={`Edit ${d.name}`}
                  className="rounded p-1 text-xs text-[var(--edh-primary)] underline"
                >
                  Edit
                </Link>
                <button
                  type="button"
                  onClick={() =>
                    deleteDomain.mutate(d.id, {
                      onSuccess: () => toast.success(`${d.name} removed`),
                      onError: () => toast.error(`Could not remove ${d.name}`),
                    })
                  }
                  title="Remove domain"
                  aria-label={`Remove ${d.name}`}
                  className="rounded p-1 text-[var(--edh-muted)] hover:bg-red-50 hover:text-red-700"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </span>
            </li>
          ))}
        </ul>
      )}
      <div className="mt-3 flex items-center gap-2">
        <input
          value={newDomain}
          onChange={(e) => setNewDomain(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onAdd()}
          placeholder="example.com"
          aria-label="Domain to add"
          className="w-64 rounded-md border border-[var(--edh-border)] px-2 py-1.5 text-sm"
        />
        <button
          type="button"
          onClick={onAdd}
          disabled={createDomain.isPending || newDomain.trim() === ""}
          className="rounded-md bg-[var(--edh-primary)] px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50"
        >
          Add domain
        </button>
      </div>
      <p className="mt-3 text-xs text-[var(--edh-muted)]">
        Global default DKIM selectors (used when a domain defines none):{" "}
        <code>{settings ? settings.config.checks.dkim.defaultSelectors.join(", ") : "…"}</code>{" "}
        (admin-only to edit).
      </p>
    </Panel>
  )
}

/* --------------------------- §2 Checks configuration (view) --------------------------- */

function ChecksReadOnlyPanel() {
  const { has } = useAuth()
  const { data } = useSettings()
  const checks = data?.config.checks
  const isAdmin = (() => {
    try {
      return has({ role: "admin" })
    } catch {
      return false
    }
  })()

  return (
    <Panel title="Checks configuration">
      <p className="mb-3 text-sm text-[var(--edh-muted)]">
        What every scheduled run does and how every domain is scored. Everything here is{" "}
        <strong>admin-only to edit</strong> — shown read-only so you can see how your domains are
        judged.
        {isAdmin && (
          <>
            {" "}
            Edit it in the{" "}
            <Link
              to="/settings/$section"
              params={{ section: "admin" }}
              className="text-[var(--edh-primary)] underline"
            >
              Admin
            </Link>{" "}
            section.
          </>
        )}
      </p>
      <Row
        label="Enabled categories"
        value={
          checks ? checks.enabled.map((c) => CATEGORY_LABEL[c] ?? c).join(", ") || "none" : "…"
        }
      />
      <Row label="DNSBL zones" value={checks ? checks.dnsbl.zones.join(", ") : "…"} />
      <Row
        label="Default DKIM selectors"
        value={checks ? checks.dkim.defaultSelectors.join(", ") : "…"}
      />
      <Row
        label="Score thresholds"
        value={
          checks
            ? `green ≥ ${checks.thresholds.green} · amber ${checks.thresholds.amber}–${checks.thresholds.green - 1} · red < ${checks.thresholds.amber}`
            : "…"
        }
      />
      <Row
        label="Severity weights"
        value={
          checks
            ? `critical −${checks.weights.critical} · warning −${checks.weights.warning} · info −${checks.weights.info}`
            : "…"
        }
      />
      <Row label="SPF lookup limit" value={checks ? String(checks.spf.maxLookups) : "…"} />
    </Panel>
  )
}

/* --------------------------------- §5 Storage & data --------------------------------- */

function StoragePanel() {
  const { data } = useSettings()
  const openDir = useOpenStateDir()
  const [exporting, setExporting] = useState(false)

  const onExport = async () => {
    setExporting(true)
    try {
      await downloadExport()
    } catch {
      toast.error("Could not build the export archive")
    } finally {
      setExporting(false)
    }
  }

  return (
    <Panel title="Storage & data">
      <Row label="State directory" value={data?.stateDir ?? "…"} />
      <Row
        label="History retention"
        value={data ? `${data.config.storage.retentionDays} days (admin-only to edit)` : "…"}
      />
      <div className="mt-3 flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() =>
            openDir.mutate(undefined, {
              onSuccess: (r) => {
                if (!r.opened) toast.error(`Could not open ${r.stateDir}`)
              },
            })
          }
          className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
        >
          <FolderOpen className="h-4 w-4" /> Open state dir
        </button>
        <button
          type="button"
          onClick={onExport}
          disabled={exporting}
          className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-50"
        >
          {exporting && <Loader2 className="h-4 w-4 animate-spin" />}
          Export backup (.zip)
        </button>
      </div>
      <p className="mt-3 text-xs text-[var(--edh-muted)]">
        Import and the destructive Reset actions are admin-only and live in the Admin section.
        There is no database — everything is YAML/JSON files under the state dir.
      </p>
    </Panel>
  )
}

/* ------------------------------ §6 Tools & environment ------------------------------ */

function ToolsPanel() {
  const { data } = useSettings()
  const detect = useDetectTools()
  const status = data?.toolStatus

  const toolValue = (tool: { found: boolean; version: string | null } | undefined) => {
    if (!tool) return "…"
    return tool.found ? (tool.version ?? "installed") : "not installed"
  }

  return (
    <Panel title="Tools & environment">
      <Row label="dig (DNS lookups)" value={toolValue(status?.dig)} />
      <Row label="swaks (SMTP tests / notification email)" value={toolValue(status?.swaks)} />
      <Row
        label="DNS resolvers"
        value={
          data
            ? data.config.tools.resolvers.length > 0
              ? data.config.tools.resolvers.join(", ")
              : "system default"
            : "…"
        }
      />
      <Row label="Query timeout" value={data ? `${data.config.tools.timeoutMs} ms` : "…"} />
      <Row
        label="Prefer CLI tools"
        value={data ? (data.config.tools.preferCli ? "yes" : "no") : "…"}
      />
      <button
        type="button"
        onClick={() =>
          detect.mutate(undefined, {
            onSuccess: () => toast.success("Tool detection refreshed"),
            onError: () => toast.error("Could not re-detect tools"),
          })
        }
        disabled={detect.isPending}
        className="mt-3 inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-50"
      >
        {detect.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
        Re-detect tools
      </button>
      <p className="mt-3 text-xs text-[var(--edh-muted)]">
        Resolver, timeout, and the CLI preference are admin-only to change.
      </p>
    </Panel>
  )
}

/* ------------------------------------ shared bits ------------------------------------ */

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-[var(--edh-border)] bg-white p-5">
      <h2 className="mb-3 font-semibold">{title}</h2>
      {children}
    </section>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-4 border-b border-[var(--edh-border)] py-2 text-sm last:border-0">
      <span className="shrink-0 text-[var(--edh-muted)]">{label}</span>
      <span className="text-right font-medium">{value}</span>
    </div>
  )
}

function FieldRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 py-1.5 text-sm">
      <span className="text-[var(--edh-muted)]">{label}</span>
      {children}
    </div>
  )
}
