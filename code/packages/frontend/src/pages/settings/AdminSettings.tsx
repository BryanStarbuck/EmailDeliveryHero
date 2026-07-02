import { useAuth } from "@auth/react"
import { Link } from "@tanstack/react-router"
import { Loader2, Minus, Plus, ShieldAlert } from "lucide-react"
import { useEffect, useRef, useState } from "react"
import { toast } from "sonner"
import {
  type BimiMvaEntry,
  type RegistrarReputationEntry,
  type SettingsView,
  type TakeoverFingerprint,
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
  /** List-Unsubscribe / one-click admin settings (pm/checks/list_unsubscribe.mdx §4). */
  unsubBulkThreshold: number
  unsubProbeTimeoutMs: number
  unsubProbeAllowed: boolean
  unsubProbeCadenceHours: number
  /**
   * URL Reputation admin settings (pm/checks/link_url_reputation.mdx §4/§5): the public
   * URL-shortener domain list (comma-separated; empty = the bundled seed list) and the Google
   * Safe Browsing API key ("" = not configured — content.url_safe_browsing stays info-gated).
   */
  urlShorteners: string
  safeBrowsingKey: string
  /** SpamAssassin binary-path overrides (pm/checks/content_scoring.mdx §4; empty = auto-detect). */
  spamassassinPath: string
  spamcPath: string
  /** BIMI VMC/CMC issuer allow-list (pm/checks/bimi.mdx §4/§5 — admin-only). */
  mvaAllowList: BimiMvaEntry[]
  /** DNS-health subdomain-takeover fingerprints (pm/checks/dns_health.mdx §4/§5 — admin-only). */
  fingerprints: TakeoverFingerprint[]
  /** Domain-registration-reputation settings (pm/checks/domain_reputation.mdx §4 — admin-only). */
  repCacheTtlHours: number
  repRdapBudget: number
  repParkingNs: string
  repHighAbuseTlds: string
  repWatchlist: RegistrarReputationEntry[]
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
    unsubBulkThreshold: checks.listUnsub?.bulkThresholdPerDay ?? 5000,
    unsubProbeTimeoutMs: checks.listUnsub?.probeTimeoutMs ?? 5000,
    unsubProbeAllowed: checks.listUnsub?.probeAllowed ?? false,
    unsubProbeCadenceHours: checks.listUnsub?.probeCadenceHours ?? 24,
    urlShorteners: (checks.content?.url?.shorteners ?? []).join(", "),
    safeBrowsingKey: checks.content?.url?.safeBrowsingKey ?? "",
    spamassassinPath: tools.paths?.spamassassin ?? "",
    spamcPath: tools.paths?.spamc ?? "",
    mvaAllowList: (checks.bimi?.mvaAllowList ?? []).map((m) => ({
      ...m,
      markTypes: [...m.markTypes],
    })),
    fingerprints: (view.config.dns_health?.fingerprints ?? []).map((f) => ({ ...f })),
    repCacheTtlHours: view.config.domain_reputation?.cache_ttl_hours ?? 24,
    repRdapBudget: view.config.domain_reputation?.rdap_request_budget ?? 5,
    repParkingNs: (view.config.domain_reputation?.parking_nameservers ?? []).join(", "),
    repHighAbuseTlds: (view.config.domain_reputation?.high_abuse_tlds ?? []).join(", "),
    repWatchlist: (view.config.domain_reputation?.registrar_reputation ?? []).map((r) => ({
      ...r,
    })),
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

const splitList = (value: string): string[] => [
  ...new Set(
    value
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  ),
]

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
        // URL Reputation (pm/checks/link_url_reputation.mdx §4/§5): an empty shortener list keeps
        // the bundled seed defaults; an empty key clears/leaves Safe Browsing unconfigured.
        url: {
          shorteners: splitList(d.urlShorteners).map((s) => s.toLowerCase()),
          safeBrowsingKey: d.safeBrowsingKey.trim(),
        },
      },
      // BIMI MVA allow-list (pm/checks/bimi.mdx §4/§5): blank rows are dropped on save.
      bimi: {
        mvaAllowList: d.mvaAllowList
          .map((m) => ({
            name: m.name.trim(),
            issuerDnMatch: m.issuerDnMatch.trim(),
            markTypes: m.markTypes,
            enabled: m.enabled,
          }))
          .filter((m) => m.name && m.issuerDnMatch),
      },
      thresholds: { green: d.green, amber: d.amber },
      weights: { critical: d.critical, warning: d.warning, info: d.info },
    },
    notifications: {
      webhook: { enabled: d.webhookEnabled, url: d.webhookUrl.trim() },
      smtp: { host: d.smtpHost.trim(), port: d.smtpPort, from: d.smtpFrom.trim() },
    },
    storage: { retentionDays: d.retentionDays },
    tools: {
      preferCli: d.preferCli,
      resolvers: splitList(d.resolvers),
      timeoutMs: d.timeoutMs,
      // SpamAssassin binary-path overrides (pm/checks/content_scoring.mdx §4); an empty value
      // clears the override so the ToolLocator falls back to PATH/Homebrew discovery.
      paths: { spamassassin: d.spamassassinPath.trim(), spamc: d.spamcPath.trim() },
    },
    access: { allowedDomains: splitList(d.allowedDomains) },
    // Subdomain-takeover fingerprints (pm/checks/dns_health.mdx §4/§5): blank rows are dropped;
    // the backend dedupes (provider, cname_suffix) pairs like the SQL UNIQUE constraint.
    dns_health: {
      fingerprints: d.fingerprints
        .map((f) => ({
          provider: f.provider.trim(),
          cname_suffix: f.cname_suffix.trim(),
          ...(f.unclaimed_signature?.trim()
            ? { unclaimed_signature: f.unclaimed_signature.trim() }
            : {}),
          enabled: f.enabled,
        }))
        .filter((f) => f.provider && f.cname_suffix),
    },
    // Domain-registration-reputation settings (pm/checks/domain_reputation.mdx §4 "Global admin
    // settings"): blank watchlist rows are dropped; the backend dedupes (match_type, match_value)
    // pairs like the SQL UNIQUE constraint and lower-cases the NS/TLD reference lists.
    domain_reputation: {
      cache_ttl_hours: d.repCacheTtlHours,
      rdap_request_budget: d.repRdapBudget,
      parking_nameservers: splitList(d.repParkingNs),
      high_abuse_tlds: splitList(d.repHighAbuseTlds),
      registrar_reputation: d.repWatchlist
        .map((r) => ({
          match_type: r.match_type,
          match_value: r.match_value.trim(),
          ...(r.note?.trim() ? { note: r.note.trim() } : {}),
        }))
        .filter((r) => r.match_value),
    },
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
      // A 403 already surfaces via the shared axios interceptor's permission toast
      // (pm/engineering.mdx §5) — only toast the generic failure for other errors.
      const status = (err as { response?: { status?: number } }).response?.status
      if (status !== 403) toast.error("Could not save admin settings")
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

        {/* BIMI VMC/CMC allow-list (pm/checks/bimi.mdx §4/§5): which Mark Verifying Authorities
            are recognized when the future certificate-validation round checks the a= VMC issuer.
            Admin-only — the backend refuses this write without role:admin. */}
        <h3 className="mb-1 mt-4 text-sm font-medium">
          BIMI — recognized Mark Verifying Authorities (VMC/CMC issuers)
        </h3>
        <p className="mb-1 text-xs text-[var(--edh-muted)]">
          The future VMC certificate round matches each certificate&apos;s issuer DN against this
          allow-list; an unrecognized issuer makes <code>content.bimi_vmc_valid</code> critical.
        </p>
        {draft.mvaAllowList.map((mva, i) => {
          const setMva = (patch: Partial<BimiMvaEntry>) =>
            set({
              mvaAllowList: draft.mvaAllowList.map((m, j) => (j === i ? { ...m, ...patch } : m)),
            })
          const toggleMark = (mark: "vmc" | "cmc") =>
            setMva({
              markTypes: mva.markTypes.includes(mark)
                ? mva.markTypes.filter((t) => t !== mark)
                : [...mva.markTypes, mark],
            })
          return (
            // biome-ignore lint/suspicious/noArrayIndexKey: rows are positional edits
            <div key={i} className="flex flex-wrap items-center gap-2 py-1">
              <input
                value={mva.name}
                onChange={(e) => setMva({ name: e.target.value })}
                placeholder="Name (e.g. DigiCert)"
                aria-label={`MVA ${i + 1} name`}
                className="w-40 rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm"
              />
              <input
                value={mva.issuerDnMatch}
                onChange={(e) => setMva({ issuerDnMatch: e.target.value })}
                placeholder="Issuer DN match"
                aria-label={`MVA ${i + 1} issuer DN match`}
                className="w-56 rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm"
              />
              <label className="flex items-center gap-1 text-xs">
                <input
                  type="checkbox"
                  checked={mva.markTypes.includes("vmc")}
                  onChange={() => toggleMark("vmc")}
                />
                VMC
              </label>
              <label className="flex items-center gap-1 text-xs">
                <input
                  type="checkbox"
                  checked={mva.markTypes.includes("cmc")}
                  onChange={() => toggleMark("cmc")}
                />
                CMC
              </label>
              <label className="flex items-center gap-1 text-xs">
                <input
                  type="checkbox"
                  checked={mva.enabled}
                  onChange={(e) => setMva({ enabled: e.target.checked })}
                />
                enabled
              </label>
              <button
                type="button"
                onClick={() => set({ mvaAllowList: draft.mvaAllowList.filter((_, j) => j !== i) })}
                aria-label={`Remove MVA ${mva.name || i + 1}`}
                title="Remove this Mark Verifying Authority"
                className="rounded p-1 text-[var(--edh-muted)] hover:bg-slate-100 hover:text-slate-700"
              >
                <Minus className="h-4 w-4" />
              </button>
            </div>
          )
        })}
        <button
          type="button"
          onClick={() =>
            set({
              mvaAllowList: [
                ...draft.mvaAllowList,
                { name: "", issuerDnMatch: "", markTypes: ["vmc"], enabled: true },
              ],
            })
          }
          className="mt-1 inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
        >
          <Plus className="h-4 w-4" /> Add MVA
        </button>

        {/* DNS-health takeover fingerprints (pm/checks/dns_health.mdx §4/§5): the bundled
            subdomain-takeover fingerprint list the dangling-CNAME sub-check matches CNAME chain
            targets against. Admin-only — keep it fresh, new SaaS endpoints appear constantly. */}
        <h3 className="mb-1 mt-4 text-sm font-medium">
          DNS health — subdomain-takeover fingerprints
        </h3>
        <p className="mb-1 text-xs text-[var(--edh-muted)]">
          A CNAME whose final target matches one of these suffixes and no longer resolves is flagged
          as a critical <code>infra.dangling_cname</code> takeover risk.
        </p>
        {draft.fingerprints.map((fp, i) => {
          const setFp = (patch: Partial<TakeoverFingerprint>) =>
            set({
              fingerprints: draft.fingerprints.map((f, j) => (j === i ? { ...f, ...patch } : f)),
            })
          return (
            // biome-ignore lint/suspicious/noArrayIndexKey: rows are positional edits
            <div key={i} className="flex flex-wrap items-center gap-2 py-1">
              <input
                value={fp.provider}
                onChange={(e) => setFp({ provider: e.target.value })}
                placeholder="Provider (e.g. Heroku)"
                aria-label={`Fingerprint ${i + 1} provider`}
                className="w-44 rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm"
              />
              <input
                value={fp.cname_suffix}
                onChange={(e) => setFp({ cname_suffix: e.target.value })}
                placeholder="CNAME suffix (e.g. .herokudns.com)"
                aria-label={`Fingerprint ${i + 1} CNAME suffix`}
                className="w-56 rounded-md border border-[var(--edh-border)] px-2 py-1 font-mono text-sm"
              />
              <label className="flex items-center gap-1 text-xs">
                <input
                  type="checkbox"
                  checked={fp.enabled}
                  onChange={(e) => setFp({ enabled: e.target.checked })}
                />
                enabled
              </label>
              <button
                type="button"
                onClick={() => set({ fingerprints: draft.fingerprints.filter((_, j) => j !== i) })}
                aria-label={`Remove fingerprint ${fp.provider || i + 1}`}
                title="Remove this fingerprint"
                className="rounded p-1 text-[var(--edh-muted)] hover:bg-slate-100 hover:text-slate-700"
              >
                <Minus className="h-4 w-4" />
              </button>
            </div>
          )
        })}
        <button
          type="button"
          onClick={() =>
            set({
              fingerprints: [
                ...draft.fingerprints,
                { provider: "", cname_suffix: "", enabled: true },
              ],
            })
          }
          className="mt-1 inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
        >
          <Plus className="h-4 w-4" /> Add fingerprint
        </button>

        {/* Domain registration reputation (pm/checks/domain_reputation.mdx §4 "Global admin
            settings"): the curated parking-nameserver / high-abuse-TLD / registrar-reputation
            reference lists and the RDAP request budget + cache TTL. Admin-only. */}
        <h3 className="mb-1 mt-4 text-sm font-medium">
          Domain registration reputation (WHOIS/RDAP)
        </h3>
        <p className="mb-1 text-xs text-[var(--edh-muted)]">
          Registration data is stale-tolerant and RDAP endpoints rate-limit hard — snapshots are
          cached for the TTL below and each run spends at most the request budget. The reference
          lists feed <code>infra.parking_nameservers</code>, <code>infra.tld_risk</code>, and{" "}
          <code>infra.registrar_reputation</code>.
        </p>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          <NumberInput
            label="RDAP cache TTL (hours, default 24)"
            value={draft.repCacheTtlHours}
            onChange={(v) => set({ repCacheTtlHours: v })}
          />
          <NumberInput
            label="RDAP request budget per run (default 5)"
            value={draft.repRdapBudget}
            onChange={(v) => set({ repRdapBudget: v })}
          />
        </div>
        <LabeledInput
          label="Parking-provider nameserver suffixes (comma-separated, e.g. sedoparking.com)"
          value={draft.repParkingNs}
          onChange={(v) => set({ repParkingNs: v })}
          wide
        />
        <LabeledInput
          label="High-abuse TLDs (comma-separated, e.g. top, xyz — Spamhaus TLD stats)"
          value={draft.repHighAbuseTlds}
          onChange={(v) => set({ repHighAbuseTlds: v })}
          wide
        />
        <h4 className="mb-1 mt-3 text-xs font-medium text-slate-600">
          Registrar abuse-reputation watchlist
        </h4>
        {draft.repWatchlist.map((entry, i) => {
          const setEntry = (patch: Partial<RegistrarReputationEntry>) =>
            set({
              repWatchlist: draft.repWatchlist.map((r, j) => (j === i ? { ...r, ...patch } : r)),
            })
          return (
            // biome-ignore lint/suspicious/noArrayIndexKey: rows are positional edits
            <div key={i} className="flex flex-wrap items-center gap-2 py-1">
              <select
                value={entry.match_type}
                onChange={(e) =>
                  setEntry({
                    match_type: e.target.value as RegistrarReputationEntry["match_type"],
                  })
                }
                aria-label={`Watchlist entry ${i + 1} match type`}
                className="rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm"
              >
                <option value="registrar_iana_id">Registrar IANA id</option>
                <option value="registrar_name">Registrar name</option>
                <option value="tld">TLD</option>
              </select>
              <input
                value={entry.match_value}
                onChange={(e) => setEntry({ match_value: e.target.value })}
                placeholder={
                  entry.match_type === "registrar_iana_id"
                    ? "IANA id (e.g. 1234)"
                    : entry.match_type === "tld"
                      ? "TLD (e.g. top)"
                      : "Name substring"
                }
                aria-label={`Watchlist entry ${i + 1} match value`}
                className="w-40 rounded-md border border-[var(--edh-border)] px-2 py-1 font-mono text-sm"
              />
              <input
                value={entry.note ?? ""}
                onChange={(e) => setEntry({ note: e.target.value })}
                placeholder="Note (optional)"
                aria-label={`Watchlist entry ${i + 1} note`}
                className="w-56 rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm"
              />
              <button
                type="button"
                onClick={() => set({ repWatchlist: draft.repWatchlist.filter((_, j) => j !== i) })}
                aria-label={`Remove watchlist entry ${entry.match_value || i + 1}`}
                title="Remove this watchlist entry"
                className="rounded p-1 text-[var(--edh-muted)] hover:bg-slate-100 hover:text-slate-700"
              >
                <Minus className="h-4 w-4" />
              </button>
            </div>
          )
        })}
        <button
          type="button"
          onClick={() =>
            set({
              repWatchlist: [
                ...draft.repWatchlist,
                { match_type: "registrar_name", match_value: "", note: "" },
              ],
            })
          }
          className="mt-1 inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
        >
          <Plus className="h-4 w-4" /> Add watchlist entry
        </button>
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
        {title}{" "}
        <span className="ml-1 align-middle text-xs text-[var(--edh-muted)]">🔒 admin-only</span>
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
