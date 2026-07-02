import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api } from "./axios"
import type { ScheduleConfig } from "./scheduler"

/**
 * The Settings contract (pm/settings.mdx "REST contract"): GET /api/settings returns the global
 * config blocks (visible to everyone — only writes are gated), the caller's own per-user block,
 * and the detected tool status. PUT /api/settings writes the caller's OWN preferences (all-users);
 * PUT /api/settings/admin writes the admin-only global fields and is refused 403 without
 * role:admin — the backend is authoritative, the UI gate is UX only.
 */

export type CheckCategory = "spf" | "dkim" | "dmarc" | "dnsbl" | "dns_infra" | "spam_content"
export type NotificationSeverity = "info" | "warning" | "critical"
export type NotificationMode = "immediate" | "daily"
export type Theme = "system" | "light" | "dark"
export type Density = "comfortable" | "compact"

/**
 * One recognized Mark Verifying Authority (pm/checks/bimi.mdx §5 — the `bimi_mva` reference table
 * mapped onto `config.yaml → checks.bimi.mvaAllowList`; admin-only editing, §4).
 */
export interface BimiMvaEntry {
  name: string
  issuerDnMatch: string
  /** Mark types the MVA may issue: "vmc" (registered trademark) and/or "cmc". */
  markTypes: string[]
  enabled: boolean
}

/**
 * One subdomain-takeover fingerprint (pm/checks/dns_health.mdx §4/§5 — the `takeover_fingerprints`
 * reference table mapped onto `config.yaml → dns_health.fingerprints`; admin-only editing). The
 * dangling-CNAME sub-check flags a CNAME whose final target matches `cname_suffix` and no longer
 * resolves as a critical takeover risk.
 */
export interface TakeoverFingerprint {
  provider: string
  /** Suffix matched against the final CNAME target, e.g. ".herokudns.com". */
  cname_suffix: string
  /** HTTP body marker for the future "unclaimed endpoint" confirmation probe. */
  unclaimed_signature?: string
  enabled: boolean
}

export interface ChecksConfig {
  enabled: string[]
  spf: { maxLookups: number }
  dkim: { defaultSelectors: string[] }
  dnsbl: { zones: string[] }
  /** Content-scoring admin settings (pm/checks/content_scoring.mdx §4). */
  content: { threshold: number; safeTarget: number; networkTests: boolean }
  /** BIMI admin settings (pm/checks/bimi.mdx §4/§5): the VMC/CMC issuer allow-list. */
  bimi: { mvaAllowList: BimiMvaEntry[] }
  /**
   * DANE / TLSA admin settings (pm/checks/dane_tlsa.mdx §4): the FUTURE :25 STARTTLS cert-match
   * probe toggle + timeout and the require-AD-bit validating-resolver switch. Optional so older
   * backend payloads stay valid.
   */
  dane?: { probeEnabled: boolean; probeTimeoutMs: number; requireAdBit: boolean }
  thresholds: { green: number; amber: number }
  weights: { critical: number; warning: number; info: number }
}

export interface NotificationChannels {
  webhook: { enabled: boolean; url: string }
  smtp: { host: string; port: number; from: string }
}

export interface UserNotificationPrefs {
  desktop: boolean
  email: boolean
  minSeverity: NotificationSeverity
  mode: NotificationMode
}

export interface ToolStatus {
  found: boolean
  version: string | null
  path: string | null
}

export interface ToolsDetection {
  dig: ToolStatus
  swaks: ToolStatus
  detectedAt: string
}

/** GET /api/settings. */
export interface SettingsView {
  stateDir: string
  config: {
    checks: ChecksConfig
    schedule: ScheduleConfig
    notifications: NotificationChannels
    storage: { retentionDays: number }
    tools: {
      preferCli: boolean
      resolvers: string[]
      timeoutMs: number
      /** Explicit per-tool binary-path overrides, e.g. spamassassin/spamc (content_scoring §4). */
      paths: Record<string, string>
    }
    access: { allowedDomains: string[] }
    /** DNS-health takeover-fingerprint list (pm/checks/dns_health.mdx §4/§5; admin-only editing). */
    dns_health: { fingerprints: TakeoverFingerprint[] }
  }
  me: {
    sub: string
    email: string
    notifications: UserNotificationPrefs
    appearance: { theme: Theme; density: Density }
  }
  toolStatus: ToolsDetection | null
}

/** PUT /api/settings — the caller's own per-user block. */
export interface UpdateMySettingsInput {
  notifications?: Partial<UserNotificationPrefs>
  appearance?: { theme?: Theme; density?: Density }
}

/** PUT /api/settings/admin — deep-partial admin-only global fields. */
export interface UpdateAdminSettingsInput {
  checks?: {
    enabled?: string[]
    spf?: { maxLookups?: number }
    dkim?: { defaultSelectors?: string[] }
    dnsbl?: { zones?: string[] }
    content?: { threshold?: number; safeTarget?: number; networkTests?: boolean }
    bimi?: { mvaAllowList?: BimiMvaEntry[] }
    dane?: { probeEnabled?: boolean; probeTimeoutMs?: number; requireAdBit?: boolean }
    thresholds?: { green?: number; amber?: number }
    weights?: { critical?: number; warning?: number; info?: number }
  }
  schedule?: { enabled?: boolean; cadence?: string }
  notifications?: {
    webhook?: { enabled?: boolean; url?: string }
    smtp?: { host?: string; port?: number; from?: string }
  }
  storage?: { retentionDays?: number }
  tools?: {
    preferCli?: boolean
    resolvers?: string[]
    timeoutMs?: number
    /** Per-tool binary-path overrides (empty string clears an override). */
    paths?: Record<string, string>
  }
  access?: { allowedDomains?: string[] }
  /** Replaces the whole takeover-fingerprint list (pm/checks/dns_health.mdx §4; admin-only). */
  dns_health?: { fingerprints?: TakeoverFingerprint[] }
}

export interface TestNotificationResult {
  desktop: { attempted: boolean; detail: string }
  email: { attempted: boolean; ok: boolean; detail: string }
  webhook: { attempted: boolean; ok: boolean; detail: string }
}

const KEY = ["settings"] as const

export function useSettings() {
  return useQuery({
    queryKey: KEY,
    queryFn: async () => (await api.get<SettingsView>("/settings")).data,
  })
}

export function useUpdateMySettings() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (input: UpdateMySettingsInput) =>
      (await api.put<SettingsView>("/settings", input)).data,
    onSuccess: (view) => qc.setQueryData(KEY, view),
  })
}

export function useUpdateAdminSettings() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (input: UpdateAdminSettingsInput) =>
      (await api.put<SettingsView>("/settings/admin", input)).data,
    onSuccess: (view) => qc.setQueryData(KEY, view),
  })
}

export function useTestNotification() {
  return useMutation({
    mutationFn: async () =>
      (await api.post<TestNotificationResult>("/settings/notifications/test")).data,
  })
}

export function useDetectTools() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async () => (await api.post<ToolsDetection>("/settings/tools/detect")).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}

/** POST /api/settings/open-state-dir — reveal the state dir in Finder (§5, localhost app). */
export function useOpenStateDir() {
  return useMutation({
    mutationFn: async () =>
      (await api.post<{ opened: boolean; stateDir: string }>("/settings/open-state-dir")).data,
  })
}

/** GET /api/settings/export — download the backup zip via a browser save (§5 Export). */
export async function downloadExport(): Promise<void> {
  const res = await api.get<Blob>("/settings/export", { responseType: "blob" })
  const disposition = String(res.headers["content-disposition"] ?? "")
  const fileName = /filename="([^"]+)"/.exec(disposition)?.[1] ?? "email-delivery-hero-export.zip"
  const url = URL.createObjectURL(res.data)
  const a = document.createElement("a")
  a.href = url
  a.download = fileName
  a.click()
  URL.revokeObjectURL(url)
}

/** POST /api/settings/import (admin) — restore from an exported archive. */
export function useImportArchive() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (archiveBase64: string) =>
      (await api.post<{ imported: string[] }>("/settings/import", { archiveBase64 })).data,
    onSuccess: () => qc.invalidateQueries(),
  })
}

/** POST /api/settings/reset (admin) — audit history only, or the whole app. */
export function useResetApp() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (scope: "audit_history" | "app") =>
      (await api.post<{ scope: string; removed: string[] }>("/settings/reset", { scope })).data,
    onSuccess: () => qc.invalidateQueries(),
  })
}
