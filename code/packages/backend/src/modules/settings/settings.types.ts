/**
 * The Settings config model (pm/settings.mdx "Settings config model"). Global, admin-owned
 * settings and per-user preference blocks all live in a single human-readable
 * ~/.email_delivery_hero/config.yaml under the state dir — no database. Per-user blocks are keyed
 * by the OpenAuthFederated `sub` (the literal "default" for the logged-out user).
 */

/** The six check categories (pm/spam_checks.mdx) that §2 "Enabled categories" toggles. */
export const CHECK_CATEGORIES = [
  "spf",
  "dkim",
  "dmarc",
  "dnsbl",
  "dns_infra",
  "spam_content",
] as const
export type CheckCategory = (typeof CHECK_CATEGORIES)[number]

export type NotificationSeverity = "info" | "warning" | "critical"
export type NotificationMode = "immediate" | "daily"
export type Theme = "system" | "light" | "dark"
export type Density = "comfortable" | "compact"

/** §4 — one user's own notification preferences (all-users editable, own block only). */
export interface UserNotificationPrefs {
  desktop: boolean
  email: boolean
  minSeverity: NotificationSeverity
  mode: NotificationMode
}

/** §8 — per-user, cosmetic only. */
export interface UserAppearance {
  theme: Theme
  density: Density
}

/** The full on-disk config.yaml shape (pm/settings.mdx config model). */
export interface AppConfig {
  checks: {
    /** §2 — which of the six categories run (admin-only). */
    enabled: CheckCategory[]
    spf: { maxLookups: number }
    dkim: { defaultSelectors: string[] }
    dnsbl: { zones: string[] }
    /** 0–100 score → colour: score >= green → green; green > score >= amber → amber; below → red. */
    thresholds: { green: number; amber: number }
    /** Points deducted per finding severity — feeds score derivation. */
    weights: { critical: number; warning: number; info: number }
  }
  /** §3 — summary here; the full scheduling config lives in pm/scheduled_checks.mdx. */
  schedule: { enabled: boolean; cadence: string }
  notifications: {
    /** Admin-only shared channel. */
    webhook: { enabled: boolean; url: string }
    /** Admin-only shared channel (sent via the configured SMTP relay / swaks). */
    smtp: { host: string; port: number; from: string }
    /** Per-user preferences, keyed by OpenAuthFederated sub ("default" when logged out). */
    users: Record<string, UserNotificationPrefs>
  }
  storage: { retentionDays: number }
  tools: { preferCli: boolean; resolvers: string[]; timeoutMs: number }
  /** §7 — display of the OAF-enforced access policy; the edit is applied on the OAF side. */
  access: { allowedDomains: string[] }
  appearance: { users: Record<string, UserAppearance> }
}

export const DEFAULT_USER_NOTIFICATIONS: UserNotificationPrefs = {
  desktop: true,
  email: false,
  minSeverity: "warning",
  mode: "immediate",
}

export const DEFAULT_USER_APPEARANCE: UserAppearance = {
  theme: "system",
  density: "comfortable",
}

/** Defaults straight from the pm/settings.mdx config-model example. */
export const DEFAULT_CONFIG: AppConfig = {
  checks: {
    enabled: ["spf", "dkim", "dmarc", "dnsbl", "dns_infra"],
    spf: { maxLookups: 10 },
    dkim: { defaultSelectors: ["google", "selector1", "selector2", "k1"] },
    dnsbl: {
      zones: ["zen.spamhaus.org", "b.barracudacentral.org", "bl.spamcop.net"],
    },
    thresholds: { green: 90, amber: 70 },
    weights: { critical: 40, warning: 15, info: 0 },
  },
  schedule: { enabled: true, cadence: "0 */6 * * *" },
  notifications: {
    webhook: { enabled: false, url: "" },
    smtp: { host: "", port: 587, from: "edh@whitehatengineering.com" },
    users: {},
  },
  storage: { retentionDays: 90 },
  tools: { preferCli: false, resolvers: [], timeoutMs: 5000 },
  access: { allowedDomains: ["whitehatengineering.com", "act3ai.com"] },
  appearance: { users: {} },
}

/** Detected status of one Brew/CLI tool (§6 — probed at runtime, never persisted). */
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

/** What GET /api/settings returns: global config + the caller's per-user block + tool status. */
export interface SettingsView {
  /** The resolved state dir (default ~/.email_delivery_hero equivalent, or EDH_STATE_DIR). */
  stateDir: string
  /** Global/admin-owned config. Other users' per-user maps are stripped for privacy. */
  config: Omit<AppConfig, "notifications" | "appearance"> & {
    notifications: Omit<AppConfig["notifications"], "users">
    appearance: Record<string, never>
  }
  /** The caller's own per-user block (created with defaults on first read). */
  me: {
    sub: string
    notifications: UserNotificationPrefs
    appearance: UserAppearance
  }
  toolStatus: ToolsDetection | null
}
