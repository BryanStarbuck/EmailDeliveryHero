import type { AppConfigFile, UserPreferences } from "@shared/config-store"

/**
 * The Settings surface types (pm/settings.mdx). Persistence is the hierarchical config store of
 * pm/storage.mdx (shared/config-store.ts): global, admin-owned settings live in
 * <state dir>/config.yaml; each user's own preferences live in users/<email>/config.yaml (the
 * literal "default" folder for the logged-out user). No database.
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

/**
 * What GET /api/settings returns: the resolved state dir, the global/admin-owned config blocks
 * (everything is *visible* to all users — only writes are gated, pm/settings.mdx "Permissions"),
 * the caller's own per-user block, and the last tool probe.
 */
export interface SettingsView {
  /** The active state dir (default ~/.email_delivery_hero, or EDH_STATE_DIR). Display only. */
  stateDir: string
  config: {
    checks: AppConfigFile["checks"]
    schedule: AppConfigFile["schedule"]
    /** Shared channels only (admin-only to edit); per-user prefs live under `me`. */
    notifications: AppConfigFile["notifications"]
    storage: AppConfigFile["storage"]
    tools: AppConfigFile["tools"]
    access: AppConfigFile["access"]
    /**
     * DNS Zone & Nameserver Health (pm/checks/dns_health.mdx §4/§5): the bundled, admin-editable
     * subdomain-takeover fingerprint list (`takeover_fingerprints` mapped onto config.yaml).
     */
    dns_health: AppConfigFile["dns_health"]
  }
  /** The caller's own per-user block (defaults when the user has never saved). */
  me: {
    /** OpenAuthFederated `sub` (`user_…`), or the literal "default" when logged out. */
    sub: string
    email: string
    notifications: UserPreferences["notifications"]
    appearance: { theme: Theme; density: Density }
  }
  toolStatus: ToolsDetection | null
}

/** POST /api/settings/notifications/test — what happened on each channel. */
export interface TestNotificationResult {
  desktop: { attempted: boolean; detail: string }
  email: { attempted: boolean; ok: boolean; detail: string }
  webhook: { attempted: boolean; ok: boolean; detail: string }
}

/** POST /api/settings/reset outcome. */
export interface ResetResult {
  scope: "audit_history" | "app"
  removed: string[]
}
