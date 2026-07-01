import { join } from "node:path"
import { resolveStateDir } from "@shared/state-dir"
import { readYaml, writeYaml } from "@shared/yaml-store"
import {
  type AppConfig,
  CHECK_CATEGORIES,
  type CheckCategory,
  DEFAULT_CONFIG,
} from "./settings.types"

/**
 * The config.yaml store (pm/settings.mdx "Settings config model"). A thin, defensive layer over
 * the shared atomic yaml-store: reads deep-merge the on-disk document over DEFAULT_CONFIG so a
 * hand-edited or older file (missing keys, wrong scalar types) always loads into a complete,
 * well-typed AppConfig; writes persist the full document with write-temp-then-rename.
 */

export const CONFIG_FILE_NAME = "config.yaml"

export function configFilePath(): string {
  return join(resolveStateDir(), CONFIG_FILE_NAME)
}

export function loadConfig(): AppConfig {
  const raw = readYaml<unknown>(configFilePath(), {})
  return normalizeConfig(raw)
}

export function saveConfig(config: AppConfig): void {
  writeYaml(configFilePath(), config)
}

/** Coerce whatever was on disk into a complete AppConfig, falling back per-field to defaults. */
export function normalizeConfig(raw: unknown): AppConfig {
  const doc = isRecord(raw) ? raw : {}
  const d = DEFAULT_CONFIG
  const checks = sub(doc, "checks")
  const notifications = sub(doc, "notifications")

  return {
    checks: {
      enabled: categoryList(get(checks, "enabled"), d.checks.enabled),
      spf: { maxLookups: num(get(sub(checks, "spf"), "maxLookups"), d.checks.spf.maxLookups) },
      dkim: {
        defaultSelectors: strList(
          get(sub(checks, "dkim"), "defaultSelectors"),
          d.checks.dkim.defaultSelectors,
        ),
      },
      dnsbl: { zones: strList(get(sub(checks, "dnsbl"), "zones"), d.checks.dnsbl.zones) },
      thresholds: {
        green: num(get(sub(checks, "thresholds"), "green"), d.checks.thresholds.green),
        amber: num(get(sub(checks, "thresholds"), "amber"), d.checks.thresholds.amber),
      },
      weights: {
        critical: num(get(sub(checks, "weights"), "critical"), d.checks.weights.critical),
        warning: num(get(sub(checks, "weights"), "warning"), d.checks.weights.warning),
        info: num(get(sub(checks, "weights"), "info"), d.checks.weights.info),
      },
    },
    schedule: {
      enabled: bool(get(sub(doc, "schedule"), "enabled"), d.schedule.enabled),
      cadence: str(get(sub(doc, "schedule"), "cadence"), d.schedule.cadence),
    },
    notifications: {
      webhook: {
        enabled: bool(get(sub(notifications, "webhook"), "enabled"), d.notifications.webhook.enabled),
        url: str(get(sub(notifications, "webhook"), "url"), d.notifications.webhook.url),
      },
      smtp: {
        host: str(get(sub(notifications, "smtp"), "host"), d.notifications.smtp.host),
        port: num(get(sub(notifications, "smtp"), "port"), d.notifications.smtp.port),
        from: str(get(sub(notifications, "smtp"), "from"), d.notifications.smtp.from),
      },
      users: userNotificationMap(get(notifications, "users")),
    },
    storage: {
      retentionDays: num(get(sub(doc, "storage"), "retentionDays"), d.storage.retentionDays),
    },
    tools: {
      preferCli: bool(get(sub(doc, "tools"), "preferCli"), d.tools.preferCli),
      resolvers: strList(get(sub(doc, "tools"), "resolvers"), d.tools.resolvers),
      timeoutMs: num(get(sub(doc, "tools"), "timeoutMs"), d.tools.timeoutMs),
    },
    access: {
      allowedDomains: strList(get(sub(doc, "access"), "allowedDomains"), d.access.allowedDomains),
    },
    appearance: { users: userAppearanceMap(get(sub(doc, "appearance"), "users")) },
  }
}

// ---------------------------------------------------------------------------
// Coercion helpers — defensive against hand-edited YAML.
// ---------------------------------------------------------------------------

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v)
}

function sub(v: unknown, key: string): Record<string, unknown> {
  const child = isRecord(v) ? v[key] : undefined
  return isRecord(child) ? child : {}
}

function get(v: Record<string, unknown>, key: string): unknown {
  return v[key]
}

function str(v: unknown, fallback: string): string {
  return typeof v === "string" ? v : fallback
}

function num(v: unknown, fallback: number): number {
  return typeof v === "number" && Number.isFinite(v) ? v : fallback
}

function bool(v: unknown, fallback: boolean): boolean {
  return typeof v === "boolean" ? v : fallback
}

function strList(v: unknown, fallback: string[]): string[] {
  if (!Array.isArray(v)) return [...fallback]
  return v.filter((s): s is string => typeof s === "string").map((s) => s.trim()).filter(Boolean)
}

function categoryList(v: unknown, fallback: CheckCategory[]): CheckCategory[] {
  if (!Array.isArray(v)) return [...fallback]
  const valid = v.filter((c): c is CheckCategory =>
    CHECK_CATEGORIES.includes(c as CheckCategory),
  )
  return [...new Set(valid)]
}

function userNotificationMap(v: unknown): AppConfig["notifications"]["users"] {
  if (!isRecord(v)) return {}
  const out: AppConfig["notifications"]["users"] = {}
  for (const [sub_, prefs] of Object.entries(v)) {
    if (!isRecord(prefs)) continue
    out[sub_] = {
      desktop: bool(prefs.desktop, true),
      email: bool(prefs.email, false),
      minSeverity: oneOf(prefs.minSeverity, ["info", "warning", "critical"] as const, "warning"),
      mode: oneOf(prefs.mode, ["immediate", "daily"] as const, "immediate"),
    }
  }
  return out
}

function userAppearanceMap(v: unknown): AppConfig["appearance"]["users"] {
  if (!isRecord(v)) return {}
  const out: AppConfig["appearance"]["users"] = {}
  for (const [sub_, ap] of Object.entries(v)) {
    if (!isRecord(ap)) continue
    out[sub_] = {
      theme: oneOf(ap.theme, ["system", "light", "dark"] as const, "system"),
      density: oneOf(ap.density, ["comfortable", "compact"] as const, "comfortable"),
    }
  }
  return out
}

function oneOf<T extends string>(v: unknown, allowed: readonly T[], fallback: T): T {
  return typeof v === "string" && (allowed as readonly string[]).includes(v) ? (v as T) : fallback
}
