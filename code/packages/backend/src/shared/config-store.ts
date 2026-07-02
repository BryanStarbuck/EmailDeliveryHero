import { existsSync } from "node:fs"
import { join } from "node:path"
import { logWarn } from "./logging"
import { resolveStateDir, stateSubdir } from "./state-dir"
import { readYaml, writeYaml } from "./yaml-store"

/**
 * The hierarchical config/settings store (pm/storage.mdx §3, §4, §8). Two scopes, both YAML under
 * the state root, both default-everything (a fresh install runs with no file present):
 *
 *   ~/.email_delivery_hero/config.yaml                — APP-LEVEL settings, install-wide
 *   ~/.email_delivery_hero/users/<email>/config.yaml  — PER-LOGGED-IN-USER settings, lazy-created
 *
 * <email> is the verified email from the OpenAuthFederated JWT (or the reserved literal "default"
 * when logged out — pm/security.mdx). Reads deep-merge the on-disk file over the typed defaults and
 * reject type-mismatched values loudly (logged, defaulted) rather than trusting them silently.
 * Writes are read-modify-write, stamp schema_version + updated_at, and go through the atomic
 * yaml-store (unique temp + rename). withFileLock() serializes async read-modify-write per file so
 * concurrent writers (server mode) never drop each other's changes; the sync helpers here are
 * inherently serialized by the event loop within one process.
 *
 * Secrets NEVER live here — Google client credentials come from env or the out-of-repo credentials
 * file, and the auth signing secret is its own file (pm/storage.mdx §7, pm/authentication.mdx).
 */

export const CONFIG_SCHEMA_VERSION = 1

// ─────────────────────────────────────────────────────────────────────────────
// App-level config.yaml (pm/storage.mdx §3) — one nested block per concern.
// ─────────────────────────────────────────────────────────────────────────────

export interface AppConfigFile {
  schema_version: number
  updated_at: string
  server: {
    frontend_port: number
    backend_port: number
    mode: "local" | "server"
  }
  checks: {
    enabled: string[]
    spf: { maxLookups: number }
    dkim: { defaultSelectors: string[] }
    dnsbl: { zones: string[] }
    thresholds: { green: number; amber: number }
    weights: { critical: number; warning: number; info: number }
  }
  schedule: {
    enabled: boolean
    cadence: "interval" | "daily" | "weekly"
    everyHours: number
    times: string[]
    weekdays: string[]
    timezone: string
    domains: "all" | string[]
    runner: "in-process" | "os"
    os: { kind: string; installed: boolean; label: string }
  }
  notifications: {
    webhook: { enabled: boolean; url: string }
    smtp: { host: string; port: number; from: string }
  }
  storage: { retentionDays: number }
  tools: { preferCli: boolean; resolvers: string[]; timeoutMs: number }
  access: { allowedDomains: string[] }
  defaults: UserPreferences
}

/** The per-user preference shape shared by `config.yaml → defaults` and each user file. */
export interface UserPreferences {
  theme: "system" | "light" | "dark"
  density: "comfortable" | "compact"
  notifications: {
    desktop: boolean
    email: boolean
    minSeverity: "info" | "warning" | "critical"
    mode: "immediate" | "daily"
  }
}

/** Detect the OS scheduling layer for the `schedule.os.kind` default (pm/scheduled_checks.mdx). */
function detectOsSchedulerKind(): string {
  if (process.platform === "darwin") return "launchd"
  if (process.platform === "win32") return "schtasks"
  return process.platform === "linux" ? "systemd" : "cron"
}

function systemTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC"
  } catch {
    return "UTC"
  }
}

/** Default-everything: the config the app boots on when no config.yaml exists (pm/storage.mdx §3). */
export function defaultAppConfig(): AppConfigFile {
  return {
    schema_version: CONFIG_SCHEMA_VERSION,
    updated_at: new Date().toISOString(),
    server: { frontend_port: 4444, backend_port: 9312, mode: "local" },
    checks: {
      enabled: ["spf", "dkim", "dmarc", "blacklists", "dns_infra"],
      spf: { maxLookups: 10 },
      dkim: { defaultSelectors: ["google", "selector1", "selector2", "k1"] },
      dnsbl: { zones: ["zen.spamhaus.org", "b.barracudacentral.org", "bl.spamcop.net"] },
      thresholds: { green: 90, amber: 70 },
      weights: { critical: 40, warning: 15, info: 0 },
    },
    schedule: {
      // DEFAULT OFF (pm/settings.mdx §3.1): a fresh install never fires scheduled DNSBL/SMTP/HTTP
      // traffic until the user flips the switch. Enabling seeds these times/weekdays: 06:00 daily.
      enabled: false,
      cadence: "daily",
      everyHours: 6,
      times: ["06:00"],
      weekdays: [],
      timezone: systemTimezone(),
      domains: "all",
      runner: "in-process",
      os: { kind: detectOsSchedulerKind(), installed: false, label: "com.emaildeliveryhero.scheduler" },
    },
    notifications: {
      webhook: { enabled: false, url: "" },
      smtp: { host: "", port: 587, from: "edh@whitehatengineering.com" },
    },
    storage: { retentionDays: 90 },
    tools: { preferCli: false, resolvers: [], timeoutMs: 5000 },
    access: { allowedDomains: ["whitehatengineering.com", "act3ai.com"] },
    defaults: {
      theme: "system",
      density: "comfortable",
      notifications: { desktop: true, email: false, minSeverity: "warning", mode: "immediate" },
    },
  }
}

function appConfigPath(): string {
  return join(resolveStateDir(), "config.yaml")
}

/**
 * Read the app-level settings. Missing file → pure defaults, no error, no first-run write
 * (pm/storage.mdx acceptance #2). On-disk values are deep-merged over the defaults with per-key
 * type validation, so a hand-edit that breaks one value never takes the whole config down.
 */
export function readAppConfig(): AppConfigFile {
  const raw = readYaml<unknown>(appConfigPath(), null)
  const defaults = defaultAppConfig()
  if (raw == null) return defaults
  return mergeValidated(defaults, raw, "config.yaml") as AppConfigFile
}

/**
 * Read-modify-write the app config: apply `mutate` to the current (merged) config, stamp
 * schema_version + updated_at, persist atomically. Sync, so serialized within the process; wrap in
 * withFileLock(appConfigFile()) from async flows that interleave their own reads.
 */
export function updateAppConfig(mutate: (config: AppConfigFile) => AppConfigFile | void): AppConfigFile {
  const current = readAppConfig()
  const next = mutate(current) ?? current
  next.schema_version = CONFIG_SCHEMA_VERSION
  next.updated_at = new Date().toISOString()
  writeYaml(appConfigPath(), next)
  return next
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-logged-in-user users/<email>/config.yaml (pm/storage.mdx §4).
// ─────────────────────────────────────────────────────────────────────────────

export interface UserConfigFile extends UserPreferences {
  schema_version: number
  updated_at: string
  /** Restore-where-you-left-off route (pm/storage.mdx §4 `ui.last_route`). */
  lastRoute?: string
  /** Remembered per-table sort/filter, keyed by table id (pm/storage.mdx §4 `tables.views`). */
  tables?: { views: Record<string, unknown> }
}

/** The reserved folder key for the logged-out user (pm/security.mdx). Never contains "@". */
export const DEFAULT_USER_KEY = "default"

/**
 * Email → directory policy (pm/storage.mdx §4): lowercase, stored verbatim as the folder name so
 * the tree is human-browsable, defensively sanitized — any `/`, `\`, `..`, or NUL is stripped
 * before the value is ever used as a path segment. An empty/unusable result falls back to the
 * reserved `default` key rather than throwing.
 */
export function sanitizeUserKey(email: string | null | undefined): string {
  const cleaned = (email ?? "")
    .trim()
    .toLowerCase()
    // biome-ignore lint/suspicious/noControlCharactersInRegex: NUL must never reach a path segment
    .replace(/[/\\\u0000]/g, "")
    .replace(/\.\./g, "")
  return cleaned.length > 0 ? cleaned : DEFAULT_USER_KEY
}

function userConfigPath(userKey: string): string {
  // stateSubdir creates users/<key>/ on demand — the lazy per-user folder (pm/storage.mdx §4).
  return join(stateSubdir("users", userKey), "config.yaml")
}

/** The user-file defaults: the app config's `defaults` block (pm/storage.mdx §4). */
function defaultUserConfig(): UserConfigFile {
  const { defaults } = readAppConfig()
  return {
    schema_version: CONFIG_SCHEMA_VERSION,
    updated_at: new Date().toISOString(),
    theme: defaults.theme,
    density: defaults.density,
    notifications: { ...defaults.notifications },
  }
}

/** Whether this user has ever written a config file (no folder/file yet → pure defaults). */
export function userConfigExists(email: string | null | undefined): boolean {
  return existsSync(join(resolveStateDir(), "users", sanitizeUserKey(email), "config.yaml"))
}

/**
 * Read one user's settings. A user with no file yet gets the app `defaults` block — never an
 * error, never a first-run write (pm/storage.mdx acceptance #3).
 */
export function readUserConfig(email: string | null | undefined): UserConfigFile {
  const key = sanitizeUserKey(email)
  const path = join(resolveStateDir(), "users", key, "config.yaml")
  const defaults = defaultUserConfig()
  if (!existsSync(path)) return defaults
  const raw = readYaml<unknown>(path, null)
  if (raw == null) return defaults
  return mergeValidated(defaults, raw, `users/${key}/config.yaml`) as UserConfigFile
}

/**
 * Read-modify-write one user's settings; creates users/<email>/ lazily on this first write,
 * stamps schema_version + updated_at, persists atomically.
 */
export function updateUserConfig(
  email: string | null | undefined,
  mutate: (config: UserConfigFile) => UserConfigFile | void,
): UserConfigFile {
  const key = sanitizeUserKey(email)
  const current = readUserConfig(email)
  const next = mutate(current) ?? current
  next.schema_version = CONFIG_SCHEMA_VERSION
  next.updated_at = new Date().toISOString()
  writeYaml(userConfigPath(key), next)
  return next
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-file mutex (pm/storage.mdx §8) — serialize async read-modify-write per file.
// ─────────────────────────────────────────────────────────────────────────────

const fileLocks = new Map<string, Promise<unknown>>()

/**
 * Run `fn` with an exclusive per-file lock: calls against the same path queue in order, calls
 * against different paths run freely. Failures release the lock without poisoning the chain.
 */
export function withFileLock<T>(path: string, fn: () => T | Promise<T>): Promise<T> {
  const previous = fileLocks.get(path) ?? Promise.resolve()
  const run = previous.then(() => fn())
  fileLocks.set(
    path,
    run.catch(() => {}),
  )
  return run
}

// ─────────────────────────────────────────────────────────────────────────────
// Validated deep-merge — schema validation on read (pm/storage.mdx §8).
// ─────────────────────────────────────────────────────────────────────────────

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

/**
 * Deep-merge `loaded` over `defaults`. A loaded value whose type disagrees with the default
 * (string where a number belongs, scalar where a block belongs, …) is rejected loudly — logged and
 * replaced by the default — rather than silently trusted. Keys the schema doesn't know (e.g. free
 * table ids under tables.views) pass through unchanged.
 */
function mergeValidated(defaults: unknown, loaded: unknown, file: string, keyPath = ""): unknown {
  if (defaults === undefined || defaults === null) return loaded
  if (loaded === undefined || loaded === null) return defaults
  if (isPlainObject(defaults)) {
    if (!isPlainObject(loaded)) {
      logWarn(`Ignoring malformed ${file} value at "${keyPath || "<root>"}": expected a block`, "ConfigStore")
      return defaults
    }
    const merged: Record<string, unknown> = { ...loaded }
    for (const [key, defaultValue] of Object.entries(defaults)) {
      merged[key] = key in loaded ? mergeValidated(defaultValue, loaded[key], file, keyPath ? `${keyPath}.${key}` : key) : defaultValue
    }
    return merged
  }
  if (Array.isArray(defaults)) {
    if (!Array.isArray(loaded)) {
      // `schedule.domains` is legitimately "all" | list — a string there is valid, not malformed.
      if (typeof loaded === "string") return loaded
      logWarn(`Ignoring malformed ${file} value at "${keyPath}": expected a list`, "ConfigStore")
      return defaults
    }
    return loaded
  }
  if (typeof loaded !== typeof defaults) {
    // Symmetric to the case above: a list where the default is the scalar "all".
    if (Array.isArray(loaded) && typeof defaults === "string") return loaded
    logWarn(`Ignoring malformed ${file} value at "${keyPath}": expected ${typeof defaults}`, "ConfigStore")
    return defaults
  }
  return loaded
}
