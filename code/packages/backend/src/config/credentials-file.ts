import { existsSync, readFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import { logInfo, logWarn } from "@shared/logging"

/**
 * Reader for EmailDeliveryHero's out-of-repo credentials file (`~/.credentials/email_delivery_hero.json`).
 *
 * Secrets live in this ONE JSON file in the user's home directory so the values stay OUTSIDE the
 * code base and are never committed. Env vars still win when set (deploy/CI override); when absent
 * the secret is read from the file.
 *
 * File shape (only the keys this app reads are shown):
 *   {
 *     "email_delivery_hero": {
 *       "google": { "clientId": "…apps.googleusercontent.com", "clientSecret": "GOCSPX-…" }
 *     }
 *   }
 *
 * Path resolution:
 *   process.env.EDH_CREDENTIALS_FILE           // explicit override
 *   ?? ~/.credentials/email_delivery_hero.json  // default location
 */

const DEFAULT_CREDENTIALS_FILE = ".credentials/email_delivery_hero.json"

export interface GoogleCredentials {
  clientId: string
  clientSecret: string
}

interface AppCredentials {
  google?: Partial<GoogleCredentials>
}

interface CredentialsFileShape {
  email_delivery_hero?: AppCredentials
}

let cached: CredentialsFileShape | null = null
let loaded = false

/**
 * Normalize whitespace that chat/editor pastes introduce and JSON.parse rejects: NBSP / narrow
 * NBSP become plain spaces; zero-width space and BOM are dropped. The file is synced by hand
 * across machines, so tolerate this instead of silently disabling sign-in.
 */
function normalizePastedWhitespace(raw: string): string {
  return raw.replace(/[\u00a0\u202f]/g, " ").replace(/[\u200b\ufeff]/g, "")
}

/**
 * Extract the FIRST balanced top-level `{…}` document (string-aware). A double-pasted file —
 * two documents back-to-back, often with stray text between — salvages to its first copy.
 */
function firstJsonObject(text: string): string | null {
  const start = text.indexOf("{")
  if (start < 0) return null
  let depth = 0
  let inString = false
  let escaped = false
  for (let i = start; i < text.length; i++) {
    const c = text[i]
    if (inString) {
      if (escaped) escaped = false
      else if (c === "\\") escaped = true
      else if (c === '"') inString = false
      continue
    }
    if (c === '"') inString = true
    else if (c === "{") depth++
    else if (c === "}" && --depth === 0) return text.slice(start, i + 1)
  }
  return null
}

/** Absolute path of the credentials file we read (env override → shared home default). */
export function credentialsFilePath(): string {
  const override = process.env.EDH_CREDENTIALS_FILE?.trim()
  if (override) return override
  return join(homedir(), DEFAULT_CREDENTIALS_FILE)
}

/** Whether the credentials file EXISTS on disk (authoritative server-side fact for the dev gate). */
export function credentialsFileExists(): boolean {
  return existsSync(credentialsFilePath())
}

function readCredentialsFile(): CredentialsFileShape {
  if (loaded && cached) return cached
  loaded = true
  const path = credentialsFilePath()
  try {
    const raw = normalizePastedWhitespace(readFileSync(path, "utf8"))
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch (parseErr) {
      // Salvage a double-pasted file: parse just the first balanced {…} document.
      const first = firstJsonObject(raw)
      if (first === null) throw parseErr
      parsed = JSON.parse(first)
      logWarn(
        `Credentials file ${path} is not valid JSON (${(parseErr as Error).message}); ` +
          "salvaged the first JSON document in it — please clean the file up.",
        "CredentialsFile",
      )
    }
    cached = parsed !== null && typeof parsed === "object" ? (parsed as CredentialsFileShape) : {}
    logInfo(`Loaded credentials from ${path}`, "CredentialsFile")
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code
    if (code !== "ENOENT") {
      logWarn(
        `Could not read credentials file ${path}: ${(err as Error).message}`,
        "CredentialsFile",
      )
    }
    cached = {}
  }
  return cached
}

/** Google OAuth client credentials from the file (empty strings when absent — env vars win). */
export function googleCredentialsFromFile(): GoogleCredentials {
  const file = readCredentialsFile()
  let google = file.email_delivery_hero?.google
  if (!google?.clientId) {
    // The canonical key is `email_delivery_hero`, but a hand-synced file sometimes carries the
    // google client under another app's key (or at the root). Fall back to the first complete
    // google section found rather than disabling sign-in on that machine.
    const candidates = [file as AppCredentials, ...Object.values(file)]
    const fallback = candidates.find(
      (v): v is AppCredentials =>
        v !== null &&
        typeof v === "object" &&
        Boolean((v as AppCredentials).google?.clientId) &&
        Boolean((v as AppCredentials).google?.clientSecret),
    )
    if (fallback) {
      google = fallback.google
      logWarn(
        `Credentials file has no email_delivery_hero.google section; using a google client ` +
          `found under another key. Move it under "email_delivery_hero" to silence this.`,
        "CredentialsFile",
      )
    }
  }
  return {
    clientId: (google?.clientId ?? "").trim(),
    clientSecret: (google?.clientSecret ?? "").trim(),
  }
}

/** The ONE source of truth for the "Google OAuth client not configured" guidance. */
export function googleOAuthRemediation(redirectUri: string): string {
  return (
    "Google OAuth client not configured — set GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET in the " +
    "backend environment, or add a `google` section under `email_delivery_hero` in " +
    "~/.credentials/email_delivery_hero.json. " +
    `Register this exact redirect URI on the Google Cloud OAuth client: ${redirectUri}`
  )
}
