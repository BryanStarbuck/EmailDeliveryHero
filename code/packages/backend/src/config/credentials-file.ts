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
    const raw = readFileSync(path, "utf8")
    const parsed: unknown = JSON.parse(raw)
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
  const google = readCredentialsFile().email_delivery_hero?.google ?? {}
  return {
    clientId: (google.clientId ?? "").trim(),
    clientSecret: (google.clientSecret ?? "").trim(),
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
