import { mkdirSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

/**
 * The single out-of-repo state directory for EmailDeliveryHero. Everything the app persists —
 * the monitored-domains store, audit history, the auth session store, and the auth signing
 * secret — lives here so no runtime data is ever committed to the repo.
 *
 * Default: ~/.email_delivery_hero (override with EDH_STATE_DIR). Created on first use.
 */
export function resolveStateDir(): string {
  const override = process.env.EDH_STATE_DIR?.trim()
  const dir = override && override.length > 0 ? override : join(homedir(), ".email_delivery_hero")
  mkdirSync(dir, { recursive: true })
  return dir
}

/** A subdirectory under the state dir, created on demand. */
export function stateSubdir(...parts: string[]): string {
  const dir = join(resolveStateDir(), ...parts)
  mkdirSync(dir, { recursive: true })
  return dir
}
