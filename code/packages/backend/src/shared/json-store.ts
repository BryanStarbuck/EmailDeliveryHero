import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs"
import { logError, logWarn } from "./logging"

/**
 * Tiny no-database persistence: read/write a single JSON file atomically. The first round of
 * EmailDeliveryHero stores the monitored-domain list and audit history as flat JSON files under
 * the state dir (see state-dir.ts). Writes go to a temp file then rename() over the target so a
 * crash mid-write can never leave a half-written, unparseable file.
 */
export function readJson<T>(path: string, fallback: T): T {
  if (!existsSync(path)) return fallback
  try {
    const raw = readFileSync(path, "utf8")
    if (!raw.trim()) return fallback
    return JSON.parse(raw) as T
  } catch (err) {
    logWarn(`Could not parse JSON store ${path}; using fallback`, "JsonStore")
    logError(`JSON parse error for ${path}`, err, "JsonStore")
    return fallback
  }
}

export function writeJson(path: string, value: unknown): void {
  const tmp = `${path}.tmp`
  try {
    writeFileSync(tmp, JSON.stringify(value, null, 2), "utf8")
    renameSync(tmp, path)
  } catch (err) {
    // A failed persist (disk full, permission denied, serialization failure) must never be
    // swallowed: log it to error.err AND rethrow so the caller and the global exception filter
    // both see it (pm/errors.mdx §3). Best-effort cleanup of the temp file first.
    try {
      if (existsSync(tmp)) renameSync(tmp, `${tmp}.failed`)
    } catch {
      /* ignore cleanup failure */
    }
    logError(`Failed to write JSON store ${path}`, err, "JsonStore")
    throw err
  }
}
