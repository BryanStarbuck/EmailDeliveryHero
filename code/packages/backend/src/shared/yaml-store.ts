import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs"
import { dirname } from "node:path"
import { parse, stringify } from "yaml"
import { logError, logWarn } from "./logging"

/**
 * Tiny no-database persistence in YAML. EmailDeliveryHero stores the monitored-domain list (and
 * other small config lists) as human-readable YAML files under the state dir (see state-dir.ts) so
 * an operator can read and hand-edit them on localhost. Writes go to a unique temp file then
 * rename() over the target, so a crash mid-write can never leave a half-written, unparseable file,
 * and two concurrent writers never share the same temp path.
 */
export function readYaml<T>(path: string, fallback: T): T {
  if (!existsSync(path)) return fallback
  try {
    const raw = readFileSync(path, "utf8")
    if (!raw.trim()) return fallback
    const parsed = parse(raw) as T | null | undefined
    // An empty document (or a bare `null`) parses to null — treat it as the fallback, not a crash.
    return parsed == null ? fallback : parsed
  } catch (err) {
    logWarn(`Could not parse YAML store ${path}; using fallback`, "YamlStore")
    logError(`YAML parse error for ${path}`, err, "YamlStore")
    return fallback
  }
}

export function writeYaml(path: string, value: unknown): void {
  // Unique temp name per write so concurrent writers to the same target never clobber each other's
  // temp file mid-flight (the fixed "<path>.tmp" scheme could). rename() itself is atomic.
  const tmp = `${path}.${process.pid}.${nextSeq()}.tmp`
  try {
    // The state dir is created up front, but be defensive: a store may point at a fresh subdir.
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(tmp, stringify(value), "utf8")
    renameSync(tmp, path)
  } catch (err) {
    // A failed persist (disk full, permission denied, serialization failure) must never be
    // swallowed: log it to error.err AND rethrow so the caller and the global exception filter
    // both see it (pm/errors.mdx §3). Best-effort cleanup of the temp file first.
    try {
      if (existsSync(tmp)) unlinkSync(tmp)
    } catch {
      /* ignore cleanup failure */
    }
    logError(`Failed to write YAML store ${path}`, err, "YamlStore")
    throw err
  }
}

// Monotonic per-process counter — keeps temp names unique even within the same millisecond.
let seq = 0
function nextSeq(): number {
  seq = (seq + 1) % Number.MAX_SAFE_INTEGER
  return seq
}
