import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs"
import { dirname } from "node:path"
import { logError, logWarn } from "./logging"

/**
 * Tiny no-database persistence: read/write a single JSON file atomically. The machine-written
 * collection stores (audits.json — the latest-audit cache) are flat JSON files under the state dir
 * (see state-dir.ts). Converged on the pm/storage.mdx §9 store contract, same as yaml-store.ts:
 * writes go to a UNIQUE temp file (so concurrent writers to the same target never share a temp
 * path) then rename() over the target — a crash mid-write can never leave a half-written,
 * unparseable file — and a failed write unlinks its temp, logs, and rethrows.
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
  // Unique temp name per write so concurrent writers to the same target never clobber each
  // other's temp file mid-flight (pm/storage.mdx §9 — the fixed "<path>.tmp" scheme could).
  const tmp = `${path}.${process.pid}.${nextSeq()}.tmp`
  try {
    // The state dir is created up front, but be defensive: a store may point at a fresh subdir.
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(tmp, JSON.stringify(value, null, 2), "utf8")
    renameSync(tmp, path)
  } catch (err) {
    // A failed persist (disk full, permission denied, serialization failure) must never be
    // swallowed: log it to error.err AND rethrow so the caller and the global exception filter
    // both see it (pm/errors.mdx §3). Best-effort cleanup of the temp file first — unlink it
    // rather than leaving a "<path>.tmp.failed" artifact behind (pm/storage.mdx §9/D16).
    try {
      if (existsSync(tmp)) unlinkSync(tmp)
    } catch {
      /* ignore cleanup failure */
    }
    logError(`Failed to write JSON store ${path}`, err, "JsonStore")
    throw err
  }
}

// Monotonic per-process counter — keeps temp names unique even within the same millisecond.
let seq = 0
function nextSeq(): number {
  seq = (seq + 1) % Number.MAX_SAFE_INTEGER
  return seq
}
