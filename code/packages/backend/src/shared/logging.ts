import { appendFileSync } from "node:fs"
import { join } from "node:path"
import type { LoggerService } from "@nestjs/common"
import { stateSubdir } from "./state-dir"

/**
 * Minimal file-and-console logger for EmailDeliveryHero. All framework and app logs are appended
 * to two flat files under the state dir (info.log for INFO/DEBUG, error.log for WARN/ERROR) and
 * echoed to the console. No log aggregator required — this is a single-instance localhost app.
 */
export const LOG_DIR = stateSubdir("logs")
const INFO_LOG = join(LOG_DIR, "info.log")
const ERROR_LOG = join(LOG_DIR, "error.log")

function line(level: string, message: string, context?: string): string {
  const ts = new Date().toISOString()
  const ctx = context ? ` [${context}]` : ""
  return `[${ts}] [${level}]${ctx} ${message}\n`
}

function write(file: string, text: string): void {
  try {
    appendFileSync(file, text)
  } catch {
    // Never let logging crash the app.
  }
}

export function logInfo(message: string, context?: string): void {
  const text = line("INFO", message, context)
  write(INFO_LOG, text)
  process.stdout.write(text)
}

export function logDebug(message: string, context?: string): void {
  const text = line("DEBUG", message, context)
  write(INFO_LOG, text)
  if (process.env.EDH_DEBUG === "true") process.stdout.write(text)
}

export function logWarn(message: string, context?: string): void {
  const text = line("WARN", message, context)
  write(ERROR_LOG, text)
  process.stderr.write(text)
}

export function logError(message: string, err?: unknown, context?: string): void {
  const detail = err instanceof Error ? `${err.name}: ${err.message}` : err ? String(err) : ""
  const text = line("ERROR", detail ? `${message} — ${detail}` : message, context)
  write(ERROR_LOG, text)
  process.stderr.write(text)
}

/** Nest LoggerService adapter so ALL framework logging flows through the files above. */
export const appLogger: LoggerService = {
  log: (message: unknown, context?: string) => logInfo(String(message), context),
  error: (message: unknown, trace?: string, context?: string) =>
    logError(String(message), trace, context),
  warn: (message: unknown, context?: string) => logWarn(String(message), context),
  debug: (message: unknown, context?: string) => logDebug(String(message), context),
  verbose: (message: unknown, context?: string) => logDebug(String(message), context),
}
