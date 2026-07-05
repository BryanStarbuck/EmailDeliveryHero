import { join } from "node:path";
import type { LoggerService, LogLevel } from "@nestjs/common";
import { RollingFileWriter } from "./rolling-file-writer";
import { resolveLogDir } from "./state-dir";

/**
 * Centralized application logging for EmailDeliveryHero (see pm/errors.mdx).
 *
 * Two rolling files directly at the storage root (~/.email_delivery_hero by default; override the
 * log dir with EDH_LOG_DIR), each stream capped at 5 MiB on the live file with 5 rotated backups:
 *   • log.log     — INFO / DEBUG / VERBOSE (the normal operational trail)
 *   • error.err   — WARN / ERROR / FATAL  (everything that needs attention)
 *
 * WARN/ERROR/FATAL lines are written to BOTH files so error.err is a complete fault trail while
 * log.log still shows them inline in sequence with surrounding context.
 *
 * Exposed two ways:
 *   • `appLogger` — a process-wide singleton usable from any code (services, guards, strategies,
 *     plain functions). Use the logInfo/logWarn/logError/… helpers for convenience.
 *   • implements NestJS `LoggerService`, so `app.useLogger(appLogger)` routes the whole framework's
 *     logging (bootstrap, request errors, etc.) through the same rolling files.
 */

/**
 * Strip control characters (< 0x20 and 0x7F) from an untrusted string before it is written to a log
 * line, so newline/CR-laced input cannot forge additional log lines (log-injection defense). An
 * optional cap bounds the field length. Uses char codes rather than a control-char regex literal so
 * this source file stays clean ASCII.
 */
export function stripControlChars(value: string, maxLength = 4000): string {
	let out = "";
	for (const ch of value) {
		const code = ch.charCodeAt(0);
		out += code < 0x20 || code === 0x7f ? " " : ch;
		if (out.length >= maxLength) break;
	}
	return out.slice(0, maxLength);
}

/** The log directory (state root by default; EDH_LOG_DIR override) and the two target files. */
export const LOG_DIR = resolveLogDir();
export const LOG_FILE = join(LOG_DIR, "log.log");
export const ERR_FILE = join(LOG_DIR, "error.err");

// Each stream keeps a 5 MiB live file plus 5 rotated backups (pm/errors.mdx §2).
const MAX_BYTES = 5 * 1024 * 1024;
const MAX_BACKUPS = 5;

/** Mirror to the console too so `just run` / docker logs still show output. */
const ECHO_CONSOLE = process.env.EDH_LOG_CONSOLE !== "false";
/** DEBUG/VERBOSE are always written to log.log but only echoed to the console when this is on. */
const DEBUG_CONSOLE = process.env.EDH_DEBUG === "true";

type Level = "LOG" | "INFO" | "DEBUG" | "VERBOSE" | "WARN" | "ERROR" | "FATAL";

function timestamp(): string {
	// ISO-8601 UTC is enough for a single-instance localhost trail; avoid an extra date dep.
	return new Date().toISOString();
}

function safeStringify(value: unknown): string {
	if (value === null || value === undefined) return "";
	if (typeof value === "string") return value;
	if (value instanceof Error)
		return value.stack ?? `${value.name}: ${value.message}`;
	try {
		return JSON.stringify(value);
	} catch {
		return String(value);
	}
}

class AppLogger implements LoggerService {
	private readonly out = new RollingFileWriter({
		filePath: LOG_FILE,
		maxBytes: MAX_BYTES,
		maxBackups: MAX_BACKUPS,
	});
	private readonly err = new RollingFileWriter({
		filePath: ERR_FILE,
		maxBytes: MAX_BYTES,
		maxBackups: MAX_BACKUPS,
	});

	private format(
		level: Level,
		message: unknown,
		context?: string,
		extra?: unknown,
	): string {
		const ctx = context ? ` [${context}]` : "";
		const tail = extra === undefined ? "" : ` ${safeStringify(extra)}`;
		return `[${timestamp()}] [${level}]${ctx} ${safeStringify(message)}${tail}`;
	}

	/** Low-level emit. WARN/ERROR/FATAL go to error.err; everything is also kept in log.log. */
	private emit(
		level: Level,
		message: unknown,
		context?: string,
		extra?: unknown,
	): void {
		const line = this.format(level, message, context, extra);
		const isError = level === "ERROR" || level === "WARN" || level === "FATAL";
		const isQuietDebug =
			(level === "DEBUG" || level === "VERBOSE") && !DEBUG_CONSOLE;
		if (isError) this.err.write(line);
		// Keep a single chronological stream in log.log too (incl. errors, for context).
		this.out.write(line);
		if (ECHO_CONSOLE && !isQuietDebug) {
			const sink = isError ? process.stderr : process.stdout;
			try {
				sink.write(`${line}\n`);
			} catch {
				/* ignore console failures */
			}
		}
	}

	// --- NestJS LoggerService surface ---------------------------------------------------
	log(message: unknown, context?: string): void {
		this.emit("INFO", message, context);
	}
	error(message: unknown, stackOrContext?: string, context?: string): void {
		// NestJS calls error(message, stack?, context?). Capture whichever was provided.
		const ctx =
			context ?? (stackOrContext?.includes("\n") ? undefined : stackOrContext);
		const extra = stackOrContext?.includes("\n") ? stackOrContext : undefined;
		this.emit("ERROR", message, ctx, extra);
	}
	warn(message: unknown, context?: string): void {
		this.emit("WARN", message, context);
	}
	debug(message: unknown, context?: string): void {
		this.emit("DEBUG", message, context);
	}
	verbose(message: unknown, context?: string): void {
		this.emit("VERBOSE", message, context);
	}
	fatal(message: unknown, context?: string): void {
		this.emit("FATAL", message, context);
	}
	setLogLevels(_levels: LogLevel[]): void {
		// Single configurable knob is the console echo; file levels are always captured.
	}

	// --- Convenience helpers for non-Nest call sites ------------------------------------
	logError(message: string, cause?: unknown, context?: string): void {
		this.emit("ERROR", message, context, cause);
	}
	logFatal(message: string, cause?: unknown, context?: string): void {
		this.emit("FATAL", message, context, cause);
	}
	logWarn(message: string, context?: string, extra?: unknown): void {
		this.emit("WARN", message, context, extra);
	}
	logInfo(message: string, context?: string, extra?: unknown): void {
		this.emit("INFO", message, context, extra);
	}
	logDebug(message: string, context?: string, extra?: unknown): void {
		this.emit("DEBUG", message, context, extra);
	}
}

/** Process-wide singleton. Import this anywhere that needs to log. */
export const appLogger = new AppLogger();

/** Standalone helpers so non-Nest modules don't need to touch the class. */
export const logError = (
	message: string,
	cause?: unknown,
	context?: string,
): void => appLogger.logError(message, cause, context);
export const logFatal = (
	message: string,
	cause?: unknown,
	context?: string,
): void => appLogger.logFatal(message, cause, context);
export const logWarn = (
	message: string,
	context?: string,
	extra?: unknown,
): void => appLogger.logWarn(message, context, extra);
export const logInfo = (
	message: string,
	context?: string,
	extra?: unknown,
): void => appLogger.logInfo(message, context, extra);
export const logDebug = (
	message: string,
	context?: string,
	extra?: unknown,
): void => appLogger.logDebug(message, context, extra);
