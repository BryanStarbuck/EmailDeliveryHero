import {
	appendFileSync,
	existsSync,
	mkdirSync,
	renameSync,
	rmSync,
	statSync,
} from "node:fs";
import { dirname } from "node:path";

/**
 * Dependency-free, size-bounded rolling file writer (see pm/errors.mdx §2, §6).
 *
 * Why not winston/pino? We want a strict per-stream cap with no extra deps and, above all, a
 * synchronous durable path so a crash immediately after an error is logged still leaves that error
 * on disk. This writer keeps one active file plus at most `maxBackups` rotated files (default 5),
 * each ≤ `maxBytes` (default 5 MiB). Set `maxBackups: 0` for a single file truncated on overflow.
 *
 * Two write paths (modeled on the Philosophers_Stone gold-standard writer):
 *   • write()      — SYNCHRONOUS + durable. Used for WARN/ERROR/FATAL so the fault trail is on disk
 *                    immediately, even before a process.exit(1) after an uncaughtException.
 *   • writeAsync() — BATCHED + non-blocking. The hot path (INFO/DEBUG/VERBOSE) enqueues and flushes
 *                    on the next tick (setImmediate) in a single appendFileSync, so request handlers
 *                    never block on log I/O. flush()/close() drain it durably on shutdown.
 *
 * All paths are best-effort and guarded: a logger must never be able to crash the process it is
 * instrumenting, so every path degrades to stderr rather than throwing.
 */
export interface RollingFileWriterOptions {
	/** Absolute path to the active log file. */
	filePath: string;
	/** Roll the file once it reaches this many bytes. Default 5 MiB. */
	maxBytes?: number;
	/** How many rotated files (`<file>.1`, `<file>.2`, …) to keep. Default 5. */
	maxBackups?: number;
}

const DEFAULT_MAX_BYTES = 5 * 1024 * 1024; // 5 MiB
const DEFAULT_MAX_BACKUPS = 5;

export class RollingFileWriter {
	private readonly filePath: string;
	private readonly maxBytes: number;
	private readonly maxBackups: number;
	/** Cached size of the active file so we avoid a statSync on every single write. */
	private size = 0;
	private ready = false;
	/** Pending lines for the async batched path, drained on the next tick or synchronously on exit. */
	private queue: string[] = [];
	private scheduled = false;

	constructor(opts: RollingFileWriterOptions) {
		this.filePath = opts.filePath;
		this.maxBytes = Math.max(1024, opts.maxBytes ?? DEFAULT_MAX_BYTES);
		this.maxBackups = Math.max(0, opts.maxBackups ?? DEFAULT_MAX_BACKUPS);
	}

	/** Lazily ensure the directory exists and seed the cached size from disk. */
	private ensureReady(): void {
		if (this.ready) return;
		try {
			mkdirSync(dirname(this.filePath), { recursive: true });
			this.size = existsSync(this.filePath) ? statSync(this.filePath).size : 0;
			this.ready = true;
		} catch {
			// If we cannot even prepare the path, leave size at 0 and ready=false so the next write
			// retries the mkdir; until then write() falls back to stderr.
			this.size = 0;
		}
	}

	/**
	 * Append one already-formatted line SYNCHRONOUSLY (durable). Best-effort and non-throwing: a
	 * logger must never be able to crash the process it is trying to instrument. Use this for the
	 * fault trail (WARN/ERROR/FATAL) so the line is on disk before a possible crash-exit.
	 *
	 * Ordering note: this flushes any queued async lines first, so a synchronous error line never
	 * jumps ahead of the batched INFO/DEBUG lines that preceded it in the same file.
	 */
	write(line: string): void {
		if (this.queue.length) this.flush();
		this.writeNow(line.endsWith("\n") ? line : `${line}\n`);
	}

	/**
	 * Append one already-formatted line on the BATCHED, non-blocking path. Lines are enqueued and
	 * drained together on the next tick (setImmediate) in a single appendFileSync, so the hot path
	 * (INFO/DEBUG/VERBOSE) never blocks a request on disk I/O. Drained durably by flush()/close().
	 */
	writeAsync(line: string): void {
		this.queue.push(line.endsWith("\n") ? line : `${line}\n`);
		if (!this.scheduled) {
			this.scheduled = true;
			setImmediate(() => this.flush());
		}
	}

	/** Drain the queued async lines in one batched write. Called on the next tick and on shutdown. */
	flush(): void {
		this.scheduled = false;
		if (this.queue.length === 0) return;
		const batch = this.queue.join("");
		this.queue.length = 0;
		this.writeNow(batch);
	}

	/** Flush everything pending — the durable drain to call on process shutdown. */
	close(): void {
		this.flush();
	}

	/** The single shared write path used by both write() and flush(): size-check, roll, append. */
	private writeNow(data: string): void {
		try {
			this.ensureReady();
			const incoming = Buffer.byteLength(data);
			if (this.size + incoming > this.maxBytes) this.roll();
			appendFileSync(this.filePath, data);
			this.size += incoming;
		} catch {
			// Last-resort fallback so a failed file write is still visible somewhere.
			try {
				process.stderr.write(data);
			} catch {
				/* nothing else we can safely do */
			}
		}
	}

	/**
	 * Rotate the active file. With maxBackups === 0 the file is simply removed (truncated to empty),
	 * giving an absolute single-file cap. Otherwise the chain `<file>.(n-1)` → `<file>.n` is shifted
	 * and the active file becomes `<file>.1`.
	 */
	private roll(): void {
		try {
			if (this.maxBackups === 0) {
				rmSync(this.filePath, { force: true });
				this.size = 0;
				return;
			}
			// Drop the oldest, then shift each backup up by one.
			rmSync(`${this.filePath}.${this.maxBackups}`, { force: true });
			for (let i = this.maxBackups - 1; i >= 1; i--) {
				const from = `${this.filePath}.${i}`;
				if (existsSync(from)) renameSync(from, `${this.filePath}.${i + 1}`);
			}
			if (existsSync(this.filePath))
				renameSync(this.filePath, `${this.filePath}.1`);
			this.size = 0;
		} catch {
			// If rotation fails, fall back to truncation so we still respect the cap.
			try {
				rmSync(this.filePath, { force: true });
			} catch {
				/* ignore */
			}
			this.size = 0;
		}
	}
}
