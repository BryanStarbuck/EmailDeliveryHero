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
 * Why not winston/pino? We want a strict per-stream cap with no extra deps and, above all,
 * synchronous writes so a crash immediately after an error is logged still leaves that error on
 * disk. This writer keeps one active file plus at most `maxBackups` rotated files (default 5), each
 * ≤ `maxBytes` (default 5 MiB). Set `maxBackups: 0` for a single file that is truncated on overflow.
 *
 * Writes are synchronous (appendFileSync) and best-effort: a logger must never be able to crash the
 * process it is instrumenting, so every path is guarded and degrades to stderr.
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
	 * Append one already-formatted line. Best-effort and non-throwing: a logger must never be able to
	 * crash the process it is trying to instrument.
	 */
	write(line: string): void {
		const data = line.endsWith("\n") ? line : `${line}\n`;
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
