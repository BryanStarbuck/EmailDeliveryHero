import { locateTool, runTool } from "@shared/tool-runner";

/**
 * The DKIM evidence bench (pm/checks/dkim.mdx §3 "How a test run executes the tools"). The
 * decision engine stays node:dns/promises; on top of it every run shells out to the Brew bench
 * tools for evidence-grade captures and cross-checks, recording ONE entry per invocation into
 * `results.dkim.tool_runs[]` with the exact terminal-reproducible command line. A missing binary
 * records the entry with `exit_code: null` and an ENOENT hint and the checker degrades to its
 * node:dns result (§5.3 graceful degradation); tool runs never change a sub-test verdict — when a
 * cross-check disagrees, the disagreement itself is surfaced as a propagation note.
 */

/** One `dkim.tool_runs[]` entry — field names per pm/checks/dkim.mdx §3/§5 (snake_case YAML). */
export interface DkimToolRun {
	tool: string;
	/** The exact argv string with every input argument inlined — paste-and-reproduce. */
	command: string;
	started_at: string;
	duration_ms: number;
	/** The child's exit code; null when it never ran (missing binary / spawn failure / killed). */
	exit_code: number | null;
	output_format: "json" | "text";
	/** The captured/parsed stdout (shape per tool). */
	parsed: unknown;
	/** null, or the failure string (timeout, ENOENT, bad JSON…). */
	error: string | null;
}

/** brew formula per tool, for the ENOENT install hint (§3). */
const BREW_FORMULA: Record<string, string> = {
	doggo: "doggo",
	kdig: "knot",
	dnsx: "dnsx",
	openssl: "openssl@3",
};

/** Per-tool hard kill budgets (§3 execution table). */
const KILL_TIMEOUT_MS: Record<string, number> = {
	doggo: 8_000,
	kdig: 8_000,
	openssl: 3_000,
	dnsx: 30_000,
};

interface CaptureSpec {
	tool: string;
	args: string[];
	outputFormat: "json" | "text";
	stdin?: string | Buffer;
	/** What was piped on stdin, recorded under `parsed.stdin_source` (§3 rows 4 and 6). */
	stdinSource?: string;
	/** Condense raw stdout into the stored `parsed` value; throw to record a parse error. */
	condense: (stdout: string) => unknown;
}

/** A condensed doggo answer row (§5 example: name/type/ttl/content). */
export interface DoggoAnswer {
	name: string;
	type: string;
	ttl: string;
	content: string;
}

const str = (v: unknown): string =>
	typeof v === "string" ? v : v === undefined ? "" : String(v);

/** Best-effort extraction of doggo --json answers (the `address` field carries the rdata). */
function condenseDoggo(stdout: string): DoggoAnswer[] {
	const parsed: unknown = JSON.parse(stdout || "[]");
	const responses = Array.isArray(parsed) ? parsed : [parsed];
	const answers: DoggoAnswer[] = [];
	for (const response of responses) {
		const rows = (response as Record<string, unknown>)?.answers;
		if (!Array.isArray(rows)) continue;
		for (const row of rows) {
			const a = row as Record<string, unknown>;
			answers.push({
				name: str(a.name),
				type: str(a.type),
				ttl: str(a.ttl),
				content: str(a.address ?? a.content ?? a.rdata),
			});
		}
	}
	return answers;
}

export class DkimToolBench {
	/** Every invocation this run made, in execution order — becomes `results.dkim.tool_runs`. */
	readonly runs: DkimToolRun[] = [];
	private readonly paths = new Map<string, string | null>();

	constructor(
		private readonly signal?: AbortSignal,
		/** Stage-0 resolved tool paths from the RunContext, when the runner provides them. */
		tools?: Record<string, string | null>,
	) {
		if (tools)
			for (const [name, path] of Object.entries(tools))
				this.paths.set(name, path);
	}

	private locate(tool: string): string | null {
		if (!this.paths.has(tool)) this.paths.set(tool, locateTool(tool));
		return this.paths.get(tool) ?? null;
	}

	/** Run one bench invocation under the §3 capture contract and record its entry. */
	private async capture(spec: CaptureSpec): Promise<DkimToolRun> {
		const entry: DkimToolRun = {
			tool: spec.tool,
			command: [spec.tool, ...spec.args].join(" "),
			started_at: new Date().toISOString(),
			duration_ms: 0,
			exit_code: null,
			output_format: spec.outputFormat,
			parsed: null,
			error: null,
		};
		this.runs.push(entry);

		const path = this.locate(spec.tool);
		if (!path) {
			// Missing binary: record the entry and degrade to node:dns (§3 — the UI offers the install).
			entry.error = `ENOENT — not installed (brew install ${BREW_FORMULA[spec.tool] ?? spec.tool})`;
			return entry;
		}

		const timeoutMs = KILL_TIMEOUT_MS[spec.tool] ?? 10_000;
		const started = Date.now();
		try {
			const res = await runTool(path, spec.args, {
				timeoutMs,
				stdin: spec.stdin,
				signal: this.signal,
			});
			entry.duration_ms = Date.now() - started;
			entry.exit_code = res.code;
			if (res.timedOut) {
				entry.error = `timeout — killed after ${timeoutMs}ms`;
			} else if (res.code === null) {
				entry.error = res.stderr.trim() || "spawn failure";
			} else if (res.code !== 0) {
				entry.error = res.stderr.trim() || `exit code ${res.code}`;
				entry.parsed = res.stdout.slice(0, 2_000) || null;
			} else {
				try {
					const parsed = spec.condense(res.stdout);
					entry.parsed = spec.stdinSource
						? {
								stdin_source: spec.stdinSource,
								...(parsed as Record<string, unknown>),
							}
						: parsed;
				} catch (err) {
					entry.parsed = res.stdout.slice(0, 2_000);
					entry.error = `bad ${spec.outputFormat.toUpperCase()} output (${err instanceof Error ? err.message : String(err)})`;
				}
			}
		} catch (err) {
			entry.duration_ms = Date.now() - started;
			entry.error = err instanceof Error ? err.message : String(err);
		}
		return entry;
	}

	/** §3 row 1/5 — `doggo <name> TXT --json --timeout 5s`; returns the answers (null on failure). */
	async doggoTxt(name: string): Promise<DoggoAnswer[] | null> {
		const entry = await this.capture({
			tool: "doggo",
			args: [name, "TXT", "--json", "--timeout", "5s"],
			outputFormat: "json",
			condense: condenseDoggo,
		});
		return entry.error === null ? (entry.parsed as DoggoAnswer[]) : null;
	}

	/** §3 row 2 — CNAME fallback, only when the TXT capture returned no answers. */
	async doggoCname(name: string): Promise<DoggoAnswer[] | null> {
		const entry = await this.capture({
			tool: "doggo",
			args: [name, "CNAME", "--json", "--timeout", "5s"],
			outputFormat: "json",
			condense: condenseDoggo,
		});
		return entry.error === null ? (entry.parsed as DoggoAnswer[]) : null;
	}

	/**
	 * §3 row 3 — `kdig @8.8.8.8 +json +timeout=5 +retry=1 TXT <name>` public-resolver cross-check.
	 * Stores the condensed RFC 8427 answer ({answerRRs, agrees_with_local}) and returns whether the
	 * public view agrees with the local answer count — null when the tool was unavailable/failed
	 * (never fabricate a disagreement).
	 */
	async kdigCrossCheck(
		name: string,
		localAnswerCount: number,
	): Promise<boolean | null> {
		const entry = await this.capture({
			tool: "kdig",
			args: ["@8.8.8.8", "+json", "+timeout=5", "+retry=1", "TXT", name],
			outputFormat: "json",
			condense: (stdout) => {
				const parsed = JSON.parse(stdout || "{}") as Record<string, unknown>;
				const answers = parsed.answerRRs;
				const count = Array.isArray(answers) ? answers.length : 0;
				return {
					answerRRs: count,
					agrees_with_local: count === localAnswerCount,
				};
			},
		});
		if (entry.error !== null) return null;
		const parsed = entry.parsed as { agrees_with_local?: boolean } | null;
		return parsed?.agrees_with_local ?? null;
	}

	/**
	 * §3 row 4 — `openssl pkey -pubin -inform DER -text -noout` with the base64-decoded p= bytes on
	 * stdin. Cross-checks the in-process crypto.createPublicKey decode; the first output line is the
	 * verdict (`RSA Public-Key: (2048 bit)` / `ED25519 Public-Key`).
	 */
	async opensslDecode(selector: string, der: Buffer): Promise<void> {
		await this.capture({
			tool: "openssl",
			args: ["pkey", "-pubin", "-inform", "DER", "-text", "-noout"],
			outputFormat: "text",
			stdin: der,
			stdinSource: `p= of ${selector} (${der.length} bytes)`,
			condense: (stdout) => {
				const firstLine = (stdout.split("\n")[0] ?? "").trim();
				const rsa = /RSA Public-Key: \((\d+) bit\)/.exec(firstLine);
				return {
					first_line: firstLine,
					key_type: rsa ? "rsa" : /ED25519/i.test(firstLine) ? "ed25519" : null,
					key_bits: rsa ? Number(rsa[1]) : null,
				};
			},
		});
	}

	/**
	 * §3 row 6 — the discovery sweep evidence: candidate FQDNs piped to
	 * `dnsx -txt -cname -resp -json -silent -retry 1 -t 6` (NDJSON out).
	 */
	async dnsxSweep(candidateNames: string[]): Promise<void> {
		await this.capture({
			tool: "dnsx",
			args: [
				"-txt",
				"-cname",
				"-resp",
				"-json",
				"-silent",
				"-retry",
				"1",
				"-t",
				"6",
			],
			outputFormat: "json",
			stdin: `${candidateNames.join("\n")}\n`,
			stdinSource: `wordlist (${candidateNames.length} names, MX-guided first)`,
			condense: (stdout) => {
				const hits: unknown[] = [];
				for (const line of stdout.split("\n")) {
					const trimmed = line.trim();
					if (!trimmed) continue;
					try {
						hits.push(JSON.parse(trimmed));
					} catch {
						// dnsx prints occasional non-JSON banners on some versions; skip them.
					}
				}
				return { hits };
			},
		});
	}
}
