import { CHECKERS } from "@module/audit/checks";
import { DomainsService } from "@module/domains/domains.service";
import {
	Controller,
	Get,
	Injectable,
	NotFoundException,
	Param,
	Post,
	Query,
} from "@nestjs/common";
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger";
import { readAppConfig } from "@shared/config-store";
import { locateTools } from "@shared/tool-runner";
import { sanitizeDomainDir } from "@module/audit/runs-store";
import type { Finding } from "@module/audit/checks";
import { buildComplaintBoard } from "./complaints/board";
import { isEspDefaultDomain } from "./complaints/classify";
import type {
	BoardVerdict,
	Complaint,
	ComplaintBoard,
	ComplaintFix,
	ComplaintFleetRow,
	ComplaintVerdict,
} from "./complaints/complaint.types";
import { buildFix } from "./complaints/fixes";
import { resolvePtrs } from "./complaints/ptr";
import {
	listComplaintSnapshots,
	readComplaintSnapshot,
} from "./complaints/snapshot-store";
import { readRawReport } from "./raw-store";
import {
	listDmarcReports,
	listTlsRptReports,
	readIngestState,
} from "./report-store";
import { ReportsService } from "./reports.service";

/** Window sizes the UI offers (pm/Email_Complaints.mdx §13); anything else is clamped. */
const ALLOWED_DAYS = [7, 30, 60, 90];
const DEFAULT_DAYS = 60;

/** Worst-first ordering for the §9.7 fleet table (pm/Email_Complaints.mdx §8.2). */
const BOARD_VERDICT_RANK: Record<BoardVerdict, number> = {
	action: 0,
	attention: 1,
	watch: 2,
	ok: 3,
	insufficient_data: 4,
};

/** Worst-first ordering of a domain's own complaints, to pick the row's headline complaint (§8.1). */
const VERDICT_RANK: Record<ComplaintVerdict, number> = {
	problem: 0,
	watch: 1,
	ok: 2,
};

function clampDays(raw: string | undefined): number {
	const n = Number(raw);
	if (!Number.isFinite(n)) return DEFAULT_DAYS;
	return ALLOWED_DAYS.reduce((best, d) =>
		Math.abs(d - n) < Math.abs(best - n) ? d : best,
	);
}

/**
 * Email Complaints (pm/Email_Complaints.mdx) — the domain-owner-facing reading of the report emails
 * receivers send us. Where ReportsService owns ingestion and the raw per-domain Reports view, this
 * service owns the MEANING: the §7 taxonomy, the §8 verdict, and the §11 fix plan.
 */
@Injectable()
export class ComplaintsService {
	constructor(private readonly domains: DomainsService) {}

	async board(
		domainId: string,
		days: number,
		opts: { reverseDns?: boolean } = {},
	): Promise<ComplaintBoard> {
		const domain = this.domains.get(domainId);
		const config = readAppConfig().reports;
		const dmarcReports = listDmarcReports(domainId);

		// Reverse DNS for the evidence tables (§10.2). Resolved here rather than inside
		// buildComplaintBoard so board assembly stays pure and synchronous; highest-volume IPs first,
		// because resolvePtrs() only looks up a bounded prefix. The §9.7 fleet roll-up opts out: it
		// shows no evidence table, and one page must never wait on N domains' worth of PTR lookups.
		let ptrByIp = new Map<string, string | null>();
		if (opts.reverseDns !== false) {
			const volumeByIp = new Map<string, number>();
			for (const report of dmarcReports)
				for (const row of report.rows)
					volumeByIp.set(row.sourceIp, (volumeByIp.get(row.sourceIp) ?? 0) + row.count);
			const ipsByVolume = [...volumeByIp.entries()]
				.sort((a, b) => b[1] - a[1])
				.map(([ip]) => ip);
			ptrByIp = await resolvePtrs(ipsByVolume);
		}

		return buildComplaintBoard({
			domainId,
			domain: domain.name,
			dmarcReports,
			tlsReports: listTlsRptReports(domainId),
			windowDays: days,
			ingestionEnabled: config.enabled,
			lastIngestAt: readIngestState(domainId).lastIngestAt,
			ptrByIp,
		});
	}

	/**
	 * §9.7 — the fleet roll-up behind the left bar's **Complaints** item: one summary row per
	 * monitored domain, worst verdict first. Built from the same boards the per-domain page renders
	 * (never a second classification path), minus reverse DNS, which the summary does not show.
	 *
	 * A domain whose reports cannot be read is reported as a row, not an exception: one unreadable
	 * domain must not blank the whole fleet.
	 */
	async fleet(days: number): Promise<ComplaintFleetRow[]> {
		const rows: ComplaintFleetRow[] = [];
		for (const domain of this.domains.list()) {
			try {
				const board = await this.board(domain.id, days, { reverseDns: false });
				const ranked = [...board.complaints].sort(
					(a, b) =>
						VERDICT_RANK[a.verdict] - VERDICT_RANK[b.verdict] ||
						b.messages - a.messages,
				);
				const top = ranked[0];
				rows.push({
					domainId: domain.id,
					domain: domain.name,
					verdict: board.verdict,
					headline: board.headline,
					messages: board.totals.messages,
					authenticatedPct: board.totals.authenticatedPct,
					problems: board.complaints.filter((c) => c.verdict === "problem").length,
					watching: board.complaints.filter((c) => c.verdict === "watch").length,
					topComplaint: top
						? { code: top.code, key: top.key, title: top.title, messages: top.messages }
						: null,
					reporters: board.reporters.length,
					reportsStored: board.ingest.reportsStored,
					lastReportAt: board.window.end || null,
					ingestionEnabled: board.ingestionEnabled,
					error: null,
				});
			} catch (err) {
				rows.push({
					domainId: domain.id,
					domain: domain.name,
					verdict: "insufficient_data",
					headline: "Could not read this domain's reports",
					messages: 0,
					authenticatedPct: 0,
					problems: 0,
					watching: 0,
					topComplaint: null,
					reporters: 0,
					reportsStored: 0,
					lastReportAt: null,
					ingestionEnabled: false,
					error: err instanceof Error ? err.message : String(err),
				});
			}
		}
		return rows.sort(
			(a, b) =>
				BOARD_VERDICT_RANK[a.verdict] - BOARD_VERDICT_RANK[b.verdict] ||
				b.messages - a.messages ||
				a.domain.localeCompare(b.domain),
		);
	}

	/** One complaint plus its fixes — the drill-down payload (§10.4). */
	async detail(
		domainId: string,
		code: string,
		days: number,
	): Promise<{
		board: Omit<ComplaintBoard, "complaints">;
		complaint: Complaint;
		fixes: ComplaintFix[];
	}> {
		const board = await this.board(domainId, days);
		return this.detailFrom(board, code, days);
	}

	/**
	 * Split out from `detail()` so a stored run snapshot (§12) can be drilled into with exactly the
	 * same logic as a live board — the run-scoped routes in §9.6 must not be a second code path.
	 */
	detailFrom(
		board: ComplaintBoard,
		code: string,
		days: number,
	): {
		board: Omit<ComplaintBoard, "complaints">;
		complaint: Complaint;
		fixes: ComplaintFix[];
	} {
		const wanted = code.toUpperCase();
		const complaint = board.complaints.find(
			(c) => c.code === wanted || c.key === code,
		);
		if (!complaint)
			throw new NotFoundException(
				`No complaint ${code} on ${board.domain} in the last ${days} days`,
			);
		const espDomains = [
			...new Set(
				complaint.sources
					.map((s) => s.dkimDomain)
					.filter((d) => d && isEspDefaultDomain(d)),
			),
		];
		const fixes = complaint.fixIds
			.map((id) =>
				buildFix(
					id,
					{
						domain: board.domain,
						byCode: new Map([[complaint.code, complaint]]),
						tlsResultTypes: [],
						brokenSelectors: [
							...new Set(
								complaint.sources.map((s) => s.dkimSelector).filter(Boolean),
							),
						],
						espDomains,
					},
					complaint.messages,
				),
			)
			.filter((f): f is ComplaintFix => f !== null);
		const { complaints: _all, ...rest } = board;
		return { board: rest, complaint, fixes };
	}

	/**
	 * §13 / §15.12 — run ONLY the checkers a fix names, and return their findings so the card can
	 * update in place.
	 *
	 * Deliberately does NOT mint a run file. "Re-check this now" answers one question — did the DNS
	 * change I just made take effect? — and a full run is neither needed nor wanted for that; §10.3
	 * says the card updates in place. Findings land in run history on the next real run.
	 */
	async recheckFix(
		domainId: string,
		checkIds: readonly string[],
	): Promise<{ checkId: string; findings: Finding[] }[]> {
		const domain = this.domains.get(domainId);
		const out: { checkId: string; findings: Finding[] }[] = [];
		for (const checkId of checkIds) {
			const checker = CHECKERS.find((c) => c.id === checkId);
			if (!checker) continue;
			try {
				const outcome = await checker.run({
					domain: domain.name,
					domainId: domain.id,
					runId: `recheck-${checkId}`,
					dkimSelectors: domain.dkimSelectors,
					sendingIps: domain.sendingIps,
					trigger: "manual",
					tools: locateTools(),
				});
				out.push({
					checkId,
					findings: Array.isArray(outcome) ? outcome : outcome.findings,
				});
			} catch (err) {
				// A failed re-check reports itself rather than 500-ing the page: the user asked
				// "did my fix land?", and "we could not tell" is a real answer.
				out.push({
					checkId,
					findings: [
						{
							checkId,
							severity: "warning",
							title: "Re-check could not complete",
							detail: err instanceof Error ? err.message : String(err),
						} as Finding,
					],
				});
			}
		}
		return out;
	}
}

/**
 * The Email Complaints API (pm/Email_Complaints.mdx §13):
 *
 *   GET  /api/domains/:id/complaints?days=60           — the whole board
 *   GET  /api/domains/:id/complaints/:code?days=60     — one complaint + its fixes
 *   GET  /api/domains/:id/complaints/:code/raw?report= — the pretty-printed source XML/JSON
 *   POST /api/domains/:id/complaints/recheck           — ingest, then rebuild the board
 *   POST /api/domains/:id/complaints/recheck/:fixId    — run only the checkers that fix names
 *
 * Reads are open (login is optional per pm/security.mdx §1); the actions that touch the mailbox or
 * the network require auth.
 */
@ApiTags("complaints")
@ApiBearerAuth()
@Controller("domains/:id/complaints")
export class ComplaintsController {
	constructor(
		private readonly complaints: ComplaintsService,
		private readonly reports: ReportsService,
		private readonly domains: DomainsService,
	) {}

	@Get()
	@ApiOperation({
		summary:
			"The Email Complaints board for one domain — verdict, complaints, fix plan",
	})
	board(
		@Param("id") id: string,
		@Query("days") days?: string,
	): Promise<ComplaintBoard> {
		return this.complaints.board(id, clampDays(days));
	}

	@Post("recheck")
	@ApiOperation({ summary: "Ingest any new reports, then rebuild the board" })
	async recheck(
		@Param("id") id: string,
		@Query("days") days?: string,
	): Promise<ComplaintBoard> {
		await this.reports.ingest();
		return this.complaints.board(id, clampDays(days));
	}

	/**
	 * §15.12 — "Re-check runs only the checkers a fix names". The fix id resolves to its
	 * `recheckCheckId` through the same fix library the UI rendered, so the two can never disagree.
	 */
	@Post("recheck/:fixId")
	@ApiOperation({ summary: "Run only the checkers the named fix declares" })
	async recheckFix(
		@Param("id") id: string,
		@Param("fixId") fixId: string,
		@Query("days") days?: string,
	) {
		const window = clampDays(days);
		const board = await this.complaints.board(id, window);
		const fix = board.fixes.find((f) => f.id === fixId);
		if (!fix) throw new NotFoundException(`No fix ${fixId} on this board`);
		const checks = fix.recheckCheckId ? [fix.recheckCheckId] : [];
		const results = await this.complaints.recheckFix(id, checks);
		// Rebuild after the re-check so the caller gets the card's new state in one round-trip.
		return { fixId, ran: checks, results, board: await this.complaints.board(id, window) };
	}

	/**
	 * §10.4 block 2 — the raw report behind a complaint, pretty-printed. `report` is
	 * `<org>/<reportId>` for a DMARC aggregate or `<org>/<reportDate>` for a TLS-RPT report.
	 */
	@Get(":code/raw")
	@ApiOperation({ summary: "The source XML/JSON of one report, pretty-printed" })
	raw(
		@Param("id") id: string,
		@Param("code") _code: string,
		@Query("report") report?: string,
	): { report: string; kind: string; format: "raw" | "normalized"; content: string } {
		if (!report)
			throw new NotFoundException(
				"Name the report as ?report=<org>/<reportId>",
			);
		const slash = report.lastIndexOf("/");
		if (slash < 1)
			throw new NotFoundException(
				`Malformed report key "${report}" — expected <org>/<reportId>`,
			);
		const org = report.slice(0, slash);
		const key = report.slice(slash + 1);

		// Prefer the receiver's own words. Reports ingested before the raw store existed have none,
		// so fall back to the normalized JSON rather than showing the user an error.
		for (const kind of ["dmarc", "tlsrpt"] as const) {
			const raw = readRawReport(id, kind, org, key);
			if (raw)
				return { report, kind, format: "raw", content: raw };
		}

		const dmarc = listDmarcReports(id).find(
			(r) => r.reporterOrg === org && r.reportId === key,
		);
		if (dmarc)
			return {
				report,
				kind: "dmarc",
				format: "normalized",
				content: JSON.stringify(dmarc, null, 2),
			};
		const tls = listTlsRptReports(id).find(
			(r) => r.reporterOrg === org && r.reportDate === key,
		);
		if (tls)
			return {
				report,
				kind: "tlsrpt",
				format: "normalized",
				content: JSON.stringify(tls, null, 2),
			};
		throw new NotFoundException(`No stored report ${report} for this domain`);
	}

	/**
	 * §10.4 — this complaint's volume across the last 10 stored windows, for the run-history strip.
	 * Reads the per-run snapshots (§12) rather than recomputing, so the strip shows what each run
	 * actually reported at the time. A window where the complaint did not fire is a real zero, not a
	 * gap — that is how a user sees a fix take effect.
	 */
	@Get(":code/history")
	@ApiOperation({ summary: "One complaint's volume across the last 10 windows" })
	history(
		@Param("id") id: string,
		@Param("code") code: string,
	): { windowEnd: string; messages: number; sharePct: number }[] {
		const domain = this.domains.get(id);
		const wanted = code.toUpperCase();
		return listComplaintSnapshots(sanitizeDomainDir(domain.name))
			.slice(0, 10)
			.map((board) => {
				const hit = board.complaints.find(
					(c) => c.code === wanted || c.key === code,
				);
				return {
					windowEnd: board.window?.end ?? "",
					messages: hit?.messages ?? 0,
					sharePct: hit?.sharePct ?? 0,
				};
			})
			.reverse();
	}

	@Get(":code")
	@ApiOperation({ summary: "One complaint's drill-down: evidence, meaning and fixes" })
	detail(
		@Param("id") id: string,
		@Param("code") code: string,
		@Query("days") days?: string,
	) {
		return this.complaints.detail(id, code, clampDays(days));
	}
}

/**
 * The run-scoped aliases (pm/Email_Complaints.mdx §9.6 / §13 / AC §15.8).
 *
 * These render the STORED SNAPSHOT for that run, never a freshly-built board: reports keep arriving
 * after a run finishes, so rebuilding live would show today's evidence under a historical heading.
 * A run with no snapshot (one that predates §12) 404s rather than silently substituting the live
 * board, because quietly showing different data than the URL promises is the bug this route exists
 * to avoid.
 *
 * Registered on its own path so it cannot shadow `/domains/:id/complaints/:code`.
 */
@ApiTags("complaints")
@Controller("domains/:id/runs/:runId/complaints")
export class RunComplaintsController {
	constructor(
		private readonly complaints: ComplaintsService,
		private readonly domains: DomainsService,
	) {}

	private snapshot(domainId: string, runId: string): ComplaintBoard {
		const domain = this.domains.get(domainId);
		const board = readComplaintSnapshot(sanitizeDomainDir(domain.name), runId);
		if (!board)
			throw new NotFoundException(
				`Run ${runId} has no stored complaint snapshot. Runs recorded before complaint snapshots shipped cannot be reconstructed, because the reports have moved on since.`,
			);
		return board;
	}

	@Get()
	@ApiOperation({ summary: "The complaint board exactly as it stood for one run" })
	board(
		@Param("id") id: string,
		@Param("runId") runId: string,
	): ComplaintBoard {
		return this.snapshot(id, runId);
	}

	@Get(":code")
	@ApiOperation({ summary: "One complaint from a run's stored snapshot" })
	detail(
		@Param("id") id: string,
		@Param("runId") runId: string,
		@Param("code") code: string,
	) {
		const board = this.snapshot(id, runId);
		return this.complaints.detailFrom(board, code, board.window.days);
	}
}

/**
 * The fleet complaint view (pm/Email_Complaints.mdx §9.7) — what the left bar's **Complaints** item
 * asks for: across every monitored domain, is anybody complaining, and about what?
 *
 * One row per domain, worst verdict first, each row a door into that domain's board. Read is open
 * (login is optional per pm/security.mdx §1); the re-check that touches the mailbox stays on the
 * per-domain controller.
 */
@ApiTags("complaints")
@Controller("complaints")
export class FleetComplaintsController {
	constructor(private readonly complaints: ComplaintsService) {}

	@Get()
	@ApiOperation({
		summary: "Every monitored domain's complaint verdict, worst first",
	})
	fleet(@Query("days") days?: string): Promise<ComplaintFleetRow[]> {
		return this.complaints.fleet(clampDays(days));
	}
}
