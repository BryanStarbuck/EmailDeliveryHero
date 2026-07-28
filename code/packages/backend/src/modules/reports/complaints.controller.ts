import { DomainsService } from "@module/domains/domains.service";
import { RequireAuth } from "@module/auth/roles.decorator";
import {
	Controller,
	Get,
	NotFoundException,
	Param,
	Post,
	Query,
} from "@nestjs/common";
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger";
import { Injectable } from "@nestjs/common";
import { readAppConfig } from "@shared/config-store";
import { buildComplaintBoard } from "./complaints/board";
import type {
	Complaint,
	ComplaintBoard,
	ComplaintFix,
} from "./complaints/complaint.types";
import { isEspDefaultDomain } from "./complaints/classify";
import { buildFix } from "./complaints/fixes";
import { listDmarcReports, listTlsRptReports, readIngestState } from "./report-store";
import { ReportsService } from "./reports.service";

/** Window sizes the UI offers (pm/Email_Complaints.mdx §13); anything else is clamped. */
const ALLOWED_DAYS = [7, 30, 60, 90];
const DEFAULT_DAYS = 60;

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

	board(domainId: string, days: number): ComplaintBoard {
		const domain = this.domains.get(domainId);
		const config = readAppConfig().reports;
		return buildComplaintBoard({
			domainId,
			domain: domain.name,
			dmarcReports: listDmarcReports(domainId),
			tlsReports: listTlsRptReports(domainId),
			windowDays: days,
			ingestionEnabled: config.enabled,
			lastIngestAt: readIngestState(domainId).lastIngestAt,
		});
	}

	/** One complaint plus its fixes — the drill-down payload (§10.4). */
	detail(
		domainId: string,
		code: string,
		days: number,
	): { board: Omit<ComplaintBoard, "complaints">; complaint: Complaint; fixes: ComplaintFix[] } {
		const board = this.board(domainId, days);
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
}

/**
 * The Email Complaints API (pm/Email_Complaints.mdx §13):
 *
 *   GET  /api/domains/:id/complaints?days=60        — the whole board
 *   GET  /api/domains/:id/complaints/:code?days=60  — one complaint + its fixes
 *   POST /api/domains/:id/complaints/recheck        — ingest now, then rebuild the board
 *
 * Reads are open (login is optional per pm/security.mdx §1); the action that touches the mailbox
 * requires auth.
 */
@ApiTags("complaints")
@ApiBearerAuth()
@Controller("domains/:id/complaints")
export class ComplaintsController {
	constructor(
		private readonly complaints: ComplaintsService,
		private readonly reports: ReportsService,
	) {}

	@Get()
	@ApiOperation({
		summary: "The Email Complaints board for one domain — verdict, complaints, fix plan",
	})
	board(
		@Param("id") id: string,
		@Query("days") days?: string,
	): ComplaintBoard {
		return this.complaints.board(id, clampDays(days));
	}

	@Post("recheck")
	@RequireAuth()
	@ApiOperation({ summary: "Ingest any new reports, then rebuild the board" })
	async recheck(
		@Param("id") id: string,
		@Query("days") days?: string,
	): Promise<ComplaintBoard> {
		await this.reports.ingest();
		return this.complaints.board(id, clampDays(days));
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
