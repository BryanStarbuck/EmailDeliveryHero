import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./axios";
import type {
	ComplaintBoard,
	ComplaintDetail,
	ComplaintFleetRow,
} from "./types";

/**
 * The Email Complaints API (pm/Email_Complaints.mdx §13) — the domain-owner-facing reading of the
 * DMARC-aggregate and TLS-RPT report emails: the board, one complaint's drill-down, and the
 * "ingest then rebuild" re-check.
 */

const BOARD_KEY = (domainId: string, days: number) =>
	["complaints", "board", domainId, days] as const;

/** Window sizes the UI offers (§13); the backend clamps anything else. */
export const COMPLAINT_WINDOWS = [30, 60, 90] as const;

/**
 * GET /domains/:id/complaints?days= — or, when `runId` is given, the STORED SNAPSHOT for that run
 * (pm/Email_Complaints.mdx §9.6/§12). The run-scoped routes must render what was true when the run
 * finished: reports keep arriving afterwards, so rebuilding live would put today's evidence under a
 * historical heading.
 */
export function useComplaintBoard(
	domainId: string | undefined,
	days = 60,
	runId?: string,
) {
	return useQuery({
		queryKey: runId
			? (["complaints", "run-board", domainId ?? "", runId] as const)
			: BOARD_KEY(domainId ?? "", days),
		queryFn: async () =>
			runId
				? (
						await api.get<ComplaintBoard>(
							`/domains/${domainId}/runs/${runId}/complaints`,
						)
					).data
				: (
						await api.get<ComplaintBoard>(`/domains/${domainId}/complaints`, {
							params: { days },
						})
					).data,
		enabled: !!domainId,
	});
}

/**
 * GET /complaints?days= — the fleet table behind the left bar's Complaints item (§9.7). One row per
 * monitored domain, worst verdict first; each row opens that domain's board.
 */
export function useComplaintFleet(days = 60) {
	return useQuery({
		queryKey: ["complaints", "fleet", days] as const,
		queryFn: async () =>
			(await api.get<ComplaintFleetRow[]>("/complaints", { params: { days } }))
				.data,
	});
}

/** GET /domains/:id/complaints/:code?days= — or the run-scoped snapshot's copy of it. */
export function useComplaintDetail(
	domainId: string | undefined,
	code: string | undefined,
	days = 60,
	runId?: string,
) {
	return useQuery({
		queryKey: [
			"complaints",
			"detail",
			domainId ?? "",
			code ?? "",
			runId ?? "live",
			days,
		] as const,
		queryFn: async () =>
			(
				await api.get<ComplaintDetail>(
					runId
						? `/domains/${domainId}/runs/${runId}/complaints/${code}`
						: `/domains/${domainId}/complaints/${code}`,
					runId ? undefined : { params: { days } },
				)
			).data,
		enabled: !!domainId && !!code,
	});
}

/** One window of a complaint's history — the §10.4 run-history strip. */
export interface ComplaintHistoryPoint {
	windowEnd: string;
	messages: number;
	sharePct: number;
}

/** GET /domains/:id/complaints/:code/history — the last 10 windows, oldest → newest. */
export function useComplaintHistory(
	domainId: string | undefined,
	code: string | undefined,
) {
	return useQuery({
		queryKey: ["complaints", "history", domainId ?? "", code ?? ""] as const,
		queryFn: async () =>
			(
				await api.get<ComplaintHistoryPoint[]>(
					`/domains/${domainId}/complaints/${code}/history`,
				)
			).data,
		enabled: !!domainId && !!code,
	});
}

/** The raw report behind a complaint, pretty-printed (§10.4 block 2). */
export interface RawReport {
	report: string;
	kind: string;
	/** `raw` = the receiver's own XML/JSON; `normalized` = our parsed shape, for pre-raw-store reports. */
	format: "raw" | "normalized";
	content: string;
}

/** GET /domains/:id/complaints/:code/raw?report=<org>/<id> — fetched on demand, never on page load. */
export function useRawReport(
	domainId: string | undefined,
	code: string | undefined,
	report: string | null,
) {
	return useQuery({
		queryKey: ["complaints", "raw", domainId ?? "", code ?? "", report ?? ""] as const,
		queryFn: async () =>
			(
				await api.get<RawReport>(
					`/domains/${domainId}/complaints/${code}/raw`,
					{ params: { report } },
				)
			).data,
		enabled: !!domainId && !!code && !!report,
	});
}

/**
 * POST /domains/:id/complaints/recheck/:fixId — run ONLY the checkers that fix names (§15.12), then
 * return the rebuilt board so the card updates in place (§10.3) without a full re-audit.
 */
export function useRecheckFix(domainId: string, days = 60) {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: async (fixId: string) =>
			(
				await api.post<{
					fixId: string;
					ran: string[];
					results: { checkId: string; findings: { severity: string; title: string; detail?: string }[] }[];
					board: ComplaintBoard;
				}>(`/domains/${domainId}/complaints/recheck/${fixId}`, undefined, {
					params: { days },
				})
			).data,
		onSuccess: (data) => {
			qc.setQueryData(BOARD_KEY(domainId, days), data.board);
			qc.invalidateQueries({ queryKey: ["complaints"] });
		},
	});
}

/** POST /domains/:id/complaints/recheck — ingest any new reports, then rebuild the board. */
export function useRecheckComplaints(domainId: string, days = 60) {
	const qc = useQueryClient();
	return useMutation({
		mutationFn: async () =>
			(
				await api.post<ComplaintBoard>(
					`/domains/${domainId}/complaints/recheck`,
					undefined,
					{ params: { days } },
				)
			).data,
		onSuccess: (board) => {
			qc.setQueryData(BOARD_KEY(domainId, days), board);
			qc.invalidateQueries({ queryKey: ["complaints"] });
			qc.invalidateQueries({ queryKey: ["reports"] });
		},
	});
}
