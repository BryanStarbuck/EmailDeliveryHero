import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./axios";
import type { ComplaintBoard, ComplaintDetail } from "./types";

/**
 * The Email Complaints API (pm/Email_Complaints.mdx §13) — the domain-owner-facing reading of the
 * DMARC-aggregate and TLS-RPT report emails: the board, one complaint's drill-down, and the
 * "ingest then rebuild" re-check.
 */

const BOARD_KEY = (domainId: string, days: number) =>
	["complaints", "board", domainId, days] as const;

/** Window sizes the UI offers (§13); the backend clamps anything else. */
export const COMPLAINT_WINDOWS = [30, 60, 90] as const;

/** GET /domains/:id/complaints?days= */
export function useComplaintBoard(
	domainId: string | undefined,
	days = 60,
) {
	return useQuery({
		queryKey: BOARD_KEY(domainId ?? "", days),
		queryFn: async () =>
			(
				await api.get<ComplaintBoard>(`/domains/${domainId}/complaints`, {
					params: { days },
				})
			).data,
		enabled: !!domainId,
	});
}

/** GET /domains/:id/complaints/:code?days= */
export function useComplaintDetail(
	domainId: string | undefined,
	code: string | undefined,
	days = 60,
) {
	return useQuery({
		queryKey: ["complaints", "detail", domainId ?? "", code ?? "", days] as const,
		queryFn: async () =>
			(
				await api.get<ComplaintDetail>(
					`/domains/${domainId}/complaints/${code}`,
					{ params: { days } },
				)
			).data,
		enabled: !!domainId && !!code,
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
