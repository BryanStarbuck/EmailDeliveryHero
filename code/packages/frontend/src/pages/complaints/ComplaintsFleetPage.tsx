import { Link } from "@tanstack/react-router";
import { ChevronRight, MailWarning } from "lucide-react";
import { useState } from "react";
import { COMPLAINT_WINDOWS, useComplaintFleet } from "@/api/complaints";
import type { ComplaintFleetRow } from "@/api/types";
import { BOARD_VERDICT_COPY } from "@/lib/complaint-catalog";
import { cn } from "@/lib/utils";

/**
 * The fleet Email Complaints view (pm/Email_Complaints.mdx §9.7) — `/complaints`, the left bar's
 * **Complaints** item.
 *
 * The per-domain board answers "what is this domain's mail doing?". This page answers the question
 * that comes before it: across everything I monitor, is anybody complaining, and where do I look
 * first? One row per domain, worst verdict first, each row a door into that domain's board.
 *
 * Deliberately a summary and nothing more: no evidence tables, no fix plans. Those live on the
 * board, one click away, and duplicating them here would give a second place for them to disagree.
 */
export function ComplaintsFleetPage() {
	const [days, setDays] = useState<number>(60);
	const { data: rows, isLoading, isError } = useComplaintFleet(days);

	const list = rows ?? [];
	const nProblem = list.filter(
		(r) => r.verdict === "action" || r.verdict === "attention",
	).length;
	const nSilent = list.filter((r) => r.reportsStored === 0).length;

	return (
		<div className="mx-auto max-w-6xl px-6 py-6">
			<header className="mb-4 flex flex-wrap items-center justify-between gap-3">
				<div>
					<h1 className="flex items-center gap-2 text-xl font-semibold text-black">
						<MailWarning className="h-5 w-5" aria-hidden />
						Email complaints
					</h1>
					<p className="mt-1 text-sm text-[var(--edh-muted)]">
						What mailbox providers are telling us about every domain you monitor —
						read as plain-language complaints, not raw reports.
					</p>
				</div>

				{/* Same window vocabulary as the per-domain board (§13), so the two never disagree. */}
				<div className="flex items-center gap-1" aria-label="Reporting window">
					{COMPLAINT_WINDOWS.map((w) => (
						<button
							key={w}
							type="button"
							onClick={() => setDays(w)}
							className={cn(
								"rounded-md border px-2 py-1 text-xs",
								days === w
									? "border-[var(--edh-primary)] bg-[var(--edh-primary)]/10 font-medium text-[var(--edh-primary)]"
									: "border-[var(--edh-border)] text-black hover:bg-slate-100",
							)}
						>
							{w} days
						</button>
					))}
				</div>
			</header>

			{!isLoading && !isError && list.length > 0 && (
				<p className="mb-3 text-sm text-black">
					{nProblem === 0
						? "No domain needs attention right now."
						: `${nProblem} domain${nProblem === 1 ? "" : "s"} need${nProblem === 1 ? "s" : ""} attention.`}
					{nSilent > 0 && (
						<span className="text-[var(--edh-muted)]">
							{" "}
							{nSilent} domain{nSilent === 1 ? " has" : "s have"} no reports yet —
							nobody has told us anything about {nSilent === 1 ? "it" : "them"}.
						</span>
					)}
				</p>
			)}

			{isLoading && (
				<p className="text-sm text-[var(--edh-muted)]">Loading complaints…</p>
			)}
			{isError && (
				<p className="text-sm text-red-700">
					Could not load the complaint roll-up — see the backend log.
				</p>
			)}

			{!isLoading && !isError && list.length === 0 && (
				<div className="rounded-lg border border-[var(--edh-border)] bg-white p-6 text-sm text-black">
					No domains are being monitored yet.{" "}
					<Link to="/domains" className="text-[var(--edh-primary)] underline">
						Add a domain
					</Link>{" "}
					and its DMARC reports will show up here.
				</div>
			)}

			{list.length > 0 && (
				<div className="overflow-x-auto rounded-lg border border-[var(--edh-border)] bg-white">
					<table className="w-full min-w-[52rem] text-sm">
						<thead>
							<tr className="border-b border-[var(--edh-border)] text-left text-xs uppercase tracking-wide text-black">
								<th className="px-3 py-2 font-semibold">Domain</th>
								<th className="px-3 py-2 font-semibold">Verdict</th>
								<th className="px-3 py-2 font-semibold">Loudest complaint</th>
								<th className="px-3 py-2 text-right font-semibold">Messages</th>
								<th className="px-3 py-2 text-right font-semibold">Authenticated</th>
								<th className="px-3 py-2 text-right font-semibold">Open</th>
								<th className="px-3 py-2" />
							</tr>
						</thead>
						<tbody>
							{list.map((row) => (
								<FleetRow key={row.domainId} row={row} />
							))}
						</tbody>
					</table>
				</div>
			)}
		</div>
	);
}

function FleetRow({ row }: { row: ComplaintFleetRow }) {
	const copy = BOARD_VERDICT_COPY[row.verdict];
	return (
		<tr className="border-b border-[var(--edh-border)] last:border-0 hover:bg-slate-50">
			<td className="px-3 py-2">
				<Link
					to="/domains/$id/complaints"
					params={{ id: row.domainId }}
					className="font-medium text-black hover:underline"
				>
					{row.domain}
				</Link>
				{/* The headline is the board's own one-sentence summary — never re-worded here. */}
				<div className="mt-0.5 text-xs text-[var(--edh-muted)]">
					{row.error ?? row.headline}
				</div>
			</td>
			<td className="px-3 py-2">
				<span
					className={cn(
						"inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs",
						copy.tone,
					)}
				>
					<span aria-hidden>{copy.icon}</span>
					{copy.label}
				</span>
			</td>
			<td className="px-3 py-2 text-black">
				{row.topComplaint ? (
					<Link
						to="/domains/$id/complaints/$code"
						params={{ id: row.domainId, code: row.topComplaint.key }}
						className="hover:underline"
					>
						{row.topComplaint.title}
					</Link>
				) : (
					<span className="text-[var(--edh-muted)]">
						{row.reportsStored === 0 ? "No reports yet" : "Nothing to report"}
					</span>
				)}
			</td>
			<td className="px-3 py-2 text-right tabular-nums text-black">
				{row.messages.toLocaleString()}
			</td>
			<td className="px-3 py-2 text-right tabular-nums text-black">
				{row.messages > 0 ? `${row.authenticatedPct}%` : "—"}
			</td>
			<td className="px-3 py-2 text-right tabular-nums text-black">
				{row.problems > 0 ? `${row.problems} problem` : "—"}
				{row.watching > 0 && (
					<span className="text-[var(--edh-muted)]"> · {row.watching} watch</span>
				)}
			</td>
			<td className="px-3 py-2 text-right">
				<Link
					to="/domains/$id/complaints"
					params={{ id: row.domainId }}
					aria-label={`Open the complaint board for ${row.domain}`}
					className="inline-flex text-[var(--edh-muted)] hover:text-black"
				>
					<ChevronRight className="h-4 w-4" aria-hidden />
				</Link>
			</td>
		</tr>
	);
}
