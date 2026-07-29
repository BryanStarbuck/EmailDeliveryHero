import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { ArrowLeft, BookOpen, Gauge, Wrench } from "lucide-react";
import { useState } from "react";
import {
	useComplaintDetail,
	useComplaintHistory,
	useRawReport,
} from "@/api/complaints";
import type { ComplaintReportRef } from "@/api/types";
import { SeverityBadge } from "@/components/Badges";
import { formatVolume, trendFor } from "@/lib/complaint-catalog";
import { cn } from "@/lib/utils";
import { EvidenceTable, ZoneC } from "./EmailComplaintsPage";

/**
 * The per-complaint drill-down (pm/Email_Complaints.mdx §10.4) —
 * `/domains/:id/complaints/:code`.
 *
 * Five blocks, the same contract the other technology pages use (pm/checks/dmarc.mdx §6.3), so this
 * surface is not a special snowflake:
 *   1 what this is · 2 what we saw · 3 what it means · 4 how to fix it · 5 re-check
 */
export function ComplaintDetailPage() {
	const { id = "", code = "", runId } = useParams({ strict: false }) as {
		id?: string;
		code?: string;
		runId?: string;
	};
	const navigate = useNavigate();
	const [days] = useState(60);
	const { data, isLoading, isError } = useComplaintDetail(id, code, days, runId);

	if (isLoading)
		return <p className="p-6 text-sm text-[var(--edh-muted)]">Loading…</p>;
	if (isError || !data)
		return (
			<p className="p-6 text-sm text-red-700">
				No complaint {code} on this domain in the last {days} days.
			</p>
		);

	const { board, complaint, fixes } = data;
	const trend = trendFor(complaint);

	return (
		<div className="mx-auto max-w-5xl pb-16">
			<button
				type="button"
				onClick={() =>
					navigate({ to: "/domains/$id/complaints", params: { id } })
				}
				className="mb-4 inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
			>
				<ArrowLeft className="h-4 w-4" /> All complaints for {board.domain}
			</button>

			<div className="mb-1 flex flex-wrap items-center gap-2">
				<span className="rounded-md bg-slate-800 px-1.5 py-0.5 text-[11px] font-semibold text-white">
					{complaint.code}
				</span>
				<h1 className="text-2xl font-semibold">{complaint.title}</h1>
				<SeverityBadge severity={complaint.severity} />
			</div>
			<p className="mb-8 text-sm text-[var(--edh-muted)]">
				{complaint.messages > 0
					? formatVolume(complaint.messages, complaint.sharePct)
					: "No message volume"}{" "}
				· <span className={trend.tone}>{trend.label}</span> vs. the previous{" "}
				{board.window.days} days
				{complaint.previousMessages > 0
					? ` (${complaint.previousMessages.toLocaleString()} then)`
					: ""}
			</p>

			<Block n={1} icon={<BookOpen className="h-4 w-4" />} title="What this is">
				<p className="max-w-3xl text-sm leading-relaxed text-slate-700">
					{complaint.explanation}
				</p>
			</Block>

			<Block n={2} icon={<Gauge className="h-4 w-4" />} title="What we saw">
				{complaint.sources.length > 0 ? (
					<>
						<p className="mb-2 text-xs text-[var(--edh-muted)]">
							{complaint.evidenceSummary}
						</p>
						{/* No truncation on the drill-down: this is the page you come to for everything. */}
						<EvidenceTable sources={complaint.sources} limit={complaint.sources.length} />
					</>
				) : (
					<p className="text-sm text-[var(--edh-muted)]">
						This complaint is derived from the reports themselves rather than
						from individual message rows, so it has no per-source table.
					</p>
				)}

				<h4 className="mt-6 mb-2 text-sm font-semibold">
					The DMARC record receivers reported seeing
				</h4>
				<div className="overflow-x-auto rounded-lg border border-[var(--edh-border)]">
					<table className="min-w-full text-left text-xs">
						<thead className="bg-slate-50 text-[var(--edh-muted)]">
							<tr>
								<th className="px-3 py-2 font-medium">p</th>
								<th className="px-3 py-2 font-medium">sp</th>
								<th className="px-3 py-2 font-medium">np</th>
								<th className="px-3 py-2 font-medium">adkim</th>
								<th className="px-3 py-2 font-medium">aspf</th>
								<th className="px-3 py-2 font-medium">pct</th>
								<th className="px-3 py-2 font-medium">Reported by</th>
							</tr>
						</thead>
						<tbody>
							{board.policyObserved.map((p) => (
								<tr
									key={`${p.p}-${p.sp}-${p.np}-${p.adkim}-${p.aspf}-${p.pct}-${p.fo}-${p.firstSeen}`}
									className="border-t border-[var(--edh-border)] font-mono"
								>
									<td className="px-3 py-2">{p.p}</td>
									<td className="px-3 py-2">{p.sp ?? "—"}</td>
									<td className="px-3 py-2">{p.np ?? "—"}</td>
									<td className="px-3 py-2">{p.adkim}</td>
									<td className="px-3 py-2">{p.aspf}</td>
									<td className="px-3 py-2">{p.pct ?? "—"}</td>
									<td className="px-3 py-2 font-sans">
										{p.reporters.join(", ")}
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>

				{/* §10.4 block 2 — the receiver's own words, on demand. The board is our reading of
				    the reports; this is the report. */}
				<RawReportViewer domainId={id} code={complaint.code} reports={board.reports} />

				<h4 className="mt-6 mb-2 text-sm font-semibold">Who reported this</h4>
				<ul className="space-y-1 text-xs">
					{board.reporters
						.filter((r) => !r.expectedButMissing)
						.map((r) => (
							<li key={r.org} className="flex flex-wrap gap-2">
								<span className="font-medium">{r.org}</span>
								<span className="text-[var(--edh-muted)]">
									{r.reportCount} report{r.reportCount === 1 ? "" : "s"} ·{" "}
									{r.messages.toLocaleString()} msgs
								</span>
								{r.email ? (
									<a
										href={`mailto:${r.email}`}
										className="text-[var(--edh-primary)] hover:underline"
									>
										{r.email}
									</a>
								) : null}
								{r.contactUrl ? (
									<a
										href={r.contactUrl}
										target="_blank"
										rel="noreferrer"
										className="text-[var(--edh-primary)] hover:underline"
									>
										help
									</a>
								) : null}
							</li>
						))}
				</ul>
			</Block>

			<Block n={3} icon={<Gauge className="h-4 w-4" />} title="What it means">
				<p className="max-w-3xl text-sm leading-relaxed text-slate-700">
					{complaint.verdict === "ok"
						? "Nothing here needs your attention. It is listed so the volumes on the board add up, and so that a blocked attacker is never mistaken for a broken configuration."
						: complaint.verdict === "watch"
							? "This is not failing today. It is a single point of failure: it depends on one mechanism holding, and there is no second leg to stand on if that one breaks. Fixing it is cheap insurance rather than an emergency."
							: "This is a live defect. Left alone it either loses mail now, or loses mail the moment the one thing propping it up changes."}
				</p>
				{complaint.verdict === "problem" ? (
					<p className="mt-2 max-w-3xl text-sm text-slate-700">
						Under the currently reported policy (
						<code className="font-mono">
							p={board.policyObserved[0]?.p ?? "none"}
						</code>
						), affected mail is{" "}
						{board.policyObserved.some((p) => p.p === "reject")
							? "rejected outright once it stops authenticating"
							: "delivered for now, which is why the problem is invisible without these reports"}
						.
					</p>
				) : null}
			</Block>

			<Block n={4} icon={<Wrench className="h-4 w-4" />} title="How to fix it">
				<ZoneC fixes={fixes} />
			</Block>

			<Block n={5} icon={<Gauge className="h-4 w-4" />} title="Re-check">
				<p className="mb-3 text-sm text-slate-700">
					Reports arrive on the receivers' schedule, so a fix shows up on the
					next report window rather than immediately.
				</p>
				<Link
					to="/domains/$id/complaints"
					params={{ id }}
					className="inline-flex items-center gap-1 rounded-md bg-[var(--edh-primary)] px-3 py-1.5 text-sm font-medium text-white"
				>
					Back to the board to ingest &amp; re-check
				</Link>

				<ComplaintHistoryStrip domainId={id} code={complaint.code} />
			</Block>
		</div>
	);
}

/**
 * The run-history strip (pm/Email_Complaints.mdx §10.4) — this complaint's volume across the last
 * 10 stored windows, oldest → newest. Bars are scaled against the largest window, and a window
 * where the complaint did not fire renders as an empty slot rather than being skipped: seeing the
 * bars shrink to nothing is how a user knows the fix worked.
 */
function ComplaintHistoryStrip({
	domainId,
	code,
}: {
	domainId: string;
	code: string;
}) {
	const { data } = useComplaintHistory(domainId, code);
	if (!data || data.length < 2) return null;
	const peak = Math.max(...data.map((d) => d.messages), 1);

	return (
		<div className="mt-6">
			<h4 className="mb-2 text-sm font-semibold">
				This complaint across the last {data.length} windows
			</h4>
			<div
				className="flex items-end gap-1"
				style={{ height: 48 }}
				aria-label={`${code} volume across the last ${data.length} windows`}
			>
				{data.map((point) => (
					<div
						key={point.windowEnd}
						title={`${point.windowEnd.slice(0, 10)} — ${point.messages.toLocaleString()} msgs (${point.sharePct}%)`}
						className={cn(
							"w-6 rounded-t",
							point.messages > 0
								? "bg-[var(--edh-primary)]"
								: "border border-dashed border-[var(--edh-border)]",
						)}
						style={{
							height: `${Math.max((point.messages / peak) * 100, point.messages > 0 ? 6 : 4)}%`,
						}}
					/>
				))}
			</div>
			<p className="mt-1 text-[11px] text-[var(--edh-muted)]">
				{data[0]?.windowEnd.slice(0, 10)} → {data.at(-1)?.windowEnd.slice(0, 10)}
			</p>
		</div>
	);
}

/**
 * "View raw report" (pm/Email_Complaints.mdx §10.4 block 2).
 *
 * The rest of this page is our READING of the reports; this is the report. Fetched only when the
 * user picks one — the payloads are large and nobody needs them on page load. When a report was
 * ingested before raw payloads were kept, the API returns the normalized JSON instead and says so,
 * which is honest about what the user is looking at.
 */
function RawReportViewer({
	domainId,
	code,
	reports,
}: {
	domainId: string;
	code: string;
	reports: ComplaintReportRef[];
}) {
	const [selected, setSelected] = useState<string | null>(null);
	const { data, isLoading, isError } = useRawReport(domainId, code, selected);

	if (reports.length === 0) return null;

	return (
		<div className="mt-6">
			<h4 className="mb-2 text-sm font-semibold">View raw report</h4>
			<p className="mb-2 text-xs text-[var(--edh-muted)]">
				The receiver's own XML or JSON, exactly as it arrived.
			</p>
			<select
				value={selected ?? ""}
				onChange={(e) => setSelected(e.target.value || null)}
				className="w-full max-w-xl rounded-md border border-[var(--edh-border)] bg-white px-2 py-1.5 text-xs"
				aria-label="Choose a report to view"
			>
				<option value="">Choose a report…</option>
				{reports.map((r) => (
					<option key={`${r.org}/${r.id}`} value={`${r.org}/${r.id}`}>
						{r.org} · {r.kind === "dmarc" ? "DMARC" : "TLS-RPT"} ·{" "}
						{r.windowBegin.slice(0, 10)} → {r.windowEnd.slice(0, 10)}
					</option>
				))}
			</select>

			{selected && isLoading ? (
				<p className="mt-2 text-xs text-[var(--edh-muted)]">Loading the report…</p>
			) : null}
			{selected && isError ? (
				<p className="mt-2 text-xs text-red-700">
					That report is no longer in the store.
				</p>
			) : null}
			{data ? (
				<div className="mt-2">
					{data.format === "normalized" ? (
						<p className="mb-1 text-xs text-amber-700">
							This report was ingested before raw payloads were kept, so this is
							our normalized reading of it rather than the original XML.
						</p>
					) : null}
					<pre className="max-h-96 overflow-auto rounded-lg border border-[var(--edh-border)] bg-slate-50 p-3 text-[11px] leading-relaxed">
						{data.content}
					</pre>
				</div>
			) : null}
		</div>
	);
}

function Block({
	n,
	icon,
	title,
	children,
}: {
	n: number;
	icon: React.ReactNode;
	title: string;
	children: React.ReactNode;
}) {
	return (
		<section className={cn("mb-8")}>
			<h2 className="mb-3 flex items-center gap-2 text-lg font-semibold">
				<span className="text-[var(--edh-muted)]">{icon}</span>
				<span className="text-[var(--edh-muted)]">{n}.</span>
				{title}
			</h2>
			{children}
		</section>
	);
}
