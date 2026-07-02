import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";
import type { DmarcReportsSnapshot } from "@/api/types";

/**
 * The DMARC ingested-reports explainer's block-2 tables (pm/emails.mdx §16.2 / AC #19). Renders
 * the RUN-SCOPED `dmarc.reports` snapshot (§16.3) the checker persists into the run file:
 *
 *   1. the aggregate breakdown table (report count, reporters, window, messages, dual-aligned,
 *      pass-rate %, DKIM-only / SPF-only / both-fail, quarantined / rejected, published policy), and
 *   2. the expandable per-source-IP table (§7.1 columns, count-desc, collapsed by default).
 *
 * Owned by pm/emails.mdx (the `reports` sub-test unit); mounted inside the shared DmarcCheckPage
 * chrome only when the viewed unit is `reports`. When the viewed run predates the checker (no
 * snapshot), nothing renders — the shared block-2 "not measured" copy covers it.
 */
export function DmarcReportsSnapshotView({
	snapshot,
}: {
	snapshot?: DmarcReportsSnapshot;
}) {
	const [open, setOpen] = useState(false);
	if (!snapshot || snapshot.report_count === 0) return null;

	const p = snapshot.policy_published;
	const policyStr = p
		? `p=${p.p}${p.sp ? `; sp=${p.sp}` : ""}; adkim=${p.adkim}; aspf=${p.aspf}${p.pct ? `; pct=${p.pct}` : ""}`
		: "—";

	return (
		<div className="mt-3">
			<p className="mb-1 text-xs font-medium uppercase text-[var(--edh-muted)]">
				Aggregate breakdown — window {fmtWindow(snapshot.window)} ·{" "}
				{snapshot.report_count} report
				{snapshot.report_count === 1 ? "" : "s"}
			</p>
			<table className="w-full text-sm">
				<tbody>
					<Row label="Reporters" value={snapshot.reporters.join(", ") || "—"} />
					<Row
						label="Messages"
						value={snapshot.total_messages.toLocaleString()}
					/>
					<Row
						label="Dual-aligned"
						value={`${snapshot.aligned_pass_messages.toLocaleString()} (pass rate ${snapshot.pass_rate_pct}%)`}
					/>
					<Row
						label="Passing on one mechanism"
						value={`DKIM-only ${snapshot.dkim_only} · SPF-only ${snapshot.spf_only}`}
					/>
					<Row label="Fail both SPF+DKIM" value={String(snapshot.both_fail)} />
					<Row
						label="Enforced against"
						value={`quarantined ${snapshot.quarantined} · rejected ${snapshot.rejected}`}
					/>
					<Row label="Published policy" value={policyStr} mono />
				</tbody>
			</table>

			{snapshot.rows.length > 0 && (
				<div className="mt-3">
					<button
						type="button"
						onClick={() => setOpen((o) => !o)}
						className="inline-flex items-center gap-1 text-xs font-medium text-[var(--edh-muted)] hover:text-slate-700"
						aria-expanded={open}
					>
						{open ? (
							<ChevronDown className="h-3.5 w-3.5" />
						) : (
							<ChevronRight className="h-3.5 w-3.5" />
						)}
						Per-source table ({snapshot.rows.length} source
						{snapshot.rows.length === 1 ? "" : "s"})
					</button>
					{open && (
						<div className="mt-2 overflow-x-auto rounded-md border border-[var(--edh-border)]">
							<table className="w-full text-xs">
								<thead className="bg-slate-50 text-left uppercase text-[var(--edh-muted)]">
									<tr>
										<th className="px-2 py-1.5">Source IP</th>
										<th className="px-2 py-1.5 text-right">Count</th>
										<th className="px-2 py-1.5">Disposition</th>
										<th className="px-2 py-1.5">SPF (eval/align)</th>
										<th className="px-2 py-1.5">DKIM (eval/align)</th>
										<th className="px-2 py-1.5">DMARC</th>
										<th className="px-2 py-1.5">Header-From</th>
										<th className="px-2 py-1.5">Envelope</th>
									</tr>
								</thead>
								<tbody>
									{snapshot.rows.map((r) => (
										<tr
											key={`${r.source_ip}-${r.envelope}-${String(r.spf_aligned)}-${String(r.dkim_aligned)}`}
											className="border-t border-[var(--edh-border)]"
										>
											<td className="px-2 py-1 font-mono">{r.source_ip}</td>
											<td className="px-2 py-1 text-right tabular-nums">
												{r.count}
											</td>
											<td className="px-2 py-1">{r.disposition}</td>
											<td className="px-2 py-1">
												{r.spf_evaluated}/
												{r.spf_aligned ? "aligned" : "not aligned"}
											</td>
											<td className="px-2 py-1">
												{r.dkim_evaluated}/
												{r.dkim_aligned ? "aligned" : "not aligned"}
											</td>
											<td
												className={`px-2 py-1 font-medium ${r.dmarc_pass ? "text-emerald-700" : "text-red-700"}`}
											>
												{r.dmarc_pass ? "pass" : "fail"}
											</td>
											<td className="px-2 py-1">{r.header_from || "—"}</td>
											<td className="px-2 py-1">{r.envelope || "—"}</td>
										</tr>
									))}
								</tbody>
							</table>
						</div>
					)}
				</div>
			)}
		</div>
	);
}

function Row({
	label,
	value,
	mono,
}: {
	label: string;
	value: string;
	mono?: boolean;
}) {
	return (
		<tr className="border-t border-[var(--edh-border)]">
			<td className="py-1.5 pr-3 align-top text-xs font-semibold text-slate-600">
				{label}
			</td>
			<td
				className={`py-1.5 align-top text-xs ${mono ? "font-mono text-slate-700" : "text-slate-700"}`}
			>
				{value}
			</td>
		</tr>
	);
}

function fmtWindow(w: { begin: string; end: string }): string {
	const d = (s: string) => (s ? s.slice(5, 10) : "?");
	return `${d(w.begin)}→${d(w.end)}`;
}
