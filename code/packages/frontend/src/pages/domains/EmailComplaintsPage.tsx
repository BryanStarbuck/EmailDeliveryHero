import { Link, useNavigate, useParams } from "@tanstack/react-router";
import {
	ArrowLeft,
	ChevronDown,
	ChevronRight,
	Inbox,
	Mailbox,
	RefreshCw,
	Terminal,
	Wrench,
} from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import {
	COMPLAINT_WINDOWS,
	useComplaintBoard,
	useRecheckComplaints,
} from "@/api/complaints";
import type {
	Complaint,
	ComplaintBoard,
	ComplaintFix,
	ComplaintSeriesPoint,
	ComplaintSource,
} from "@/api/types";
import { CopyFixButton } from "@/components/CopyFixButton";
import {
	BOARD_VERDICT_COPY,
	trendFor,
	COMPLAINT_FILTERS,
	COMPLAINT_GROUPS,
	type ComplaintFilter,
	filterComplaints,
	formatDelta,
	formatVolume,
} from "@/lib/complaint-catalog";
import { cn } from "@/lib/utils";

/**
 * The Email Complaints page (pm/Email_Complaints.mdx §10) — `/domains/:id/complaints`.
 *
 * One page, three zones, in the order a person actually asks the questions:
 *   Zone A  Am I OK?        — verdict banner, four metric tiles, trend chart, reporter coverage
 *   Zone B  What's wrong?   — complaint cards grouped problem / watch / working-as-intended
 *   Zone C  What do I do?   — the ordered fix plan, biggest win first
 *
 * The page's whole job is to say the true thing plainly: the dramatic-looking spoofing is usually
 * fine, and the boring configuration defect behind a green-looking pass rate is the real problem.
 */
export function EmailComplaintsPage() {
	const { id = "" } = useParams({ strict: false }) as { id?: string };
	const navigate = useNavigate();
	const [days, setDays] = useState<number>(60);
	const [filter, setFilter] = useState<ComplaintFilter>("all");
	const { data: board, isLoading, isError } = useComplaintBoard(id, days);
	const recheck = useRecheckComplaints(id, days);

	const onRecheck = () =>
		recheck.mutate(undefined, {
			onSuccess: (next) =>
				toast.success(
					`Re-checked — ${next.ingest.reportsStored} report(s) stored, ${next.complaints.filter((c) => c.verdict === "problem").length} problem(s) open.`,
				),
			onError: () =>
				toast.error("Could not re-check the complaints — see the backend log."),
		});

	if (isLoading) {
		return <p className="p-6 text-sm text-[var(--edh-muted)]">Loading complaints…</p>;
	}
	if (isError || !board) {
		return (
			<p className="p-6 text-sm text-red-700">
				Could not load the complaints for this domain.
			</p>
		);
	}

	const visible = filterComplaints(board.complaints, filter);

	return (
		<div className="mx-auto max-w-6xl pb-16">
			<div className="mb-4 flex flex-wrap items-center justify-between gap-2">
				<button
					type="button"
					onClick={() => navigate({ to: "/domains/$id", params: { id } })}
					className="inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
				>
					<ArrowLeft className="h-4 w-4" /> {board.domain}
				</button>
				<div className="flex items-center gap-2">
					<Link
						to="/domains/$id/reports"
						params={{ id }}
						className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm hover:bg-white"
					>
						<Mailbox className="h-4 w-4" /> Raw reports
					</Link>
					<button
						type="button"
						onClick={onRecheck}
						disabled={recheck.isPending}
						className="inline-flex items-center gap-1 rounded-md bg-[var(--edh-primary)] px-3 py-1.5 text-sm font-medium text-white disabled:opacity-60"
					>
						<RefreshCw
							className={cn("h-4 w-4", recheck.isPending && "animate-spin")}
						/>
						{recheck.isPending ? "Re-checking…" : "Ingest & re-check"}
					</button>
				</div>
			</div>

			<h1 className="mb-1 text-2xl font-semibold">Email complaints</h1>
			<p className="mb-6 text-sm text-[var(--edh-muted)]">
				What mailbox providers are telling you about mail sent as{" "}
				<span className="font-medium text-slate-700">{board.domain}</span>.
			</p>

			{board.totals.messages === 0 ? (
				<EmptyState board={board} />
			) : (
				<>
					<ZoneA board={board} days={days} onDays={setDays} onJump={setFilter} />
					<ZoneB
						board={board}
						visible={visible}
						filter={filter}
						onFilter={setFilter}
						domainId={id}
					/>
					<ZoneC fixes={board.fixes} />
				</>
			)}
		</div>
	);
}

// ─── Zone A — the verdict (§10.1) ────────────────────────────────────────────────────────────────

function ZoneA({
	board,
	days,
	onDays,
	onJump,
}: {
	board: ComplaintBoard;
	days: number;
	onDays: (d: number) => void;
	onJump: (f: ComplaintFilter) => void;
}) {
	const verdict = BOARD_VERDICT_COPY[board.verdict];
	const problems = board.complaints.filter((c) => c.verdict === "problem").length;
	const watching = board.complaints.filter((c) => c.verdict === "watch").length;
	const reporting = board.reporters.filter((r) => !r.expectedButMissing);

	return (
		<section className="mb-8">
			<div className={cn("rounded-xl border p-5", verdict.tone)}>
				<div className="flex items-baseline gap-3">
					<span className="text-2xl" aria-hidden>
						{verdict.icon}
					</span>
					{/* Verdict is never colour-only — the words always state it (§10.5). */}
					<h2 className="text-[28px] font-semibold leading-tight">
						{verdict.label}
					</h2>
				</div>
				<p className="mt-1 text-sm opacity-80">
					{problems} problem{problems === 1 ? "" : "s"}, {watching} thing
					{watching === 1 ? "" : "s"} to watch ·{" "}
					{board.totals.messages.toLocaleString()} messages · {reporting.length}{" "}
					receiver{reporting.length === 1 ? "" : "s"} · {board.window.days} days
				</p>
				<p className="mt-3 max-w-3xl text-[15px] font-medium">{board.headline}</p>
			</div>

			<div className="mt-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
				<Tile
					label="Authenticated"
					value={`${board.totals.authenticatedPct}%`}
					sub={`${board.totals.authenticated.toLocaleString()} msgs`}
					delta={formatDelta(board.deltas.authenticatedPct, " pts")}
					onClick={() => onJump("ok")}
				/>
				<Tile
					label="Not aligned"
					value={board.totals.notAligned.toLocaleString()}
					sub={`${pct(board.totals.notAligned, board.totals.messages)} of volume`}
					onClick={() => onJump("problem")}
				/>
				<Tile
					label="Blocked"
					value={board.totals.blocked.toLocaleString()}
					sub={`${pct(board.totals.blocked, board.totals.messages)} of volume`}
					onClick={() => onJump("all")}
				/>
				<Tile
					label="Spoofing"
					value={board.totals.spoof.toLocaleString()}
					sub={board.totals.spoof > 0 ? "blocked by your policy" : "none seen"}
					onClick={() => onJump("ok")}
				/>
			</div>

			<div className="mt-4 rounded-xl border border-[var(--edh-border)] bg-[var(--edh-card)] p-4">
				<div className="mb-3 flex items-center justify-between">
					<h3 className="text-sm font-semibold">Messages by outcome, daily</h3>
					<div className="flex gap-1">
						{COMPLAINT_WINDOWS.map((d) => (
							<button
								key={d}
								type="button"
								onClick={() => onDays(d)}
								className={cn(
									"rounded-md px-2 py-1 text-xs",
									d === days
										? "bg-[var(--edh-primary)] text-white"
										: "border border-[var(--edh-border)] hover:bg-slate-50",
								)}
							>
								{d}d
							</button>
						))}
					</div>
				</div>
				<OutcomeChart series={board.series} />
			</div>

			<div className="mt-4 flex flex-wrap items-center gap-2">
				<span className="text-xs font-medium text-[var(--edh-muted)]">
					Who is reporting:
				</span>
				{board.reporters.map((r) => (
					<span
						key={r.org}
						title={
							r.expectedButMissing
								? "Expected, but sent nothing this window"
								: [r.email, r.contactUrl].filter(Boolean).join(" · ")
						}
						className={cn(
							"inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs",
							r.expectedButMissing
								? "border border-dashed border-slate-300 text-slate-400"
								: "bg-slate-100 text-slate-700",
						)}
					>
						{r.org}
						<span className="opacity-60">
							{r.expectedButMissing ? "silent" : r.reportCount}
						</span>
					</span>
				))}
			</div>
		</section>
	);
}

function Tile({
	label,
	value,
	sub,
	delta,
	onClick,
}: {
	label: string;
	value: string;
	sub: string;
	delta?: string;
	onClick: () => void;
}) {
	return (
		<button
			type="button"
			onClick={onClick}
			className="rounded-xl border border-[var(--edh-border)] bg-[var(--edh-card)] p-4 text-left transition hover:border-slate-300"
		>
			<div className="text-[11px] font-semibold uppercase tracking-wide text-[var(--edh-muted)]">
				{label}
			</div>
			<div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>
			<div className="mt-0.5 text-xs text-[var(--edh-muted)]">
				{sub}
				{delta && delta !== "—" ? (
					<span className="tabular-nums"> · {delta}</span>
				) : null}
			</div>
		</button>
	);
}

/**
 * A dependency-free stacked bar chart of daily outcomes (§10.1 item 3). Wide content scrolls inside
 * its own container so the page body never scrolls sideways.
 */
function OutcomeChart({ series }: { series: ComplaintSeriesPoint[] }) {
	const max = Math.max(
		1,
		...series.map((p) => p.aligned + p.oneMechanism + p.failedBoth),
	);
	if (series.length === 0)
		return (
			<p className="text-sm text-[var(--edh-muted)]">
				No reports in this window yet.
			</p>
		);
	return (
		<div className="overflow-x-auto">
			<div className="flex min-w-full items-stretch gap-[3px]" style={{ height: 140 }}>
				{series.map((p) => {
					const total = p.aligned + p.oneMechanism + p.failedBoth;
					const h = (n: number) => `${(n / max) * 100}%`;
					return (
						<div
							key={p.date}
							className="flex min-w-[6px] flex-1 flex-col justify-end"
							title={`${p.date} — ${p.aligned} aligned, ${p.oneMechanism} one mechanism, ${p.failedBoth} failed both, ${p.rejected} rejected`}
						>
							<div style={{ height: h(p.failedBoth) }} className="bg-red-400" />
							<div
								style={{ height: h(p.oneMechanism) }}
								className="bg-amber-300"
							/>
							<div style={{ height: h(p.aligned) }} className="bg-emerald-400" />
							{total === 0 ? <div className="h-px bg-slate-200" /> : null}
						</div>
					);
				})}
			</div>
			<div className="mt-2 flex items-center justify-between text-[11px] text-[var(--edh-muted)]">
				<span>{series[0]?.date}</span>
				<span className="flex gap-3">
					<Legend className="bg-emerald-400" label="aligned" />
					<Legend className="bg-amber-300" label="one mechanism" />
					<Legend className="bg-red-400" label="failed both" />
				</span>
				<span>{series[series.length - 1]?.date}</span>
			</div>
		</div>
	);
}

function Legend({ className, label }: { className: string; label: string }) {
	return (
		<span className="inline-flex items-center gap-1">
			<span className={cn("inline-block h-2 w-3 rounded-sm", className)} />
			{label}
		</span>
	);
}

// ─── Zone B — what to work on (§10.2) ────────────────────────────────────────────────────────────

function ZoneB({
	board,
	visible,
	filter,
	onFilter,
	domainId,
}: {
	board: ComplaintBoard;
	visible: Complaint[];
	filter: ComplaintFilter;
	onFilter: (f: ComplaintFilter) => void;
	domainId: string;
}) {
	return (
		<section className="mb-10">
			<div className="mb-4 flex flex-wrap items-center justify-between gap-2">
				<h2 className="text-lg font-semibold">What to work on</h2>
				<div className="flex gap-1">
					{COMPLAINT_FILTERS.map((f) => (
						<button
							key={f.id}
							type="button"
							onClick={() => onFilter(f.id)}
							className={cn(
								"rounded-md px-2.5 py-1 text-xs",
								f.id === filter
									? "bg-slate-800 text-white"
									: "border border-[var(--edh-border)] hover:bg-slate-50",
							)}
						>
							{f.label}
						</button>
					))}
				</div>
			</div>

			{COMPLAINT_GROUPS.map((group) => {
				const items = visible.filter((c) => c.verdict === group.verdict);
				if (items.length === 0) return null;
				return (
					<div key={group.verdict} className="mb-6">
						<h3 className="text-sm font-semibold">{group.heading}</h3>
						<p className="mb-3 text-xs text-[var(--edh-muted)]">{group.sub}</p>
						<div className="space-y-3">
							{items.map((c) => (
								<ComplaintCard
									key={c.code}
									complaint={c}
									chip={group.chip}
									domainId={domainId}
									hasFix={board.fixes.some((f) => c.fixIds.includes(f.id))}
								/>
							))}
						</div>
					</div>
				);
			})}

			{visible.length === 0 ? (
				<p className="text-sm text-[var(--edh-muted)]">
					Nothing in this category.
				</p>
			) : null}
		</section>
	);
}

function ComplaintCard({
	complaint,
	chip,
	domainId,
	hasFix,
}: {
	complaint: Complaint;
	chip: string;
	domainId: string;
	hasFix: boolean;
}) {
	const [open, setOpen] = useState(false);
	const trend = trendFor(complaint);
	return (
		<article className="rounded-xl border border-[var(--edh-border)] bg-[var(--edh-card)] p-4">
			<div className="flex flex-wrap items-start justify-between gap-2">
				<div className="flex items-center gap-2">
					<span
						className={cn(
							"rounded-md px-1.5 py-0.5 text-[11px] font-semibold",
							chip,
						)}
					>
						{complaint.code}
					</span>
					<Link
						to="/domains/$id/complaints/$code"
						params={{ id: domainId, code: complaint.code }}
						className="font-medium hover:underline"
					>
						{complaint.title}
					</Link>
				</div>
				<div className="flex items-center gap-2 text-xs tabular-nums text-[var(--edh-muted)]">
					{complaint.messages > 0
						? formatVolume(complaint.messages, complaint.sharePct)
						: null}
					<span className={trend.tone} title={trend.label}>
						{trend.glyph} {trend.label}
					</span>
				</div>
			</div>

			<p className="mt-2 max-w-4xl text-sm leading-relaxed text-slate-700">
				{complaint.explanation}
			</p>

			<div className="mt-3 flex flex-wrap items-center gap-3">
				{complaint.sources.length > 0 ? (
					<button
						type="button"
						onClick={() => setOpen((v) => !v)}
						className="inline-flex items-center gap-1 text-xs text-[var(--edh-muted)] hover:text-slate-700"
					>
						{open ? (
							<ChevronDown className="h-3.5 w-3.5" />
						) : (
							<ChevronRight className="h-3.5 w-3.5" />
						)}
						{complaint.evidenceSummary}
					</button>
				) : null}
				{/* Fix links only ever appear on things that are actually yours to fix (§10.3). */}
				{hasFix && complaint.verdict !== "ok" ? (
					<a
						href={`#${complaint.fixIds[0]}`}
						className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-medium hover:bg-slate-50"
					>
						<Wrench className="h-3.5 w-3.5" /> How to fix this ↓
					</a>
				) : null}
				<Link
					to="/domains/$id/complaints/$code"
					params={{ id: domainId, code: complaint.code }}
					className="text-xs text-[var(--edh-primary)] hover:underline"
				>
					Explain this in full →
				</Link>
			</div>

			{open ? <EvidenceTable sources={complaint.sources} /> : null}
		</article>
	);
}

/** The per-source evidence table — the jargon lives HERE, not in the card title (§10.2). */
export function EvidenceTable({
	sources,
	limit = 50,
}: {
	sources: ComplaintSource[];
	limit?: number;
}) {
	const [showAll, setShowAll] = useState(false);
	const rows = showAll ? sources : sources.slice(0, limit);
	return (
		<div className="mt-3">
			<div className="overflow-x-auto rounded-lg border border-[var(--edh-border)]">
				<table className="min-w-full text-left text-xs">
					<thead className="bg-slate-50 text-[var(--edh-muted)]">
						<tr>
							<th className="px-3 py-2 font-medium">Source IP</th>
							<th className="px-3 py-2 font-medium">Msgs</th>
							<th className="px-3 py-2 font-medium">SPF</th>
							<th className="px-3 py-2 font-medium">DKIM (d= / s=)</th>
							<th className="px-3 py-2 font-medium">Disposition</th>
							<th className="px-3 py-2 font-medium">Target</th>
							<th className="px-3 py-2 font-medium">Reporters</th>
						</tr>
					</thead>
					<tbody>
						{rows.map((s) => (
							<tr
								key={`${s.sourceIp}-${s.dkimSelector}-${s.spfDomain}-${s.disposition}`}
								className="border-t border-[var(--edh-border)]"
							>
								<td className="px-3 py-2 font-mono">{s.sourceIp}</td>
								<td className="px-3 py-2 tabular-nums">
									{s.count.toLocaleString()}
								</td>
								<td className="px-3 py-2">
									<Aligned ok={s.spfAligned} />{" "}
									<span className="font-mono">
										{s.spfResult}
										{s.spfDomain ? ` (${s.spfDomain})` : ""}
									</span>
								</td>
								<td className="px-3 py-2">
									<Aligned ok={s.dkimAligned} />{" "}
									<span className="font-mono">
										{s.dkimResult}
										{s.dkimDomain
											? ` (${s.dkimDomain}${s.dkimSelector ? ` / ${s.dkimSelector}` : ""})`
											: ""}
									</span>
								</td>
								<td className="px-3 py-2">
									<span
										className={cn(
											"rounded px-1.5 py-0.5",
											s.disposition === "reject"
												? "bg-red-100 text-red-800"
												: s.disposition === "quarantine"
													? "bg-amber-100 text-amber-800"
													: "bg-slate-100 text-slate-600",
										)}
									>
										{s.disposition}
									</span>
									{s.reasons.length > 0 ? (
										<span className="ml-1 text-[var(--edh-muted)]">
											{s.reasons
												.map((r) => r.comment || r.type)
												.join(", ")}
										</span>
									) : null}
								</td>
								<td className="px-3 py-2">{s.envelopeTo ?? "—"}</td>
								<td className="px-3 py-2">{s.reporters.join(", ")}</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
			{sources.length > limit ? (
				<button
					type="button"
					onClick={() => setShowAll((v) => !v)}
					className="mt-2 text-xs text-[var(--edh-primary)] hover:underline"
				>
					{showAll
						? "Show fewer"
						: `Show all ${sources.length.toLocaleString()} rows`}
				</button>
			) : null}
		</div>
	);
}

function Aligned({ ok }: { ok: boolean }) {
	return (
		<span className={ok ? "text-emerald-700" : "text-red-700"} title={ok ? "aligned" : "not aligned"}>
			{ok ? "✓" : "✕"}
		</span>
	);
}

// ─── Zone C — how to fix it (§10.3) ──────────────────────────────────────────────────────────────

export function ZoneC({ fixes }: { fixes: ComplaintFix[] }) {
	if (fixes.length === 0) {
		return (
			<section>
				<h2 className="mb-2 text-lg font-semibold">How to fix it</h2>
				<p className="text-sm text-[var(--edh-muted)]">
					Nothing to fix. Keep your policy enforcing and keep the reports
					flowing.
				</p>
			</section>
		);
	}
	return (
		<section>
			<h2 className="mb-1 text-lg font-semibold">How to fix it</h2>
			<p className="mb-4 text-sm text-[var(--edh-muted)]">
				Ordered by how much mail each step repairs.
			</p>
			<div className="space-y-4">
				{fixes.map((fix, i) => (
					<FixStep key={fix.id} fix={fix} index={i + 1} />
				))}
			</div>
		</section>
	);
}

const CIRCLED = ["①", "②", "③", "④", "⑤", "⑥", "⑦", "⑧", "⑨", "⑩"];

function FixStep({ fix, index }: { fix: ComplaintFix; index: number }) {
	return (
		<article
			id={fix.id}
			className="scroll-mt-6 rounded-xl border border-[var(--edh-border)] bg-[var(--edh-card)] p-4"
		>
			<div className="flex flex-wrap items-baseline justify-between gap-2">
				<h3 className="font-medium">
					<span className="mr-2 text-[var(--edh-muted)]">
						{CIRCLED[index - 1] ?? `${index}.`}
					</span>
					{fix.title}
				</h3>
				<span className="text-xs text-[var(--edh-muted)]">
					fixes {fix.appliesTo.join(", ")}
					{fix.messagesFixed > 0
						? ` · ${fix.messagesFixed.toLocaleString()} msgs`
						: ""}
				</span>
			</div>

			<ol className="mt-3 list-decimal space-y-1.5 pl-5 text-sm text-slate-700">
				{fix.steps.map((s) => (
					<li key={s}>{s}</li>
				))}
			</ol>

			{fix.records.map((r) => (
				<div
					key={`${r.name}-${r.type}`}
					className="mt-3 rounded-lg border border-[var(--edh-border)] bg-slate-50 p-3"
				>
					<div className="flex items-start justify-between gap-2">
						<code className="break-all font-mono text-xs">
							{r.name} {r.type} {r.value}
						</code>
						<CopyFixButton text={`${r.name} ${r.type} ${r.value}`} label="Copy" />
					</div>
					{r.note ? (
						<p className="mt-1 text-[11px] text-[var(--edh-muted)]">{r.note}</p>
					) : null}
				</div>
			))}

			{fix.verify.length > 0 ? (
				<div className="mt-3">
					<div className="mb-1 flex items-center gap-1 text-xs font-medium text-[var(--edh-muted)]">
						<Terminal className="h-3.5 w-3.5" /> Verify
					</div>
					{fix.verify.map((v) => (
						/*
             CopyFixButton inherits its text colour, so on a dark panel its label vanished. The
             verify block therefore uses the same light surface as the record block above.
            */
						<div
							key={v}
							className="mb-1 flex items-center justify-between gap-2 rounded-lg border border-[var(--edh-border)] bg-slate-100 px-3 py-2"
						>
							<code className="break-all font-mono text-xs text-slate-800">
								{v}
							</code>
							<CopyFixButton text={v} label="Copy" />
						</div>
					))}
				</div>
			) : null}
		</article>
	);
}

// ─── Empty state (§10.1) — never an error, never a green verdict ─────────────────────────────────

function EmptyState({ board }: { board: ComplaintBoard }) {
	return (
		<div className="rounded-xl border border-[var(--edh-border)] bg-[var(--edh-card)] p-6">
			<div className="flex items-center gap-2">
				<Inbox className="h-5 w-5 text-[var(--edh-muted)]" />
				<h2 className="text-lg font-semibold">No reports yet</h2>
			</div>
			<p className="mt-2 max-w-2xl text-sm text-slate-700">
				Mailbox providers start sending DMARC aggregate reports 24–72 hours after
				you publish a <code className="font-mono">rua=</code> address on{" "}
				<code className="font-mono">_dmarc.{board.domain}</code>. Until then
				there is nothing to read — this is not a problem, and it is not a clean
				bill of health either.
			</p>
			{!board.ingestionEnabled ? (
				<p className="mt-3 rounded-lg bg-amber-50 p-3 text-sm text-amber-900">
					Report ingestion is switched off in Settings → Admin, so reports would
					not be read even if they arrived.
				</p>
			) : null}
			<p className="mt-3 text-xs text-[var(--edh-muted)]">
				{board.ingest.reportsStored} report(s) stored ·{" "}
				{board.ingest.lastIngestAt
					? `last ingest ${new Date(board.ingest.lastIngestAt).toLocaleString()}`
					: "never ingested"}
			</p>
		</div>
	);
}

function pct(n: number, total: number): string {
	if (total === 0 || n === 0) return "0%";
	const v = Math.round((n / total) * 1000) / 10;
	// A real count must never render as a flat 0% — 4 of 8,978 is "<0.1%", not "none" (§10.5).
	return v < 0.1 ? "<0.1%" : `${v}%`;
}
