import { Link, useNavigate, useParams } from "@tanstack/react-router";
import {
	ArrowLeft,
	ChevronLeft,
	ChevronRight,
	Info,
	Loader2,
	RefreshCw,
	ShieldAlert,
	ShieldCheck,
	Star,
} from "lucide-react";
import { useEffect, useMemo } from "react";
import { useAuditResults, useAuditRun, useAuditRuns } from "@/api/audit";
import { useDomains } from "@/api/domains";
import { useIngestReports } from "@/api/reports";
import type { AuditResult, DmarcResults, DmarcTestRow } from "@/api/types";
import { CopyFixButton } from "@/components/CopyFixButton";
import { DmarcReportsSnapshotView } from "@/components/DmarcReportsSnapshotView";
import { RunHistoryStrip } from "@/components/RunHistoryStrip";
import { normalizeDmarcSection } from "@/lib/dmarc";
import {
	type DmarcCheckUnit,
	dmarcUnitByKey,
	dmarcUnitResult,
	type UnitResult,
} from "@/lib/dmarc-checks";
import { cn } from "@/lib/utils";
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext";

/**
 * The DMARC sub-test explainer page (pm/checks/dmarc.mdx §6.4) — the LOCKED five-block contract:
 * what this is / your current state / what it means / what you can do about it / run this check
 * now — followed by the unit-scoped run-history strip (§6.7) and the references footer. Serves
 * the canonical run-scoped route /domains/:id/runs/:runId/dmarc/check/:checkKey and the
 * newest-run alias /domains/:id/dmarc/check/:checkKey. Everything in block 2 renders from the
 * viewed run only — an older run stays a historical snapshot. An unknown :checkKey renders the
 * "No such sub-test" panel with a back link, never a blank screen.
 */
export function DmarcCheckPage() {
	const {
		id = "",
		runId,
		checkKey = "",
	} = useParams({ strict: false }) as {
		id?: string;
		runId?: string;
		checkKey?: string;
	};
	const { data: domains } = useDomains();
	const { data: results } = useAuditResults();
	const { data: allRuns } = useAuditRuns();
	const { data: historicalRun } = useAuditRun(runId);
	const runDomains = useScanRunner();
	const scanning = useScanProgress().some((s) => s.domainId === id);
	const ingest = useIngestReports(id);
	const navigate = useNavigate();

	const domain = (domains ?? []).find((d) => d.id === id);
	const name = domain?.name ?? id;
	const unit = dmarcUnitByKey(checkKey);

	const latest = (results ?? []).find((r) => r.domainId === id);
	const run = runId ? historicalRun : latest;

	// The domain's runs oldest → newest — the pager rail and the history strip (§6.2/§6.7).
	const domainRuns = useMemo(
		() =>
			(allRuns ?? [])
				.filter((r) => r.domainId === id)
				.sort((a, b) =>
					(a.startedAt ?? a.ranAt).localeCompare(b.startedAt ?? b.ranAt),
				),
		[allRuns, id],
	);
	const indexInRail = domainRuns.findIndex(
		(r) => r.runId && r.runId === run?.runId,
	);
	const effectiveIndex =
		indexInRail >= 0 ? indexInRail : !runId ? domainRuns.length - 1 : -1;
	const prevRun =
		effectiveIndex > 0 ? domainRuns[effectiveIndex - 1] : undefined;
	const nextRun =
		effectiveIndex >= 0 && effectiveIndex < domainRuns.length - 1
			? domainRuns[effectiveIndex + 1]
			: undefined;
	const isNewest =
		!runId || (effectiveIndex >= 0 && effectiveIndex === domainRuns.length - 1);

	// Paging swaps :runId exactly as on the category page (§6.3).
	const goToRun = (r: AuditResult | undefined): void => {
		if (r?.runId) {
			navigate({
				to: "/domains/$id/runs/$runId/dmarc/check/$checkKey",
				params: { id, runId: r.runId, checkKey },
			});
		}
	};

	// Block 5 / header Re-run (§6.5 v1): a full run for this domain; on completion the newest
	// alias of the SAME explainer resolves the fresh run automatically. The `reports` unit's
	// freshness is the ingestion job's, so its button triggers the ingestion poll instead.
	const isReportsUnit = unit?.sibling === "reports";
	const onRunNow = (): void => {
		if (isReportsUnit) {
			ingest.mutate();
			return;
		}
		runDomains([{ id, name }]);
		navigate({
			to: "/domains/$id/dmarc/check/$checkKey",
			params: { id, checkKey },
		});
	};

	// Keyboard: ←/→ steps the pager; `r` triggers Run this check now (§6.5) — input-field guarded.
	useEffect(() => {
		const onKey = (e: KeyboardEvent): void => {
			const target = e.target as HTMLElement | null;
			if (target && ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName))
				return;
			if (e.key === "ArrowLeft" && prevRun) goToRun(prevRun);
			if (e.key === "ArrowRight" && nextRun) goToRun(nextRun);
			if (e.key === "r" && !scanning) onRunNow();
		};
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	});

	const backToDmarc = (): void => {
		if (runId && run?.runId) {
			navigate({
				to: "/domains/$id/runs/$runId/dmarc",
				params: { id, runId: run.runId },
			});
		} else {
			navigate({ to: "/domains/$id/dmarc", params: { id } });
		}
	};

	// Unknown checkKey → the "No such sub-test" panel (§6.4 states), never a blank screen.
	if (!unit) {
		return (
			<div className="mx-auto max-w-3xl">
				<div className="rounded-lg border border-[var(--edh-border)] bg-white p-8 text-center">
					<p className="font-medium">No such sub-test</p>
					<p className="mt-1 text-sm text-slate-600">
						"{checkKey}" is not a DMARC sub-test unit for {name}.
					</p>
					<button
						type="button"
						onClick={backToDmarc}
						className="mt-3 inline-flex items-center gap-1 text-sm text-[var(--edh-primary)] underline"
					>
						<ArrowLeft className="h-4 w-4" /> Back to the run's DMARC page
					</button>
				</div>
			</div>
		);
	}

	const { record, tests } = normalizeDmarcSection(run?.results?.dmarc);
	const findings = (run?.findings ?? []).filter(
		(f) =>
			f.checkId === "dmarc" ||
			f.checkId === "arc" ||
			f.checkId === "dmarc.reports",
	);
	const result = run ? dmarcUnitResult(unit, tests, findings) : null;
	const unitTests = unitTestRows(unit, tests, findings);

	const busy = isReportsUnit ? ingest.isPending : scanning;

	return (
		<div className="mx-auto max-w-4xl">
			{/* Header row — reuses the category page's chrome (§6.4); back link → the run's DMARC page. */}
			<div className="mb-4 flex items-center justify-between">
				<button
					type="button"
					onClick={backToDmarc}
					className="inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
				>
					<ArrowLeft className="h-4 w-4" /> Back to DMARC
				</button>
				<button
					type="button"
					onClick={onRunNow}
					disabled={busy}
					className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
				>
					<RefreshCw className={busy ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
					Re-run
				</button>
			</div>

			<h1 className="text-2xl font-bold">{unit.title}</h1>
			<div className="mt-1 text-sm text-[var(--edh-muted)]">
				<span className="font-medium text-slate-900">{name}</span> · DMARC ›
				sub-test
			</div>

			{/* Run context strip (§6.4): timestamp, ‹ prev / next › pager, ★ newest, history chips. */}
			{run && (
				<div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-[var(--edh-muted)]">
					<span className="tabular-nums">
						Run {fmtStamp(run.startedAt ?? run.ranAt)}
					</span>
					<span>·</span>
					<button
						type="button"
						onClick={() => goToRun(prevRun)}
						disabled={!prevRun}
						aria-label="Previous run"
						className="inline-flex items-center gap-0.5 rounded border border-[var(--edh-border)] px-2 py-0.5 text-xs hover:bg-slate-50 disabled:opacity-40"
					>
						<ChevronLeft className="h-3.5 w-3.5" /> prev
					</button>
					<button
						type="button"
						onClick={() => goToRun(nextRun)}
						disabled={!nextRun}
						aria-label="Next run"
						className="inline-flex items-center gap-0.5 rounded border border-[var(--edh-border)] px-2 py-0.5 text-xs hover:bg-slate-50 disabled:opacity-40"
					>
						next <ChevronRight className="h-3.5 w-3.5" />
					</button>
					{isNewest && (
						<span className="inline-flex items-center gap-1 rounded bg-amber-50 px-1.5 py-0.5 text-xs font-medium text-amber-700">
							<Star className="h-3 w-3" /> newest
						</span>
					)}
					<span>·</span>
					<UnitHistoryStrip
						unit={unit}
						runs={domainRuns}
						currentRunId={run.runId}
						goToRun={goToRun}
						domainId={id}
					/>
				</div>
			)}

			{/* Block 1 — What this is. The concept never disappears, whatever this run observed. */}
			<Block title="What this is">
				{unit.whatItIs.map((p) => (
					<p
						key={p.slice(0, 32)}
						className="text-sm leading-relaxed text-slate-700"
					>
						{p.replaceAll("<domain>", name)}
					</p>
				))}
			</Block>

			{/* Block 2 — Your current state: this run's live status for the unit. */}
			<Block
				title="Your current state"
				right={<ResultChip result={run ? result : undefined} />}
			>
				{!run ? (
					<p className="text-sm text-slate-600">
						No audit yet — run one to measure this unit.
					</p>
				) : result === null ? (
					<p className="text-sm text-slate-600">
						Not measured in this run — none of this unit's tests fired
						{unit.sibling === "reports"
							? " (no aggregate reports have been ingested for this domain yet)"
							: unit.sibling === "arc"
								? " (the ARC checker produced no rows in this run)"
								: record && !record.record_found
									? " (there is no DMARC record to evaluate — fix record presence first)"
									: ""}
						.
					</p>
				) : (
					<ul className="space-y-2">
						{unitTests.map((t) => (
							<li
								key={t.id + t.title}
								id={`finding-${t.id}`}
								className="scroll-mt-20 rounded-md border border-[var(--edh-border)] bg-white p-2"
							>
								<div className="flex flex-wrap items-center gap-2">
									<ResultChip result={t.result} small />
									<span className="font-mono text-xs text-[var(--edh-muted)]">
										{t.id}
									</span>
									<span className="text-sm font-medium">{t.title}</span>
								</div>
								{t.detail && (
									<p className="mt-1 text-sm text-slate-600">{t.detail}</p>
								)}
								{t.evidence && (
									<p className="mt-1 break-all rounded bg-slate-50 p-1.5 font-mono text-xs text-slate-600">
										observed: {t.evidence}
									</p>
								)}
								{t.dns_value_expected && (
									<p className="mt-1 break-all rounded bg-slate-50 p-1.5 font-mono text-xs text-slate-600">
										expected: {t.dns_value_expected}
									</p>
								)}
							</li>
						))}
					</ul>
				)}
				{run && record?.raw_record && (
					<div className="mt-3">
						<p className="mb-1 text-xs font-medium uppercase text-[var(--edh-muted)]">
							Raw record
							{unit.tags.length > 0 ? " — this unit's tags highlighted" : ""}
						</p>
						<p className="break-all rounded-md bg-slate-50 p-2 font-mono text-xs text-slate-700">
							<HighlightedRecord raw={record.raw_record} tags={unit.tags} />
						</p>
					</div>
				)}
				{run && record && unit.tags.length > 0 && (
					<ScopedFieldTable unit={unit} record={record} />
				)}
				{/* The `reports` unit's scoped block-2 tables (pm/emails.mdx §16.2 / AC #19): the
            run-scoped aggregate breakdown + expandable per-source-IP table from the §16.3 snapshot. */}
				{run && isReportsUnit && (
					<DmarcReportsSnapshotView snapshot={run.results?.["dmarc.reports"]} />
				)}
			</Block>

			{/* Block 3 — What it means, keyed to the current result. */}
			<Block title="What it means">
				<p className="text-sm leading-relaxed text-slate-700">
					{(result === "fail" || result === "warn"
						? unit.meaningFail
						: unit.meaningPass
					).replaceAll("<domain>", name)}
				</p>
			</Block>

			{/* Block 4 — What you can do about it: copy-pasteable fixes; healthy collapses to one line. */}
			<Block title="What you can do about it">
				{result === "pass" ? (
					<>
						<p className="text-sm text-slate-700">
							Nothing to do — keep it this way.
						</p>
						<ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-[var(--edh-muted)]">
							{unit.fixSteps.map((s) => (
								<li key={s.slice(0, 32)}>{s.replaceAll("<domain>", name)}</li>
							))}
						</ul>
					</>
				) : (
					<ol className="list-decimal space-y-2 pl-5 text-sm text-slate-700">
						{/* Prerequisite/per-test fixes first (this run's failing rows carry exact records). */}
						{unitTests
							.filter((t) => t.fix && t.result !== "pass")
							.map((t) => (
								<li key={`fix-${t.id}-${t.title}`}>
									<span className="align-middle">{t.fix}</span>{" "}
									<CopyFixButton
										text={t.dns_value_expected ?? t.fix ?? ""}
										label="Copy"
									/>
								</li>
							))}
						{unit.fixSteps.map((s) => (
							<li key={s.slice(0, 32)}>{s.replaceAll("<domain>", name)}</li>
						))}
					</ol>
				)}
			</Block>

			{/* Block 5 — Run this check now (§6.5): the scoped re-run affordance. */}
			<Block title="Run this check now">
				<div className="flex items-center justify-between gap-3">
					<p className="text-sm text-slate-600">
						{isReportsUnit
							? `Polls the report mailbox for newly arrived aggregate reports for ${name}.`
							: `Re-runs all checks for ${name} and refreshes this page with the new run. (Keyboard: r)`}
					</p>
					<button
						type="button"
						onClick={onRunNow}
						disabled={busy}
						title={
							isReportsUnit
								? "Check for new reports"
								: `Re-runs all checks for ${name}`
						}
						className="inline-flex shrink-0 items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
					>
						{busy ? (
							<Loader2 className="h-4 w-4 animate-spin" />
						) : (
							<RefreshCw className="h-4 w-4" />
						)}
						{isReportsUnit ? "Check for new reports" : "Run check"}
					</button>
				</div>
				{isReportsUnit && ingest.isError && (
					<p className="mt-2 text-sm text-red-600">
						The ingestion poll failed — try again.
					</p>
				)}
			</Block>

			{/* Run-history strip scoped to this unit (§6.7): did my fix work? when did this regress? */}
			{domainRuns.length > 0 && (
				<Block title="History">
					<div className="flex items-center gap-2 text-xs text-[var(--edh-muted)]">
						<UnitHistoryStrip
							unit={unit}
							runs={domainRuns}
							currentRunId={run?.runId}
							goToRun={goToRun}
							domainId={id}
						/>
						<span>
							this sub-test, last 10 runs — click a chip to view that run
						</span>
					</div>
				</Block>
			)}

			{/* References footer (§6.4): the only external navigation on the page; new tabs. */}
			<Block title="References">
				<ul className="list-disc space-y-1 pl-5 text-sm">
					{unit.references.map((ref) => (
						<li key={ref.href}>
							<a
								href={ref.href}
								target="_blank"
								rel="noreferrer"
								className="text-[var(--edh-primary)] underline"
							>
								{ref.label}
							</a>
						</li>
					))}
				</ul>
			</Block>
		</div>
	);
}

/** The unit's §5 tests[] rows in this run (falling back to findings for pre-tests[] runs). */
function unitTestRows(
	unit: DmarcCheckUnit,
	tests: DmarcTestRow[],
	findings: {
		id: string;
		title: string;
		severity: string;
		detail?: string;
		evidence?: string;
		remediation?: string;
	}[],
): DmarcTestRow[] {
	const owns = (id: string): boolean =>
		unit.findingIds.includes(id) ||
		(unit.prefixIds ?? []).some(
			(p) => id === p.replace(/\.$/, "") || id.startsWith(p),
		);
	const fromTests = tests.filter((t) => owns(t.id));
	if (fromTests.length > 0) return fromTests;
	const sevToResult: Record<string, DmarcTestRow["result"]> = {
		ok: "pass",
		info: "info",
		warning: "warn",
		critical: "fail",
	};
	return findings
		.filter((f) => owns(f.id))
		.map((f) => ({
			id: f.id,
			title: f.title,
			result: sevToResult[f.severity] ?? "info",
			...(f.detail ? { detail: f.detail } : {}),
			...(f.evidence ? { evidence: f.evidence } : {}),
			...(f.remediation ? { fix: f.remediation } : {}),
		}));
}

/** The unit-scoped §6.7 strip: this unit's result per run, gray when not measured in that run. */
function UnitHistoryStrip({
	unit,
	runs,
	currentRunId,
	goToRun,
	domainId,
}: {
	unit: DmarcCheckUnit;
	runs: AuditResult[];
	currentRunId?: string;
	goToRun: (run: AuditResult) => void;
	domainId: string;
}) {
	const resultFor = (r: AuditResult): UnitResult | null => {
		const { tests } = normalizeDmarcSection(r.results?.dmarc);
		const fs = (r.findings ?? []).filter(
			(f) =>
				f.checkId === "dmarc" ||
				f.checkId === "arc" ||
				f.checkId === "dmarc.reports",
		);
		return dmarcUnitResult(unit, tests, fs);
	};
	return (
		<RunHistoryStrip
			runs={runs}
			currentRunId={currentRunId}
			resultFor={resultFor}
			deltaFor={(r, prev) => {
				if (!prev) return null;
				const a = resultFor(prev) ?? "not measured";
				const b = resultFor(r) ?? "not measured";
				return a === b ? null : `${a} → ${b}`;
			}}
			onSelect={goToRun}
			overflow={
				<Link
					to="/domains/$id"
					params={{ id: domainId }}
					title="All runs for this domain"
					className="px-0.5 text-xs text-[var(--edh-muted)] hover:text-slate-700"
				>
					…
				</Link>
			}
			ariaLabel={`${unit.title} — result across the last 10 runs`}
		/>
	);
}

/** The block-2 status/severity chip — same colors as the Dashboard cells (§6.4). */
function ResultChip({
	result,
	small,
}: {
	result?: UnitResult | null;
	small?: boolean;
}) {
	const style: Record<
		string,
		{ cls: string; label: string; icon: React.ReactNode }
	> = {
		pass: {
			cls: "bg-emerald-50 text-emerald-700",
			label: "PASS",
			icon: <ShieldCheck className={small ? "h-3.5 w-3.5" : "h-4 w-4"} />,
		},
		info: {
			cls: "bg-slate-100 text-slate-600",
			label: "INFO",
			icon: <Info className={small ? "h-3.5 w-3.5" : "h-4 w-4"} />,
		},
		warn: {
			cls: "bg-amber-50 text-amber-700",
			label: "WARN",
			icon: <ShieldAlert className={small ? "h-3.5 w-3.5" : "h-4 w-4"} />,
		},
		fail: {
			cls: "bg-red-50 text-red-700",
			label: "FAIL — critical",
			icon: <ShieldAlert className={small ? "h-3.5 w-3.5" : "h-4 w-4"} />,
		},
	};
	const s = result ? style[result] : undefined;
	return (
		<span
			className={cn(
				"inline-flex items-center gap-1 rounded-full font-semibold uppercase",
				small ? "px-2 py-0.5 text-[10px]" : "px-3 py-1 text-xs",
				s ? s.cls : "bg-slate-100 text-slate-500",
			)}
		>
			{s?.icon}
			{s ? s.label : "not measured"}
		</span>
	);
}

/** The raw record with the unit's owned tags visually highlighted (§6.4 block 2). */
function HighlightedRecord({ raw, tags }: { raw: string; tags: string[] }) {
	if (tags.length === 0) return <>{raw}</>;
	const owned = new Set(tags.map((t) => t.toLowerCase()));
	return (
		<>
			{raw.split(";").map((token, i) => {
				const name = token.split("=")[0]?.trim().toLowerCase() ?? "";
				const hit = owned.has(name);
				return (
					<span key={`${token}-${String(i)}`}>
						{i > 0 && ";"}
						<span
							className={
								hit
									? "rounded bg-amber-100 font-semibold text-amber-900"
									: undefined
							}
						>
							{token}
						</span>
					</span>
				);
			})}
		</>
	);
}

/** Field meanings for the block-2 scoped parsed-field table (only the fields this unit reads). */
const FIELD_META: Record<
	string,
	{ meaning: string; fallback?: (r: DmarcResults) => string }
> = {
	v: { meaning: "Version — must be DMARC1" },
	p: { meaning: "Policy for the domain: none / quarantine / reject" },
	sp: {
		meaning: "Policy for subdomains",
		fallback: (r) => `${r.policy ?? "—"} (inherits p)`,
	},
	np: {
		meaning: "Policy for non-existent subdomains (RFC 9989)",
		fallback: (r) => `${r.subdomain_policy ?? "—"} (inherits sp)`,
	},
	t: {
		meaning: "Testing flag — t=y disables enforcement",
		fallback: () => "n (enforced)",
	},
	adkim: {
		meaning: "DKIM alignment: r relaxed / s strict",
		fallback: () => "r (relaxed)",
	},
	aspf: {
		meaning: "SPF alignment: r relaxed / s strict",
		fallback: () => "r (relaxed)",
	},
	pct: {
		meaning: "Percent of mail the policy applies to (obsolete)",
		fallback: () => "100",
	},
	rua: { meaning: "Where aggregate reports are sent" },
	ruf: { meaning: "Where failure reports are sent (optional)" },
	fo: {
		meaning: "Failure-report options (1 = either mechanism fails)",
		fallback: () => "0",
	},
	ri: {
		meaning: "Aggregate report interval, seconds (obsolete)",
		fallback: () => "86400",
	},
	rf: { meaning: "Failure-report format (obsolete)", fallback: () => "afrf" },
};

/** Block 2's scoped parsed-field table: published value, grayed effective default, meaning. */
function ScopedFieldTable({
	unit,
	record,
}: {
	unit: DmarcCheckUnit;
	record: DmarcResults;
}) {
	return (
		<table className="mt-3 w-full text-sm">
			<tbody>
				{unit.tags.map((tag) => {
					const meta = FIELD_META[tag];
					const published = record.parsed?.[tag];
					const value = published ?? meta?.fallback?.(record) ?? "—";
					return (
						<tr key={tag} className="border-t border-[var(--edh-border)]">
							<td className="py-1.5 pr-3 align-top font-mono text-xs font-semibold">
								{tag}
							</td>
							<td
								className={cn(
									"py-1.5 pr-3 align-top font-mono text-xs",
									!published && "text-slate-400",
								)}
							>
								{value}
							</td>
							<td className="py-1.5 align-top text-xs text-slate-500">
								{meta?.meaning ?? ""}
							</td>
						</tr>
					);
				})}
			</tbody>
		</table>
	);
}

function fmtStamp(iso: string): string {
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) return iso;
	const p = (n: number): string => String(n).padStart(2, "0");
	return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function Block({
	title,
	right,
	children,
}: {
	title: string;
	right?: React.ReactNode;
	children: React.ReactNode;
}) {
	return (
		<section className="mt-6 rounded-lg border border-[var(--edh-border)] bg-white p-4">
			<div className="mb-2 flex items-center justify-between">
				<h2 className="font-semibold uppercase tracking-wide text-sm">
					{title}
				</h2>
				{right}
			</div>
			{children}
		</section>
	);
}
