import { Link, useNavigate, useParams } from "@tanstack/react-router";
import {
	ArrowLeft,
	ChevronDown,
	ChevronLeft,
	ChevronRight,
	RefreshCw,
	ShieldAlert,
	ShieldCheck,
	Star,
} from "lucide-react";
import { type ReactNode, useEffect, useMemo, useState } from "react";
import { useAuditResults, useAuditRun, useAuditRuns } from "@/api/audit";
import { useDomains } from "@/api/domains";
import type {
	AuditResult,
	DmarcResults,
	DmarcToolRun,
	Finding,
	Severity,
} from "@/api/types";
import { CopyFixButton } from "@/components/CopyFixButton";
import { RunHistoryStrip } from "@/components/RunHistoryStrip";
import { StatusCell } from "@/components/StatusCell";
import { TestResultsTable } from "@/components/TestResultsTable";
import { NEVER_CELL, rollupCategories } from "@/lib/categories";
import { normalizeDmarcSection } from "@/lib/dmarc";
import {
	DMARC_CHECK_UNITS,
	DMARC_TAG_TO_CHECK_KEY,
	dmarcBandOrder,
	dmarcUnitForFindingId,
	dmarcUnitResult,
	type UnitResult,
} from "@/lib/dmarc-checks";
import {
	matchArcProblemStates,
	matchDmarcbisProblemStates,
	matchProblemStates,
	problemStateById,
} from "@/lib/dmarc-problems";
import { cn } from "@/lib/utils";
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext";

/** Tag meanings for the parsed-record table (pm/checks/dmarc.mdx §6.2). Order = display order. */
const TAG_META: {
	tag: string;
	meaning: string;
	fallback?: (r: DmarcResults) => string;
	obsolete?: boolean;
}[] = [
	{ tag: "v", meaning: "Version — must be DMARC1" },
	{ tag: "p", meaning: "Policy for the domain: none / quarantine / reject" },
	{
		tag: "sp",
		meaning: "Policy for subdomains",
		fallback: (r) => `${r.policy ?? "—"} (inherits p)`,
	},
	{
		tag: "np",
		meaning: "Policy for non-existent subdomains (RFC 9989)",
		fallback: (r) => `${r.subdomain_policy ?? "—"} (inherits sp)`,
	},
	{
		tag: "adkim",
		meaning: "DKIM alignment: r relaxed / s strict",
		fallback: () => "r (relaxed)",
	},
	{
		tag: "aspf",
		meaning: "SPF alignment: r relaxed / s strict",
		fallback: () => "r (relaxed)",
	},
	{ tag: "rua", meaning: "Where aggregate reports are sent" },
	{ tag: "ruf", meaning: "Where failure reports are sent (optional)" },
	{
		tag: "fo",
		meaning: "Failure-report options (1 = either mechanism fails)",
		fallback: () => "0",
	},
	{ tag: "t", meaning: "Testing flag (RFC 9989) — t=y disables enforcement" },
	{ tag: "pct", meaning: "Percent of mail policy applies to", obsolete: true },
	{ tag: "ri", meaning: "Aggregate report interval (seconds)", obsolete: true },
	{ tag: "rf", meaning: "Report format", obsolete: true },
];

/** The run context strip's timestamp format (pm/checks/dmarc.mdx §6.2: YYYY-MM-DD HH:mm). */
function fmtRunStamp(iso: string): string {
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) return iso;
	const p = (n: number): string => String(n).padStart(2, "0");
	return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

const SEVERITY_TO_RESULT: Record<Severity, UnitResult> = {
	ok: "pass",
	info: "info",
	warning: "warn",
	critical: "fail",
};
const RESULT_RANK: Record<UnitResult, number> = {
	pass: 0,
	info: 1,
	warn: 2,
	fail: 3,
};

/** The DMARC (+ARC + DMARCbis companions) findings of one run — the band/history data source. */
function dmarcCategoryFindings(run: AuditResult): Finding[] {
	return (run.findings ?? []).filter(
		(f) =>
			f.checkId === "dmarc" ||
			f.checkId === "arc" ||
			f.checkId === "dmarcbis" ||
			f.checkId === "dmarc.reports",
	);
}

/**
 * The category's worst result in one run (pm/checks/dmarc.mdx §6.7 category scope): the worst
 * severity across every DMARC finding in that run; null = the category was not measured.
 */
function categoryResultFor(run: AuditResult): UnitResult | null {
	const fs = dmarcCategoryFindings(run);
	if (fs.length === 0) return null;
	let worst: UnitResult = "pass";
	for (const f of fs) {
		const r = SEVERITY_TO_RESULT[f.severity];
		if (RESULT_RANK[r] > RESULT_RANK[worst]) worst = r;
	}
	return worst;
}

/** Small colored status chip for the sub-tests band rows (§6.3). */
function BandChip({ result }: { result: UnitResult | null }) {
	const meta: Record<UnitResult, { cls: string; icon: ReactNode }> = {
		pass: {
			cls: "bg-emerald-50 text-emerald-700",
			icon: <ShieldCheck className="h-3.5 w-3.5" />,
		},
		info: {
			cls: "bg-slate-100 text-slate-600",
			icon: <ShieldCheck className="h-3.5 w-3.5" />,
		},
		warn: {
			cls: "bg-amber-50 text-amber-700",
			icon: <ShieldAlert className="h-3.5 w-3.5" />,
		},
		fail: {
			cls: "bg-red-50 text-red-700",
			icon: <ShieldAlert className="h-3.5 w-3.5" />,
		},
	};
	const m = result ? meta[result] : undefined;
	return (
		<span
			className={cn(
				"inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase",
				m ? m.cls : "bg-slate-100 text-slate-500",
			)}
		>
			{m?.icon}
			{result ?? "—"}
		</span>
	);
}

/**
 * The sub-tests band (pm/checks/dmarc.mdx §6.2 item 2 / §6.3): the clickable directory of every
 * unit in the DMARC category — all 11 dmarc units plus the sibling ARC and Ingested-reports rows.
 * Fail-first order (fail → warn → info → not-measured → pass, then registry order). Each row is a
 * whole-row click target into the unit's explainer, carrying a small ⟳ "run this check now" icon
 * button (§6.5) before the chevron.
 */
function SubTestsBand({
	result,
	goToCheck,
	onRunNow,
	scanning,
}: {
	result: AuditResult;
	goToCheck: (checkKey: string) => void;
	onRunNow: () => void;
	scanning: boolean;
}) {
	const { tests } = normalizeDmarcSection(result.results?.dmarc);
	const findings = dmarcCategoryFindings(result);
	const rows = DMARC_CHECK_UNITS.map((unit) => ({
		unit,
		result: dmarcUnitResult(unit, tests, findings),
	})).sort((a, b) => dmarcBandOrder(a.result) - dmarcBandOrder(b.result));
	return (
		<section className="mt-4">
			<h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-[var(--edh-muted)]">
				Sub-tests
			</h2>
			<div className="grid gap-2 sm:grid-cols-2">
				{rows.map(({ unit, result: r }) => (
					<div
						key={unit.key}
						className="group flex items-center gap-2 rounded-lg border border-[var(--edh-border)] bg-white p-2 hover:border-[var(--edh-primary)]"
					>
						<button
							type="button"
							onClick={() => goToCheck(unit.key)}
							className="flex min-w-0 flex-1 items-center gap-2 text-left"
						>
							<BandChip result={r} />
							<span className="min-w-0 flex-1">
								<span className="block truncate text-sm font-medium">
									{unit.title}
									{unit.sibling && (
										<span className="ml-1 text-[10px] uppercase text-[var(--edh-muted)]">
											(sibling)
										</span>
									)}
								</span>
								<span className="block truncate text-xs text-slate-500">
									{unit.oneLiner}
								</span>
							</span>
						</button>
						{!unit.sibling && (
							<button
								type="button"
								onClick={onRunNow}
								disabled={scanning}
								aria-label={`Run ${unit.title} now`}
								title="Run this check now"
								className="shrink-0 rounded p-1 text-[var(--edh-muted)] opacity-0 hover:bg-slate-100 disabled:opacity-50 group-hover:opacity-100"
							>
								<RefreshCw
									className={
										scanning ? "h-3.5 w-3.5 animate-spin" : "h-3.5 w-3.5"
									}
								/>
							</button>
						)}
						<ChevronRight className="h-4 w-4 shrink-0 text-[var(--edh-muted)] group-hover:text-[var(--edh-primary)]" />
					</div>
				))}
			</div>
		</section>
	);
}

/**
 * The full-page DMARC view — one category of ONE run (pm/checks/dmarc.mdx §6.2/§7). Serves the
 * canonical run-scoped route /domains/:id/runs/:runId/dmarc AND the newest-run alias
 * /domains/:id/dmarc. Renders, top to bottom: header + run context strip (timestamp, ‹ prev /
 * next › pager, ★ newest badge), the policy ladder, the raw + parsed record, report-destination
 * authorization, the fail-first test-results table, matched problem-state cards, the optional
 * suggested-record builder, and the collapsed tool-runs provenance footer. An older run is a
 * historical snapshot — every band renders from that run's data, never silently the latest.
 */
export function DmarcPage() {
	const { id = "", runId } = useParams({ strict: false }) as {
		id?: string;
		runId?: string;
	};
	const { data: domains } = useDomains();
	const { data: results } = useAuditResults();
	const { data: allRuns } = useAuditRuns();
	const { data: historicalRun } = useAuditRun(runId);
	const runDomains = useScanRunner();
	const scanning = useScanProgress().some((s) => s.domainId === id);
	const navigate = useNavigate();

	const domain = (domains ?? []).find((d) => d.id === id);
	const latest = (results ?? []).find((r) => r.domainId === id);
	const result = runId ? historicalRun : latest;

	// This domain's runs in startedAt order (oldest → newest) — the ‹ prev / next › pager rail.
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
		(r) => r.runId && r.runId === result?.runId,
	);
	const effectiveIndex =
		indexInRail >= 0 ? indexInRail : !runId ? domainRuns.length - 1 : -1;
	const prevRun =
		effectiveIndex > 0 ? domainRuns[effectiveIndex - 1] : undefined;
	const nextRun =
		effectiveIndex >= 0 && effectiveIndex < domainRuns.length - 1
			? domainRuns[effectiveIndex + 1]
			: undefined;
	// The alias route always shows the newest indicator (pm/checks/dmarc.mdx §6.2).
	const isNewest =
		!runId || (effectiveIndex >= 0 && effectiveIndex === domainRuns.length - 1);

	const goToRun = (r: AuditResult | undefined): void => {
		if (r?.runId) {
			navigate({
				to: "/domains/$id/runs/$runId/dmarc",
				params: { id, runId: r.runId },
			});
		}
	};

	// Deep-link to a sub-test explainer (pm/checks/dmarc.mdx §6.3), staying run-scoped when a
	// specific run is being viewed so the user never loses run context (§6.4).
	const goToCheck = (checkKey: string): void => {
		if (runId && result?.runId) {
			navigate({
				to: "/domains/$id/runs/$runId/dmarc/check/$checkKey",
				params: { id, runId: result.runId, checkKey },
			});
		} else {
			navigate({
				to: "/domains/$id/dmarc/check/$checkKey",
				params: { id, checkKey },
			});
		}
	};

	// Keyboard ←/→ steps the pager (pm/checks/dmarc.mdx §7), ignoring keystrokes inside inputs.
	useEffect(() => {
		const onKey = (e: KeyboardEvent): void => {
			const target = e.target as HTMLElement | null;
			if (target && ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName))
				return;
			if (e.key === "ArrowLeft" && prevRun) goToRun(prevRun);
			if (e.key === "ArrowRight" && nextRun) goToRun(nextRun);
		};
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	});

	const findings = (result?.findings ?? []).filter(
		(f) => f.checkId === "dmarc",
	);
	const {
		record: dmarc,
		toolRuns,
		tests,
		problemStates,
	} = normalizeDmarcSection(result?.results?.dmarc);
	// Expected DNS value per test id (§6.2 item 4) — from the §5 tests[] rows' dns_value_expected.
	const expectedById = new Map(
		tests
			.filter((t): t is typeof t & { dns_value_expected: string } =>
				Boolean(t.dns_value_expected),
			)
			.map((t) => [t.id, t.dns_value_expected]),
	);
	// Pass the structured results too so the cell label is the policy level (§6.1).
	const cell =
		rollupCategories(result?.findings, result?.results).dmarc ?? NEVER_CELL;

	// Problem cards: prefer the backend-derived §9 ids; fall back to finding-id matching for runs
	// persisted before the backend derivation existed. Matched ARC-nn cards (the advisory companion,
	// pm/checks/arc.mdx §10) append AFTER the PS-nn cards, same card anatomy, same drill-down route.
	const dmarcProblems = problemStates
		? problemStates
				.map((psId) => problemStateById(psId))
				.filter((ps): ps is NonNullable<typeof ps> => ps !== undefined)
		: matchProblemStates(findings);
	const problems = [
		...dmarcProblems,
		...matchArcProblemStates(
			(result?.findings ?? []).filter((f) => f.checkId === "arc"),
		),
		// DMARCbis-nn conformance cards (pm/checks/dmarcbis.mdx §10) append after ARC-nn, same
		// anatomy + drill-down route; matched from this run's dmarcbis.* findings.
		...matchDmarcbisProblemStates(result?.findings ?? []),
	];

	// Re-run (pm/checks/dmarc.mdx §6.2): starts a NEW run for just this domain; the alias route then
	// shows the new run once the scan lands, so navigate there when viewing an older snapshot.
	const onRunAgain = (): void => {
		runDomains([{ id, name: domain?.name ?? id }]);
		if (runId) navigate({ to: "/domains/$id/dmarc", params: { id } });
	};

	return (
		<div className="mx-auto max-w-5xl">
			<div className="mb-4 flex items-center justify-between">
				<button
					type="button"
					onClick={() =>
						runId && result?.runId
							? navigate({
									to: "/domains/$id/runs/$runId",
									params: { id, runId: result.runId },
								})
							: navigate({ to: "/domains/$id", params: { id } })
					}
					className="inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
				>
					<ArrowLeft className="h-4 w-4" /> Back to this run's report
				</button>
				<button
					type="button"
					onClick={onRunAgain}
					disabled={scanning}
					className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
				>
					<RefreshCw
						className={scanning ? "h-4 w-4 animate-spin" : "h-4 w-4"}
					/>
					Re-run
				</button>
			</div>

			<h1 className="text-2xl font-bold">DMARC</h1>
			<div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-[var(--edh-muted)]">
				<span className="font-medium text-slate-900">{domain?.name ?? id}</span>
				<span className="w-32">
					<StatusCell status={cell} />
				</span>
			</div>

			{/* Run context strip (pm/checks/dmarc.mdx §6.2/§7): pins the page to ONE run. */}
			{result && (
				<div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-[var(--edh-muted)]">
					<span className="tabular-nums">
						Run {fmtRunStamp(result.startedAt ?? result.ranAt)}
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
					{domainRuns.length > 0 && (
						<>
							<span>·</span>
							<RunHistoryStrip
								runs={domainRuns}
								currentRunId={result?.runId}
								resultFor={categoryResultFor}
								deltaFor={(r, prev) => {
									if (!prev) return null;
									const a = categoryResultFor(prev) ?? "not measured";
									const b = categoryResultFor(r) ?? "not measured";
									return a === b ? null : `${a} → ${b}`;
								}}
								onSelect={goToRun}
								overflow={
									<Link
										to="/domains/$id"
										params={{ id }}
										title="All runs for this domain"
										className="px-0.5 text-xs text-[var(--edh-muted)] hover:text-slate-700"
									>
										…
									</Link>
								}
								ariaLabel="DMARC category result across the last 10 runs"
							/>
						</>
					)}
				</div>
			)}

			{!result ? (
				<div className="mt-6 rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center">
					<p className="text-slate-600">No audit yet — run one.</p>
					<button
						type="button"
						onClick={onRunAgain}
						className="mt-2 inline-flex items-center gap-2 text-[var(--edh-primary)] underline"
					>
						Run checks
					</button>
				</div>
			) : (
				<>
					<SubTestsBand
						result={result}
						goToCheck={goToCheck}
						onRunNow={onRunAgain}
						scanning={scanning}
					/>

					<PolicyLadder
						dmarc={dmarc}
						findings={findings}
						goToCheck={goToCheck}
					/>

					<div className="mt-4 grid gap-4 lg:grid-cols-2">
						<RecordPanel dmarc={dmarc} goToCheck={goToCheck} />
						<ReportDestinations
							dmarc={dmarc}
							domainName={domain?.name ?? id}
							goToCheck={goToCheck}
						/>
					</div>

					<TestResultsTable
						findings={findings}
						emptyText="No DMARC tests in this run."
						expectedById={expectedById}
						titleLinkFor={(findingId) => {
							const unit = dmarcUnitForFindingId(findingId);
							return unit ? () => goToCheck(unit.key) : undefined;
						}}
					/>

					{problems.length > 0 && (
						<section className="mt-6">
							<h2 className="mb-2 font-semibold">Problem states</h2>
							<div className="grid gap-3 sm:grid-cols-2">
								{problems.map((ps) => {
									const card = (
										<>
											<div className="flex items-center justify-between">
												<span className="text-xs font-semibold uppercase text-[var(--edh-muted)]">
													{ps.id}
												</span>
												<ChevronRight className="h-4 w-4 text-[var(--edh-muted)] group-hover:text-[var(--edh-primary)]" />
											</div>
											<div className="mt-1 font-medium">{ps.title}</div>
											<p className="mt-1 text-sm text-slate-600">{ps.hook}</p>
										</>
									);
									const className =
										"group rounded-lg border border-[var(--edh-border)] bg-white p-4 hover:border-[var(--edh-primary)]";
									// Drill-downs stay run-scoped so the user never loses run context (§7).
									return runId && result.runId ? (
										<Link
											key={ps.id}
											to="/domains/$id/runs/$runId/dmarc/$problemId"
											params={{ id, runId: result.runId, problemId: ps.id }}
											className={className}
										>
											{card}
										</Link>
									) : (
										<Link
											key={ps.id}
											to="/domains/$id/dmarc/$problemId"
											params={{ id, problemId: ps.id }}
											className={className}
										>
											{card}
										</Link>
									);
								})}
							</div>
						</section>
					)}

					<SuggestedRecordBuilder
						domainName={domain?.name ?? id}
						dmarc={dmarc}
					/>

					<ToolRunsFooter toolRuns={toolRuns} />
				</>
			)}
		</div>
	);
}

/**
 * The none → quarantine → reject progress visual with the recommended next step
 * (pm/checks/dmarc.mdx §8 state machine).
 */
function PolicyLadder({
	dmarc,
	findings,
	goToCheck,
}: {
	dmarc?: DmarcResults;
	findings: Finding[];
	goToCheck: (checkKey: string) => void;
}) {
	const steps = ["none", "quarantine", "reject"] as const;
	const policy = dmarc?.policy ?? null;
	const stepIndex = policy ? steps.indexOf(policy) : -1;
	const testing = dmarc?.parsed?.t?.toLowerCase() === "y";
	const failing = findings.filter(
		(f) => f.severity === "critical" || f.severity === "warning",
	);

	let verdict: string;
	let next: string;
	if (!dmarc?.record_found) {
		verdict = "No DMARC record — the domain is unprotected.";
		next = "Publish the starter record below to begin monitoring.";
	} else if (stepIndex === -1) {
		verdict = "The record is broken — receivers treat it as no policy.";
		next =
			"Fix the failing tests below first; a malformed record protects nothing.";
	} else if (testing) {
		verdict = `t=y testing mode — p=${policy} is advisory only.`;
		next = "Remove t=y once you are ready to enforce.";
	} else if (policy === "none") {
		verdict = "Monitoring only — spoofed mail is still delivered.";
		next =
			failing.length > 0
				? `Fix the ${failing.length} failing test${failing.length === 1 ? "" : "s"} below, then raise to p=quarantine.`
				: "Reports look clean? Raise to p=quarantine.";
	} else if (policy === "quarantine") {
		verdict = "Enforcing — failing mail is sent to spam folders.";
		next = "After ≥30 clean days, raise to p=reject.";
	} else {
		verdict = "Fully enforced — spoofed mail is rejected.";
		next = "Keep rua monitoring forever; tighten sp=/np= if not already set.";
	}

	return (
		<div className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
			<div className="flex items-center gap-2">
				{steps.map((s, i) => (
					<div key={s} className="flex items-center gap-2">
						{i > 0 && (
							<div
								className={cn(
									"h-0.5 w-10",
									i <= stepIndex ? "bg-[var(--edh-primary)]" : "bg-slate-200",
								)}
							/>
						)}
						<button
							type="button"
							onClick={() => goToCheck("policy")}
							title="What do these policy levels mean?"
							className={cn(
								"rounded-full px-3 py-1 text-xs font-medium hover:ring-2 hover:ring-[var(--edh-primary)]/40",
								i === stepIndex && !testing
									? "bg-[var(--edh-primary)] text-white"
									: i < stepIndex
										? "bg-slate-200 text-slate-700"
										: "border border-slate-300 text-slate-500",
							)}
						>
							{s}
						</button>
					</div>
				))}
			</div>
			<p className="mt-3 text-sm text-slate-700">{verdict}</p>
			<p className="mt-1 text-sm font-medium text-[var(--edh-primary)]">
				Next step: {next}
			</p>
		</div>
	);
}

/** Raw TXT record (copyable) over the parsed-tag table with grayed inherited defaults. */
function RecordPanel({
	dmarc,
	goToCheck,
}: {
	dmarc?: DmarcResults;
	goToCheck: (checkKey: string) => void;
}) {
	return (
		<section className="rounded-lg border border-[var(--edh-border)] bg-white p-4">
			<div className="mb-2 flex items-center justify-between">
				<h2 className="font-semibold">Published record</h2>
				{dmarc?.raw_record && (
					<CopyFixButton text={dmarc.raw_record} label="Copy" />
				)}
			</div>
			{!dmarc?.raw_record ? (
				<p className="text-sm text-slate-600">
					No record published
					{dmarc?.query_name ? ` at ${dmarc.query_name}` : ""}.
				</p>
			) : (
				<>
					<p className="break-all rounded-md bg-slate-50 p-2 font-mono text-xs text-slate-700">
						{dmarc.raw_record}
					</p>
					{dmarc.found_at && dmarc.found_at !== dmarc.query_name && (
						<p className="mt-1 text-xs text-[var(--edh-muted)]">
							Found at <span className="font-mono">{dmarc.found_at}</span>{" "}
							(tree-walk coverage from a parent domain).
						</p>
					)}
					<table className="mt-3 w-full text-sm">
						<tbody>
							{TAG_META.map((meta) => {
								const published = dmarc.parsed?.[meta.tag];
								const value =
									published ?? (meta.fallback ? meta.fallback(dmarc) : null);
								if (value === null || value === undefined) return null;
								const checkKey = DMARC_TAG_TO_CHECK_KEY[meta.tag];
								return (
									<tr
										key={meta.tag}
										onClick={checkKey ? () => goToCheck(checkKey) : undefined}
										className={cn(
											"border-t border-[var(--edh-border)]",
											checkKey && "cursor-pointer hover:bg-slate-50",
										)}
									>
										<td className="py-1.5 pr-3 align-top font-mono text-xs font-semibold">
											<span
												className={cn(
													meta.obsolete && "line-through opacity-60",
												)}
											>
												{meta.tag}
											</span>
											{meta.obsolete && (
												<span className="ml-1 rounded bg-slate-100 px-1 text-[10px] uppercase text-slate-500">
													obsolete
												</span>
											)}
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
											{meta.meaning}
										</td>
									</tr>
								);
							})}
						</tbody>
					</table>
				</>
			)}
		</section>
	);
}

/** One card per rua/ruf destination with its _report._dmarc authorization state. */
function ReportDestinations({
	dmarc,
	domainName,
	goToCheck,
}: {
	dmarc?: DmarcResults;
	domainName: string;
	goToCheck: (checkKey: string) => void;
}) {
	const uris = [
		...(dmarc?.rua_uris ?? []).map((u) => ({ kind: "rua" as const, uri: u })),
		...(dmarc?.ruf_uris ?? []).map((u) => ({ kind: "ruf" as const, uri: u })),
	];
	const authByUri = new Map(
		(dmarc?.external_report_auth ?? []).map((a) => [a.report_uri, a]),
	);
	return (
		<section className="rounded-lg border border-[var(--edh-border)] bg-white p-4">
			<h2 className="mb-2 font-semibold">Report destinations</h2>
			{uris.length === 0 ? (
				<p className="text-sm text-slate-600">
					No report destinations. Add{" "}
					<span className="font-mono text-xs">
						rua=mailto:dmarc@{domainName}
					</span>{" "}
					so you can see who sends as this domain.
				</p>
			) : (
				<ul className="space-y-2">
					{uris.map(({ kind, uri }) => {
						const auth = authByUri.get(uri);
						const external = Boolean(auth);
						const ok = !external || auth?.authorized;
						// §6.3: external destinations open the external-authorization explainer; in-domain
						// mailboxes open the reporting explainer.
						const checkKey = external ? "external-authorization" : "reporting";
						return (
							<li
								key={`${kind}:${uri}`}
								className="rounded-md border border-[var(--edh-border)] p-2 text-sm hover:border-[var(--edh-primary)]"
							>
								<button
									type="button"
									onClick={() => goToCheck(checkKey)}
									className="flex w-full items-center gap-2 text-left"
								>
									{ok ? (
										<ShieldCheck className="h-4 w-4 shrink-0 text-emerald-600" />
									) : (
										<ShieldAlert className="h-4 w-4 shrink-0 text-red-600" />
									)}
									<span className="break-all font-mono text-xs">{uri}</span>
									<span className="ml-auto shrink-0 text-[10px] uppercase text-[var(--edh-muted)]">
										{kind}
									</span>
								</button>
								{external && auth && (
									<div className="mt-1 pl-6 text-xs text-slate-500">
										<span className="font-mono">{auth.auth_name}</span> →{" "}
										{auth.authorized
											? "v=DMARC1 (authorized)"
											: "no record — reports are silently dropped"}
										{!auth.authorized && (
											<div className="mt-1">
												<CopyFixButton
													text={`${auth.auth_name} TXT "v=DMARC1"`}
													label="Copy expected record"
												/>
											</div>
										)}
									</div>
								)}
							</li>
						);
					})}
				</ul>
			)}
		</section>
	);
}

/**
 * The optional "Suggested record" builder (pm/checks/dmarc.mdx §6.2 per-domain config inputs):
 * desired p, rua mailbox, cover subdomains? → a ready-to-publish TXT string. Advisory only —
 * never auto-published.
 */
function SuggestedRecordBuilder({
	domainName,
	dmarc,
}: {
	domainName: string;
	dmarc?: DmarcResults;
}) {
	const [policy, setPolicy] = useState<"none" | "quarantine" | "reject">(
		dmarc?.policy ?? "none",
	);
	const [mailbox, setMailbox] = useState(`dmarc@${domainName}`);
	const [coverSubdomains, setCoverSubdomains] = useState(false);
	const record = `v=DMARC1; p=${policy}; rua=mailto:${mailbox}${coverSubdomains ? "; sp=reject; np=reject" : ""}`;
	return (
		<section className="mt-6 rounded-lg border border-[var(--edh-border)] bg-white p-4">
			<h2 className="font-semibold">Suggested record</h2>
			<p className="mt-1 text-xs text-[var(--edh-muted)]">
				Build a ready-to-publish TXT string for{" "}
				<span className="font-mono">_dmarc.{domainName}</span>. Advisory only —
				nothing is published automatically.
			</p>
			<div className="mt-3 flex flex-wrap items-center gap-3 text-sm">
				<label className="flex items-center gap-1.5">
					Policy
					<select
						value={policy}
						onChange={(e) =>
							setPolicy(e.target.value as "none" | "quarantine" | "reject")
						}
						className="rounded border border-[var(--edh-border)] px-2 py-1 text-sm"
					>
						<option value="none">none (monitor)</option>
						<option value="quarantine">quarantine</option>
						<option value="reject">reject</option>
					</select>
				</label>
				<label className="flex items-center gap-1.5">
					Reports to
					<input
						value={mailbox}
						onChange={(e) => setMailbox(e.target.value)}
						className="w-56 rounded border border-[var(--edh-border)] px-2 py-1 font-mono text-xs"
					/>
				</label>
				<label className="flex items-center gap-1.5">
					<input
						type="checkbox"
						checked={coverSubdomains}
						onChange={(e) => setCoverSubdomains(e.target.checked)}
					/>
					Cover subdomains (sp=reject; np=reject)
				</label>
			</div>
			<div className="mt-3 flex items-center justify-between gap-2 rounded-md bg-slate-50 p-2">
				<code className="break-all font-mono text-xs text-slate-700">
					{record}
				</code>
				<CopyFixButton text={record} label="Copy" />
			</div>
		</section>
	);
}

/**
 * The collapsed tool-runs provenance footer (pm/checks/dmarc.mdx §6.2 item 7 / §7): one monospace
 * row per `dmarc.tool_runs[]` entry — exact command (copyable, reproducible in a terminal),
 * duration, exit code — with an accordion for the captured `parsed` output. Failed invocations
 * render their `error` in red. It answers "prove it", never "what do I do", so it ships last
 * and collapsed.
 */
function ToolRunsFooter({ toolRuns }: { toolRuns: DmarcToolRun[] }) {
	const [open, setOpen] = useState(false);
	if (toolRuns.length === 0) return null;
	const failed = toolRuns.filter((t) => t.error !== null).length;
	return (
		<section className="mt-6 rounded-lg border border-[var(--edh-border)] bg-white">
			<button
				type="button"
				onClick={() => setOpen((o) => !o)}
				className="flex w-full items-center justify-between px-4 py-3 text-left"
			>
				<span className="flex items-center gap-2 font-semibold">
					{open ? (
						<ChevronDown className="h-4 w-4" />
					) : (
						<ChevronRight className="h-4 w-4" />
					)}
					Tool runs ({toolRuns.length})
				</span>
				<span
					className={cn(
						"text-xs",
						failed > 0 ? "text-red-600" : "text-[var(--edh-muted)]",
					)}
				>
					{failed > 0 ? `${failed} failed` : "all succeeded"}
				</span>
			</button>
			{open && (
				<ul className="border-t border-[var(--edh-border)]">
					{toolRuns.map((t) => (
						<ToolRunRow
							key={`${t.tool}-${t.started_at}-${t.command}`}
							run={t}
						/>
					))}
				</ul>
			)}
		</section>
	);
}

function ToolRunRow({ run }: { run: DmarcToolRun }) {
	const [open, setOpen] = useState(false);
	return (
		<li className="border-b border-[var(--edh-border)] px-4 py-2 text-sm last:border-b-0">
			<div className="flex items-center gap-2">
				<code className="min-w-0 flex-1 break-all font-mono text-xs text-slate-700">
					{run.command}
				</code>
				<span className="shrink-0 text-xs tabular-nums text-[var(--edh-muted)]">
					{run.duration_ms} ms
				</span>
				<span
					className={cn(
						"shrink-0 text-xs tabular-nums",
						run.error ? "text-red-600" : "text-[var(--edh-muted)]",
					)}
				>
					{run.exit_code === null ? "killed" : `exit ${run.exit_code}`}
				</span>
				<CopyFixButton text={run.command} label="Copy" />
				<button
					type="button"
					onClick={() => setOpen((o) => !o)}
					aria-label={`Toggle ${run.tool} output`}
					className="rounded p-1 text-[var(--edh-muted)] hover:bg-slate-100"
				>
					{open ? (
						<ChevronDown className="h-4 w-4" />
					) : (
						<ChevronRight className="h-4 w-4" />
					)}
				</button>
			</div>
			{open && (
				<div className="mt-2">
					{run.error && (
						<p className="mb-1 break-all font-mono text-xs text-red-600">
							{run.error}
						</p>
					)}
					{run.parsed !== null && run.parsed !== undefined && (
						<pre className="max-h-72 overflow-auto rounded-md bg-slate-900 p-2 font-mono text-xs text-slate-100">
							{JSON.stringify(run.parsed, null, 2)}
						</pre>
					)}
				</div>
			)}
		</li>
	);
}
