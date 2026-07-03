import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { ChevronRight, Loader2, Play, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useAuditResults, useAuditRuns, useDeleteRun } from "@/api/audit";
import { useDeleteDomain, useDomains, useUpdateDomain } from "@/api/domains";
import { fetchPreflight } from "@/api/install";
import { useSchedulerStatus, useSetScheduleEnabled } from "@/api/scheduler";
import type { AuditResult, MonitoredDomain } from "@/api/types";
import { NewProblemBadge } from "@/components/Badges";
import { BrandHeader } from "@/components/BrandHeader";
import { RowMenu } from "@/components/RowMenu";
import { StatusCell } from "@/components/StatusCell";
import {
	CATEGORIES,
	type CellStatus,
	NEVER_CELL,
	rollupCategories,
	techPageRoute,
} from "@/lib/categories";
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext";

/**
 * The Dashboard (pm/dashboard.mdx) — two tables under the brand header:
 *   Table 1 "Domain health": one row per monitored domain, six TEST cells from its newest run,
 *   a ▶ play button that runs checks for just that domain, and a ⋮ menu. Row click → newest report.
 *   Table 2 "Runs": one row per RUN (per-domain, startedAt/finishedAt), Date + Domain + the six
 *   test cells, a › chevron and a ⋮ menu. Row click → that run's report.
 * Top-right: Run checks (all domains) and the scheduled-checks toggle with its chevron.
 */
export function DashboardPage() {
	const { data: domains, isLoading } = useDomains();
	const { data: results } = useAuditResults();
	const { data: runs } = useAuditRuns();
	const runDomains = useScanRunner();
	const scanning = useScanProgress().length > 0;
	const navigate = useNavigate();
	const { resume } = useSearch({ strict: false }) as { resume?: string };
	const list = domains ?? [];

	const runAll = useCallback(
		() => runDomains(list.map((d) => ({ id: d.id, name: d.name }))),
		[runDomains, list],
	);

	// Preflight gate (pm/install_brew.mdx §1): before fanning out, ask the backend what this run needs
	// that isn't installed. If anything is missing, divert to the Install page carrying `from`+`intent`
	// so it can resume this exact run afterward (§8); otherwise run now.
	const onRunChecks = useCallback(async () => {
		if (list.length === 0) return;
		try {
			const pf = await fetchPreflight("brew", "run-all");
			if (pf.missing.length > 0) {
				navigate({
					to: "/install",
					search: { manager: "brew", from: "/", intent: "run-all" },
				});
				return;
			}
		} catch {
			// Preflight is advisory — if it fails, never block the run.
		}
		runAll();
	}, [list.length, navigate, runAll]);

	// Resume after an install diversion: fire the run once, then clear the token so a manual refresh
	// of "/" doesn't re-trigger it (pm/install_brew.mdx §8.3).
	const resumedRef = useRef(false);
	useEffect(() => {
		if (!resume || resumedRef.current || isLoading || list.length === 0) return;
		resumedRef.current = true;
		if (resume === "run-all" || resume.startsWith("run-domain")) runAll();
		navigate({ to: "/", search: {}, replace: true });
	}, [resume, isLoading, list.length, runAll, navigate]);

	return (
		<div className="mx-auto max-w-6xl">
			<header className="mb-8 flex items-start justify-between gap-4">
				<BrandHeader />
				<div className="flex shrink-0 flex-col items-end gap-2">
					<button
						type="button"
						onClick={onRunChecks}
						disabled={scanning || list.length === 0}
						className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
					>
						<RefreshCw
							className={scanning ? "h-4 w-4 animate-spin" : "h-4 w-4"}
						/>
						{scanning ? "Running…" : "Run checks"}
					</button>
					<ScheduledToggle />
				</div>
			</header>

			{isLoading ? (
				<SkeletonGrid />
			) : list.length === 0 ? (
				<div className="rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center">
					<p className="text-slate-600">No domains yet.</p>
					<Link
						to="/domains"
						className="mt-2 inline-block text-[var(--edh-primary)] underline"
					>
						Add your first domain →
					</Link>
				</div>
			) : (
				<>
					<DomainHealthTable domains={list} results={results ?? []} />
					{(results ?? []).length === 0 && (
						<p className="mt-2 text-sm text-[var(--edh-muted)]">
							No checks have run yet — press{" "}
							<span className="font-medium">Run checks</span> to audit every
							domain.
						</p>
					)}
					<RunsTable runs={runs ?? []} />
				</>
			)}
		</div>
	);
}

/* ------------------------------------------------------------------------------------------------
 * Table 1 — Domain health (pm/dashboard.mdx §4.1): one row per domain, cells from the newest run.
 * Row click → newest report; ▶ runs just that domain; ⋮ menu carries the domain actions.
 * ---------------------------------------------------------------------------------------------- */
function DomainHealthTable({
	domains,
	results,
}: {
	domains: MonitoredDomain[];
	results: AuditResult[];
}) {
	const navigate = useNavigate();
	const runDomains = useScanRunner();
	const progress = useScanProgress();
	const updateDomain = useUpdateDomain();
	const deleteDomain = useDeleteDomain();
	const byId = new Map(results.map((r) => [r.domainId, r]));

	const onDelete = (d: MonitoredDomain) => {
		if (
			window.confirm(
				`Delete ${d.name}? Its run history stays until each run is deleted.`,
			)
		) {
			deleteDomain.mutate(d.id);
		}
	};

	return (
		<div className="overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
			<table className="w-full text-sm">
				<thead className="bg-slate-50 text-left text-xs uppercase text-[var(--edh-muted)]">
					<tr>
						<th className="px-4 py-2">Domain</th>
						{CATEGORIES.map((c) => (
							<th key={c.key} className="px-2 py-2 text-center">
								{c.header}
							</th>
						))}
						<th className="px-2 py-2" aria-label="Row actions" />
					</tr>
				</thead>
				<tbody>
					{domains.map((d) => {
						const cells = rollupCategories(
							byId.get(d.id)?.findings,
							byId.get(d.id)?.results,
						);
						const domainScanning = progress.some((s) => s.domainId === d.id);
						return (
							<tr
								key={d.id}
								onClick={() =>
									navigate({ to: "/domains/$id", params: { id: d.id } })
								}
								className="cursor-pointer border-t border-[var(--edh-border)] hover:bg-slate-50"
							>
								<td className="px-4 py-3 font-medium">
									<span className="flex items-center gap-2">
										{d.name}
										{/* Regression marker (pm/engineering.mdx §8): new problems in the newest run. */}
										<NewProblemBadge
											count={byId.get(d.id)?.newProblemCount ?? 0}
										/>
									</span>
								</td>
								{CATEGORIES.map((c) => {
									// Test-cell click (pm/dashboard.mdx §6.2): the WHOLE cell opens that test's
									// "view one category run" page for the domain's newest run. Blacklists' page
									// is keyed by domain NAME; tests without a page yet fall through to the row.
									const techRoute = techPageRoute(c.key);
									const onOpen =
										c.key === "blacklists"
											? () =>
													navigate({
														to: "/blacklists/$domain",
														params: { domain: d.name },
													})
											: c.key === "dnssec"
												? // DNSSEC has no standalone page; its drill-in is the DNS-family
													// explainer (pm/checks/dns.mdx §6.2) for the newest run.
													() =>
														navigate({
															to: "/domains/$id/dns/check/$checkKey",
															params: { id: d.id, checkKey: "dnssec" },
														})
												: techRoute
													? () =>
															navigate({ to: techRoute, params: { id: d.id } })
													: undefined;
									return (
										<td key={c.key} className="px-2 py-2">
											<TestCell
												status={cells[c.key] ?? NEVER_CELL}
												openLabel={`Open the ${c.header} results for ${d.name}`}
												onOpen={onOpen}
											/>
										</td>
									);
								})}
								<td className="px-2 py-2">
									{/* Row controls (§4.3) — each control stops propagation so a click never also
                      fires the whole-row navigation. */}
									<span className="flex items-center justify-end gap-1">
										<button
											type="button"
											onClick={(e) => {
												e.stopPropagation();
												runDomains([{ id: d.id, name: d.name }]);
											}}
											disabled={domainScanning}
											aria-label={`Run checks for ${d.name}`}
											title={`Run checks for ${d.name}`}
											className="rounded p-1 text-[var(--edh-primary)] hover:bg-slate-100 disabled:opacity-50"
										>
											{domainScanning ? (
												<Loader2 className="h-4 w-4 animate-spin" />
											) : (
												<Play className="h-4 w-4" />
											)}
										</button>
										<RowMenu
											label={`Actions for ${d.name}`}
											items={[
												{
													label: "Run checks now",
													onClick: () =>
														runDomains([{ id: d.id, name: d.name }]),
												},
												{
													label: "Open newest report",
													onClick: () =>
														navigate({
															to: "/domains/$id",
															params: { id: d.id },
														}),
												},
												{
													// Lands on the Domains page with this domain's editor open (§4.3).
													label: "Edit domain",
													onClick: () =>
														navigate({
															to: "/domains",
															search: { edit: d.id },
														}),
												},
												{
													label: d.scheduleEnabled
														? "Scheduled checks: turn off"
														: "Scheduled checks: turn on",
													onClick: () =>
														updateDomain.mutate({
															id: d.id,
															input: { scheduleEnabled: !d.scheduleEnabled },
														}),
												},
												{
													label: "Delete domain",
													danger: true,
													onClick: () => onDelete(d),
												},
											]}
										/>
									</span>
								</td>
							</tr>
						);
					})}
				</tbody>
			</table>
		</div>
	);
}

/* ------------------------------------------------------------------------------------------------
 * Table 2 — Runs (pm/dashboard.mdx §4.2): one row per run, newest startedAt first. Date + Domain +
 * six test cells; the › chevron and the row click both open that run's report; ⋮ menu per run.
 * ---------------------------------------------------------------------------------------------- */
function RunsTable({ runs }: { runs: AuditResult[] }) {
	const navigate = useNavigate();
	const runDomains = useScanRunner();
	const deleteRun = useDeleteRun();
	const shown = runs.slice(0, 100);

	const openRun = (r: AuditResult) => {
		if (r.runId) {
			navigate({
				to: "/domains/$id/runs/$runId",
				params: { id: r.domainId, runId: r.runId },
			});
		} else {
			navigate({ to: "/domains/$id", params: { id: r.domainId } });
		}
	};

	return (
		<section className="mt-8">
			<h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-900">
				Runs
			</h2>
			{shown.length === 0 ? (
				<div className="rounded-lg border border-dashed border-[var(--edh-border)] p-6 text-center text-slate-600">
					No runs yet. Press <span className="font-medium">Run checks</span> to
					create the first one.
				</div>
			) : (
				<div className="overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
					<table className="w-full text-sm">
						<thead className="bg-slate-50 text-left text-xs uppercase text-[var(--edh-muted)]">
							<tr>
								<th className="px-4 py-2">Date</th>
								<th className="px-4 py-2">Domain</th>
								{CATEGORIES.map((c) => (
									<th key={c.key} className="px-2 py-2 text-center">
										{c.header}
									</th>
								))}
								<th className="px-2 py-2" aria-label="Row actions" />
							</tr>
						</thead>
						<tbody>
							{shown.map((r) => {
								const cells = rollupCategories(r.findings, r.results);
								return (
									<tr
										key={r.runId ?? `${r.domainId}-${r.ranAt}`}
										onClick={() => openRun(r)}
										className="cursor-pointer border-t border-[var(--edh-border)] hover:bg-slate-50"
									>
										<td className="whitespace-nowrap px-4 py-3 font-medium tabular-nums">
											{fmtRunDate(r.startedAt ?? r.ranAt)}
										</td>
										<td className="px-4 py-3">
											<span className="flex items-center gap-2">
												{r.domain}
												<NewProblemBadge count={r.newProblemCount ?? 0} />
											</span>
										</td>
										{CATEGORIES.map((c) => {
											// Test-cell click for a HISTORICAL run (pm/dashboard.mdx §6.2) needs the
											// per-run category routes (/domains/$id/runs/$runId/<slug>). DKIM has one
											// (pm/checks/dkim.mdx §6.1 — the Runs-table cell opens THAT run's DKIM
											// page), DMARC too (pm/checks/dmarc.mdx §6.1 — the Runs-row cell opens
											// THAT run's DMARC page), and so does DNS & Infrastructure
											// (pm/checks/dns.mdx §6.1 — the cell opens THAT run's DNS page), and now
											// SPF (pm/checks/spf.mdx) and Blacklists (pm/checks/blacklists.mdx §13.2)
											// have run-scoped pages too; Spam & Content has no run-scoped page yet, so
											// it falls through to the row.
											const onOpen =
												c.key === "dkim" && r.runId
													? () =>
															navigate({
																to: "/domains/$id/runs/$runId/dkim",
																params: {
																	id: r.domainId,
																	runId: r.runId as string,
																},
															})
													: c.key === "dmarc" && r.runId
														? () =>
																navigate({
																	to: "/domains/$id/runs/$runId/dmarc",
																	params: {
																		id: r.domainId,
																		runId: r.runId as string,
																	},
																})
														: c.key === "dnsInfra" && r.runId
															? () =>
																	navigate({
																		to: "/domains/$id/runs/$runId/dns",
																		params: {
																			id: r.domainId,
																			runId: r.runId as string,
																		},
																	})
															: c.key === "spf" && r.runId
																? () =>
																		navigate({
																			to: "/domains/$id/runs/$runId/spf",
																			params: {
																				id: r.domainId,
																				runId: r.runId as string,
																			},
																		})
																: c.key === "blacklists" && r.runId
																	? () =>
																			navigate({
																				to: "/domains/$id/runs/$runId/blacklists",
																				params: {
																					id: r.domainId,
																					runId: r.runId as string,
																				},
																			})
																	: undefined;
											return (
												<td key={c.key} className="px-2 py-2">
													<TestCell
														status={cells[c.key] ?? NEVER_CELL}
														openLabel={`Open the ${c.header} results for this ${r.domain} run`}
														onOpen={onOpen}
													/>
												</td>
											);
										})}
										<td className="px-2 py-2">
											{/* Row controls (§4.4) — each control stops propagation so a click never
                          also fires the whole-row navigation. */}
											<span className="flex items-center justify-end gap-1">
												<button
													type="button"
													onClick={(e) => {
														e.stopPropagation();
														openRun(r);
													}}
													aria-label={`Open the ${r.domain} run report`}
													title="Open this run's report"
													className="rounded p-1 text-[var(--edh-muted)] hover:bg-slate-100 hover:text-slate-700"
												>
													<ChevronRight className="h-4 w-4" />
												</button>
												<RowMenu
													label={`Actions for the ${r.domain} run`}
													items={[
														{ label: "Open report", onClick: () => openRun(r) },
														{
															label: "Run checks again",
															onClick: () =>
																runDomains([
																	{ id: r.domainId, name: r.domain },
																]),
														},
														{
															label: "Delete run",
															danger: true,
															onClick: () => {
																if (
																	r.runId &&
																	window.confirm(
																		"Delete this run from the history?",
																	)
																) {
																	deleteRun.mutate(r.runId);
																}
															},
														},
													]}
												/>
											</span>
										</td>
									</tr>
								);
							})}
						</tbody>
					</table>
				</div>
			)}
		</section>
	);
}

/**
 * One TEST cell (pm/dashboard.mdx §6.2): the WHOLE cell is its own click target that goes INSIDE
 * that test (the "view one category run" page) instead of the whole-run report. On hover the cell
 * — not the row — gets the highlight, and a small › appears at its right edge as the affordance.
 * Cell clicks stop propagation so they never also trigger the row navigation (§6.3 precedence:
 * row controls > test cell > whole row). A gray never-run cell has no test data to open, and a
 * test whose category page isn't built yet has nowhere to go — both render as a plain cell whose
 * click falls through to the row.
 */
function TestCell({
	status,
	openLabel,
	onOpen,
}: {
	status: CellStatus;
	openLabel: string;
	onOpen?: () => void;
}) {
	if (!onOpen || status.color === "gray") return <StatusCell status={status} />;
	return (
		<button
			type="button"
			onClick={(e) => {
				e.stopPropagation();
				onOpen();
			}}
			aria-label={openLabel}
			className="group/cell block w-full cursor-pointer rounded transition-shadow hover:ring-2 hover:ring-[var(--edh-primary)]"
		>
			<StatusCell status={status} hoverChevron />
		</button>
	);
}

/** `YYYY-MM-DD HH:mm` in local time (pm/dashboard.mdx §4.2). */
function fmtRunDate(iso: string): string {
	const d = new Date(iso);
	const pad = (n: number) => String(n).padStart(2, "0");
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/**
 * The recurring-checks on/off switch with a chevron to the scheduling page (pm/dashboard.mdx §7.2).
 * The toggle reflects/sets whether recurring checks are enabled through the scheduler contract
 * (GET /api/scheduler + PUT /api/scheduler/config, pm/scheduled_checks.mdx). While the scheduler
 * module isn't reachable it degrades to the client-side preference so the switch stays usable.
 * The chevron only navigates to the Scheduling settings page at /settings/scheduling
 * (pm/ui.mdx §4, pm/dashboard.mdx §7.2) — it never flips the toggle; its tooltip shows the next
 * scheduled run time when one is armed.
 */
function ScheduledToggle() {
	const status = useSchedulerStatus();
	const setEnabled = useSetScheduleEnabled();
	const [on, setOn] = useState(false);
	useEffect(() => {
		if (status.data) {
			setOn(status.data.enabled);
		} else if (status.isError) {
			setOn(localStorage.getItem("edh.scheduled") === "on");
		}
	}, [status.data, status.isError]);
	const toggle = () => {
		const next = !on;
		setOn(next); // optimistic; the status query refetch settles the truth
		localStorage.setItem("edh.scheduled", next ? "on" : "off");
		setEnabled.mutate(next);
	};
	return (
		<div className="inline-flex items-center gap-2 rounded-md border border-[var(--edh-border)] bg-white px-3 py-1.5 text-sm">
			<span className="text-[var(--edh-muted)]">Scheduled</span>
			<button
				type="button"
				role="switch"
				aria-checked={on}
				aria-label="Toggle scheduled checks"
				onClick={toggle}
				className={`relative h-5 w-9 rounded-full transition-colors ${on ? "bg-[var(--edh-primary)]" : "bg-slate-300"}`}
			>
				<span
					className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${on ? "left-4" : "left-0.5"}`}
				/>
			</button>
			<Link
				to="/settings/$section"
				params={{ section: "scheduling" }}
				aria-label="Configure scheduled checks"
				title={
					status.data?.nextRunAt
						? `Next run: ${new Date(status.data.nextRunAt).toLocaleString()}`
						: "Configure scheduled checks"
				}
				className="text-[var(--edh-muted)] hover:text-slate-700"
			>
				<ChevronRight className="h-4 w-4" />
			</Link>
		</div>
	);
}

/** Loading skeletons sized like the two tables so there is no layout shift (pm/dashboard.mdx §8). */
function SkeletonGrid() {
	return (
		<div>
			<div className="space-y-2">
				{["a", "b", "c"].map((k) => (
					<div key={k} className="h-11 animate-pulse rounded-md bg-slate-100" />
				))}
			</div>
			<div className="mt-10 space-y-2">
				{["a", "b", "c", "d"].map((k) => (
					<div key={k} className="h-11 animate-pulse rounded-md bg-slate-100" />
				))}
			</div>
		</div>
	);
}
