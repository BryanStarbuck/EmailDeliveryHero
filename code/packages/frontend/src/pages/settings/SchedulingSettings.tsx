import { Link } from "@tanstack/react-router";
import { Info, Loader2, Minus, Plus } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
	type ScheduleConfig,
	useRunScheduledNow,
	useSaveScheduleConfig,
	useScheduleConfig,
	useSchedulerStatus,
	useSetScheduleEnabled,
	WEEKDAYS,
	type Weekday,
} from "@/api/scheduler";

/**
 * Settings › Scheduling (pm/settings.mdx §3.2) — the Scheduling tab at /settings/scheduling the
 * dashboard chevron opens. Scheduling defaults OFF; the master toggle saves immediately (one flip
 * yields a working 06:00-daily schedule), the times/days form uses an explicit Save, and the
 * status block reads GET /api/scheduler. The full configuration page (/scheduled-checks,
 * pm/scheduled_checks.mdx) keeps the advanced controls: interval cadence, timezone, domain scope,
 * and the OS-level schedule install.
 */

const WEEKDAY_LABEL: Record<Weekday, string> = {
	mon: "Mon",
	tue: "Tue",
	wed: "Wed",
	thu: "Thu",
	fri: "Fri",
	sat: "Sat",
	sun: "Sun",
};

const HHMM_RE = /^([01]\d|2[0-3]):[0-5]\d$/;

const TRIGGER_LABEL: Record<string, string> = {
	"in-process": "scheduled",
	os: "scheduled (background agent)",
	manual: "manual",
};

function fmtInstant(iso: string | null | undefined): string {
	if (!iso) return "—";
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) return "—";
	return d.toLocaleString(undefined, {
		weekday: "short",
		month: "short",
		day: "numeric",
		hour: "2-digit",
		minute: "2-digit",
	});
}

/** One editable time row — the id keeps React keys stable as rows are added/removed. */
interface TimeRow {
	id: number;
	value: string;
}

/** The tab's editable slice of the schedule block: times + the day chips. */
interface Draft {
	times: TimeRow[];
	days: Weekday[];
}

let nextRowId = 0;
const timeRow = (value: string): TimeRow => ({ id: nextRowId++, value });

function toDraft(cfg: ScheduleConfig): Draft {
	return {
		times: (cfg.times.length > 0 ? cfg.times : ["06:00"]).map(timeRow),
		// Weekly-with-subset shows that subset; everything else (daily, empty weekdays) = every day.
		days:
			cfg.cadence === "weekly" && cfg.weekdays.length > 0
				? [...cfg.weekdays]
				: [...WEEKDAYS],
	};
}

/** Map the tab's model back to the schedule block: all seven days = daily, a subset = weekly. */
function fromDraft(draft: Draft): Partial<ScheduleConfig> {
	const everyDay = draft.days.length === WEEKDAYS.length;
	return {
		times: [...new Set(draft.times.map((t) => t.value))].sort(),
		cadence: everyDay ? "daily" : "weekly",
		weekdays: everyDay ? [] : WEEKDAYS.filter((d) => draft.days.includes(d)),
	};
}

function sameDraft(a: Draft, b: Draft): boolean {
	const times = (d: Draft) =>
		[...new Set(d.times.map((t) => t.value))].sort().join(",");
	const days = (d: Draft) =>
		WEEKDAYS.filter((w) => d.days.includes(w)).join(",");
	return times(a) === times(b) && days(a) === days(b);
}

export function SchedulingSettings() {
	const status = useSchedulerStatus();
	const config = useScheduleConfig();
	const setEnabled = useSetScheduleEnabled();
	const save = useSaveScheduleConfig();
	const runNow = useRunScheduledNow();

	const [draft, setDraft] = useState<Draft | null>(null);
	// Optimistic master switch — settles from the status refetch (like the dashboard toggle).
	const [on, setOn] = useState(false);
	useEffect(() => {
		if (status.data) setOn(status.data.enabled);
	}, [status.data]);
	// Seed the editable form once the persisted block arrives; refetches never clobber edits.
	useEffect(() => {
		if (config.data && draft === null) setDraft(toDraft(config.data));
	}, [config.data, draft]);

	if (!draft || !config.data) {
		return (
			<section className="rounded-lg border border-[var(--edh-border)] bg-white p-5">
				<h2 className="mb-3 font-semibold">Scheduling</h2>
				<div className="space-y-3">
					{["a", "b", "c"].map((k) => (
						<div
							key={k}
							className="h-16 animate-pulse rounded-md bg-slate-100"
						/>
					))}
				</div>
			</section>
		);
	}

	const baseline = toDraft(config.data);
	const dirty = !sameDraft(draft, baseline);
	const timesValid =
		draft.times.length > 0 && draft.times.every((t) => HHMM_RE.test(t.value));
	const canSave =
		dirty && timesValid && draft.days.length > 0 && !save.isPending;

	const toggle = () => {
		const next = !on;
		setOn(next);
		setEnabled.mutate(next, {
			onError: () => {
				setOn(!next);
				toast.error("Could not save the scheduling switch");
			},
		});
	};

	const onSave = async () => {
		try {
			const saved = await save.mutateAsync(fromDraft(draft));
			setDraft(toDraft(saved));
			toast.success("Schedule saved");
		} catch {
			toast.error("Could not save the schedule");
		}
	};

	const onRunNow = async () => {
		try {
			const outcome = await runNow.mutateAsync();
			if (outcome.started) {
				toast.success(
					`Scheduled check ran (${outcome.domains ?? 0} domain(s))`,
				);
			} else if (outcome.reason === "already_running") {
				toast.info("A scheduled run is already in progress");
			} else {
				toast.info("The scheduled run was skipped");
			}
		} catch {
			toast.error("Could not run the scheduled check");
		}
	};

	return (
		<div className="space-y-4">
			{/* Master toggle — the same schedule.enabled flag as the dashboard switch; saves instantly. */}
			<section className="rounded-lg border border-[var(--edh-border)] bg-white p-5">
				<div className="flex items-center justify-between">
					<div>
						<h2 className="font-semibold">Scheduled checks</h2>
						<p className="mt-1 text-sm text-[var(--edh-muted)]">
							Re-audit every monitored domain automatically and flag new
							problems.
						</p>
					</div>
					<button
						type="button"
						role="switch"
						aria-checked={on}
						aria-label="Toggle scheduled checks"
						onClick={toggle}
						className={`relative h-6 w-11 shrink-0 rounded-full transition-colors ${on ? "bg-[var(--edh-primary)]" : "bg-slate-300"}`}
					>
						<span
							className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all ${on ? "left-[22px]" : "left-0.5"}`}
						/>
					</button>
				</div>
				{!on && (
					<p className="mt-3 flex items-center gap-2 rounded-md bg-slate-50 px-3 py-2 text-sm text-slate-600">
						<Info className="h-4 w-4 shrink-0" />
						Scheduling is off — checks only run when you press "Run checks".
						Turning it on starts the schedule below.
					</p>
				)}
			</section>

			{/* Times + days — editable while off, explicit Save (pm/settings.mdx §3.2). */}
			<section className="rounded-lg border border-[var(--edh-border)] bg-white p-5">
				<h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-900">
					Time(s) of day
				</h2>
				{draft.times.map((row, i) => (
					<div key={row.id} className="flex items-center gap-2 py-1">
						<input
							type="time"
							value={row.value}
							onChange={(e) =>
								setDraft({
									...draft,
									times: draft.times.map((t) =>
										t.id === row.id ? { ...t, value: e.target.value } : t,
									),
								})
							}
							aria-label={`Scheduled time ${i + 1}`}
							className="rounded-md border border-[var(--edh-border)] px-2 py-1 text-sm"
						/>
						<button
							type="button"
							onClick={() =>
								setDraft({
									...draft,
									times: draft.times.filter((t) => t.id !== row.id),
								})
							}
							disabled={draft.times.length <= 1}
							aria-label={`Remove time ${row.value}`}
							title={
								draft.times.length <= 1
									? "At least one time is required"
									: "Remove this time"
							}
							className="rounded p-1 text-[var(--edh-muted)] hover:bg-slate-100 hover:text-slate-700 disabled:opacity-40"
						>
							<Minus className="h-4 w-4" />
						</button>
					</div>
				))}
				<button
					type="button"
					onClick={() =>
						setDraft({ ...draft, times: [...draft.times, timeRow("18:00")] })
					}
					className="mt-1 inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
				>
					<Plus className="h-4 w-4" /> Add another time
				</button>
				<p className="mt-2 text-xs text-[var(--edh-muted)]">
					Times use this machine's local timezone. Add more rows to run more
					than once per day.
				</p>

				<h2 className="mb-2 mt-5 text-sm font-semibold uppercase tracking-wide text-slate-900">
					Days
				</h2>
				<div className="flex flex-wrap gap-1">
					{WEEKDAYS.map((d) => {
						const active = draft.days.includes(d);
						return (
							<button
								key={d}
								type="button"
								aria-pressed={active}
								onClick={() =>
									setDraft({
										...draft,
										days: active
											? draft.days.filter((w) => w !== d)
											: [...draft.days, d],
									})
								}
								className={`rounded-md border px-2.5 py-1 text-xs ${
									active
										? "border-[var(--edh-primary)] bg-[var(--edh-primary)] text-white"
										: "border-[var(--edh-border)] bg-white text-slate-700"
								}`}
							>
								{WEEKDAY_LABEL[d]}
							</button>
						);
					})}
				</div>
				{draft.days.length === 0 && (
					<p className="mt-1 text-xs text-red-700">Select at least one day.</p>
				)}

				{dirty && (
					<div className="mt-4 flex justify-end gap-2 border-t border-[var(--edh-border)] pt-3">
						<button
							type="button"
							onClick={() => setDraft(baseline)}
							className="rounded-md border border-[var(--edh-border)] px-4 py-2 text-sm text-slate-700 hover:bg-slate-50"
						>
							Cancel
						</button>
						<button
							type="button"
							onClick={onSave}
							disabled={!canSave}
							className="rounded-md bg-[var(--edh-primary)] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
						>
							{save.isPending ? "Saving…" : "Save"}
						</button>
					</div>
				)}
			</section>

			{/* Status — one GET /api/scheduler read (pm/settings.mdx §3.2 "Status block"). */}
			<section className="rounded-lg border border-[var(--edh-border)] bg-white p-5">
				<h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-900">
					Status
				</h2>
				<StatusRow label="Next run">
					{on ? fmtInstant(status.data?.nextRunAt) : "— (scheduling is off)"}
				</StatusRow>
				<StatusRow label="Last run">
					{status.data?.lastRunAt ? (
						<>
							{fmtInstant(status.data.lastRunAt)}
							{status.data.lastTrigger && (
								<span className="text-[var(--edh-muted)]">
									{" "}
									·{" "}
									{TRIGGER_LABEL[status.data.lastTrigger] ??
										status.data.lastTrigger}
								</span>
							)}{" "}
							·{" "}
							<Link to="/" className="text-[var(--edh-primary)] underline">
								view in Runs
							</Link>
						</>
					) : (
						"—"
					)}
				</StatusRow>
				<StatusRow label="Covers">
					{status.data?.domainsTotal != null ? (
						<>
							{status.data.domainsCovered ?? 0} of {status.data.domainsTotal}{" "}
							monitored domains ·{" "}
							<Link
								to="/domains"
								className="text-[var(--edh-primary)] underline"
							>
								per-domain toggles
							</Link>
						</>
					) : (
						"—"
					)}
				</StatusRow>
				<StatusRow label="Runs while the app is closed">
					{status.data?.os?.installed ? (
						<span className="font-medium text-green-700">
							background agent installed ✓ ({status.data.os.kind})
						</span>
					) : (
						"background agent not installed"
					)}
				</StatusRow>

				<div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-[var(--edh-border)] pt-3">
					<button
						type="button"
						onClick={onRunNow}
						disabled={runNow.isPending || status.data?.running === true}
						className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-50"
					>
						{(runNow.isPending || status.data?.running === true) && (
							<Loader2 className="h-4 w-4 animate-spin" />
						)}
						Run a scheduled check now
					</button>
					<Link
						to="/scheduled-checks"
						className="text-sm text-[var(--edh-primary)] underline"
					>
						Advanced: cadence, timezone, domain scope, background agent →
					</Link>
				</div>
			</section>
		</div>
	);
}

function StatusRow({
	label,
	children,
}: {
	label: string;
	children: React.ReactNode;
}) {
	return (
		<div className="flex justify-between gap-4 border-b border-[var(--edh-border)] py-2 text-sm last:border-0">
			<span className="shrink-0 text-[var(--edh-muted)]">{label}</span>
			<span className="text-right font-medium">{children}</span>
		</div>
	);
}
