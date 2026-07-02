import { Link, Navigate, useParams } from "@tanstack/react-router";
import { ExternalLink, RefreshCw, Terminal } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useBlacklistRecheck } from "@/api/blacklists";
import { useDomains } from "@/api/domains";
import type {
	BlacklistLiveRecheck,
	BlacklistRunResults,
	BlacklistZoneResult,
	ProblemStateId,
} from "@/api/types";
import { SeverityBadge } from "@/components/Badges";
import { PROBLEM_STATES, problemState } from "@/lib/problemStates";
import { cn } from "@/lib/utils";
import { useScopedBlacklistRun } from "./useScopedBlacklistRun";

/**
 * The grown problem-state deep-dive page (pm/checks/blacklists.mdx §20.5 / AC 25): run-scoped
 * canonical /domains/$id/runs/$runId/blacklists/state/$psId with newest-run alias
 * /domains/$id/blacklists/state/$psId; the legacy /blacklists/$domain/state/$psId shorthand
 * redirects into the alias. Renders the locked §20.2 five-point template — the concept, the
 * verdict against the VIEWED run with raw+parsed evidence (§20.6), the severity rationale, the
 * "progress forward" playbook, and the state-scoped re-run (§21.3) — plus the presence-strip
 * history (which of the last 30 runs had this state active) and the References block (§20.7).
 */

const CHANGE_CHIP: Record<string, { label: string; cls: string }> = {
	now_listed: { label: "▲ now listed", cls: "bg-red-100 text-red-800" },
	now_clean: { label: "▼ now clean", cls: "bg-emerald-100 text-emerald-800" },
	unchanged: { label: "unchanged", cls: "bg-slate-100 text-slate-600" },
	inconclusive: { label: "? inconclusive", cls: "bg-gray-100 text-gray-500" },
	untracked: { label: "new pair", cls: "bg-sky-100 text-sky-800" },
};

/** Per-state reference links (§20.7) beyond the always-present RFC 5782. */
const STATE_REFERENCES: Partial<
	Record<ProblemStateId, Array<{ label: string; url: string }>>
> = {
	"PS-1": [
		{
			label: "check.spamhaus.org (SBL case lookup)",
			url: "https://check.spamhaus.org",
		},
	],
	"PS-2": [
		{
			label: "check.spamhaus.org (XBL self-delist)",
			url: "https://check.spamhaus.org",
		},
	],
	"PS-3": [
		{
			label: "Spamhaus PBL removal",
			url: "https://www.spamhaus.org/pbl/removal/",
		},
		{
			label: "SpamRATS removal (fix PTR first)",
			url: "https://www.spamrats.com/removal.php",
		},
	],
	"PS-4": [
		{
			label: "Spamhaus DBL removal",
			url: "https://www.spamhaus.org/dbl/removal/",
		},
		{
			label: "Google Search Console (hacked-site check)",
			url: "https://search.google.com/search-console",
		},
	],
	"PS-5": [
		{
			label: "SpamCop SCBL lookup (report ages)",
			url: "https://www.spamcop.net/bl.shtml",
		},
	],
	"PS-6": [
		{
			label: "RFC 6471 — never pay for delisting",
			url: "https://www.rfc-editor.org/rfc/rfc6471",
		},
		{
			label: "UCEPROTECT rblcheck",
			url: "https://www.uceprotect.net/en/rblcheck.php",
		},
	],
	"PS-8": [
		{ label: "Google Postmaster Tools", url: "https://postmaster.google.com" },
		{
			label: "Microsoft SNDS",
			url: "https://sendersupport.olc.protection.outlook.com/snds/",
		},
		{
			label: "sender.office.com delist portal",
			url: "https://sender.office.com",
		},
	],
	"PS-9": [
		{
			label: "Spamhaus DQS (free key)",
			url: "https://www.spamhaus.com/free-trial/sign-up-for-a-free-data-query-service-account/",
		},
	],
	"PS-10": [
		{ label: "dnsbl.com dead-DNSBL registry", url: "https://www.dnsbl.com" },
		{
			label: "multirbl.valli.org zone liveness",
			url: "https://multirbl.valli.org",
		},
	],
	"PS-12": [
		{
			label: "dnswl.org self-registration (free)",
			url: "https://www.dnswl.org",
		},
	],
	"PS-13": [
		{
			label: "RFC 6471 — never pay for delisting",
			url: "https://www.rfc-editor.org/rfc/rfc6471",
		},
	],
};

/** States whose evidence is not DNS-queryable — the §21.3 manual step replaces the re-run. */
const MANUAL_RERUN_NOTE: Partial<Record<ProblemStateId, string>> = {
	"PS-8":
		"Provider-side reputation has no DNS zone to re-query — check the portal ↗ instead.",
	"PS-11":
		"Domain age is a waiting game — nothing to re-run; the gates expire on their own.",
};

function queryNameOf(r: BlacklistZoneResult): string {
	return r.kind === "ip"
		? `${r.target.split(".").reverse().join(".")}.${r.zone}`
		: `${r.target}.${r.zone}`;
}

/** The results[]/zone_health rows that triggered this state in the viewed run (§20.5 block 2). */
function evidenceRows(
	run: BlacklistRunResults,
	psId: ProblemStateId,
): BlacklistZoneResult[] {
	if (psId === "PS-9")
		return run.results.filter((r) => r.refusal_code !== null);
	return run.results.filter((r) => r.listed && r.problem_state === psId);
}

function statesOf(run: BlacklistRunResults): ProblemStateId[] {
	return run.problem_states ?? run.summary.problem_states ?? [];
}

export function BlacklistStatePage() {
	const params = useParams({ strict: false }) as {
		id?: string;
		runId?: string;
		domain?: string;
		psId?: string;
	};
	const psId = params.psId ?? "";
	const { data: domains } = useDomains();
	const scope = useScopedBlacklistRun();
	const recheck = useBlacklistRecheck();
	const [live, setLive] = useState<BlacklistLiveRecheck | null>(null);
	const ps = problemState(psId);

	// ---- the legacy /blacklists/$domain/state/$psId shorthand redirects into the alias (AC 25) ---
	if (params.domain && domains !== undefined) {
		const record = domains.find((d) => d.name === params.domain);
		if (record) {
			return (
				<Navigate
					to="/domains/$id/blacklists/state/$psId"
					params={{ id: record.id, psId }}
					replace
				/>
			);
		}
		// Domain not (or no longer) monitored — render by name so persisted runs stay reachable.
	}

	// §20.8 loading — skeletons sized to the final layout, never a blank screen.
	if (scope.isLoading || !scope.domainsLoaded) {
		return (
			<div className="mx-auto max-w-3xl space-y-4">
				{[0, 1, 2, 3].map((i) => (
					<div key={i} className="h-24 animate-pulse rounded-lg bg-slate-100" />
				))}
			</div>
		);
	}

	const backTo = scope.domainId ? (
		scope.runId ? (
			<Link
				to="/domains/$id/runs/$runId/blacklists"
				params={{ id: scope.domainId, runId: scope.runId }}
				className="text-sm text-[var(--edh-primary)]"
			>
				‹ Back to this run's Blacklists page
			</Link>
		) : (
			<Link
				to="/domains/$id/blacklists"
				params={{ id: scope.domainId }}
				className="text-sm text-[var(--edh-primary)]"
			>
				‹ Back to the Blacklists page
			</Link>
		)
	) : (
		<Link to="/blacklists" className="text-sm text-[var(--edh-primary)]">
			‹ Back to Blacklists
		</Link>
	);

	// §20.8 unknown-param state — name the bad param and link back; never a blank screen.
	if (!ps) {
		return (
			<div className="mx-auto max-w-3xl">
				{backTo}
				<h1 className="mt-2 text-2xl font-bold">Unknown problem state</h1>
				<p className="mt-2 rounded-lg border border-dashed border-[var(--edh-border)] p-6 text-sm text-[var(--edh-muted)]">
					No problem state named <span className="font-mono">{psId}</span>{" "}
					exists. The catalog is {Object.keys(PROBLEM_STATES).join(", ")}.
				</p>
			</div>
		);
	}

	const run = scope.run;
	const detected = run ? statesOf(run).includes(ps.id) : false;
	const evidence = run ? evidenceRows(run, ps.id) : [];
	const firstIp = run?.targets.ips[0]?.ip;
	const substitute = (cmd: string) =>
		cmd
			.replaceAll("<domain>", scope.domainName ?? "<domain>")
			.replaceAll("<ip>", firstIp ?? "<ip>")
			.replaceAll(
				"<reversed-ip>",
				firstIp ? firstIp.split(".").reverse().join(".") : "<reversed-ip>",
			);

	// ---- §21.3 the state-scoped re-run: exactly this state's evidence (zone × target) pairs ------
	const manualNote = MANUAL_RERUN_NOTE[ps.id];
	const rerunZones = [...new Set(evidence.map((r) => r.zone))];
	const rerunTargets = [...new Set(evidence.map((r) => r.target))];
	const canRerun =
		!manualNote && rerunZones.length > 0 && rerunTargets.length > 0;
	const rerunNow = async () => {
		if (!scope.domainName) return;
		try {
			const res = await recheck.mutateAsync({
				domain: scope.domainName,
				zones: rerunZones,
				targets: rerunTargets,
			});
			setLive(res);
			const changed = res.results.filter(
				(r) => r.change === "now_listed" || r.change === "now_clean",
			).length;
			toast.success(
				changed > 0
					? `Re-checked ${res.summary.pairs_queried} pair(s) — ${changed} change(s)`
					: "Re-checked — no change",
			);
		} catch (err) {
			toast.error(
				`Live recheck failed: ${err instanceof Error ? err.message : String(err)} — retry?`,
			);
		}
	};

	// History: which of the last 30 runs had this state active (§20.5), points navigate per run.
	const historyRuns = [...scope.domainRuns]
		.filter((r) => r.runId)
		.reverse()
		.slice(-30);
	const activeCount = historyRuns.filter((r) =>
		(r.results?.blacklist ? statesOf(r.results.blacklist) : []).includes(ps.id),
	).length;

	const references = STATE_REFERENCES[ps.id] ?? [];

	return (
		<div className="mx-auto max-w-3xl">
			{backTo}

			<div className="mt-2 flex items-center gap-3">
				<SeverityBadge severity={ps.severity} />
				<h1 className="text-2xl font-bold">
					{ps.id}: {ps.name}
				</h1>
			</div>
			<p className="mt-1 text-sm text-[var(--edh-muted)]">
				Trigger: {ps.trigger}
			</p>

			{/* §20.2 point 1 — what this is */}
			<section className="mt-5 rounded-lg border border-[var(--edh-border)] bg-white p-4">
				<h2 className="mb-1 font-semibold">What this is</h2>
				<p className="text-sm text-slate-700">{ps.concept}</p>
			</section>

			{/* §20.2 point 2 — is it healthy right now? Always answers for the viewed run. */}
			<section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
				<h2 className="mb-1 font-semibold">
					Is it healthy right now?
					{run && (
						<span className="ml-2 text-xs font-normal text-slate-500">
							run {new Date(run.ran_at).toLocaleString()}
						</span>
					)}
				</h2>
				{!run ? (
					<p className="text-sm text-[var(--edh-muted)]">
						No run to compare against — run a blacklist check first; this page
						still teaches the concept above.
					</p>
				) : detected ? (
					<p className="text-sm font-semibold text-red-700">
						{ps.id} is active in this run.
					</p>
				) : (
					<p className="text-sm text-emerald-700">
						{ps.id} was not detected in this run.
					</p>
				)}
				{evidence.length > 0 && (
					<div className="mt-2 space-y-2">
						{evidence.map((r) => {
							const raw = `${queryNameOf(r)} → ${r.return_code ?? r.refusal_code ?? "NXDOMAIN"}${r.reason_txt ? `\nTXT: ${r.reason_txt}` : ""}`;
							return (
								<div key={`${r.zone}|${r.target}`}>
									{/* §20.6 raw first — the ground truth, copyable */}
									<button
										type="button"
										onClick={() => navigator.clipboard?.writeText(raw)}
										title="Click to copy"
										className="block w-full overflow-x-auto whitespace-pre rounded-md bg-slate-900 p-2 text-left font-mono text-xs text-slate-100"
									>
										{raw}
									</button>
									{/* §20.6 parsed second — field by field */}
									<table className="mt-1 w-full text-xs">
										<tbody>
											<tr className="border-b border-[var(--edh-border)]">
												<td className="py-0.5 pr-2 text-slate-500">Zone</td>
												<td className="py-0.5 font-mono">
													{scope.domainId ? (
														<Link
															to={
																scope.runId
																	? "/domains/$id/runs/$runId/blacklists/zone/$zoneId"
																	: "/domains/$id/blacklists/zone/$zoneId"
															}
															params={{
																id: scope.domainId,
																...(scope.runId ? { runId: scope.runId } : {}),
																zoneId: r.zone,
															}}
															className="text-[var(--edh-primary)] underline"
														>
															{r.zone}
														</Link>
													) : (
														r.zone
													)}{" "}
													<span className="text-slate-400">
														({r.tier} tier)
													</span>
												</td>
											</tr>
											<tr className="border-b border-[var(--edh-border)]">
												<td className="py-0.5 pr-2 text-slate-500">Target</td>
												<td className="py-0.5 font-mono">
													{scope.domainId ? (
														<Link
															to={
																scope.runId
																	? "/domains/$id/runs/$runId/blacklists/target/$target"
																	: "/domains/$id/blacklists/target/$target"
															}
															params={{
																id: scope.domainId,
																...(scope.runId ? { runId: scope.runId } : {}),
																target: r.target,
															}}
															className="text-[var(--edh-primary)] underline"
														>
															{r.target}
														</Link>
													) : (
														r.target
													)}
												</td>
											</tr>
											<tr className="border-b border-[var(--edh-border)]">
												<td className="py-0.5 pr-2 text-slate-500">Answer</td>
												<td className="py-0.5">
													<span className="font-mono">
														{r.return_code ?? r.refusal_code ?? "NXDOMAIN"}
													</span>{" "}
													{r.refusal_code
														? "— query refused: inconclusive, never a listing"
														: r.sub_list
															? `= ${r.sub_list}`
															: ""}
													<SeverityBadge severity={r.severity ?? "info"} />
												</td>
											</tr>
											{r.listed && (
												<tr>
													<td className="py-0.5 pr-2 text-slate-500">Delist</td>
													<td className="py-0.5">
														<a
															href={r.delist_url}
															target="_blank"
															rel="noreferrer"
															className="inline-flex items-center gap-1 text-[var(--edh-primary)] underline"
														>
															{r.delist_url}{" "}
															<ExternalLink className="h-3 w-3" />
														</a>
													</td>
												</tr>
											)}
										</tbody>
									</table>
								</div>
							);
						})}
					</div>
				)}
				{live && (
					<div className="mt-3 rounded-lg border border-sky-200 bg-sky-50 p-3">
						<p className="text-xs font-semibold text-sky-900">
							live recheck{" "}
							{new Date(live.checked_at).toLocaleTimeString([], {
								hour: "2-digit",
								minute: "2-digit",
							})}{" "}
							— ephemeral, the stored run is untouched
						</p>
						<ul className="mt-1 space-y-0.5 text-xs">
							{live.results.map((r) => {
								const chip = CHANGE_CHIP[r.change] ?? CHANGE_CHIP.unchanged;
								return (
									<li
										key={`${r.zone}|${r.target}`}
										className="flex items-center gap-2"
									>
										<span className="font-mono">{r.zone}</span>
										<span className="font-mono">{r.target}</span>
										<span
											className={cn("rounded px-1.5 font-medium", chip.cls)}
										>
											{chip.label}
										</span>
									</li>
								);
							})}
						</ul>
					</div>
				)}
			</section>

			{/* §20.2 point 3 — what it means for your deliverability */}
			<section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
				<h2 className="mb-1 font-semibold">
					What it means for your deliverability
				</h2>
				<p className="text-sm text-slate-700">
					Default severity after per-zone weighting:{" "}
					<SeverityBadge severity={ps.severity} />{" "}
					{ps.severity === "critical"
						? "— a listing in this class measurably hurts placement at the major receivers (Gmail, Microsoft, Yahoo) until fixed and delisted."
						: ps.severity === "warning"
							? "— receivers score on this class; placement degrades but usually recovers once the cause stops (many of these listings auto-expire)."
							: "— informational: near-zero real-world impact at major receivers on its own; it never turns the Blacklists cell amber or red by itself."}
				</p>
			</section>

			{/* §20.2 point 4 — what you can do about it */}
			<section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
				<h2 className="mb-2 font-semibold">What you can do about it</h2>
				<ol className="list-decimal space-y-1 pl-5 text-sm text-slate-700">
					{ps.progress.map((step) => (
						<li key={step}>{step}</li>
					))}
				</ol>
				<h3 className="mt-3 mb-1 flex items-center gap-2 text-sm font-semibold">
					<Terminal className="h-4 w-4" /> Diagnose it yourself
				</h3>
				<button
					type="button"
					onClick={() =>
						navigator.clipboard?.writeText(
							ps.diagnose.map((c) => substitute(c)).join("\n"),
						)
					}
					title="Click to copy"
					className="block w-full overflow-x-auto whitespace-pre rounded-md bg-slate-900 p-3 text-left text-xs text-slate-100"
				>
					{ps.diagnose.map((c) => substitute(c)).join("\n")}
				</button>
				<p className="mt-2 text-xs text-[var(--edh-muted)]">
					Tools: {ps.tools.join(" · ")}
				</p>
				<h3 className="mt-3 mb-1 text-sm font-semibold">
					More health metrics to test
				</h3>
				<ul className="list-disc space-y-1 pl-5 text-sm text-slate-700">
					{ps.furtherHealth.map((m) => (
						<li key={m}>{m}</li>
					))}
				</ul>
			</section>

			{/* History — the runs in which this state was active (§20.5) */}
			{historyRuns.length > 1 && (
				<section className="mt-4">
					<h2 className="mb-2 text-sm font-semibold text-slate-600">
						Active in {activeCount} of the last {historyRuns.length} runs
					</h2>
					<div className="flex h-10 items-end gap-1">
						{historyRuns.map((r) => {
							const active = (
								r.results?.blacklist ? statesOf(r.results.blacklist) : []
							).includes(ps.id);
							return (
								<Link
									key={r.runId ?? r.ranAt}
									to="/domains/$id/runs/$runId/blacklists/state/$psId"
									params={{
										id: scope.domainId ?? "",
										runId: r.runId ?? "",
										psId: ps.id,
									}}
									title={`${new Date(r.ranAt).toLocaleString()}: ${active ? "active" : "not detected"}${r.scope ? " (blacklists-only run)" : ""}`}
									className={cn(
										"w-3 rounded-t",
										active ? "bg-red-600" : "bg-emerald-500",
										r.scope && "ring-1 ring-sky-400",
									)}
									style={{ height: active ? "100%" : "40%" }}
								/>
							);
						})}
					</div>
				</section>
			)}

			{/* §20.7 references */}
			<section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
				<h2 className="mb-1 font-semibold">References</h2>
				<ul className="space-y-1 text-sm">
					<li>
						<a
							href="https://www.rfc-editor.org/rfc/rfc5782"
							target="_blank"
							rel="noreferrer"
							className="inline-flex items-center gap-1 text-[var(--edh-primary)] underline"
						>
							RFC 5782 — DNS blocklist query mechanics{" "}
							<ExternalLink className="h-3 w-3" />
						</a>
					</li>
					{references.map((ref) => (
						<li key={ref.url}>
							<a
								href={ref.url}
								target="_blank"
								rel="noreferrer"
								className="inline-flex items-center gap-1 text-[var(--edh-primary)] underline"
							>
								{ref.label} <ExternalLink className="h-3 w-3" />
							</a>
						</li>
					))}
				</ul>
			</section>

			{/* §20.2 point 5 / §21.3 — re-check exactly this state's evidence set */}
			<div className="mt-5 flex flex-wrap items-center gap-2">
				{manualNote ? (
					<p className="text-sm text-[var(--edh-muted)]">{manualNote}</p>
				) : (
					<>
						<button
							type="button"
							onClick={rerunNow}
							disabled={recheck.isPending || !canRerun || !scope.domainName}
							title={
								canRerun
									? `${rerunZones.length} zone(s) × ${rerunTargets.length} target(s)`
									: "No evidence pairs in this run to re-check"
							}
							className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50"
						>
							<RefreshCw
								className={cn(
									"h-3.5 w-3.5",
									recheck.isPending && "animate-spin",
								)}
							/>
							{recheck.isPending
								? "Re-checking evidence…"
								: "Re-check this evidence"}
						</button>
						{canRerun && (
							<span className="text-xs text-[var(--edh-muted)]">
								{rerunZones.length} zone(s) × {rerunTargets.length} target(s)
							</span>
						)}
					</>
				)}
			</div>
		</div>
	);
}
