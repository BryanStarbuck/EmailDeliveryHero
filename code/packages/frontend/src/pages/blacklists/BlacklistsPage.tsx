import { Link, useNavigate } from "@tanstack/react-router";
import {
	Ban,
	ChevronRight,
	ExternalLink,
	Mailbox,
	RefreshCw,
} from "lucide-react";
import { useBlacklistRegistry, useBlacklistRuns } from "@/api/blacklists";
import { useDomains } from "@/api/domains";
import type {
	BlacklistRunResults,
	BlacklistZoneResult,
	Severity,
} from "@/api/types";
import { ActionLinksRow } from "@/components/ActionLinksRow";
import { cn } from "@/lib/utils";
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext";

/**
 * The Blacklists Dashboard — what the left-bar Blacklists tab opens (pm/checks/blacklists.mdx §17).
 * Fleet-level triage in fixed order: stats strip → Needs-attention table (every listing across all
 * domains, worst first) → Domains grid → email-derived targets strip (§19) → registry health (§18).
 * Pure aggregation over the per-run documents; chevrons drill to /blacklists/:domain.
 */

const RANK: Record<Severity, number> = {
	ok: 0,
	info: 1,
	warning: 2,
	critical: 3,
};

const DOT: Record<Severity, string> = {
	critical: "bg-red-700",
	warning: "bg-amber-500",
	info: "bg-green-700",
	ok: "bg-green-700",
};

const SEVERITY_BADGE: Record<Severity, string> = {
	critical: "bg-red-700 text-white",
	warning: "bg-amber-500 text-black",
	info: "bg-gray-200 text-gray-800",
	ok: "bg-green-700 text-white",
};

interface ListedRow extends BlacklistZoneResult {
	domain: string;
	isNew: boolean;
}

function fleetWorst(runs: BlacklistRunResults[]): Severity {
	let worst: Severity = "ok";
	for (const run of runs) {
		if (RANK[run.summary.worst_severity] > RANK[worst])
			worst = run.summary.worst_severity;
	}
	return worst;
}

function StatTile({
	value,
	label,
	tone,
}: {
	value: string | number;
	label: string;
	tone?: "verdict-bad" | "verdict-warn" | "verdict-ok" | "new";
}) {
	return (
		<div
			className={cn(
				"rounded-lg border border-[var(--edh-border)] px-4 py-3",
				tone === "verdict-bad" && "border-transparent bg-red-700 text-white",
				tone === "verdict-warn" && "border-transparent bg-amber-500 text-black",
				tone === "verdict-ok" && "border-transparent bg-green-700 text-white",
				tone === "new" && "border-amber-500",
			)}
		>
			<div className="text-2xl font-bold leading-tight">{value}</div>
			<div
				className={cn(
					"text-xs",
					tone ? "opacity-90" : "text-[var(--edh-muted)]",
				)}
			>
				{label}
			</div>
		</div>
	);
}

export function BlacklistsPage() {
	const { data: runs, isLoading: runsLoading } = useBlacklistRuns();
	const { data: domains, isLoading: domainsLoading } = useDomains();
	const { data: registry } = useBlacklistRegistry();
	// Manual scans route through the shared per-domain fan-out (pm/progress_ui.mdx §4.1) — never the
	// blocking POST /audit/run — so each domain gets its own "Running <domain>" card in the dock.
	const runDomains = useScanRunner();
	const scanning = useScanProgress().length > 0;
	const navigate = useNavigate();

	const isLoading = runsLoading || domainsLoading;
	const runList = runs ?? [];
	const runByDomain = new Map(runList.map((r) => [r.domain, r]));

	// ---- Stats strip ---------------------------------------------------------------------------
	const targetCount = runList.reduce(
		(n, r) => n + r.targets.ips.length + r.targets.domains.length,
		0,
	);
	const listedCount = runList.reduce((n, r) => n + r.summary.listed, 0);
	const inconclusiveCount = runList.reduce(
		(n, r) => n + r.summary.inconclusive,
		0,
	);
	const newCount = runList.reduce((n, r) => n + r.diff.new_listings.length, 0);
	const resolvedCount = runList.reduce((n, r) => n + r.diff.cleared.length, 0);
	const zonesEnabled =
		registry?.zones.filter((z) => z.enabled).length ??
		Math.max(0, ...runList.map((r) => r.summary.zones_enabled));
	const worst = fleetWorst(runList);
	const verdictTone =
		listedCount === 0
			? "verdict-ok"
			: worst === "critical"
				? "verdict-bad"
				: "verdict-warn";

	// ---- Needs attention -----------------------------------------------------------------------
	const listedRows: ListedRow[] = runList
		.flatMap((run) =>
			run.results
				.filter((r) => r.listed)
				.map((r) => ({
					...r,
					domain: run.domain,
					isNew: run.diff.new_listings.some(
						(n) => n.zone === r.zone && n.target === r.target,
					),
				})),
		)
		.sort(
			(a, b) =>
				RANK[b.severity ?? "info"] - RANK[a.severity ?? "info"] ||
				a.tier.localeCompare(b.tier) ||
				a.zone.localeCompare(b.zone),
		);

	// ---- Email-derived targets (§19) -----------------------------------------------------------
	const emailIps = runList.flatMap((run) =>
		run.targets.ips
			.filter((ip) => ip.source === "email_report")
			.map((ip) => ({ run, ip })),
	);
	const emailListed = emailIps.filter(({ run, ip }) =>
		run.results.some((r) => r.target === ip.ip && r.listed),
	);

	// ---- Registry health -----------------------------------------------------------------------
	const enabledIp =
		registry?.zones.filter((z) => z.enabled && z.kind === "ip").length ?? 0;
	const enabledDomain =
		registry?.zones.filter((z) => z.enabled && z.kind === "domain").length ?? 0;
	const blockedZones = [
		...new Set(
			runList.flatMap((r) =>
				r.zone_health.filter((z) => z.status === "blocked").map((z) => z.zone),
			),
		),
	];

	return (
		<div className="mx-auto max-w-5xl">
			<h1 className="text-2xl font-bold">Blacklists</h1>
			{/* Page action in the house action-links row directly under the title (pm/page_actions.mdx)
			    — "Re-check all" is an operational re-run, not a create CTA, so it belongs here as a link. */}
			<ActionLinksRow
				className="mb-2 mt-1"
				actions={[
					{
						label: scanning ? "Re-checking…" : "Re-check all",
						icon: RefreshCw,
						busy: scanning,
						disabled: scanning || (domains ?? []).length === 0,
						title: "Re-run blocklist checks for every monitored domain",
						onClick: () =>
							runDomains(
								(domains ?? []).map((d) => ({ id: d.id, name: d.name })),
							),
					},
				]}
			/>
			<p className="mb-6 text-sm text-[var(--edh-muted)]">
				Fleet-wide blocklist status: every listing across every monitored
				domain, the fix for each, and what the registry could and couldn't
				query.
			</p>

			{isLoading ? (
				<p className="text-sm text-[var(--edh-muted)]">Loading…</p>
			) : (domains ?? []).length === 0 ? (
				<p className="rounded-lg border border-dashed border-[var(--edh-border)] p-8 text-center text-[var(--edh-muted)]">
					No domains monitored yet —{" "}
					<Link
						to="/domains"
						className="font-semibold text-green-700 underline"
					>
						add a domain
					</Link>{" "}
					to start checking blacklists.
				</p>
			) : (
				<div className="space-y-8">
					{/* 1 — Stats strip */}
					<div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
						<StatTile value={(domains ?? []).length} label="domains" />
						<StatTile value={targetCount} label="targets checked" />
						<StatTile value={zonesEnabled} label="zones enabled" />
						<StatTile value={listedCount} label="listed" tone={verdictTone} />
						<StatTile
							value={
								newCount > 0
									? `▲ ${newCount}`
									: resolvedCount > 0
										? `▼ ${resolvedCount}`
										: "—"
							}
							label={
								newCount > 0
									? "new listings"
									: resolvedCount > 0
										? "resolved"
										: "unchanged"
							}
							tone={newCount > 0 ? "new" : undefined}
						/>
						<StatTile value={inconclusiveCount} label="unknown (resolver)" />
					</div>

					{/* 2 — Needs attention */}
					<section>
						<h2 className="mb-2 text-lg font-semibold">
							Needs attention{" "}
							{listedRows.length > 0 && `(${listedRows.length})`}
						</h2>
						{listedRows.length === 0 ? (
							<p className="rounded-lg border border-[var(--edh-border)] bg-green-50 p-4 text-sm text-green-900">
								No listings across {zonesEnabled} zones ×{" "}
								{targetCount || "your"} targets.
							</p>
						) : (
							<div className="overflow-x-auto rounded-lg border border-[var(--edh-border)]">
								<table className="w-full text-sm">
									<thead>
										<tr className="border-b border-[var(--edh-border)] text-left text-xs text-[var(--edh-muted)]">
											<th className="px-3 py-2">Severity</th>
											<th className="px-3 py-2">Domain</th>
											<th className="px-3 py-2">List (tier)</th>
											<th className="px-3 py-2">Target</th>
											<th className="px-3 py-2">Meaning</th>
											<th className="px-3 py-2">Fix</th>
											<th className="px-3 py-2" />
										</tr>
									</thead>
									<tbody>
										{listedRows.map((row) => (
											<tr
												key={`${row.domain}|${row.zone}|${row.target}`}
												className="cursor-pointer border-b border-[var(--edh-border)] last:border-0 hover:bg-gray-50"
												onClick={() =>
													navigate({
														to: "/blacklists/$domain",
														params: { domain: row.domain },
													})
												}
											>
												<td className="px-3 py-2">
													<span
														className={cn(
															"rounded px-2 py-0.5 text-xs font-semibold",
															SEVERITY_BADGE[row.severity ?? "info"],
														)}
													>
														{(row.severity ?? "info").toUpperCase()}
													</span>
													{row.isNew && (
														<span className="ml-2 text-xs font-semibold text-amber-600">
															▲ NEW
														</span>
													)}
												</td>
												<td className="px-3 py-2 font-medium">{row.domain}</td>
												<td className="px-3 py-2">
													{row.name}{" "}
													<span className="rounded border border-[var(--edh-border)] px-1 text-[10px] uppercase text-[var(--edh-muted)]">
														{row.tier}
													</span>
												</td>
												<td className="px-3 py-2 font-mono text-xs">
													{row.target}
												</td>
												<td className="max-w-56 truncate px-3 py-2 text-xs">
													{row.sub_list ?? row.return_code ?? "listed"}
												</td>
												<td className="px-3 py-2">
													<a
														href={row.delist_url}
														target="_blank"
														rel="noreferrer"
														onClick={(e) => e.stopPropagation()}
														className="inline-flex items-center gap-1 text-xs font-semibold text-green-700 underline"
													>
														Delist <ExternalLink className="h-3 w-3" />
													</a>
												</td>
												<td className="px-3 py-2">
													<ChevronRight className="h-4 w-4 text-[var(--edh-muted)]" />
												</td>
											</tr>
										))}
									</tbody>
								</table>
							</div>
						)}
					</section>

					{/* 3 — Domains grid */}
					<section>
						<h2 className="mb-2 text-lg font-semibold">
							Domains ({(domains ?? []).length})
						</h2>
						<div className="divide-y divide-[var(--edh-border)] rounded-lg border border-[var(--edh-border)]">
							{(domains ?? []).map((d) => {
								const run = runByDomain.get(d.name);
								if (!run) {
									return (
										<div
											key={d.id}
											className="flex items-center justify-between px-4 py-3"
										>
											<div className="flex items-center gap-3">
												<span className="h-2.5 w-2.5 rounded-full bg-gray-300" />
												<span className="font-medium">{d.name}</span>
												<span className="text-xs text-[var(--edh-muted)]">
													never checked
												</span>
											</div>
											<button
												type="button"
												onClick={() => runDomains([{ id: d.id, name: d.name }])}
												disabled={scanning}
												className="rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-semibold hover:bg-gray-50 disabled:opacity-50"
											>
												Run check
											</button>
										</div>
									);
								}
								const hasNew = run.diff.new_listings.length > 0;
								const hasResolved = run.diff.cleared.length > 0;
								return (
									<Link
										key={d.id}
										to="/blacklists/$domain"
										params={{ domain: d.name }}
										className="flex items-center justify-between px-4 py-3 hover:bg-gray-50"
									>
										<div className="flex items-center gap-3">
											<span
												className={cn(
													"h-2.5 w-2.5 rounded-full",
													DOT[run.summary.worst_severity],
												)}
											/>
											<span className="font-medium">{run.domain}</span>
											<span className="text-xs text-[var(--edh-muted)]">
												{run.summary.listed} listed · {run.summary.clean} clean
												· {run.summary.inconclusive} unknown
											</span>
										</div>
										<div className="flex items-center gap-3 text-xs text-[var(--edh-muted)]">
											{hasNew && (
												<span className="font-semibold text-amber-600">
													▲ new
												</span>
											)}
											{!hasNew && hasResolved && (
												<span className="font-semibold text-green-700">
													▼ resolved
												</span>
											)}
											<span>
												{new Date(run.ran_at).toLocaleTimeString([], {
													hour: "2-digit",
													minute: "2-digit",
												})}
											</span>
											<ChevronRight className="h-4 w-4" />
										</div>
									</Link>
								);
							})}
						</div>
					</section>

					{/* 4 — Email-derived targets (§19; hidden until report emails are ingested) */}
					{emailIps.length > 0 && (
						<section className="rounded-lg border border-[var(--edh-border)] px-4 py-3">
							<div className="flex items-center gap-2 text-sm">
								<Mailbox className="h-4 w-4 text-[var(--edh-muted)]" />
								<span className="font-semibold">Email-derived targets:</span>
								<span>
									{emailIps.length} IP{emailIps.length === 1 ? "" : "s"} seen
									sending as your domains in DMARC reports
								</span>
								<span
									className={cn(
										"rounded px-2 py-0.5 text-xs font-semibold",
										emailListed.length > 0
											? SEVERITY_BADGE.warning
											: SEVERITY_BADGE.ok,
									)}
								>
									{emailListed.length} listed
								</span>
							</div>
						</section>
					)}

					{/* 5 — Registry health (§18) */}
					{registry && (
						<section className="rounded-lg border border-[var(--edh-border)] px-4 py-3 text-sm">
							<div className="flex flex-wrap items-center gap-x-2 gap-y-1">
								<Ban className="h-4 w-4 text-[var(--edh-muted)]" />
								<span className="font-semibold">Registry health:</span>
								<span>
									{registry.lists_total} lists in registry ·{" "}
									{enabledIp + enabledDomain} enabled ({enabledIp} IP ·{" "}
									{enabledDomain} domain) · {registry.dead_zones.length} dead
									(never queried)
								</span>
								{blockedZones.length > 0 && (
									<span className="font-semibold text-amber-600">
										· {blockedZones.length} blocked this run (resolver)
									</span>
								)}
								<span className="text-xs text-[var(--edh-muted)]">
									blacklists.yaml · compiled {registry.compiled}
								</span>
							</div>
						</section>
					)}
				</div>
			)}
		</div>
	);
}
