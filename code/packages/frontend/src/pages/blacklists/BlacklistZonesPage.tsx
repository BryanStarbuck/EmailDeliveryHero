import { Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import {
	useBlacklistRegistry,
	useBlacklistRuns,
	useUpdateBlacklistZone,
} from "@/api/blacklists";
import type { BlocklistZoneRow, ZoneHealthStatus } from "@/api/types";
import { cn } from "@/lib/utils";

/**
 * The admin "Blocklist Zones" panel (pm/checks/blacklists.mdx §4 "Dedicated panel", §18.2):
 * every effective registry row with zone host, kind, tier, weight (editable), delisting URL,
 * requires-registration / paid chips, an enable/disable toggle, and a per-zone RFC 5782
 * "test point OK / unavailable" health dot from the latest runs. Edits write operator
 * overrides to <stateDir>/blacklist_zones.yaml — never the checked-in registry — and a zone
 * on the dead-zone registry can never be enabled from anywhere.
 */

const TIER_ORDER = { high: 0, medium: 1, low: 2 } as const;

const HEALTH_DOT: Record<ZoneHealthStatus, { cls: string; label: string }> = {
	ok: { cls: "bg-emerald-500", label: "test point OK" },
	slow: { cls: "bg-amber-400", label: "test point slow" },
	blocked: { cls: "bg-amber-500", label: "queries refused (resolver blocked)" },
	dead: { cls: "bg-red-600", label: "test point failed — zone dead?" },
	wildcarding: { cls: "bg-red-600", label: "wildcarding — lists the world" },
};

function WeightCell({
	row,
	onSave,
	saving,
}: {
	row: BlocklistZoneRow;
	onSave: (weight: number) => void;
	saving: boolean;
}) {
	const [value, setValue] = useState(String(row.weight));
	const parsed = Number(value);
	const valid = Number.isFinite(parsed) && parsed >= 0 && parsed <= 1;
	const dirty = valid && parsed !== row.weight;
	return (
		<span className="inline-flex items-center gap-1">
			<input
				type="number"
				min={0}
				max={1}
				step={0.05}
				value={value}
				onChange={(e) => setValue(e.target.value)}
				className={cn(
					"w-16 rounded border px-1 py-0.5 font-mono text-xs",
					valid ? "border-[var(--edh-border)]" : "border-red-500",
				)}
				aria-label={`Weight for ${row.zone}`}
			/>
			{dirty && (
				<button
					type="button"
					disabled={saving}
					onClick={() => onSave(parsed)}
					className="rounded bg-[var(--edh-primary)] px-1.5 py-0.5 text-[10px] font-semibold text-white disabled:opacity-50"
				>
					Save
				</button>
			)}
		</span>
	);
}

export function BlacklistZonesPage() {
	const { data: registry, isLoading } = useBlacklistRegistry();
	const { data: runs } = useBlacklistRuns();
	const update = useUpdateBlacklistZone();

	// Latest observed RFC 5782 health per zone across every domain's newest run.
	const healthByZone = useMemo(() => {
		const map = new Map<string, ZoneHealthStatus>();
		for (const run of runs ?? []) {
			for (const h of run.zone_health) map.set(h.zone, h.status);
		}
		return map;
	}, [runs]);

	const zones = useMemo(
		() =>
			[...(registry?.zones ?? [])].sort(
				(a, b) =>
					TIER_ORDER[a.tier] - TIER_ORDER[b.tier] ||
					a.zone.localeCompare(b.zone) ||
					a.kind.localeCompare(b.kind),
			),
		[registry],
	);

	return (
		<div className="mx-auto max-w-5xl">
			<Link to="/blacklists" className="text-sm text-[var(--edh-primary)]">
				‹ Back to Blacklists
			</Link>
			<h1 className="mt-1 text-2xl font-bold">Blocklist Zones</h1>
			<p className="mb-4 mt-1 text-sm text-[var(--edh-muted)]">
				The effective zone catalog — the checked-in <code>blacklists.yaml</code>{" "}
				registry merged with your operator overrides. Toggling or re-weighting a
				zone writes an override to the state directory; the checked-in registry
				is never edited at runtime. Zones on the dead-zone registry are
				hard-blocked and never queried.
			</p>

			{isLoading || !registry ? (
				<p className="text-sm text-[var(--edh-muted)]">Loading…</p>
			) : (
				<>
					<div className="overflow-x-auto rounded-lg border border-[var(--edh-border)] bg-white">
						<table className="w-full text-sm">
							<thead>
								<tr className="border-b border-[var(--edh-border)] text-left text-xs text-[var(--edh-muted)]">
									<th className="px-3 py-2">Health</th>
									<th className="px-3 py-2">Zone</th>
									<th className="px-3 py-2">Kind</th>
									<th className="px-3 py-2">Tier</th>
									<th className="px-3 py-2">Weight</th>
									<th className="px-3 py-2">Access</th>
									<th className="px-3 py-2">Delisting</th>
									<th className="px-3 py-2">Enabled</th>
								</tr>
							</thead>
							<tbody>
								{zones.map((z) => {
									const health = healthByZone.get(z.zone);
									const dot = health ? HEALTH_DOT[health] : null;
									return (
										<tr
											key={`${z.zone}|${z.kind}`}
											className="border-b border-[var(--edh-border)] last:border-b-0"
										>
											<td className="px-3 py-1.5">
												<span
													className={cn(
														"inline-block h-2.5 w-2.5 rounded-full",
														dot?.cls ?? "bg-gray-300",
													)}
													title={dot?.label ?? "not probed yet"}
												/>
											</td>
											<td className="px-3 py-1.5">
												<span className="font-mono text-xs">{z.zone}</span>
												<span className="ml-2 text-xs text-[var(--edh-muted)]">
													{z.name}
												</span>
											</td>
											<td className="px-3 py-1.5">
												<span className="rounded border border-[var(--edh-border)] px-1 text-[10px] uppercase text-[var(--edh-muted)]">
													{z.kind}
												</span>
											</td>
											<td className="px-3 py-1.5 text-xs uppercase text-[var(--edh-muted)]">
												{z.tier}
											</td>
											<td className="px-3 py-1.5">
												<WeightCell
													row={z}
													saving={update.isPending}
													onSave={(weight) =>
														update.mutate({
															zone: z.zone,
															kind: z.kind,
															weight,
														})
													}
												/>
											</td>
											<td className="px-3 py-1.5">
												{z.requires_registration && (
													<span className="mr-1 rounded bg-amber-100 px-1.5 text-[10px] font-medium text-amber-800">
														registration
													</span>
												)}
												{z.is_paid && (
													<span className="mr-1 rounded bg-purple-100 px-1.5 text-[10px] font-medium text-purple-800">
														paid
													</span>
												)}
												{z.paid_delist_offered && (
													<span
														className="mr-1 rounded bg-red-100 px-1.5 text-[10px] font-medium text-red-800"
														title="Operator sells 'express' delisting — never pay (RFC 6471)"
													>
														pay-to-delist
													</span>
												)}
												{z.positive && (
													<span className="rounded bg-emerald-100 px-1.5 text-[10px] font-medium text-emerald-800">
														positive
													</span>
												)}
											</td>
											<td className="px-3 py-1.5">
												<a
													href={z.delist_url}
													target="_blank"
													rel="noreferrer"
													className="text-xs text-[var(--edh-primary)] underline"
												>
													delist ↗
												</a>
											</td>
											<td className="px-3 py-1.5">
												<button
													type="button"
													role="switch"
													aria-checked={z.enabled}
													disabled={update.isPending}
													onClick={() =>
														update.mutate({
															zone: z.zone,
															kind: z.kind,
															enabled: !z.enabled,
														})
													}
													className={cn(
														"relative h-5 w-9 rounded-full transition-colors disabled:opacity-50",
														z.enabled
															? "bg-[var(--edh-primary)]"
															: "bg-gray-300",
													)}
													title={
														z.enabled
															? "Enabled — click to disable"
															: "Disabled — click to enable"
													}
												>
													<span
														className={cn(
															"absolute left-0.5 top-0.5 h-4 w-4 rounded-full bg-white transition-transform",
															z.enabled && "translate-x-4",
														)}
													/>
												</button>
											</td>
										</tr>
									);
								})}
							</tbody>
						</table>
					</div>

					{/* Dead-zone registry (§9.5) — hard-blocked, never queryable from anywhere. */}
					<section className="mt-6 rounded-lg border border-[var(--edh-border)] bg-white p-4">
						<h2 className="mb-1 font-semibold">
							Dead zones — never queried ({registry.dead_zones.length})
						</h2>
						<p className="mb-2 text-xs text-[var(--edh-muted)]">
							Dead lists sometimes wildcard on shutdown and "list the world".
							These zones are hard-blocked: they cannot be enabled from any
							override.
						</p>
						<ul className="grid grid-cols-1 gap-x-6 gap-y-1 text-xs sm:grid-cols-2">
							{registry.dead_zones.map((d) => (
								<li key={d.zone} className="flex items-baseline gap-2">
									<span className="font-mono">{d.zone}</span>
									<span className="text-[var(--edh-muted)]">
										{d.name}
										{d.died ? ` — died ${d.died}` : ""}
									</span>
								</li>
							))}
						</ul>
					</section>
				</>
			)}
		</div>
	);
}
