import { useNavigate } from "@tanstack/react-router";
import { RefreshCw, ShieldCheck, ShieldOff } from "lucide-react";
import { useMemo, useState } from "react";
import { useAuditResults } from "@/api/audit";
import { useDomains } from "@/api/domains";
import type { Severity } from "@/api/types";
import {
	algName,
	compareFleetRows,
	type DnssecFleetRow,
	isDeprecatedAlgo,
	SEV_BADGE,
	SEV_DOT,
	toDnssecFleetRow,
} from "@/lib/dnssec-fleet";
import { cn } from "@/lib/utils";
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext";
import { DnssecFleetHeader } from "./DnssecFleetHeader";

/**
 * DNSSEC fleet view (pm/checks/dnssec.mdx §19.1 / §22.5). One row per domain: signed / DS / validates
 * / algorithm / soonest RRSIG expiry / worst state. Pure roll-up over the newest run per domain
 * (useAuditResults) — no new storage. Row click drills to that domain's DNSSEC explainer.
 */
export function DnssecPage() {
	const { data: results, isLoading: resultsLoading } = useAuditResults();
	const { data: domains, isLoading: domainsLoading } = useDomains();
	const runDomains = useScanRunner();
	const scanning = useScanProgress().length > 0;
	const navigate = useNavigate();
	const [filter, setFilter] = useState<"all" | "signed" | "broken">("all");

	// Rows are frozen at first render's clock so days-to-expiry is stable within a paint.
	const now = useMemo(() => Date.now(), []);
	const rows = useMemo<DnssecFleetRow[]>(() => {
		const list = (results ?? []).map((r) => toDnssecFleetRow(r, now));
		return list.sort(compareFleetRows);
	}, [results, now]);

	const shown = rows.filter((r) => {
		if (filter === "signed") return r.signed;
		if (filter === "broken") return r.severity === "critical";
		return true;
	});

	const nSigned = rows.filter((r) => r.signed).length;
	const nValidate = rows.filter((r) => r.validates === true).length;
	const nBroken = rows.filter((r) => r.severity === "critical").length;
	const nUnsigned = rows.filter((r) => !r.signed && !r.unknown).length;

	const isLoading = resultsLoading || domainsLoading;

	return (
		<div className="mx-auto max-w-6xl px-6 py-6">
			<DnssecFleetHeader active="fleet" />

			{/* Summary chips double as filters (pm/checks/dnssec.mdx §22.5). */}
			<div className="mb-4 flex flex-wrap items-center gap-2">
				<Chip
					label={`${nSigned} signed`}
					active={filter === "signed"}
					onClick={() =>
						setFilter(filter === "signed" ? "all" : "signed")
					}
				/>
				<Chip label={`${nValidate} validate`} />
				<Chip
					label={`${nBroken} broken`}
					tone="critical"
					active={filter === "broken"}
					onClick={() =>
						setFilter(filter === "broken" ? "all" : "broken")
					}
				/>
				<Chip label={`${nUnsigned} unsigned`} tone="info" />
				<button
					type="button"
					disabled={scanning || !(domains ?? []).length}
					onClick={() =>
						runDomains((domains ?? []).map((d) => ({ id: d.id, name: d.name })))
					}
					className="ml-auto inline-flex items-center gap-1.5 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm font-medium hover:bg-[var(--edh-card)] disabled:opacity-50"
				>
					<RefreshCw className={cn("h-4 w-4", scanning && "animate-spin")} />
					Re-check all
				</button>
			</div>

			{isLoading ? (
				<p className="text-sm text-[var(--edh-muted)]">Loading fleet…</p>
			) : rows.length === 0 ? (
				<EmptyState />
			) : (
				<div className="overflow-x-auto rounded-lg border border-[var(--edh-border)]">
					<table className="w-full text-sm">
						<thead>
							<tr className="border-b border-[var(--edh-border)] text-left text-xs uppercase tracking-wide text-[var(--edh-muted)]">
								<th className="px-4 py-2 font-medium">Domain</th>
								<th className="px-4 py-2 font-medium">Signed</th>
								<th className="px-4 py-2 font-medium">DS</th>
								<th className="px-4 py-2 font-medium">Validates</th>
								<th className="px-4 py-2 font-medium">Algorithm</th>
								<th className="px-4 py-2 font-medium">Soonest RRSIG expiry</th>
								<th className="px-4 py-2 font-medium">State</th>
							</tr>
						</thead>
						<tbody>
							{shown.map((r) => (
								<FleetRow
									key={r.domainId}
									row={r}
									onOpen={() =>
										navigate({
											to: "/domains/$id/dns/check/$checkKey",
											params: { id: r.domainId, checkKey: "dnssec" },
										})
									}
								/>
							))}
						</tbody>
					</table>
				</div>
			)}
		</div>
	);
}

function FleetRow({
	row,
	onOpen,
}: {
	row: DnssecFleetRow;
	onOpen: () => void;
}) {
	const expiryLabel = (() => {
		if (row.rrsigEarliestExpiry == null)
			return <span className="text-[var(--edh-muted)]">—</span>;
		const d = row.daysToExpiry;
		const abs = new Date(row.rrsigEarliestExpiry).toISOString().slice(0, 10);
		if (d == null) return abs;
		if (d < 0)
			return <span className="font-medium text-red-700">expired ({abs})</span>;
		return (
			<span>
				{abs}{" "}
				<span className="text-[var(--edh-muted)]">
					(in {d} d)
				</span>
			</span>
		);
	})();

	return (
		<tr
			onClick={onOpen}
			className="cursor-pointer border-b border-[var(--edh-border)] last:border-0 hover:bg-[var(--edh-card)]"
		>
			<td className="px-4 py-2 font-medium">{row.domain}</td>
			<td className="px-4 py-2">
				<Bool
					value={row.unknown ? null : row.signed}
					yes="signed"
					no="unsigned"
				/>
			</td>
			<td className="px-4 py-2">
				<Bool value={row.dsPresent} yes="present" no="missing" />
			</td>
			<td className="px-4 py-2">
				<Bool value={row.validates} yes="AD=1" no="no AD" />
			</td>
			<td className="px-4 py-2">
				{row.algorithms.length ? (
					<span
						className={cn(
							row.algorithms.some(isDeprecatedAlgo) && "text-amber-600",
						)}
					>
						{row.algorithms.map(algName).join(", ")}
					</span>
				) : (
					<span className="text-[var(--edh-muted)]">—</span>
				)}
			</td>
			<td className="px-4 py-2">{expiryLabel}</td>
			<td className="px-4 py-2">
				<StateBadge severity={row.severity} unknown={row.unknown} />
			</td>
		</tr>
	);
}

/** A boolean cell: shield glyph for true, ShieldOff for false, muted em-dash for null/unknown. */
function Bool({
	value,
	yes,
	no,
}: {
	value: boolean | null | undefined;
	yes: string;
	no: string;
}) {
	if (value == null)
		return (
			<span className="text-[var(--edh-muted)]" title="not captured this run">
				—
			</span>
		);
	return value ? (
		<span className="inline-flex items-center gap-1 text-green-700">
			<ShieldCheck className="h-4 w-4" />
			<span className="sr-only sm:not-sr-only sm:text-xs">{yes}</span>
		</span>
	) : (
		<span className="inline-flex items-center gap-1 text-red-700">
			<ShieldOff className="h-4 w-4" />
			<span className="sr-only sm:not-sr-only sm:text-xs">{no}</span>
		</span>
	);
}

function StateBadge({
	severity,
	unknown,
}: {
	severity: Severity;
	unknown: boolean;
}) {
	if (unknown)
		return (
			<span className="inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs bg-gray-200 text-gray-700">
				<span className="h-2 w-2 rounded-full bg-gray-400" />
				unknown
			</span>
		);
	const label =
		severity === "critical"
			? "broken"
			: severity === "warning"
				? "weak"
				: severity === "info"
					? "advisory"
					: "healthy";
	return (
		<span
			className={cn(
				"inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs",
				SEV_BADGE[severity],
			)}
		>
			<span className={cn("h-2 w-2 rounded-full", SEV_DOT[severity])} />
			{label}
		</span>
	);
}

function Chip({
	label,
	tone,
	active,
	onClick,
}: {
	label: string;
	tone?: "critical" | "info";
	active?: boolean;
	onClick?: () => void;
}) {
	const Comp = onClick ? "button" : "span";
	return (
		<Comp
			type={onClick ? "button" : undefined}
			onClick={onClick}
			className={cn(
				"rounded-full border px-3 py-1 text-xs font-medium",
				active
					? "border-[var(--edh-primary)] bg-[var(--edh-primary)] text-white"
					: "border-[var(--edh-border)] text-[var(--edh-fg)]",
				tone === "critical" && !active && "text-red-700",
				tone === "info" && !active && "text-[var(--edh-muted)]",
				onClick && "hover:border-[var(--edh-primary)]",
			)}
		>
			{label}
		</Comp>
	);
}

function EmptyState() {
	return (
		<div className="rounded-lg border border-dashed border-[var(--edh-border)] px-6 py-12 text-center">
			<ShieldCheck className="mx-auto mb-3 h-8 w-8 text-[var(--edh-muted)]" />
			<p className="font-medium">No DNSSEC data yet</p>
			<p className="mt-1 text-sm text-[var(--edh-muted)]">
				Run an audit on your domains to see their DNSSEC posture here.
			</p>
		</div>
	);
}
