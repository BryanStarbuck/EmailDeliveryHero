import { useNavigate } from "@tanstack/react-router";
import { Clock, RefreshCw } from "lucide-react";
import { useMemo } from "react";
import { useAuditResults } from "@/api/audit";
import { useDomains } from "@/api/domains";
import {
	type DnssecFleetRow,
	SEV_DOT,
	toDnssecFleetRow,
} from "@/lib/dnssec-fleet";
import { cn } from "@/lib/utils";
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext";
import { DnssecFleetHeader } from "./DnssecFleetHeader";

/**
 * RRSIG expiry radar (pm/checks/dnssec.mdx §19.2 / §22.6). The early-warning board for the
 * silent-march-to-outage failure mode — a stalled re-signing job. Every signed domain whose earliest
 * RRSIG is expiring, sorted soonest-first; past-due pins to the top. "Re-check expiring" re-runs the
 * fleet's near-threshold domains.
 */

// The default near-expiry lead time (pm/checks/dnssec.mdx §4, config `checks.dnssec.rrsigLeadHours`).
const LEAD_DAYS = 3;

export function DnssecExpiryPage() {
	const { data: results, isLoading } = useAuditResults();
	const { data: domains } = useDomains();
	const runDomains = useScanRunner();
	const scanning = useScanProgress().length > 0;
	const navigate = useNavigate();

	const now = useMemo(() => Date.now(), []);
	const rows = useMemo<DnssecFleetRow[]>(() => {
		return (results ?? [])
			.map((r) => toDnssecFleetRow(r, now))
			// Only signed zones with a captured expiry belong on the radar.
			.filter((r) => r.signed && r.daysToExpiry != null)
			.sort((a, b) => (a.daysToExpiry ?? 0) - (b.daysToExpiry ?? 0));
	}, [results, now]);

	const expiring = rows.filter((r) => (r.daysToExpiry ?? 999) <= LEAD_DAYS);
	const expiringDomains = expiring
		.map((r) => (domains ?? []).find((d) => d.id === r.domainId))
		.filter((d): d is NonNullable<typeof d> => !!d)
		.map((d) => ({ id: d.id, name: d.name }));

	return (
		<div className="mx-auto max-w-6xl px-6 py-6">
			<DnssecFleetHeader active="expiry" />

			<div className="mb-4 flex items-center gap-3">
				<p className="text-sm text-[var(--edh-muted)]">
					RRSIGs expire on a schedule; a stalled re-signing job walks them to
					expiry and the whole zone goes bogus. Anything red is at or past the{" "}
					{LEAD_DAYS}-day lead time.
				</p>
				<button
					type="button"
					disabled={scanning || expiringDomains.length === 0}
					onClick={() => runDomains(expiringDomains)}
					className="ml-auto inline-flex shrink-0 items-center gap-1.5 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm font-medium hover:bg-[var(--edh-card)] disabled:opacity-50"
				>
					<RefreshCw className={cn("h-4 w-4", scanning && "animate-spin")} />
					Re-check expiring
				</button>
			</div>

			{isLoading ? (
				<p className="text-sm text-[var(--edh-muted)]">Loading radar…</p>
			) : rows.length === 0 ? (
				<div className="rounded-lg border border-dashed border-[var(--edh-border)] px-6 py-12 text-center">
					<Clock className="mx-auto mb-3 h-8 w-8 text-[var(--edh-muted)]" />
					<p className="font-medium">Nothing expiring</p>
					<p className="mt-1 text-sm text-[var(--edh-muted)]">
						All signed zones have healthy signature windows (or the deep
						validation path hasn't captured RRSIG expiry yet).
					</p>
				</div>
			) : (
				<ol className="space-y-2">
					{rows.map((r) => (
						<ExpiryRow
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
				</ol>
			)}
		</div>
	);
}

function daysBadge(days: number): { cls: string; label: string } {
	if (days < 0)
		return { cls: "bg-red-700 text-white", label: "expired — zone bogus" };
	if (days <= LEAD_DAYS)
		return { cls: "bg-red-700 text-white", label: `${days} d left` };
	if (days <= 7)
		return { cls: "bg-amber-500 text-black", label: `${days} d left` };
	return { cls: "bg-green-700 text-white", label: `${days} d left` };
}

function ExpiryRow({
	row,
	onOpen,
}: {
	row: DnssecFleetRow;
	onOpen: () => void;
}) {
	const days = row.daysToExpiry ?? 0;
	const badge = daysBadge(days);
	const abs = row.rrsigEarliestExpiry
		? new Date(row.rrsigEarliestExpiry).toISOString().replace("T", " ").slice(0, 16) +
			" UTC"
		: "—";
	return (
		<li
			onClick={onOpen}
			className={cn(
				"flex cursor-pointer items-center gap-3 rounded-lg border border-[var(--edh-border)] px-4 py-3 hover:bg-[var(--edh-card)]",
				days < 0 && "border-l-4 border-l-red-600",
			)}
		>
			<span className={cn("h-2.5 w-2.5 rounded-full", SEV_DOT[row.severity])} />
			<span className="min-w-0 flex-1 truncate font-medium">{row.domain}</span>
			<span
				className={cn(
					"shrink-0 rounded px-2 py-0.5 text-xs font-medium",
					badge.cls,
				)}
			>
				{badge.label}
			</span>
			<span className="hidden shrink-0 text-xs text-[var(--edh-muted)] sm:inline">
				{abs}
			</span>
		</li>
	);
}
