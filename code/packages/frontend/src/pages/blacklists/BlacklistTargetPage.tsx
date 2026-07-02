import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { ExternalLink, RefreshCw } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useBlacklistRecheck, useRunBlacklistsCheck } from "@/api/blacklists";
import type { BlacklistLiveRecheck, BlacklistZoneResult } from "@/api/types";
import { cn } from "@/lib/utils";
import { useScopedBlacklistRun } from "./useScopedBlacklistRun";

/**
 * The target explainer page (pm/checks/blacklists.mdx §20.4 / AC 24):
 * /domains/$id/runs/$runId/blacklists/target/$target with newest-run alias
 * /domains/$id/blacklists/target/$target. Shows the target identity panel (PTR, FCrDNS, ASN/org,
 * domain age — raw + parsed), the provenance block (how this target entered the sweep, incl. §19
 * report evidence for email_report targets), the one-column listings matrix for this run,
 * per-target history, references, and the target-scoped [Run this check now].
 */

const SOURCE_LABEL: Record<string, string> = {
	sending_ips: "configured on the domain record (sending_ips)",
	mx_resolved: "resolved from the domain's MX hosts",
	spf_authorized: "authorized by the domain's SPF record (ip4 mechanism)",
	email_report:
		"mined from ingested DMARC aggregate reports (§19) — observed actually sending as this domain in the last 30 days",
	primary: "the monitored sending domain itself",
	return_path:
		"a Return-Path (envelope) domain seen authenticating for this domain",
	dkim_d: "a DKIM d= domain seen authenticating for this domain",
};

const CHANGE_CHIP: Record<string, { label: string; cls: string }> = {
	now_listed: { label: "▲ now listed", cls: "bg-red-100 text-red-800" },
	now_clean: { label: "▼ now clean", cls: "bg-emerald-100 text-emerald-800" },
	unchanged: { label: "unchanged", cls: "bg-slate-100 text-slate-600" },
	inconclusive: { label: "? inconclusive", cls: "bg-gray-100 text-gray-500" },
	untracked: { label: "new pair", cls: "bg-sky-100 text-sky-800" },
};

export function BlacklistTargetPage() {
	const { target } = useParams({ strict: false }) as { target?: string };
	const navigate = useNavigate();
	const scope = useScopedBlacklistRun();
	const recheck = useBlacklistRecheck();
	const runCheck = useRunBlacklistsCheck();
	const [live, setLive] = useState<BlacklistLiveRecheck | null>(null);

	if (scope.isLoading || !scope.domainsLoaded) {
		return (
			<div className="mx-auto max-w-3xl space-y-4">
				{[0, 1, 2].map((i) => (
					<div key={i} className="h-28 animate-pulse rounded-lg bg-slate-100" />
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

	const run = scope.run;
	if (!run) {
		return (
			<div className="mx-auto max-w-3xl">
				{backTo}
				<h1 className="mt-2 text-2xl font-bold">Target — {target}</h1>
				<p className="mt-2 rounded-lg border border-dashed border-[var(--edh-border)] p-6 text-sm text-[var(--edh-muted)]">
					No blacklist run yet for this domain — run a check to sweep this
					target.
				</p>
			</div>
		);
	}

	const t = target ?? "";
	const ipTarget = run.targets.ips.find((x) => x.ip === t);
	const domainTarget = run.targets.domains.find(
		(x) => x.domain.toLowerCase() === t.toLowerCase(),
	);
	const rows: BlacklistZoneResult[] = run.results.filter(
		(r) => r.target.toLowerCase() === t.toLowerCase(),
	);

	// §20.8 unknown-target state — name the bad param, link back, never a blank screen.
	if (!ipTarget && !domainTarget && rows.length === 0) {
		return (
			<div className="mx-auto max-w-3xl">
				{backTo}
				<h1 className="mt-2 text-2xl font-bold">Unknown target</h1>
				<p className="mt-2 rounded-lg border border-dashed border-[var(--edh-border)] p-6 text-sm text-[var(--edh-muted)]">
					<span className="font-mono">{target}</span> was not part of this run's
					sweep. The run tested {run.targets.ips.length} IP(s) and{" "}
					{run.targets.domains.length} domain(s).
				</p>
			</div>
		);
	}

	const listed = rows.filter((r) => r.listed);
	const source = ipTarget?.source ?? domainTarget?.source ?? "primary";

	const runTargetNow = async () => {
		try {
			const res = await recheck.mutateAsync({
				domain: run.domain,
				targets: [t],
			});
			setLive(res);
		} catch (err) {
			toast.error(
				`Live recheck failed: ${err instanceof Error ? err.message : String(err)} — retry?`,
			);
		}
	};
	const runFullCheck = async () => {
		if (!scope.domainId) return;
		try {
			const result = await runCheck.mutateAsync(scope.domainId);
			toast.success("Blacklists check finished — opening the new run");
			navigate({
				to: "/domains/$id/runs/$runId/blacklists/target/$target",
				params: { id: scope.domainId, runId: result.runId ?? "", target: t },
			});
		} catch (err) {
			toast.error(
				`Check failed: ${err instanceof Error ? err.message : String(err)} — retry?`,
			);
		}
	};

	const identity: Array<[string, string]> = ipTarget
		? [
				["Kind", "sending IP"],
				["PTR (raw)", ipTarget.ptr ?? "none — no reverse DNS"],
				[
					"FCrDNS (parsed)",
					ipTarget.fcrdns_ok === null
						? "unknown"
						: ipTarget.fcrdns_ok
							? "ok — PTR forward-confirms to this IP"
							: "FAILS — the PTR's A record does not include this IP",
				],
				[
					"ASN / org",
					ipTarget.asn
						? `AS${ipTarget.asn.number} — ${ipTarget.asn.org ?? "?"}`
						: "unknown",
				],
			]
		: [
				["Kind", "domain (RHSBL target)"],
				["Domain age", domainTarget?.created ?? "unknown (whois pending)"],
			];

	return (
		<div className="mx-auto max-w-3xl">
			{backTo}

			<div className="mt-2 flex flex-wrap items-center gap-3">
				<h1 className="font-mono text-2xl font-bold">{t}</h1>
				{source === "email_report" && (
					<span className="rounded bg-sky-100 px-1.5 py-0.5 text-xs font-medium text-sky-800">
						via DMARC reports
					</span>
				)}
				<span
					className={cn(
						"rounded px-1.5 py-0.5 text-xs font-semibold",
						listed.length > 0
							? "bg-red-100 text-red-800"
							: "bg-emerald-100 text-emerald-800",
					)}
				>
					{listed.length > 0 ? `${listed.length} listing(s)` : "clean"} this run
				</span>
			</div>

			{/* Identity panel — raw + parsed (§20.4) */}
			<section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
				<h2 className="mb-2 font-semibold">Identity</h2>
				<dl className="grid grid-cols-[10rem_1fr] gap-x-3 gap-y-1 text-sm">
					{identity.map(([k, v]) => (
						<div key={k} className="contents">
							<dt className="text-slate-500">{k}</dt>
							<dd className="font-mono text-slate-800">{v}</dd>
						</div>
					))}
				</dl>
			</section>

			{/* Provenance — how this target entered the sweep (§19 / §20.4) */}
			<section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
				<h2 className="mb-1 font-semibold">
					How this target entered the sweep
				</h2>
				<p className="text-sm text-slate-700">
					{SOURCE_LABEL[source] ?? source}
				</p>
				{source === "email_report" && (
					<p className="mt-1 text-xs text-[var(--edh-muted)]">
						Email-derived targets are swept against every enabled IP zone
						exactly like configured sending IPs; a listing here is your
						delisting problem — the evidence trail is your own DMARC reports
						(see the domain's Reports page).
					</p>
				)}
			</section>

			{/* One-column listings matrix for this run (§20.4) */}
			<section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
				<h2 className="mb-2 font-semibold">Zone results for this run</h2>
				<table className="w-full text-xs">
					<thead>
						<tr className="border-b border-[var(--edh-border)] text-left text-slate-500">
							<th className="py-1 pr-2 font-medium">Zone</th>
							<th className="py-1 pr-2 font-medium">Answer</th>
							<th className="py-1 pr-2 font-medium">Meaning</th>
							<th className="py-1 font-medium">Fix</th>
						</tr>
					</thead>
					<tbody>
						{[...rows]
							.sort(
								(a, b) =>
									Number(b.listed) - Number(a.listed) ||
									a.zone.localeCompare(b.zone),
							)
							.map((r) => (
								<tr
									key={r.zone}
									className="border-b border-[var(--edh-border)] last:border-0"
								>
									<td className="py-1 pr-2">
										<Link
											to={
												scope.runId
													? "/domains/$id/runs/$runId/blacklists/zone/$zoneId"
													: "/domains/$id/blacklists/zone/$zoneId"
											}
											params={{
												id: scope.domainId ?? "",
												...(scope.runId ? { runId: scope.runId } : {}),
												zoneId: r.zone,
											}}
											className="font-mono text-[var(--edh-primary)] hover:underline"
										>
											{r.zone}
										</Link>
									</td>
									<td
										className={cn(
											"py-1 pr-2 font-mono",
											r.listed && "font-semibold text-red-700",
											r.inconclusive && "text-gray-500",
										)}
									>
										{r.return_code ?? r.refusal_code ?? "NXDOMAIN"}
									</td>
									<td className="py-1 pr-2">
										{r.inconclusive
											? "query refused / zone unavailable — inconclusive"
											: r.listed
												? (r.sub_list ?? "listed")
												: "clean"}
									</td>
									<td className="py-1">
										{r.listed && (
											<a
												href={r.delist_url}
												target="_blank"
												rel="noreferrer"
												className="inline-flex items-center gap-1 text-[var(--edh-primary)]"
											>
												Delist <ExternalLink className="h-3 w-3" />
											</a>
										)}
									</td>
								</tr>
							))}
					</tbody>
				</table>
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
									<li key={r.zone} className="flex items-center gap-2">
										<span className="font-mono">{r.zone}</span>
										<span className="font-mono text-slate-500">
											{r.inconclusive
												? (r.refusal_code ?? "inconclusive")
												: r.listed
													? (r.return_code ?? "listed")
													: "NXDOMAIN"}
										</span>
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

			{/* Per-target history */}
			{scope.domainRuns.length > 1 && (
				<section className="mt-4">
					<h2 className="mb-2 text-sm font-semibold text-slate-600">
						This target over the last {Math.min(scope.domainRuns.length, 30)}{" "}
						runs
					</h2>
					<div className="flex h-10 items-end gap-1">
						{[...scope.domainRuns]
							.reverse()
							.slice(-30)
							.map((r) => {
								const targetRows = (r.results?.blacklist?.results ?? []).filter(
									(row) => row.target.toLowerCase() === t.toLowerCase(),
								);
								const hit = targetRows.some((row) => row.listed);
								const absent = targetRows.length === 0;
								return (
									<Link
										key={r.runId ?? r.ranAt}
										to="/domains/$id/runs/$runId/blacklists/target/$target"
										params={{
											id: scope.domainId ?? "",
											runId: r.runId ?? "",
											target: t,
										}}
										title={`${new Date(r.ranAt).toLocaleString()}: ${absent ? "not swept" : hit ? "listed" : "clean"}${r.scope ? " (blacklists-only run)" : ""}`}
										className={cn(
											"w-3 rounded-t",
											absent
												? "bg-slate-200"
												: hit
													? "bg-red-600"
													: "bg-emerald-500",
											r.scope && "ring-1 ring-sky-400",
										)}
										style={{ height: hit ? "100%" : "40%" }}
									/>
								);
							})}
					</div>
				</section>
			)}

			{/* References */}
			<section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
				<h2 className="mb-1 font-semibold">References</h2>
				<ul className="list-disc space-y-1 pl-5 text-xs text-[var(--edh-muted)]">
					<li>
						RFC 5782 — DNS blocklist query mechanics (reversed-IP A queries).
					</li>
					<li>
						multirbl.valli.org — cross-check this target against ~892 zones.
					</li>
					{ipTarget && (
						<li>
							whois / mmdblookup — netblock owner and ASN context for this IP.
						</li>
					)}
				</ul>
			</section>

			{/* Target-scoped [Run this check now] (§21.2 / AC 28) */}
			<div className="mt-5 flex flex-wrap items-center gap-2">
				<button
					type="button"
					onClick={runTargetNow}
					disabled={recheck.isPending}
					className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50"
				>
					<RefreshCw
						className={cn("h-3.5 w-3.5", recheck.isPending && "animate-spin")}
					/>
					{recheck.isPending
						? "Re-querying this target…"
						: "Run this check now (this target)"}
				</button>
				<button
					type="button"
					onClick={runFullCheck}
					disabled={runCheck.isPending || !scope.domainId}
					className="inline-flex items-center gap-2 rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-sm font-medium disabled:opacity-50"
					title={
						runCheck.isPending
							? "A blacklists run for this domain is already in flight"
							: undefined
					}
				>
					<RefreshCw
						className={cn("h-3.5 w-3.5", runCheck.isPending && "animate-spin")}
					/>
					Run full blacklist check
				</button>
			</div>
		</div>
	);
}
