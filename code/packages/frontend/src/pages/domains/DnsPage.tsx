import { Link, useNavigate, useParams } from "@tanstack/react-router";
import {
	ArrowLeft,
	ChevronDown,
	ChevronLeft,
	ChevronRight,
	Info,
	Loader2,
	Network,
	RefreshCw,
	ShieldAlert,
	ShieldCheck,
	Wrench,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useAuditResults, useDnsSpotCheck, useDomainRuns } from "@/api/audit";
import { useDomains } from "@/api/domains";
import type {
	AuditResult,
	DaneTlsaResults,
	DnsHealthResults,
	DnsSpotCheckResult,
	DnssecResults,
	DomainRegistrationResults,
	Finding,
	InfraToolRun,
	MxRoutingResults,
	ReverseDnsResults,
	Severity,
} from "@/api/types";
import { CopyFixButton } from "@/components/CopyFixButton";
import { StatusCell } from "@/components/StatusCell";
import { NEVER_CELL, rollupCategories } from "@/lib/categories";
import {
	type DnsFamilyKey,
	type FamilyRollup,
	infraFindings,
	rollupFamilies,
} from "@/lib/dns-families";
import { matchDnsProblemStates } from "@/lib/dns-problems";
import { cn } from "@/lib/utils";
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext";

const ORDER: Record<Severity, number> = {
	critical: 0,
	warning: 1,
	info: 2,
	ok: 3,
};
const WORST_RANK: Record<Severity, number> = {
	ok: 0,
	info: 1,
	warning: 2,
	critical: 3,
};

/**
 * The since-last-run direction of one family (pm/checks/dns.mdx §6.2 item 6): "regressed" (▲ —
 * worse worst-severity than the previous run), "improved" (▼), "unchanged" (=).
 */
type FamilyTrend = "regressed" | "improved" | "unchanged";

/**
 * Per-family since-last-run trend glyphs (pm/checks/dns.mdx §6.2 item 6): compare each family's
 * worst severity in the viewed run against the domain's previous run. No previous run → no glyph.
 */
function familyTrends(
	current: FamilyRollup[],
	previous: AuditResult | undefined,
): Partial<Record<DnsFamilyKey, FamilyTrend>> {
	if (!previous) return {};
	const prevFamilies = rollupFamilies(infraFindings(previous.findings));
	const prevWorst = new Map(prevFamilies.map((f) => [f.def.key, f.worst]));
	const out: Partial<Record<DnsFamilyKey, FamilyTrend>> = {};
	for (const fam of current) {
		const before = prevWorst.get(fam.def.key) ?? null;
		if (fam.worst === null && before === null) continue;
		const nowRank = fam.worst ? WORST_RANK[fam.worst] : 0;
		const beforeRank = before ? WORST_RANK[before] : 0;
		out[fam.def.key] =
			nowRank > beforeRank
				? "regressed"
				: nowRank < beforeRank
					? "improved"
					: "unchanged";
	}
	return out;
}

/**
 * The DNS & Infrastructure category run page (pm/checks/dns.mdx §6.2/§7) — the DNS results of ONE
 * specific run for one domain, never a blend of runs. Run-scoped at
 * /domains/:id/runs/:runId/dns with the newest-run alias /domains/:id/dns (which rewrites itself
 * to the canonical run URL). Top to bottom: header + run context strip (timestamp, `newest`
 * badge, ‹ prev / next › run navigation), the ten-chip family strip, the §8 fix-order-ladder
 * verdict + CTA, the Mail path panel (MX → IP → PTR), the Zone panel
 * (NS/SOA/TTL/wildcard/DNSSEC), the family-grouped fail-first test-results table with tool-run
 * traceability, and problem-state cards linking to the drill-down pages.
 */
export function DnsPage() {
	const { id = "", runId } = useParams({ strict: false }) as {
		id?: string;
		runId?: string;
	};
	const { data: domains } = useDomains();
	const { data: results } = useAuditResults();
	const { data: runs, isLoading: runsLoading } = useDomainRuns(id);
	const runDomains = useScanRunner();
	const scanning = useScanProgress().some((s) => s.domainId === id);
	const navigate = useNavigate();

	const domain = (domains ?? []).find((d) => d.id === id);
	// The domain's run history, newest first (the API sorts by startedAt). The latest-results cache
	// is the fallback for pre-history data that has no run files yet.
	const history = runs ?? [];
	const newest: AuditResult | undefined =
		history[0] ?? (results ?? []).find((r) => r.domainId === id);
	const result = runId ? history.find((r) => r.runId === runId) : newest;
	const unknownRun =
		Boolean(runId) && !runsLoading && runs !== undefined && !result;

	// The alias /domains/:id/dns rewrites itself to the canonical run URL so links stay stable
	// (pm/checks/dns.mdx §6.2).
	useEffect(() => {
		if (!runId && newest?.runId) {
			navigate({
				to: "/domains/$id/runs/$runId/dns",
				params: { id, runId: newest.runId },
				replace: true,
			});
		}
	}, [runId, newest?.runId, id, navigate]);

	const findings = infraFindings(result?.findings);
	const families = rollupFamilies(findings);
	const cell =
		rollupCategories(result?.findings, result?.results).dnsInfra ?? NEVER_CELL;
	const problems = matchDnsProblemStates(findings);
	// Since-last-run trend per family (pm/checks/dns.mdx §6.2 item 6): the run immediately older
	// than the one being viewed is the baseline (history is newest-first).
	const prevRun = result?.runId
		? history[history.findIndex((r) => r.runId === result.runId) + 1]
		: undefined;
	const trends = familyTrends(families, prevRun);

	const mx = result?.results?.["infra.mx_routing"] as
		| MxRoutingResults
		| undefined;
	const rdns = result?.results?.["infra.reverse_dns"] as
		| ReverseDnsResults
		| undefined;
	const zone = result?.results?.["infra.dns_health"] as
		| DnsHealthResults
		| undefined;
	const dnssec = result?.results?.["infra.dnssec"] as DnssecResults | undefined;
	const dane = result?.results?.["infra.dane_tlsa"] as
		| DaneTlsaResults
		| undefined;
	// The §5 registration snapshot (pm/checks/domain_reputation.mdx) — feeds the Registration
	// summary panel rendered at the top of the "Domain registration" family group (§4).
	const registration = result?.results?.["infra.domain_reputation"] as
		| DomainRegistrationResults
		| undefined;
	// The category's external-tool audit trail (dns_infra.tool_runs[] — pm/checks/dns.mdx §3.1/§5):
	// expanded rows link their evidence to the exact command that produced it.
	const toolRuns =
		(result?.results?.["infra.tool_runs"] as InfraToolRun[] | undefined) ?? [];

	const onRunAgain = () => runDomains([{ id, name: domain?.name ?? id }]);

	// Back link target: the run report of the run being viewed (canonical when run-scoped).
	const onBack = () =>
		result?.runId
			? navigate({
					to: "/domains/$id/runs/$runId",
					params: { id, runId: result.runId },
				})
			: navigate({ to: "/domains/$id", params: { id } });

	return (
		<div className="mx-auto max-w-5xl">
			<div className="mb-4 flex items-center justify-between">
				<button
					type="button"
					onClick={onBack}
					className="inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
				>
					<ArrowLeft className="h-4 w-4" /> Back to run report
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

			<h1 className="text-2xl font-bold">DNS & Infrastructure</h1>
			<div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-[var(--edh-muted)]">
				<span className="font-medium text-slate-900">{domain?.name ?? id}</span>
				<span className="w-32">
					<StatusCell status={cell} />
				</span>
			</div>

			{/* Run context strip (pm/checks/dns.mdx §6.2/§7): pinned above any verdict so an old run is
          never misread as "the domain's current state". Absent when the domain has no runs. */}
			{result && (
				<RunContextStrip
					domainId={id}
					viewed={result}
					history={history}
					newestRunId={newest?.runId}
					scanning={scanning}
				/>
			)}

			{unknownRun ? (
				<div className="mt-6 rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center">
					<p className="text-slate-600">
						This run no longer exists — runs are pruned per the retention
						policy.
					</p>
					<Link
						to="/domains/$id/dns"
						params={{ id }}
						className="mt-2 inline-block text-[var(--edh-primary)] underline"
					>
						Open the newest run's DNS page
					</Link>
				</div>
			) : !result ? (
				runsLoading ? (
					// Loading state (pm/checks/dns.mdx §6.2): skeleton rows, not a spinner.
					<div
						className="mt-4 animate-pulse space-y-4"
						role="status"
						aria-label="Loading run history"
					>
						<div className="h-10 rounded-lg bg-slate-100" />
						<div className="h-24 rounded-lg bg-slate-100" />
						<div className="grid gap-4 lg:grid-cols-2">
							<div className="h-40 rounded-lg bg-slate-100" />
							<div className="h-40 rounded-lg bg-slate-100" />
						</div>
						<div className="space-y-2 rounded-lg border border-[var(--edh-border)] bg-white p-3">
							{[0, 1, 2, 3, 4].map((i) => (
								<div key={i} className="h-6 rounded bg-slate-100" />
							))}
						</div>
					</div>
				) : (
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
				)
			) : (
				<>
					<FamilyStrip
						families={families}
						findings={findings}
						dnssec={dnssec}
					/>

					<div className="mt-4 grid gap-4 lg:grid-cols-2">
						<MailPathPanel mx={mx} rdns={rdns} />
						<ZonePanel zone={zone} dnssec={dnssec} />
					</div>

					<TestResultsByFamily
						families={families}
						dane={dane}
						registration={registration}
						onRecheck={onRunAgain}
						scanning={scanning}
						toolRuns={toolRuns}
						domainId={id}
						runId={result?.runId}
						trends={trends}
					/>

					{problems.length > 0 && (
						<section className="mt-6">
							<h2 className="mb-2 font-semibold">Problem states</h2>
							<div className="grid gap-3 sm:grid-cols-2">
								{problems.map((ps) => (
									<Link
										key={ps.id}
										to="/domains/$id/dns/$problemId"
										params={{ id, problemId: ps.id }}
										// The drill-down renders from the run being viewed (pm/checks/dns.mdx §7).
										search={result?.runId ? { run: result.runId } : undefined}
										className="group rounded-lg border border-[var(--edh-border)] bg-white p-4 hover:border-[var(--edh-primary)]"
									>
										<div className="flex items-center justify-between">
											<span className="text-xs font-semibold uppercase text-[var(--edh-muted)]">
												{ps.id}
											</span>
											<ChevronRight className="h-4 w-4 text-[var(--edh-muted)] group-hover:text-[var(--edh-primary)]" />
										</div>
										<div className="mt-1 font-medium">{ps.title}</div>
										<p className="mt-1 text-sm text-slate-600">{ps.hook}</p>
									</Link>
								))}
							</div>
						</section>
					)}
				</>
			)}
		</div>
	);
}

/** `YYYY-MM-DD HH:mm` in local time — the run context strip's timestamp (pm/checks/dns.mdx §7). */
function fmtRunStamp(iso: string): string {
	const d = new Date(iso);
	const pad = (n: number) => String(n).padStart(2, "0");
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/**
 * The run context strip (pm/checks/dns.mdx §6.2 item 2 / §7): the run's start timestamp, a
 * `newest` badge on the domain's latest run only, and ‹ prev / next › navigation that steps
 * through the SAME domain's runs in startedAt order, staying on the DNS category page (‹ = older,
 * › = newer; each disabled at the ends of the history). Keyboard: `[` / `]` mirror ‹ / ›.
 */
function RunContextStrip({
	domainId,
	viewed,
	history,
	newestRunId,
	scanning,
}: {
	domainId: string;
	viewed: AuditResult;
	history: AuditResult[];
	newestRunId?: string;
	scanning: boolean;
}) {
	const navigate = useNavigate();
	// history is newest-first; ‹ prev = older (index + 1), next › = newer (index - 1).
	const index = history.findIndex((r) => r.runId === viewed.runId);
	const older = index >= 0 ? history[index + 1] : undefined;
	const newer = index > 0 ? history[index - 1] : undefined;
	const isNewest = Boolean(viewed.runId) && viewed.runId === newestRunId;

	const goTo = (run: AuditResult | undefined) => {
		if (run?.runId) {
			navigate({
				to: "/domains/$id/runs/$runId/dns",
				params: { id: domainId, runId: run.runId },
			});
		}
	};

	// `[` / `]` mirror the ‹ prev / next › controls (pm/checks/dns.mdx §7).
	const olderRunId = older?.runId;
	const newerRunId = newer?.runId;
	useEffect(() => {
		const jump = (runId: string) =>
			navigate({
				to: "/domains/$id/runs/$runId/dns",
				params: { id: domainId, runId },
			});
		const onKey = (e: KeyboardEvent) => {
			const target = e.target as HTMLElement | null;
			if (target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName)) return;
			if (e.key === "[" && olderRunId) jump(olderRunId);
			if (e.key === "]" && newerRunId) jump(newerRunId);
		};
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	}, [olderRunId, newerRunId, domainId, navigate]);

	return (
		<div className="mt-4 flex items-center justify-between rounded-lg border border-[var(--edh-border)] bg-white px-3 py-2 text-sm">
			<button
				type="button"
				onClick={() => goTo(older)}
				disabled={!older?.runId}
				title="Older run ( [ )"
				className="inline-flex items-center gap-1 text-[var(--edh-muted)] hover:text-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
			>
				<ChevronLeft className="h-4 w-4" /> prev run
			</button>
			<span className="flex items-center gap-2">
				<span className="font-medium text-slate-900">
					Run {fmtRunStamp(viewed.startedAt ?? viewed.ranAt)}
				</span>
				{isNewest && (
					<span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-semibold uppercase text-emerald-700">
						newest
					</span>
				)}
				{scanning && (
					<span className="inline-flex items-center gap-1 text-xs text-[var(--edh-muted)]">
						<Loader2 className="h-3.5 w-3.5 animate-spin" /> running…
					</span>
				)}
			</span>
			<button
				type="button"
				onClick={() => goTo(newer)}
				disabled={!newer?.runId}
				title="Newer run ( ] )"
				className="inline-flex items-center gap-1 text-[var(--edh-muted)] hover:text-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
			>
				next run <ChevronRight className="h-4 w-4" />
			</button>
		</div>
	);
}

/** True when any warning/critical finding's id (after "infra.") starts with one of the prefixes. */
function anyFailing(
	findings: Finding[],
	prefixes: string[],
	severities: Severity[],
): boolean {
	return findings.some((f) => {
		if (!severities.includes(f.severity)) return false;
		const bare = f.id.startsWith("infra.") ? f.id.slice("infra.".length) : f.id;
		return prefixes.some((p) => bare.startsWith(p));
	});
}

/**
 * The §8 fix-order ladder — FIRST MATCHING RUNG WINS, in exactly the spec's rung order (0–10):
 * registration critical → MX critical → rDNS critical → STARTTLS critical → zone warnings →
 * DNSSEC signed-but-broken → MTA-STS → TLS-RPT → DNSSEC unsigned → DANE (zone signed) → healthy.
 * So a registration hold outranks an MX problem, which outranks rDNS, and DANE advice never
 * appears while FCrDNS is failing.
 */
function ladderNextStep(findings: Finding[], dnssec?: DnssecResults): string {
	const crit: Severity[] = ["critical"];
	const warnUp: Severity[] = ["critical", "warning"];
	// Rung 0 — registration critical (hold_status, expired, pending_delete).
	if (
		anyFailing(
			findings,
			["hold_status", "pending_delete", "domain_expiry"],
			crit,
		)
	)
		return "Fix the registration first — a domain on hold or expiring resolves for no one; nothing else matters until it's back.";
	// Rung 1 — MX critical (mx_present, mx_resolve, mx_public_ip, misused mx_null).
	if (anyFailing(findings, ["mx_", "dangling_include.mx"], crit))
		return "Restore inbound routing: publish MX records whose targets resolve to public A/AAAA hosts. Bounces, FBL mail, and DMARC reports all depend on it.";
	// Rung 2 — reverse-DNS critical (missing/failed FCrDNS, the v6 gap).
	if (anyFailing(findings, ["ptr_", "fcrdns", "reverse_dns"], crit))
		return "Close FCrDNS on every mail IP — a hard Gmail/Microsoft gate, not a score. Open the hosting-provider PTR ticket today, or disable outbound IPv6 until its PTR exists.";
	// Rung 3 — STARTTLS critical (an MX without TLS, expired cert).
	if (anyFailing(findings, ["tls_transport"], crit))
		return "Get every MX offering STARTTLS with a valid certificate matching the MX hostname — TLS in transit is required by all three major receivers.";
	// Rung 4 — zone warnings (ns_*, glue_records, soa_*, ttl_sanity, wildcard …).
	if (
		anyFailing(
			findings,
			[
				"ns_",
				"glue_records",
				"soa_",
				"ttl_sanity",
				"wildcard",
				"cname_at_apex",
				"multi_txt_spf",
				"txt_bloat",
				"recursion_open",
				"zone_transfer",
				"dangling_",
			],
			warnUp,
		)
	)
		return "Stabilize the zone: second NS provider, sync parent↔child NS, close recursion/AXFR, bring SOA/TTLs into range. Flaky DNS causes intermittent auth failures everywhere else.";
	// Rung 5 — DNSSEC signed-but-broken (never rung 8's unsigned advisory).
	if (
		anyFailing(findings, ["dnssec_"], crit) ||
		(dnssec?.signed && dnssec.ds_matches_dnskey === false)
	)
		return "Fix or temporarily remove the DS at the registrar — a bogus DNSSEC chain SERVFAILs your whole zone at Google/Cloudflare/Quad9 resolvers. Broken beats unsigned only in damage.";
	// Rung 6 — MTA-STS absent or mode: testing matured.
	if (anyFailing(findings, ["mta_sts"], warnUp))
		return "Publish MTA-STS (mode: testing with TLS-RPT for 14–30 days, then enforce with max_age 604800).";
	// Rung 7 — TLS-RPT absent while MTA-STS/DANE exist.
	if (anyFailing(findings, ["tls_rpt"], warnUp))
		return "Add TLS-RPT (_smtp._tls TXT) — you can't run an enforce-mode TLS policy blind.";
	// Rung 8 — DNSSEC unsigned (info): the DANE prerequisite.
	if (dnssec && !dnssec.signed)
		return "Sign the zone (algorithm 13, automated re-signing, CDS/CDNSKEY for the DS) — the prerequisite for DANE.";
	// Rung 9 — DANE absent/incomplete while the zone is signed (DANE findings are info when absent).
	if (
		dnssec?.dane_ready &&
		findings.some((f) => {
			const bare = f.id.startsWith("infra.")
				? f.id.slice("infra.".length)
				: f.id;
			return bare.startsWith("dane_") && f.severity !== "ok";
		})
	)
		return "Publish a 3 1 1 TLSA record for every MX host (current + next during rollover); verify with gnutls-cli --dane.";
	// Rung 10 — all healthy.
	return "Keep it healthy: registrar auto-renew + transfer lock, RRSIG-expiry watch, scheduled re-runs — regressions are the real enemy now.";
}

/** The plain-language verdict line above the CTA — rejected now / eroding / hardening / healthy. */
function verdictLine(findings: Finding[]): string {
	const gate = [
		"ptr_",
		"fcrdns",
		"mx_",
		"tls_transport",
		"hold_status",
		"pending_delete",
		"smtp_security",
		"dnssec_ds_algo_match",
		"dangling_",
	];
	if (anyFailing(findings, gate, ["critical"]))
		return "Mail is being REJECTED: a hard receiver gate (FCrDNS, MX, TLS, or registration) is failing.";
	if (findings.some((f) => f.severity === "critical"))
		return "A critical infrastructure problem is hurting delivery.";
	if (findings.some((f) => f.severity === "warning"))
		return "Delivery works, but reputation-eroding infrastructure warnings are open.";
	return "Plumbing healthy end to end — hardening options below are optional upgrades.";
}

const CHIP_STYLE: Record<string, string> = {
	critical: "bg-red-600 text-white",
	warning: "bg-amber-500 text-white",
	info: "bg-slate-200 text-slate-600",
	ok: "bg-emerald-600 text-white",
	never: "border border-slate-300 text-slate-400",
};

function chipGlyph(worst: Severity | null): string {
	if (worst === "critical") return "✗";
	if (worst === "warning") return "⚠";
	if (worst === "info") return "ⓘ";
	if (worst === "ok") return "✓";
	return "·";
}

/** The hero band: ten family chips (anchor-linked to their table groups) + verdict + one CTA. */
function FamilyStrip({
	families,
	findings,
	dnssec,
}: {
	families: FamilyRollup[];
	findings: Finding[];
	dnssec?: DnssecResults;
}) {
	return (
		<div className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
			<div className="flex flex-wrap gap-2">
				{families.map((fam) => (
					<button
						key={fam.def.key}
						type="button"
						onClick={() =>
							document
								.getElementById(`fam-${fam.def.key}`)
								?.scrollIntoView({ behavior: "smooth", block: "start" })
						}
						className={cn(
							"rounded-full px-3 py-1 text-xs font-medium",
							CHIP_STYLE[fam.worst ?? "never"],
						)}
						title={`${fam.def.header} — ${fam.findings.length} tests, ${fam.failCount} failing`}
					>
						{chipGlyph(fam.worst)} {fam.def.chip}
					</button>
				))}
			</div>
			<p className="mt-3 text-sm text-slate-700">{verdictLine(findings)}</p>
			<p className="mt-1 text-sm font-medium text-[var(--edh-primary)]">
				Next step: {ladderNextStep(findings, dnssec)}
			</p>
		</div>
	);
}

/** MX → IP → PTR topology with per-hop status (pm/checks/dns.mdx §7 "Mail path"). */
function MailPathPanel({
	mx,
	rdns,
}: {
	mx?: MxRoutingResults;
	rdns?: ReverseDnsResults;
}) {
	const ptrByIp = new Map((rdns?.ips ?? []).map((r) => [r.ip, r]));
	return (
		<section className="rounded-lg border border-[var(--edh-border)] bg-white p-4">
			<h2 className="mb-2 flex items-center gap-2 font-semibold">
				<Network className="h-4 w-4 text-[var(--edh-muted)]" /> Mail path
			</h2>
			{!mx ? (
				<p className="text-sm text-slate-600">
					No MX topology captured — re-run the audit.
				</p>
			) : !mx.mx_found ? (
				<p className="text-sm text-slate-600">
					No MX record.{" "}
					{mx.implicit_a_fallback
						? "Mail implicit-routes to the apex A record (fragile)."
						: "Inbound mail has nowhere to go."}
				</p>
			) : mx.null_mx && mx.hosts.length === 0 ? (
				<p className="text-sm text-slate-600">
					Null MX (<span className="font-mono text-xs">MX 0 "."</span>) — this
					domain declares it accepts no mail.
				</p>
			) : (
				<ul className="space-y-2">
					{mx.hosts.map((h) => (
						<li
							key={h.host}
							className="rounded-md border border-[var(--edh-border)] p-2 text-sm"
						>
							<div className="flex items-center gap-2">
								<span className="w-8 shrink-0 text-right font-mono text-xs text-[var(--edh-muted)]">
									{h.priority}
								</span>
								<span className="break-all font-mono text-xs font-semibold">
									{h.host}
								</span>
								{h.is_cname && (
									<span className="rounded bg-red-100 px-1 text-[10px] font-semibold uppercase text-red-700">
										CNAME ✗
									</span>
								)}
								{/* Reach(:25) is probe-gated — a muted ⏳ chip until the SMTP-probe round lands
                    (pm/checks/mx_routing.mdx §4 "Probe-gated rows"). */}
								{h.reachable == null ? (
									<span
										className="ml-auto shrink-0 rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium text-slate-500"
										title="SMTP reachability (TCP/25 + 220 banner) pending the network-probe round"
									>
										:25 ⏳ future
									</span>
								) : (
									<span
										className={cn(
											"ml-auto shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold",
											h.reachable
												? "bg-emerald-100 text-emerald-700"
												: "bg-red-100 text-red-700",
										)}
									>
										:25 {h.reachable ? "✓" : "✗"}
									</span>
								)}
							</div>
							<ul className="mt-1 space-y-0.5 pl-10">
								{h.ips.length === 0 && (
									<li className="text-xs text-red-600">
										no A/AAAA — dangling target
									</li>
								)}
								{h.ips.map((ip) => {
									const bad = h.non_public.find((n) => n.ip === ip);
									const ptr = ptrByIp.get(ip);
									return (
										<li
											key={ip}
											className="flex flex-wrap items-center gap-1 font-mono text-xs"
										>
											<span className={cn(bad && "text-red-600")}>{ip}</span>
											{bad && (
												<span className="text-red-600">({bad.cls}) ✗</span>
											)}
											{ptr && (
												<>
													<span className="text-slate-400">→</span>
													{ptr.ptr ? (
														<span
															className={cn(
																ptr.forward_confirmed && !ptr.generic
																	? "text-emerald-700"
																	: "text-amber-600",
															)}
														>
															{ptr.ptr}
															{ptr.forward_confirmed ? " ✓" : " (no FCrDNS) ✗"}
															{ptr.generic ? " generic" : ""}
														</span>
													) : (
														<span className="text-red-600">no PTR ✗</span>
													)}
												</>
											)}
										</li>
									);
								})}
							</ul>
						</li>
					))}
					<li className="pl-10 text-xs text-[var(--edh-muted)]">
						{mx.redundancy.host_count} host
						{mx.redundancy.host_count === 1 ? "" : "s"} ·{" "}
						{mx.redundancy.network_count} network
						{mx.redundancy.network_count === 1 ? "" : "s"}
					</li>
				</ul>
			)}
		</section>
	);
}

/** NS / parent-child / SOA-with-ranges / TTL / wildcard / DNSSEC digest (§7 "Zone"). */
function ZonePanel({
	zone,
	dnssec,
}: {
	zone?: DnsHealthResults;
	dnssec?: DnssecResults;
}) {
	const soaRows: { label: string; value: number | string; range: string }[] =
		zone?.soa
			? [
					{ label: "serial", value: zone.soa.serial, range: "YYYYMMDDnn" },
					{ label: "refresh", value: zone.soa.refresh, range: "3600–86400" },
					{ label: "retry", value: zone.soa.retry, range: "< refresh" },
					{ label: "expire", value: zone.soa.expire, range: "604800–2419200" },
					{ label: "min TTL", value: zone.soa.min_ttl, range: "300–86400" },
				]
			: [];
	return (
		<section className="rounded-lg border border-[var(--edh-border)] bg-white p-4">
			<h2 className="mb-2 font-semibold">Zone</h2>
			{!zone ? (
				<p className="text-sm text-slate-600">
					No zone snapshot captured — re-run the audit.
				</p>
			) : (
				<div className="space-y-2 text-sm">
					{/* Delegation snapshot sub-table (pm/checks/dns_health.mdx §4): NS set, resolved IPs,
              network group, and the lame flag; the Auth?/TCP columns stay ⏳ until the per-server
              AA-bit and TCP/53 probes ship. */}
					{zone.ns.length === 0 ? (
						<div>
							<span className="text-[var(--edh-muted)]">NS </span>
							<span className="font-mono text-xs">
								(none of its own — served by parent zone)
							</span>
						</div>
					) : (
						<div className="overflow-x-auto">
							<table className="w-full text-xs">
								<thead>
									<tr className="text-left text-[var(--edh-muted)]">
										<th className="py-1 pr-2 font-medium">Nameserver</th>
										<th className="py-1 pr-2 font-medium">Resolved IP</th>
										<th className="py-1 pr-2 font-medium">Net (/24·/48)</th>
										<th className="py-1 pr-2 font-medium">Auth?</th>
										<th className="py-1 pr-2 font-medium">TCP</th>
										<th className="py-1 font-medium">Lame</th>
									</tr>
								</thead>
								<tbody>
									{zone.ns.map((n) => (
										<tr
											key={n.host}
											className="border-t border-[var(--edh-border)]"
										>
											<td className="break-all py-1 pr-2 font-mono">
												{n.host}
												{n.is_cname && (
													<span className="ml-1 rounded bg-red-100 px-1 text-[10px] font-semibold uppercase text-red-700">
														CNAME ✗
													</span>
												)}
											</td>
											<td className="break-all py-1 pr-2 font-mono">
												{n.ips.length > 0 ? n.ips.join(", ") : "—"}
											</td>
											<td className="py-1 pr-2 font-mono">
												{n.net_group || "—"}
											</td>
											<td
												className="py-1 pr-2 text-slate-400"
												title="AA-bit probe pending (future)"
											>
												⏳
											</td>
											<td
												className="py-1 pr-2 text-slate-400"
												title="TCP/53 probe pending (future)"
											>
												⏳
											</td>
											<td className="py-1">
												{n.lame ? (
													<span className="text-red-600">yes ✗</span>
												) : (
													"no"
												)}
											</td>
										</tr>
									))}
								</tbody>
							</table>
							<div className="mt-1 text-xs text-[var(--edh-muted)]">
								{zone.ns_count} server{zone.ns_count === 1 ? "" : "s"},{" "}
								{zone.network_count} network
								{zone.network_count === 1 ? "" : "s"}{" "}
								{zone.ns_count >= 2 && zone.network_count >= 2 ? "✓" : "⚠"}
							</div>
						</div>
					)}
					<div className="text-xs text-[var(--edh-muted)]">
						parent/child match:{" "}
						{zone.parent_child_match === null
							? "pending probe"
							: zone.parent_child_match
								? "✓"
								: "✗"}
					</div>
					{soaRows.length > 0 && (
						<table className="w-full text-xs">
							<tbody>
								{soaRows.map((r) => (
									<tr
										key={r.label}
										className="border-t border-[var(--edh-border)]"
									>
										<td className="py-1 pr-2 text-[var(--edh-muted)]">
											SOA {r.label}
										</td>
										<td className="py-1 pr-2 font-mono">{r.value}</td>
										<td className="py-1 text-slate-400">{r.range}</td>
									</tr>
								))}
							</tbody>
						</table>
					)}
					<div className="text-xs">
						wildcard:{" "}
						{zone.wildcard.detected ? (
							<span className="text-amber-600">
								detected ({zone.wildcard.types.join(", ")}) ⚠
							</span>
						) : (
							<span className="text-emerald-700">none ✓</span>
						)}
						{" · apex CNAME: "}
						{zone.cname_at_apex ? (
							<span className="text-red-600">present ✗</span>
						) : (
							<span className="text-emerald-700">none ✓</span>
						)}
					</div>
					<div className="border-t border-[var(--edh-border)] pt-2 text-xs">
						<span className="text-[var(--edh-muted)]">DNSSEC </span>
						{!dnssec ? (
							"state not captured"
						) : !dnssec.signed ? (
							<span className="text-slate-600">
								unsigned (advisory — required for DANE)
							</span>
						) : dnssec.ds_matches_dnskey === false ? (
							<span className="font-semibold text-red-600">
								BROKEN — DS does not match a live key; validating resolvers
								SERVFAIL this zone ✗
							</span>
						) : (
							<span className="text-emerald-700">
								signed · alg {dnssec.algorithms.join("/") || "?"} · DS{" "}
								{dnssec.ds_present === null
									? "?"
									: dnssec.ds_present
										? "✓"
										: "missing ⚠"}
								{dnssec.dane_ready ? " · DANE-ready" : ""}
							</span>
						)}
					</div>
				</div>
			)}
		</section>
	);
}

/**
 * The per-MX DANE coverage matrix (pm/checks/dane_tlsa.mdx §4): one row per MX host showing
 * DNSSEC / TLSA presence / params / cert-match / rollover at a glance, rendered inside the
 * "DANE / TLSA" family group. Cert match stays "—" until the FUTURE :25 probe is enabled.
 */
function DaneMatrix({ rows }: { rows: DaneTlsaResults }) {
	const ok = <span className="text-emerald-700">✔</span>;
	const bad = <span className="text-red-600">✖</span>;
	return (
		<div className="overflow-x-auto border-t border-[var(--edh-border)] px-3 py-2">
			<table className="w-full text-xs">
				<thead>
					<tr className="text-left text-[var(--edh-muted)]">
						<th className="py-1 pr-2 font-medium">MX host (prio)</th>
						<th className="py-1 pr-2 font-medium">DNSSEC</th>
						<th className="py-1 pr-2 font-medium">TLSA</th>
						<th className="py-1 pr-2 font-medium">Params</th>
						<th className="py-1 pr-2 font-medium">Cert match</th>
						<th className="py-1 font-medium">Rollover</th>
					</tr>
				</thead>
				<tbody>
					{rows.map((r) => (
						<tr key={r.mxHost} className="border-t border-[var(--edh-border)]">
							<td className="py-1 pr-2 font-mono">
								{r.mxHost}
								{r.mxPreference !== null ? ` (${r.mxPreference})` : ""}
							</td>
							<td className="py-1 pr-2">{r.dnssecSigned ? ok : bad}</td>
							<td className="py-1 pr-2">
								{r.probeError ? (
									<span className="text-amber-600">error: {r.probeError}</span>
								) : r.tlsaPresent ? (
									`present (${r.tlsaRecords.length})`
								) : (
									<span className="text-slate-500">none</span>
								)}
							</td>
							<td className="py-1 pr-2 font-mono">
								{r.recommended311
									? "3 1 1"
									: r.paramsOk === null
										? "—"
										: r.paramsOk
											? "usable"
											: "unusable"}
							</td>
							<td className="py-1 pr-2 text-slate-500">
								{r.certMatch === null ? "— (probe)" : r.certMatch ? ok : bad}
							</td>
							<td className="py-1">
								{r.rolloverReady ? (
									<span className="text-emerald-700">✔ ≥2</span>
								) : (
									<span
										className={
											r.tlsaPresent ? "text-amber-600" : "text-slate-500"
										}
									>
										✖ ({r.tlsaRecords.length})
									</span>
								)}
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}

/** "6y 3m" / "45d" from an age in days (Registration summary panel, domain_reputation.mdx §4). */
function formatAge(days: number): string {
	if (days < 90) return `${days}d`;
	const years = Math.floor(days / 365);
	const months = Math.floor((days % 365) / 30);
	if (years === 0) return `${months}m`;
	return months > 0 ? `${years}y ${months}m` : `${years}y`;
}

/** Colored status dot for the Registration summary rows (🟢/🟡/🔴/🔵 in the §4 wireframe). */
function RegDot({ tone }: { tone: "ok" | "warn" | "bad" | "unknown" }) {
	const color =
		tone === "ok"
			? "bg-emerald-500"
			: tone === "warn"
				? "bg-amber-400"
				: tone === "bad"
					? "bg-red-500"
					: "bg-sky-400";
	return (
		<span className={cn("inline-block h-2 w-2 shrink-0 rounded-full", color)} />
	);
}

/** One key/value row of the Registration summary panel. */
function RegRow({
	label,
	value,
	note,
	tone = "ok",
}: {
	label: string;
	value: string;
	note?: string;
	tone?: "ok" | "warn" | "bad" | "unknown";
}) {
	return (
		<tr className="border-t border-[var(--edh-border)] first:border-t-0">
			<td className="py-1 pr-3 align-top font-medium text-[var(--edh-muted)]">
				{label}
			</td>
			<td className="py-1 pr-3 align-top">{value}</td>
			<td className="py-1 align-top whitespace-nowrap">
				<span className="inline-flex items-center gap-1.5">
					<RegDot tone={tone} />
					{note && (
						<span
							className={cn(
								"text-[11px]",
								tone === "bad"
									? "font-semibold text-red-600"
									: tone === "warn"
										? "font-semibold text-amber-600"
										: "text-[var(--edh-muted)]",
							)}
						>
							{note}
						</span>
					)}
				</span>
			</td>
		</tr>
	);
}

/** EPP lifecycle-danger codes rendered red in the Status rows (spec §1/§2 hold/pending_delete). */
const DANGER_STATUSES = new Set([
	"serverHold",
	"clientHold",
	"pendingDelete",
	"redemptionPeriod",
]);
/** EPP lock codes rendered green with a "locked" note (spec §2 registrar/delete/update locks). */
const LOCK_STATUSES = new Set([
	"clientTransferProhibited",
	"clientDeleteProhibited",
	"clientUpdateProhibited",
	"serverTransferProhibited",
	"serverDeleteProhibited",
	"serverUpdateProhibited",
]);

/**
 * The Registration summary panel (pm/checks/domain_reputation.mdx §4): the parsed WHOIS/RDAP
 * record at a glance — registrar + source, registered/age, expiry runway, auto-renew, EPP
 * statuses, DNSSEC-at-registrar, privacy, parked — with a Copy-record button, a "Re-check now"
 * that bypasses the 24h RDAP cache (a manual run always re-queries), and the stale-tolerant
 * "as of <timestamp>" caption since registration data is intentionally cached.
 */
function RegistrationSummary({
	reg,
	onRecheck,
	scanning = false,
}: {
	reg: DomainRegistrationResults;
	onRecheck?: () => void;
	scanning?: boolean;
}) {
	const expiryTone =
		reg.days_to_expiry === null
			? "unknown"
			: reg.days_to_expiry < 0
				? "bad"
				: reg.days_to_expiry < 30
					? "warn"
					: "ok";
	const expiryNote =
		reg.days_to_expiry === null
			? undefined
			: reg.days_to_expiry < 0
				? "expired — renew"
				: reg.days_to_expiry < 30
					? "renew"
					: undefined;
	const statuses = reg.statuses.length > 0 ? reg.statuses : ["(none)"];
	// The copy-record payload: the whole parsed snapshot as key: value lines (spec §4 Copy record).
	const copyText = [
		`registrar: ${reg.registrar ?? "unknown"}${reg.registrar_iana_id !== null ? ` (IANA ${reg.registrar_iana_id})` : ""}`,
		`source: ${reg.source}`,
		`registered: ${reg.created_date ?? "unknown"}`,
		`expires: ${reg.expiry_date ?? "unknown"}`,
		`updated: ${reg.updated_date ?? "unknown"}`,
		`transferred: ${reg.transfer_date ?? "never"}`,
		`statuses: ${reg.statuses.join(", ") || "(none)"}`,
		`auto-renew: ${reg.auto_renew === null ? "unknown" : reg.auto_renew ? "yes" : "no"}`,
		`dnssec delegationSigned: ${reg.dnssec_at_registrar === null ? "unknown" : reg.dnssec_at_registrar}`,
		`privacy: ${reg.privacy_enabled === null ? "unknown" : reg.privacy_enabled ? "redacted/private" : "public"}`,
		`parked: ${reg.parked === null ? "unknown" : reg.parked ? "yes" : "no"}`,
		`nameservers: ${reg.nameservers.join(", ") || "(none)"}`,
		`checked at: ${reg.checked_at}`,
	].join("\n");
	return (
		<div className="border-t border-[var(--edh-border)] px-3 py-2">
			<div className="flex items-center justify-between">
				<span className="text-xs font-semibold text-slate-600">
					Domain Registration
				</span>
				<span className="inline-flex items-center gap-2 text-[11px] text-[var(--edh-muted)]">
					<span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono uppercase">
						source {reg.source}
					</span>
					{/* Stale-tolerant cache caption (spec §4 States "Cached"). */}
					<span>as of {new Date(reg.checked_at).toLocaleString()}</span>
				</span>
			</div>
			<table className="mt-1 w-full text-xs">
				<tbody>
					<RegRow
						label="Registrar"
						value={`${reg.registrar ?? "unknown"}${reg.registrar_iana_id !== null ? ` (IANA ${reg.registrar_iana_id})` : ""}`}
						tone={reg.registrar ? "ok" : "unknown"}
					/>
					<RegRow
						label="Registered"
						value={
							reg.created_date
								? `${reg.created_date}${reg.age_days !== null ? `   Age ${formatAge(reg.age_days)}` : ""}`
								: "unknown"
						}
						tone={
							reg.age_days === null
								? "unknown"
								: reg.age_days < 30
									? "warn"
									: reg.age_days < 90
										? "unknown"
										: "ok"
						}
						note={
							reg.age_days !== null && reg.age_days < 30
								? "new — spam prior"
								: undefined
						}
					/>
					<RegRow
						label="Expires"
						value={
							reg.expiry_date
								? `${reg.expiry_date}${
										reg.days_to_expiry !== null
											? reg.days_to_expiry < 0
												? `   ${-reg.days_to_expiry} days ago`
												: `   in ${reg.days_to_expiry} days`
											: ""
									}`
								: "unknown"
						}
						tone={expiryTone}
						note={expiryNote}
					/>
					<RegRow
						label="Auto-renew"
						value={
							reg.auto_renew === null
								? "unknown"
								: reg.auto_renew
									? "on"
									: "off"
						}
						tone={
							reg.auto_renew === null
								? "unknown"
								: reg.auto_renew
									? "ok"
									: "warn"
						}
					/>
					{statuses.map((s, i) => (
						<RegRow
							key={s}
							label={i === 0 ? "Status" : ""}
							value={s}
							tone={
								DANGER_STATUSES.has(s)
									? "bad"
									: LOCK_STATUSES.has(s)
										? "ok"
										: "unknown"
							}
							note={
								DANGER_STATUSES.has(s)
									? "danger"
									: LOCK_STATUSES.has(s)
										? "locked"
										: undefined
							}
						/>
					))}
					<RegRow
						label="DNSSEC (reg)"
						value={`delegationSigned = ${reg.dnssec_at_registrar === null ? "unknown" : reg.dnssec_at_registrar}`}
						tone={reg.dnssec_at_registrar ? "ok" : "unknown"}
					/>
					<RegRow
						label="Privacy"
						value={
							reg.privacy_enabled === null
								? "unknown"
								: reg.privacy_enabled
									? "redacted (GDPR / privacy service)"
									: "registrant public"
						}
						tone={
							reg.privacy_enabled === null
								? "unknown"
								: reg.privacy_enabled
									? "ok"
									: "unknown"
						}
					/>
					<RegRow
						label="Parked"
						value={
							reg.parking_nameservers
								? "parking nameservers"
								: reg.parked === null
									? reg.parking_nameservers === null
										? "unknown"
										: "no"
									: reg.parked
										? "yes"
										: "no"
						}
						tone={
							reg.parked || reg.parking_nameservers
								? "warn"
								: reg.parked === null && reg.parking_nameservers === null
									? "unknown"
									: "ok"
						}
						note={
							reg.parked || reg.parking_nameservers
								? "raises spam scores"
								: undefined
						}
					/>
				</tbody>
			</table>
			<div className="mt-2 flex items-center gap-2">
				<CopyFixButton text={copyText} label="Copy record" />
				{onRecheck && (
					<button
						type="button"
						onClick={onRecheck}
						disabled={scanning}
						className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-medium hover:bg-white disabled:opacity-50"
					>
						<RefreshCw
							className={cn("h-3.5 w-3.5", scanning && "animate-spin")}
						/>
						Re-check now
					</button>
				)}
			</div>
		</div>
	);
}

/**
 * Match a finding to the tool_runs[] entry that fed it (pm/checks/dns.mdx §7 — "ran: `dig …` ·
 * 187 ms"): the command must contain one of the evidence's DNS-name/IP-looking tokens.
 */
function matchToolRun(
	f: Finding,
	toolRuns: InfraToolRun[],
): InfraToolRun | undefined {
	if (toolRuns.length === 0 || !f.evidence) return undefined;
	const tokens = (
		f.evidence.match(/[a-zA-Z0-9_][a-zA-Z0-9_.:-]{3,}/g) ?? []
	).filter((t) => t.includes(".") || t.includes(":"));
	if (tokens.length === 0) return undefined;
	return toolRuns.find((tr) => tokens.some((t) => tr.command.includes(t)));
}

/**
 * One family group header's since-last-run trend glyph (pm/checks/dns.mdx §6.2 item 6):
 * ▲ regressed / ▼ improved / = unchanged. Absent (null) with no previous run to diff against.
 */
function TrendGlyph({
	trend,
}: {
	trend?: "regressed" | "improved" | "unchanged";
}) {
	if (!trend) return null;
	if (trend === "regressed")
		return (
			<span className="text-red-600" title="Regressed since the previous run">
				▲
			</span>
		);
	if (trend === "improved")
		return (
			<span
				className="text-emerald-600"
				title="Improved since the previous run"
			>
				▼
			</span>
		);
	return (
		<span className="text-slate-400" title="Unchanged since the previous run">
			=
		</span>
	);
}

/** The main table: one group per family (spec order), fail-first rows inside each group. */
function TestResultsByFamily({
	families,
	dane,
	registration,
	onRecheck,
	scanning = false,
	toolRuns = [],
	domainId,
	runId,
	trends = {},
}: {
	families: FamilyRollup[];
	dane?: DaneTlsaResults;
	/** The §5 registration snapshot — renders the summary panel atop the registration group. */
	registration?: DomainRegistrationResults;
	/** "Re-check now" on the registration panel — a manual run bypasses the 24h RDAP cache. */
	onRecheck?: () => void;
	scanning?: boolean;
	toolRuns?: InfraToolRun[];
	/** Route context for the group headers' `details ›` explainer links (§6.2 item 6). */
	domainId?: string;
	runId?: string;
	/** Since-last-run trend per family (▲ regressed / ▼ improved / = unchanged, §6.2 item 6). */
	trends?: Partial<Record<DnsFamilyKey, FamilyTrend>>;
}) {
	const spot = useDnsSpotCheck();
	// Which family's ⟳ spot-check result (a live re-run, never persisted) is shown inline.
	const [spotFamily, setSpotFamily] = useState<DnsFamilyKey | null>(null);
	const onSpotCheck = (key: DnsFamilyKey) => {
		if (!domainId || spot.isPending) return;
		setSpotFamily(key);
		spot.mutate({ domainId, checkKey: key });
	};
	const all = families.flatMap((f) => f.findings);
	const counts = {
		pass: all.filter((f) => f.severity === "ok").length,
		fail: all.filter((f) => f.severity === "critical").length,
		warn: all.filter((f) => f.severity === "warning").length,
		info: all.filter((f) => f.severity === "info").length,
	};
	return (
		<section className="mt-4">
			<div className="mb-2 flex items-center justify-between">
				<h2 className="font-semibold">Test results</h2>
				<span className="text-xs text-[var(--edh-muted)]">
					{counts.pass} passed · {counts.fail} failed · {counts.warn} warnings ·{" "}
					{counts.info} info
				</span>
			</div>
			<div className="overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
				{all.length === 0 ? (
					<p className="p-4 text-sm text-slate-600">
						No DNS & Infrastructure tests in this run.
					</p>
				) : (
					families
						// The registration family stays visible even with no findings so its never-run state
						// ("runs on the slow cadence", pm/checks/domain_reputation.mdx §4) has a home.
						.filter(
							(fam) =>
								fam.findings.length > 0 || fam.def.key === "domain_reputation",
						)
						.map((fam) => (
							<div
								key={fam.def.key}
								id={`fam-${fam.def.key}`}
								className="scroll-mt-4"
							>
								<div className="flex items-center justify-between gap-2 border-t border-[var(--edh-border)] bg-slate-50 px-3 py-1.5 first:border-t-0">
									<span className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-slate-600">
										{fam.def.header}
										<TrendGlyph trend={trends[fam.def.key]} />
									</span>
									<span className="flex items-center gap-3 text-xs text-[var(--edh-muted)]">
										<span>
											{fam.failCount > 0
												? `${fam.failCount} of ${fam.findings.length} failing`
												: `${fam.findings.length} tests`}
										</span>
										{/* ⟳ spot-check (§6.2 item 6): re-run just this family live — never saved. */}
										{domainId && (
											<button
												type="button"
												onClick={() => onSpotCheck(fam.def.key)}
												disabled={spot.isPending}
												title={`Spot-check ${fam.def.header} now (live, not saved)`}
												aria-label={`Spot-check ${fam.def.header} now`}
												className="rounded p-0.5 text-[var(--edh-muted)] hover:bg-slate-200 hover:text-slate-700 disabled:opacity-50"
											>
												{spot.isPending && spotFamily === fam.def.key ? (
													<Loader2 className="h-3.5 w-3.5 animate-spin" />
												) : (
													<RefreshCw className="h-3.5 w-3.5" />
												)}
											</button>
										)}
										{/* details › — the family's run-scoped check-detail explainer (§6.2 item 6). */}
										{domainId && runId && (
											<Link
												to="/domains/$id/runs/$runId/dns/check/$checkKey"
												params={{ id: domainId, runId, checkKey: fam.def.slug }}
												className="font-medium text-[var(--edh-primary)] hover:underline"
											>
												details ›
											</Link>
										)}
									</span>
								</div>
								{spotFamily === fam.def.key && spot.data && !spot.isPending && (
									<SpotCheckResultStrip
										result={spot.data}
										onDismiss={() => setSpotFamily(null)}
									/>
								)}
								{spotFamily === fam.def.key && spot.isError && (
									<p className="border-t border-[var(--edh-border)] px-3 py-2 text-xs text-red-600">
										Spot check failed — try again in a moment.
									</p>
								)}
								{fam.def.key === "dane_tlsa" && dane && dane.length > 0 && (
									<DaneMatrix rows={dane} />
								)}
								{/* Healthy state (pm/checks/dns_health.mdx §4 States): when the zone family has no
                    warning/critical findings, one green summary row above the individual rows. */}
								{fam.def.key === "dns_health" &&
									fam.findings.length > 0 &&
									fam.failCount === 0 && (
										<p className="flex items-center gap-2 border-t border-[var(--edh-border)] bg-emerald-50 px-3 py-2 text-sm text-emerald-800">
											<ShieldCheck className="h-4 w-4 shrink-0 text-emerald-600" />
											Delegation OK — 2+ diverse NS, consistent SOA, no dangling
											records.
										</p>
									)}
								{/* Registration summary panel (pm/checks/domain_reputation.mdx §4): the parsed
                    record at a glance, atop the group's finding rows. Never-run → the slow-cadence
                    note; no snapshot with findings → the amber record_available row explains. */}
								{fam.def.key === "domain_reputation" &&
									(registration ? (
										<RegistrationSummary
											reg={registration}
											onRecheck={onRecheck}
											scanning={scanning}
										/>
									) : fam.findings.length === 0 ? (
										<p className="border-t border-[var(--edh-border)] px-3 py-2 text-sm text-slate-600">
											Registration not yet checked — runs on the slow cadence.
										</p>
									) : null)}
								<ul>
									{[...fam.findings]
										.sort((a, b) => ORDER[a.severity] - ORDER[b.severity])
										.map((f) => (
											<TestRow
												key={f.id + f.title}
												finding={f}
												toolRun={matchToolRun(f, toolRuns)}
											/>
										))}
								</ul>
							</div>
						))
				)}
			</div>
		</section>
	);
}

/**
 * The inline result of a family ⟳ spot-check (pm/checks/dns.mdx §6.2 item 6): a LIVE single-family
 * re-run summarized under the group header. Never persisted — the stored run stays untouched.
 */
function SpotCheckResultStrip({
	result,
	onDismiss,
}: {
	result: DnsSpotCheckResult;
	onDismiss: () => void;
}) {
	const failing = result.findings.filter(
		(f) => f.severity === "critical" || f.severity === "warning",
	);
	const worst = failing.find((f) => f.severity === "critical") ?? failing[0];
	return (
		<div
			className={cn(
				"border-t border-[var(--edh-border)] px-3 py-2 text-xs",
				failing.length > 0
					? "bg-amber-50 text-amber-800"
					: "bg-emerald-50 text-emerald-800",
			)}
		>
			<span className="font-medium">Spot check (live, not saved): </span>
			{failing.length > 0
				? `${failing.length} of ${result.findings.length} failing — ${worst?.title ?? ""}`
				: `all ${result.findings.length} tests pass right now`}
			<button
				type="button"
				onClick={onDismiss}
				className="ml-2 font-medium underline hover:no-underline"
			>
				dismiss
			</button>
		</div>
	);
}

function TestRow({
	finding: f,
	toolRun,
}: {
	finding: Finding;
	toolRun?: InfraToolRun;
}) {
	const [open, setOpen] = useState(f.severity === "critical");
	const icon =
		f.severity === "ok" ? (
			<ShieldCheck className="h-4 w-4 text-emerald-600" />
		) : f.severity === "info" ? (
			<Info className="h-4 w-4 text-sky-600" />
		) : (
			<ShieldAlert
				className={cn(
					"h-4 w-4",
					f.severity === "critical" ? "text-red-600" : "text-amber-500",
				)}
			/>
		);
	return (
		<li className="border-t border-[var(--edh-border)] first:border-t-0">
			<button
				type="button"
				onClick={() => setOpen(!open)}
				className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-slate-50"
			>
				{icon}
				<span className="font-mono text-xs uppercase text-[var(--edh-muted)]">
					{f.id}
				</span>
				<span className="font-medium">{f.title}</span>
				{/* Dangling findings carry a distinct red "takeover risk" badge (pm/checks/dns_health.mdx §4). */}
				{f.id.startsWith("infra.dangling_") &&
					(f.severity === "critical" || f.severity === "warning") && (
						<span className="shrink-0 rounded bg-red-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-red-700">
							takeover risk
						</span>
					)}
				{/* Probe-gated sub-checks render with a muted "future" chip (pm/checks/dns_health.mdx §4 States). */}
				{f.severity === "info" && f.title.includes("not evaluated") && (
					<span className="shrink-0 rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium text-slate-500">
						⏳ future
					</span>
				)}
				<ChevronDown
					className={cn(
						"ml-auto h-4 w-4 shrink-0 text-[var(--edh-muted)] transition-transform",
						open && "rotate-180",
					)}
				/>
			</button>
			{open && (
				<div className="px-3 pb-3 pl-9">
					<p className="text-sm text-slate-600">{f.detail}</p>
					{f.evidence && (
						<p className="mt-1 break-all rounded bg-slate-50 p-2 font-mono text-xs text-slate-600">
							observed: {f.evidence}
						</p>
					)}
					{toolRun && (
						// Tool-run traceability (pm/checks/dns.mdx §7): the exact command behind the evidence.
						<p className="mt-1 break-all text-xs text-[var(--edh-muted)]">
							ran: <code className="font-mono">{toolRun.command}</code> ·{" "}
							{toolRun.duration_ms} ms
							{toolRun.error ? ` · ${toolRun.error}` : ""}
						</p>
					)}
					{f.remediation && f.severity !== "ok" && (
						<div className="mt-2 flex items-start justify-between gap-2 rounded-md bg-slate-50 p-2 text-sm text-slate-700">
							<span className="flex items-start gap-2">
								<Wrench className="mt-0.5 h-4 w-4 shrink-0 text-[var(--edh-primary)]" />
								<span>
									<span className="font-medium">Fix: </span>
									{f.remediation}
								</span>
							</span>
							<CopyFixButton text={f.remediation} />
						</div>
					)}
				</div>
			)}
		</li>
	);
}
