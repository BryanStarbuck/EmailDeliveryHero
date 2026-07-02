import { Link, useNavigate, useParams } from "@tanstack/react-router";
import {
	ArrowLeft,
	ChevronDown,
	ChevronLeft,
	ChevronRight,
	RefreshCw,
	Star,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useAuditResults, useAuditRun, useAuditRuns } from "@/api/audit";
import { useDomains } from "@/api/domains";
import type {
	ArcForwarderObservation,
	ArcResults,
	AuditResult,
	Finding,
	Severity,
} from "@/api/types";
import { SeverityBadge } from "@/components/Badges";
import { CopyFixButton } from "@/components/CopyFixButton";
import { normalizeDmarcSection } from "@/lib/dmarc";
import { arcProblemIdFor } from "@/lib/dmarc-problems";
import { cn } from "@/lib/utils";
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext";

const ORDER: Record<Severity, number> = {
	critical: 0,
	warning: 1,
	info: 2,
	ok: 3,
};
const WORST: Record<Severity, number> = {
	ok: 0,
	info: 1,
	warning: 2,
	critical: 3,
};

/** `YYYY-MM-DD HH:mm`, matching the category pages' run context strips. */
function fmtStamp(iso: string): string {
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) return iso;
	const p = (n: number): string => String(n).padStart(2, "0");
	return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** The worst `arc.*` severity in one run; null when the ARC checker did not run ("not measured"). */
function worstArc(run: AuditResult | undefined): Severity | null {
	let worst: Severity | null = null;
	for (const f of run?.findings ?? []) {
		if (f.checkId !== "arc") continue;
		if (worst === null || WORST[f.severity] > WORST[worst]) worst = f.severity;
	}
	return worst;
}

/** §9.1 status chip: one rule shared by the band row, mini-row, and this page's block-2 headline. */
function chipFor(
	worst: Severity | null,
	arc: ArcResults | undefined,
): { label: string; className: string } {
	if (worst === null)
		return { label: "not measured", className: "bg-slate-100 text-slate-500" };
	if (worst === "critical")
		return { label: "✗ signer key", className: "bg-red-100 text-red-700" };
	if (worst === "warning")
		return { label: "⚠ unverified", className: "bg-amber-100 text-amber-700" };
	if (worst === "info") {
		if (arc?.applicable === false)
			return { label: "ⓘ N/A", className: "bg-slate-100 text-slate-600" };
		if (arc?.applicable === null || arc === undefined)
			return {
				label: "ⓘ undetermined",
				className: "bg-slate-100 text-slate-600",
			};
		return { label: "ⓘ advisory", className: "bg-slate-100 text-slate-600" };
	}
	return { label: "✓ verified", className: "bg-emerald-100 text-emerald-700" };
}

const HISTORY_DOT: Record<string, string> = {
	critical: "bg-red-600",
	warning: "bg-amber-500",
	info: "bg-slate-400",
	ok: "bg-emerald-600",
	none: "bg-slate-200",
};

/** §9.5 copy-button payloads — always the publishable value / runnable command, never prose. */
const MAILMAN_ARC_CONFIG = `# /etc/mailman3/mailman.cfg
[ARC]
enabled: yes
authserv_id: lists.example.org
domain: lists.example.org
selector: arc1
privkey: /etc/mailman3/arc.private.pem`;
const OPENSSL_KEYGEN = `openssl genrsa -out arc.private.pem 2048
openssl rsa -in arc.private.pem -pubout -outform der | openssl base64 -A`;

/** §9.7 references footer — the only external navigation on the page (new tab). */
const REFERENCES: { label: string; href: string }[] = [
	{ label: "RFC 8617 (ARC)", href: "https://www.rfc-editor.org/rfc/rfc8617" },
	{
		label: "RFC 8301 (key strength)",
		href: "https://www.rfc-editor.org/rfc/rfc8301",
	},
	{
		label: "RFC 6376 (DKIM signatures)",
		href: "https://www.rfc-editor.org/rfc/rfc6376",
	},
	{
		label: "DMARCbis (RFC 9989)",
		href: "https://www.rfc-editor.org/rfc/rfc9989",
	},
	{
		label: "dmarc.org — ARC overview",
		href: "https://dmarc.org/presentations/ARC-Overview.pdf",
	},
	{ label: "arc-spec.org", href: "http://arc-spec.org/" },
	{
		label: "Gmail ARC authentication",
		href: "https://support.google.com/a/answer/13198639",
	},
	{
		label: "Mailman 3 ARC configuration",
		href: "https://docs.mailman3.org/projects/mailman/en/latest/src/mailman/config/docs/config.html",
	},
	{ label: "OpenARC", href: "https://github.com/trusteddomainproject/OpenARC" },
	{
		label: "M3AAWG forwarding best practices",
		href: "https://www.m3aawg.org/sites/default/files/m3aawg-mailing-lists-bcp-2014-06.pdf",
	},
];

/**
 * The ARC sub-test explainer page (pm/checks/arc.mdx §9) at the category's shared explainer route
 * (pm/checks/dmarc.mdx §6.3–§6.5 chrome): /domains/:id/runs/:runId/dmarc/check/arc, with the
 * newest-run alias /domains/:id/dmarc/check/arc. Renders the five locked blocks — what this is /
 * your current state / what it means / what you can do / run this check now — plus the unit-scoped
 * ten-chip history strip and the references footer. Every block-2 datum comes from the VIEWED
 * run's persisted `results.arc` + `checkId === "arc"` findings, never a live lookup (§9.3).
 */
export function ArcCheckPage() {
	const {
		id = "",
		runId,
		checkKey = "",
	} = useParams({ strict: false }) as {
		id?: string;
		runId?: string;
		checkKey?: string;
	};
	const { data: domains } = useDomains();
	const { data: results } = useAuditResults();
	const { data: allRuns } = useAuditRuns();
	const { data: historicalRun } = useAuditRun(runId);
	const runDomains = useScanRunner();
	const scanning = useScanProgress().some((s) => s.domainId === id);
	const navigate = useNavigate();

	const domain = (domains ?? []).find((d) => d.id === id);
	const name = domain?.name ?? id;
	const latest = (results ?? []).find((r) => r.domainId === id);
	const result = runId ? historicalRun : latest;

	// The domain's runs oldest → newest: the pager rail and the §9.7 history strip.
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
	const isNewest =
		!runId || (effectiveIndex >= 0 && effectiveIndex === domainRuns.length - 1);

	// Paging / history clicks swap :runId only (§9 route contract).
	const goToRun = (r: AuditResult | undefined): void => {
		if (r?.runId) {
			navigate({
				to: "/domains/$id/runs/$runId/dmarc/check/$checkKey",
				params: { id, runId: r.runId, checkKey: "arc" },
			});
		}
	};

	// Block 5's Run-this-check-now (§9.6): v1 re-runs the full audit via the shared scan runner
	// (POST /api/audit/run/:domainId), then lands on the newest alias of this page.
	const onRunNow = (): void => {
		if (scanning) return;
		runDomains([{ id, name }]);
		if (runId)
			navigate({
				to: "/domains/$id/dmarc/check/$checkKey",
				params: { id, checkKey: "arc" },
			});
	};

	// Keyboard: ←/→ pages runs (category chrome), `r` triggers the re-run (§9.6).
	useEffect(() => {
		const onKey = (e: KeyboardEvent): void => {
			const target = e.target as HTMLElement | null;
			if (target && ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName))
				return;
			if (e.key === "ArrowLeft" && prevRun) goToRun(prevRun);
			if (e.key === "ArrowRight" && nextRun) goToRun(nextRun);
			if (e.key === "r") onRunNow();
		};
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	});

	// Unknown-checkKey panel — the category chrome's "No such sub-test" state (§9.8).
	if (checkKey !== "arc") {
		return (
			<div className="mx-auto max-w-3xl">
				<Link
					to="/domains/$id/dmarc"
					params={{ id }}
					className="mb-4 inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
				>
					<ArrowLeft className="h-4 w-4" /> Back to DMARC for {name}
				</Link>
				<div className="rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center text-slate-600">
					No such sub-test "{checkKey}" in the DMARC category.
				</div>
			</div>
		);
	}

	const arcFindings = (result?.findings ?? [])
		.filter((f) => f.checkId === "arc")
		.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
	const arc = result?.results?.arc;
	const worst = worstArc(result);
	const chip = chipFor(worst, arc);
	const notMeasured = result !== undefined && worst === null;

	// The applicability panel's policy: §9.11 persisted fields first, sibling dmarc record fallback.
	const dmarcRecord = normalizeDmarcSection(result?.results?.dmarc).record;
	const policy = arc?.dmarcPolicy ?? dmarcRecord?.policy ?? null;
	const enforcing = policy === "quarantine" || policy === "reject";
	const forwarders = arc?.forwarders ?? [];
	const declaredCount = domain?.arc?.forwarders.length ?? forwarders.length;
	const usesForwarding = domain?.arc?.usesForwarding ?? declaredCount > 0;

	const failingSelectors = forwarders.filter(
		(f) => f.selectorResolves === false,
	);
	const weakKeys = arcFindings.filter(
		(f) =>
			f.id.startsWith("arc.signature_algorithm") && f.severity === "warning",
	);

	const verdict = !result
		? "No audit yet."
		: notMeasured
			? "The ARC checker did not run in this audit."
			: arc?.applicable === false
				? enforcing
					? "ARC not applicable — no forwarding declared for this domain."
					: "ARC not applicable — DMARC is not enforcing."
				: arc?.applicable === null || arc === undefined
					? "ARC applicability could not be determined this run (transient DNS failure)."
					: worst === "critical"
						? `ARC applies (p=${policy ?? "?"} + ${declaredCount} forwarder${declaredCount === 1 ? "" : "s"} declared) and at least one signer key cannot be verified.`
						: `ARC applies (p=${policy ?? "?"} + ${declaredCount} forwarder${declaredCount === 1 ? "" : "s"} declared) but no chain has been verified yet.`;

	return (
		<div className="mx-auto max-w-4xl">
			{/* ── Header row + run context strip (category chrome, dmarc.mdx §6.4) ─────────────── */}
			<div className="mb-4 flex items-center justify-between">
				<button
					type="button"
					onClick={() =>
						runId && result?.runId
							? navigate({
									to: "/domains/$id/runs/$runId/dmarc",
									params: { id, runId: result.runId },
								})
							: navigate({ to: "/domains/$id/dmarc", params: { id } })
					}
					className="inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
				>
					<ArrowLeft className="h-4 w-4" /> Back to DMARC
				</button>
			</div>

			<h1 className="text-2xl font-bold">ARC (Authenticated Received Chain)</h1>
			<div className="mt-1 flex flex-wrap items-center gap-2 text-sm text-[var(--edh-muted)]">
				<span className="font-medium text-slate-900">{name}</span>
				<span>· DMARC › sub-test ·</span>
				<span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium uppercase">
					advisory
				</span>
			</div>

			{result && (
				<div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-[var(--edh-muted)]">
					<span className="tabular-nums">
						Run {fmtStamp(result.startedAt ?? result.ranAt)}
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
				</div>
			)}

			{/* ── Block 1 — What this is (§9.2, static; renders even for "not measured") ────────── */}
			<Block title="What this is">
				<p className="text-sm leading-relaxed text-slate-700">
					ARC (Authenticated Received Chain, RFC 8617) lets a forwarder or
					mailing list record "this message passed SPF/DKIM/DMARC when it
					reached me," sign that record, and pass it downstream. Three headers
					cooperate:{" "}
					<span className="font-mono text-xs">ARC-Authentication-Results</span>{" "}
					(the snapshot of the results the intermediary observed),{" "}
					<span className="font-mono text-xs">ARC-Message-Signature</span> (a
					DKIM-style signature over the message as received), and{" "}
					<span className="font-mono text-xs">ARC-Seal</span> (a signature over
					the whole chain so far, carrying{" "}
					<span className="font-mono text-xs">cv=</span>).
				</p>
				<p className="mt-2 text-sm leading-relaxed text-slate-700">
					It exists because forwarding breaks DMARC: the envelope changes (SPF
					alignment lost) and the body or subject often change —{" "}
					<Link
						to={
							runId && result?.runId
								? "/domains/$id/runs/$runId/dkim"
								: "/domains/$id/dkim"
						}
						params={
							runId && result?.runId ? { id, runId: result.runId } : { id }
						}
						className="text-[var(--edh-primary)] underline"
					>
						breaking the DKIM signature
					</Link>
					. Concretely: mail from billing@{name} to a Google Group arrives at
					Gmail failing both, and under p=reject it is rejected even though it
					is legitimate.
				</p>
				<p className="mt-2 text-sm leading-relaxed text-slate-700">
					The crucial caveat: ARC is <em>not a DNS record you publish</em> and{" "}
					<em>not a guarantee</em> — intermediaries add it in transit, and
					receivers <em>may</em> honor a valid chain (cv=pass) from a forwarder
					they trust. That is why this unit is advisory: EmailDeliveryHero
					verifies the pieces that live in DNS/config today, and the chain
					itself only from a captured forwarded message.
				</p>
			</Block>

			{/* ── Block 2 — Your current state (§9.3, this run's persisted data only) ───────────── */}
			<Block
				title="Your current state"
				right={
					<span
						className={cn(
							"rounded-full px-3 py-1 text-sm font-semibold",
							chip.className,
						)}
					>
						{chip.label}
					</span>
				}
			>
				{!result ? (
					<p className="text-sm text-slate-600">
						No audit yet — run one below.
					</p>
				) : notMeasured ? (
					<p className="text-sm text-slate-600">
						The ARC checker did not run in this audit (disabled, errored before
						emitting, or the run predates ARC). Re-run below to measure it.
					</p>
				) : (
					<>
						<p className="text-sm font-medium text-slate-800">{verdict}</p>

						{/* Applicability panel — observed value + provenance per row (§9.3 item 2). */}
						<div className="mt-3 overflow-hidden rounded-md border border-[var(--edh-border)]">
							<table className="w-full text-sm">
								<tbody>
									<tr className="border-b border-[var(--edh-border)]">
										<td className="w-44 px-3 py-1.5 text-xs font-semibold">
											DMARC policy
										</td>
										<td className="px-3 py-1.5">
											{policy ? (
												<Link
													to={
														runId && result.runId
															? "/domains/$id/runs/$runId/dmarc/check/$checkKey"
															: "/domains/$id/dmarc/check/$checkKey"
													}
													params={
														runId && result.runId
															? { id, runId: result.runId, checkKey: "policy" }
															: { id, checkKey: "policy" }
													}
													className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs text-[var(--edh-primary)] hover:underline"
													title="Open the DMARC policy sub-test explainer"
												>
													p={policy}
												</Link>
											) : (
												<span className="font-mono text-xs text-slate-400">
													— not read
												</span>
											)}
											<span className="ml-2 text-xs text-slate-600">
												→ enforcing:{" "}
												{policy ? (enforcing ? "yes" : "no") : "unknown"}
											</span>
										</td>
										<td className="px-3 py-1.5 text-right text-xs text-[var(--edh-muted)]">
											{arc?.policySource === "sibling"
												? "from this run's DMARC result"
												: arc?.policySource === "dns"
													? "fallback _dmarc lookup"
													: "from this run's DMARC section"}
										</td>
									</tr>
									<tr className="border-b border-[var(--edh-border)]">
										<td className="px-3 py-1.5 text-xs font-semibold">
											Forwarding declared
										</td>
										<td className="px-3 py-1.5 text-xs text-slate-700">
											{usesForwarding ? "declared" : "not declared"} ·{" "}
											{declaredCount} forwarder
											{declaredCount === 1 ? "" : "s"}
										</td>
										<td className="px-3 py-1.5 text-right text-xs">
											<Link
												to="/domains"
												search={{ edit: id }}
												className="text-[var(--edh-primary)] hover:underline"
											>
												domain settings
											</Link>
										</td>
									</tr>
									<tr>
										<td className="px-3 py-1.5 text-xs font-semibold">
											Verdict
										</td>
										<td
											className="px-3 py-1.5 font-mono text-xs text-slate-700"
											colSpan={2}
										>
											applicable ={" "}
											{arc?.applicable === null || arc?.applicable === undefined
												? "— not determined"
												: String(arc.applicable)}{" "}
											· forwardingRisk ={" "}
											{arc?.forwardingRisk === null ||
											arc?.forwardingRisk === undefined
												? "—"
												: String(arc.forwardingRisk)}
										</td>
									</tr>
								</tbody>
							</table>
						</div>

						{/* Finding rows — fail → warn → info → pass, accordion + drill-down link (§9.3 item 3). */}
						<ul className="mt-3 space-y-2">
							{arcFindings.map((f) => (
								<ArcFindingRow
									key={f.id}
									finding={f}
									id={id}
									runId={result.runId}
								/>
							))}
						</ul>

						{/* Raw record slot — one signer-key card per declared forwarder (§9.3 item 4). */}
						{forwarders.length > 0 && (
							<div className="mt-3 space-y-2">
								{forwarders.map((fw) => (
									<SignerKeyCard
										key={fw.label + fw.forwardAddress}
										fw={fw}
										domainId={id}
										findings={arcFindings}
									/>
								))}
							</div>
						)}

						{/* Scoped parsed-field table over results.arc — nulls render grayed, never hidden (§9.3 item 5). */}
						<ParsedFieldTable arc={arc} />
					</>
				)}
			</Block>

			{/* ── Block 3 — What it means (§9.4, keyed to the current state) ────────────────────── */}
			<Block title="What it means">
				{!result || notMeasured ? (
					<p className="text-sm text-slate-700">
						Nothing measured yet — the concept above still applies; re-run the
						audit to see where this domain stands.
					</p>
				) : arc?.applicable === false && !enforcing ? (
					<p className="text-sm text-slate-700">
						DMARC is not enforcing (p={policy ?? "none/absent"}), so nothing is
						being rejected and there is nothing for ARC to rescue; the real work
						is on the DMARC policy ladder. Deliverability impact today from ARC:
						none.
					</p>
				) : arc?.applicable === false ? (
					<p className="text-sm text-slate-700">
						No forwarding is declared, and directly-sent mail never needs ARC.
						Impact: none — <em>unless</em> this domain actually does send
						through lists it hasn't declared, in which case losses are
						invisible. If that is possible, declare the forwarders in settings.
					</p>
				) : (
					<div className="space-y-2 text-sm text-slate-700">
						{failingSelectors.length > 0 && (
							<p>
								<strong>Signer key broken:</strong> the forwarder may be
								sealing, but receivers cannot verify the seal —
								cryptographically equivalent to no ARC at all. The ARC evidence
								is discarded and mail through{" "}
								{failingSelectors.map((f) => f.label).join(", ")} falls back to
								the raw DMARC failure under p={policy ?? "?"}.
							</p>
						)}
						{weakKeys.length > 0 && (
							<p>
								<strong>Weak/legacy signer key:</strong> verifiers increasingly
								refuse &lt;1024-bit or non-rsa/ed25519 keys (RFC 8301), so the
								chain's protection erodes receiver by receiver.
							</p>
						)}
						{arc?.forwardingRisk && (
							<p>
								<strong>Unverified forwarding path:</strong> the classic silent
								failure — "some recipients never get our mail, but only via{" "}
								{forwarders.length > 0
									? forwarders.map((f) => f.label).join(" / ")
									: "the declared paths"}
								." Under p={policy ?? "quarantine/reject"}, forwarded legitimate
								mail is being spam-foldered or rejected at strict receivers
								until each forwarder demonstrably seals a valid chain (cv=pass).
							</p>
						)}
						{worst === "ok" && (
							<p>
								A cv=pass chain was verified on every declared path — forwarded
								mail survives p=reject on those hops. Residual caveat: honoring
								is per-receiver trust; ARC supplies evidence, it does not compel
								delivery.
							</p>
						)}
					</div>
				)}
			</Block>

			{/* ── Block 4 — What you can do about it (§9.5, copy buttons carry publishable values) ── */}
			<Block title="What you can do about it">
				{!result || notMeasured ? (
					<p className="text-sm text-slate-700">
						Re-run the audit (below) — that is exactly the fix for an unmeasured
						unit.
					</p>
				) : arc?.applicable === false ? (
					<div className="text-sm text-slate-700">
						<p className="font-medium">Nothing to do for ARC right now.</p>
						<p className="mt-1">
							Revisit when moving to p=quarantine/reject or when mail starts
							flowing through a list/forwarder. If forwarding exists but was
							never declared,{" "}
							<Link
								to="/domains"
								search={{ edit: id }}
								className="text-[var(--edh-primary)] underline"
							>
								declare it in the domain's ARC / forwarding settings
							</Link>{" "}
							(label + forwarding address + signer d=/s= if known).
						</p>
					</div>
				) : arc?.applicable === null || arc === undefined ? (
					<ol className="list-decimal space-y-2 pl-5 text-sm text-slate-700">
						<li>
							Retry the audit (the button below) — the applicability lookup
							failed transiently.
						</li>
					</ol>
				) : (
					<ol className="list-decimal space-y-3 pl-5 text-sm text-slate-700">
						{forwarders.length === 0 && (
							<li>
								Register each forwarder / mailing list (label + forwarding
								address + ARC signer d=/s= if known) in the{" "}
								<Link
									to="/domains"
									search={{ edit: id }}
									className="text-[var(--edh-primary)] underline"
								>
									domain's ARC / forwarding settings
								</Link>{" "}
								— nothing can be verified until each path is listed.
							</li>
						)}
						<li>
							If you run the list (Mailman 3): enable ARC sealing.
							<div className="mt-1 flex items-start justify-between gap-2 rounded-md bg-slate-50 p-2">
								<pre className="whitespace-pre-wrap font-mono text-xs text-slate-700">
									{MAILMAN_ARC_CONFIG}
								</pre>
								<CopyFixButton text={MAILMAN_ARC_CONFIG} label="Copy" />
							</div>
						</li>
						<li>
							Generate the signing key:
							<div className="mt-1 flex items-start justify-between gap-2 rounded-md bg-slate-50 p-2">
								<pre className="whitespace-pre-wrap font-mono text-xs text-slate-700">
									{OPENSSL_KEYGEN}
								</pre>
								<CopyFixButton text={OPENSSL_KEYGEN} label="Copy" />
							</div>
						</li>
						{(failingSelectors.length > 0 ? failingSelectors : forwarders).map(
							(fw) => {
								const qname =
									fw.signerDomain && fw.signerSelector
										? `${fw.signerSelector}._domainkey.${fw.signerDomain}`
										: `arc1._domainkey.lists.example.org`;
								const txt = `${qname} TXT "v=DKIM1; k=rsa; p=<base64-from-step-2>"`;
								const verify = `doggo ${qname} TXT --json`;
								return (
									<li key={`fix-${fw.label}`}>
										Publish (or ask "{fw.label}" to repair) the public key
										{fw.selectorResolves === false && (
											<span className="text-red-700"> — currently failing</span>
										)}
										:
										<div className="mt-1 flex items-center justify-between gap-2 rounded-md bg-slate-50 p-2">
											<code className="break-all font-mono text-xs text-slate-700">
												{txt}
											</code>
											<CopyFixButton text={txt} label="Copy" />
										</div>
										<div className="mt-1 flex items-center justify-between gap-2 rounded-md bg-slate-50 p-2">
											<code className="break-all font-mono text-xs text-slate-700">
												{verify}
											</code>
											<CopyFixButton text={verify} label="Copy" />
										</div>
										<p className="mt-1 text-xs text-[var(--edh-muted)]">
											DNS changes take up to the record's TTL to propagate
											before receivers see them.
										</p>
									</li>
								);
							},
						)}
						<li>
							Third-party forwarder (Google Groups, a listserv you don't run)?
							Ask them to enable ARC sealing and tell you the d=/s= they sign
							with; record those in settings so the key check runs here. Google
							Groups and Microsoft 365 seal by default — record their observed
							signer once a sample is captured.
						</li>
						<li>
							Verify with the capture probe once available, or manually: forward
							a test message through the path and inspect its headers for{" "}
							<span className="font-mono text-xs">ARC-Seal: … cv=pass</span>.
						</li>
					</ol>
				)}
			</Block>

			{/* ── Block 5 — Run this check now + the (future) Capture sample probe (§9.6) ────────── */}
			<Block title="Run this check now">
				<div className="flex flex-wrap items-center gap-3">
					<button
						type="button"
						onClick={onRunNow}
						disabled={scanning}
						title={`Re-runs all checks for ${name}`}
						className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
					>
						<RefreshCw
							className={scanning ? "h-4 w-4 animate-spin" : "h-4 w-4"}
						/>
						Run check
					</button>
					{/* Deliberately distinct secondary action — never triggered by the re-run (§9.6). */}
					<button
						type="button"
						disabled
						title="Sends a real swaks probe through a declared forwarder to capture and validate the ARC chain. Admin-only; ships in a later round."
						className="rounded-md border border-[var(--edh-border)] px-3 py-2 text-sm text-[var(--edh-muted)] opacity-60"
					>
						Capture sample…
					</button>
				</div>
				<p className="mt-2 text-xs text-[var(--edh-muted)]">
					Re-runs the DMARC + ARC checks for {name} and refreshes this page.
					Keyboard:{" "}
					<kbd className="rounded border border-[var(--edh-border)] px-1">
						r
					</kbd>
				</p>
			</Block>

			{/* ── History strip — last 10 runs colored by worst arc.* severity (§9.7) ───────────── */}
			<Block title="History">
				{domainRuns.length === 0 ? (
					<p className="text-sm text-slate-600">No runs yet.</p>
				) : (
					<div className="flex items-center gap-1.5">
						{domainRuns.slice(-10).map((r) => {
							const w = worstArc(r);
							const viewed = r.runId !== undefined && r.runId === result?.runId;
							return (
								<button
									key={r.runId ?? r.ranAt}
									type="button"
									onClick={() => goToRun(r)}
									disabled={!r.runId}
									title={`${fmtStamp(r.startedAt ?? r.ranAt)} — ARC: ${w ?? "did not run"}`}
									aria-label={`View run ${fmtStamp(r.startedAt ?? r.ranAt)}`}
									className={cn(
										"h-4 w-4 rounded-sm",
										HISTORY_DOT[w ?? "none"],
										viewed && "ring-2 ring-slate-700 ring-offset-1",
									)}
								/>
							);
						})}
						<span className="ml-2 text-xs text-[var(--edh-muted)]">
							ARC, last {Math.min(10, domainRuns.length)} runs — click to view
						</span>
					</div>
				)}
			</Block>

			{/* ── References footer — external links, new tab (§9.7) ────────────────────────────── */}
			<Block title="References">
				<ul className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
					{REFERENCES.map((ref) => (
						<li key={ref.href}>
							<a
								href={ref.href}
								target="_blank"
								rel="noreferrer"
								className="text-[var(--edh-primary)] hover:underline"
							>
								{ref.label}
							</a>
						</li>
					))}
				</ul>
			</Block>
		</div>
	);
}

/** One five-block section with the category chrome's heading style. */
function Block({
	title,
	right,
	children,
}: {
	title: string;
	right?: React.ReactNode;
	children: React.ReactNode;
}) {
	return (
		<section className="mt-6 rounded-lg border border-[var(--edh-border)] bg-white p-4">
			<div className="mb-2 flex items-center justify-between">
				<h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--edh-muted)]">
					{title}
				</h2>
				{right}
			</div>
			{children}
		</section>
	);
}

/**
 * One finding row (§9.3 item 3): status icon + id in small caps + title, chevron accordion with
 * observed evidence, why it matters, the copyable remediation, and the "Full drill-down ›" link
 * to its ARC-nn problem page (§10).
 */
function ArcFindingRow({
	finding: f,
	id,
	runId,
}: {
	finding: Finding;
	id: string;
	runId?: string;
}) {
	const [open, setOpen] = useState(
		f.severity === "critical" || f.severity === "warning",
	);
	const problemId = arcProblemIdFor(f);
	return (
		<li className="rounded-md border border-[var(--edh-border)] bg-white">
			<button
				type="button"
				onClick={() => setOpen((o) => !o)}
				className="flex w-full items-center gap-2 px-3 py-2 text-left"
			>
				<SeverityBadge severity={f.severity} />
				<span className="font-mono text-xs uppercase text-[var(--edh-muted)]">
					{f.id}
				</span>
				<span className="min-w-0 flex-1 truncate text-sm font-medium">
					{f.title}
				</span>
				{open ? (
					<ChevronDown className="h-4 w-4 shrink-0 text-[var(--edh-muted)]" />
				) : (
					<ChevronRight className="h-4 w-4 shrink-0 text-[var(--edh-muted)]" />
				)}
			</button>
			{open && (
				<div className="border-t border-[var(--edh-border)] px-3 py-2 text-sm">
					{f.evidence && (
						<p className="break-all rounded bg-slate-50 p-1.5 font-mono text-xs text-slate-600">
							observed: {f.evidence}
						</p>
					)}
					<p className="mt-1 text-slate-700">{f.detail}</p>
					{f.remediation && f.severity !== "ok" && (
						<div className="mt-2 flex items-start justify-between gap-2 rounded-md bg-slate-50 p-2 text-slate-700">
							<span>
								<span className="font-medium">Fix: </span>
								{f.remediation}
							</span>
							<CopyFixButton text={f.remediation} label="copy fix" />
						</div>
					)}
					{problemId &&
						(runId ? (
							<Link
								to="/domains/$id/runs/$runId/dmarc/$problemId"
								params={{ id, runId, problemId }}
								className="mt-2 inline-block text-xs text-[var(--edh-primary)] underline"
							>
								Full drill-down ({problemId}) ›
							</Link>
						) : (
							<Link
								to="/domains/$id/dmarc/$problemId"
								params={{ id, problemId }}
								className="mt-2 inline-block text-xs text-[var(--edh-primary)] underline"
							>
								Full drill-down ({problemId}) ›
							</Link>
						))}
				</div>
			)}
		</li>
	);
}

/**
 * The raw-record slot's signer-key card (§9.3 item 4): ARC has no DNS record of its own, so one
 * card renders per declared forwarder — the query name, the raw TXT with p=/k= highlighted, a
 * resolve badge, and [copy]; or the muted "signer not yet known" placeholder linking to settings.
 */
function SignerKeyCard({
	fw,
	domainId,
	findings,
}: {
	fw: ArcForwarderObservation;
	domainId: string;
	findings: Finding[];
}) {
	if (!fw.signerDomain || !fw.signerSelector) {
		return (
			<div className="rounded-md border border-dashed border-[var(--edh-border)] p-3 text-sm text-[var(--edh-muted)]">
				ARC signer not yet known for{" "}
				<span className="font-medium">{fw.label}</span> —{" "}
				<Link
					to="/domains"
					search={{ edit: domainId }}
					className="text-[var(--edh-primary)] underline"
				>
					record its d=/s= in settings
				</Link>{" "}
				or capture a forwarded sample.
			</div>
		);
	}
	const qname = `${fw.signerSelector}._domainkey.${fw.signerDomain}`;
	// §9.11 rawKeyRecord, with the finding evidence as fallback for runs that predate the field.
	const raw =
		fw.rawKeyRecord ??
		findings.find(
			(f) => f.id.startsWith("arc.selector_dns") && f.evidence?.includes("p="),
		)?.evidence ??
		null;
	const badge =
		fw.selectorResolves === true ? (
			<span className="text-xs font-medium text-emerald-700">✓ resolves</span>
		) : fw.selectorResolves === false ? (
			<span className="text-xs font-medium text-red-700">
				✗ {raw ? "revoked p=" : "NXDOMAIN"}
			</span>
		) : (
			<span className="text-xs font-medium text-slate-500">
				ⓘ lookup failed
			</span>
		);
	return (
		<div className="rounded-md border border-[var(--edh-border)] p-3">
			<div className="flex items-center justify-between gap-2">
				<span className="break-all font-mono text-xs font-semibold">
					SIGNER KEY — {qname}{" "}
					<span className="font-sans font-normal text-[var(--edh-muted)]">
						({fw.label})
					</span>
				</span>
				{badge}
			</div>
			<div className="mt-2 flex items-start justify-between gap-2">
				{raw ? (
					<p className="break-all rounded bg-slate-50 p-2 font-mono text-xs text-slate-700">
						<HighlightTags record={raw} />
					</p>
				) : (
					<p className="rounded bg-slate-50 p-2 font-mono text-xs text-slate-400">
						(no TXT answer)
					</p>
				)}
				<CopyFixButton
					text={raw ?? `${qname} TXT "v=DKIM1; k=rsa; p=<base64 public key>"`}
					label={raw ? "copy" : "copy expected"}
				/>
			</div>
		</div>
	);
}

/** Highlights the unit's owned tags (`p=`, `k=`) inside the raw key record (§9.3 item 4). */
function HighlightTags({ record }: { record: string }) {
	const parts = record.split(/((?:^|;)\s*(?:p|k)\s*=)/i);
	return (
		<>
			{parts.map((part, i) =>
				/^(?:;)?\s*(?:p|k)\s*=$/i.test(part.trim()) ||
				/(?:p|k)\s*=$/i.test(part) ? (
					// biome-ignore lint/suspicious/noArrayIndexKey: split parts have no stable identity
					<mark key={i} className="rounded bg-amber-100 px-0.5 text-amber-900">
						{part}
					</mark>
				) : (
					// biome-ignore lint/suspicious/noArrayIndexKey: split parts have no stable identity
					<span key={i}>{part}</span>
				),
			)}
		</>
	);
}

/**
 * The scoped parsed-field table (§9.3 item 5): exactly the `results.arc` shape, one row per field,
 * with every sample-derived field rendered grayed "— not yet sampled" while null (never hidden, so
 * the user sees what a future capture will add).
 */
function ParsedFieldTable({ arc }: { arc: ArcResults | undefined }) {
	const gray = (label = "— not yet sampled") => (
		<span className="text-slate-400">{label}</span>
	);
	const val = (
		v: boolean | number | string | null | undefined,
	): React.ReactNode =>
		v === null || v === undefined ? gray() : <span>{String(v)}</span>;
	const rows: { field: string; value: React.ReactNode; meaning: string }[] = [
		{
			field: "applicable",
			value: arc ? val(arc.applicable) : gray("—"),
			meaning: "enforcing DMARC + forwarding declared → ARC matters here",
		},
		{
			field: "forwardingRisk",
			value: arc ? val(arc.forwardingRisk) : gray("—"),
			meaning: "a declared path could drop mail until a chain is verified",
		},
		{
			field: "messageSampleId",
			value: val(arc?.messageSampleId),
			meaning: "the captured forwarded message the chain checks need",
		},
		{
			field: "chainPresent / chainLength",
			value: (
				<>
					{val(arc?.chainPresent)} / {val(arc?.chainLength)}
				</>
			),
			meaning: "ARC header set found / highest i= (hop count)",
		},
		{
			field: "cvResult / sealValid / amsValid",
			value: (
				<>
					{val(arc?.cvResult)} / {val(arc?.sealValid)} / {val(arc?.amsValid)}
				</>
			),
			meaning: "newest seal's cv= / seal chain verified / newest AMS verified",
		},
		{
			field: "instancesOk / oldestPass",
			value: (
				<>
					{val(arc?.instancesOk)} / {val(arc?.oldestPass)}
				</>
			),
			meaning: "i= contiguous & ordered / origin passed at i=1",
		},
		{
			field: "probeSentAt",
			value: arc?.probeSentAt ?? gray("— never"),
			meaning: "last swaks-through-forwarder probe",
		},
	];
	const forwarders = arc?.forwarders ?? [];
	return (
		<div className="mt-3 overflow-hidden rounded-md border border-[var(--edh-border)]">
			<table className="w-full text-sm">
				<thead>
					<tr className="text-left text-xs text-[var(--edh-muted)]">
						<th className="px-3 py-1.5 font-medium">field</th>
						<th className="px-3 py-1.5 font-medium">value</th>
						<th className="px-3 py-1.5 font-medium">meaning</th>
					</tr>
				</thead>
				<tbody>
					{rows.slice(0, 2).map((r) => (
						<tr key={r.field} className="border-t border-[var(--edh-border)]">
							<td className="px-3 py-1.5 align-top font-mono text-xs font-semibold">
								{r.field}
							</td>
							<td className="px-3 py-1.5 align-top font-mono text-xs">
								{r.value}
							</td>
							<td className="px-3 py-1.5 align-top text-xs text-slate-500">
								{r.meaning}
							</td>
						</tr>
					))}
					<tr className="border-t border-[var(--edh-border)]">
						<td className="px-3 py-1.5 align-top font-mono text-xs font-semibold">
							forwarders[]
						</td>
						<td className="px-3 py-1.5 align-top font-mono text-xs" colSpan={2}>
							{forwarders.length === 0 ? (
								gray("— none declared")
							) : (
								<table className="w-full">
									<thead>
										<tr className="text-left text-[10px] uppercase text-[var(--edh-muted)]">
											<th className="pr-2 font-medium">label</th>
											<th className="pr-2 font-medium">address</th>
											<th className="pr-2 font-medium">d= / s=</th>
											<th className="pr-2 font-medium">resolves</th>
											<th className="font-medium">key type · bits</th>
										</tr>
									</thead>
									<tbody>
										{forwarders.map((fw) => (
											<tr key={fw.label + fw.forwardAddress}>
												<td className="pr-2">{fw.label}</td>
												<td className="break-all pr-2">{fw.forwardAddress}</td>
												<td className="break-all pr-2">
													{fw.signerDomain && fw.signerSelector
														? `${fw.signerDomain} / ${fw.signerSelector}`
														: "— unknown"}
												</td>
												<td className="pr-2">
													{fw.selectorResolves === null
														? "—"
														: fw.selectorResolves
															? "✓"
															: "✗"}
												</td>
												<td>
													{fw.keyType ?? "—"}
													{fw.keyBits ? ` · ~${fw.keyBits}` : ""}
												</td>
											</tr>
										))}
									</tbody>
								</table>
							)}
						</td>
					</tr>
					{rows.slice(2).map((r) => (
						<tr key={r.field} className="border-t border-[var(--edh-border)]">
							<td className="px-3 py-1.5 align-top font-mono text-xs font-semibold">
								{r.field}
							</td>
							<td className="px-3 py-1.5 align-top font-mono text-xs">
								{r.value}
							</td>
							<td className="px-3 py-1.5 align-top text-xs text-slate-500">
								{r.meaning}
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}
