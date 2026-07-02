import { useNavigate, useParams } from "@tanstack/react-router";
import {
	ArrowLeft,
	ChevronRight,
	ExternalLink,
	FileText,
	Gauge,
	Link2,
	RefreshCw,
	UploadCloud,
} from "lucide-react";
import { type DragEvent, useRef, useState } from "react";
import { toast } from "sonner";
import { useAuditResults } from "@/api/audit";
import {
	useContentSample,
	useContentSampleRaw,
	useRescoreContent,
	useUploadContentSample,
} from "@/api/content-sample";
import { useDomains } from "@/api/domains";
import { useSettings } from "@/api/settings";
import type {
	ContentRuleFired,
	ContentScoreResults,
	Finding,
	LinkUrlResults,
	UrlLinkResult,
} from "@/api/types";
import { SeverityBadge } from "@/components/Badges";
import { CopyFixButton } from "@/components/CopyFixButton";
import { StatusCell } from "@/components/StatusCell";
import { TestResultsTable } from "@/components/TestResultsTable";
import { NEVER_CELL, rollupCategories } from "@/lib/categories";
import { isContentScoringFinding } from "@/lib/content-scoring";
import { cn } from "@/lib/utils";
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext";

/**
 * The full-page Content-scoring view (pm/checks/content_scoring.mdx §4): the headline SpamAssassin
 * score as a colored gauge, the scored sample's subject/from, one row per fired rule sorted by
 * points with a copy-to-clipboard fix, the Sample-message upload panel (drag-drop .eml or paste),
 * and the Re-score / Upload-new-sample / View-raw actions.
 */
export function ContentScoringPage() {
	const { id = "" } = useParams({ strict: false }) as { id?: string };
	const { data: domains } = useDomains();
	const { data: results } = useAuditResults();
	const runDomains = useScanRunner();
	const scanning = useScanProgress().some((s) => s.domainId === id);
	const navigate = useNavigate();

	const domain = (domains ?? []).find((d) => d.id === id);
	const result = (results ?? []).find((r) => r.domainId === id);
	const findings = (result?.findings ?? []).filter(isContentScoringFinding);
	const score = result?.results?.["content.scoring"] as
		| ContentScoreResults
		| undefined;
	const cell = rollupCategories(result?.findings).spamContent ?? NEVER_CELL;
	// Link / URL reputation (pm/checks/link_url_reputation.mdx §4): the content.url_* sub-family
	// renders as its own grouped subsection of Spam & Content, one row per flagged link/domain.
	const urlFindings = (result?.findings ?? []).filter((f) =>
		f.id.startsWith("content.url"),
	);
	const urlResults = result?.results?.["content.url"] as
		| LinkUrlResults
		| undefined;

	const onRunAgain = () => runDomains([{ id, name: domain?.name ?? id }]);

	return (
		<div className="mx-auto max-w-5xl">
			<div className="mb-4 flex items-center justify-between">
				<button
					type="button"
					onClick={() => navigate({ to: "/domains/$id", params: { id } })}
					className="inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
				>
					<ArrowLeft className="h-4 w-4" /> Back to {domain?.name ?? id}
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

			<h1 className="text-2xl font-bold">Content scoring</h1>
			<div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-[var(--edh-muted)]">
				<span className="font-medium text-slate-900">{domain?.name ?? id}</span>
				<span className="w-32">
					<StatusCell status={cell} />
				</span>
				{result && <span>· ran {new Date(result.ranAt).toLocaleString()}</span>}
			</div>

			<ScoreGauge score={score} hasRun={!!result} />

			<div className="mt-4 grid gap-4 lg:grid-cols-2">
				<SampleMessagePanel domainId={id} />
				<FiredRulesPanel score={score} findings={findings} />
			</div>

			<LinkUrlReputationSection
				findings={urlFindings}
				results={urlResults}
				hasRun={!!result}
			/>

			<TestResultsTable
				findings={findings}
				emptyText="Not scored yet — run checks or upload a sample message."
			/>
		</div>
	);
}

/** The headline gauge: `3.2 / 5.0`, colored by band (< 2 green, 2–5 amber, ≥ 5 red). */
function ScoreGauge({
	score,
	hasRun,
}: {
	score?: ContentScoreResults;
	hasRun: boolean;
}) {
	// The inbox-safe target is admin-overridable (§4 Settings); the gauge band must agree with the
	// backend's §3.5 severity banding, which uses the configured value.
	const { data: settings } = useSettings();
	const safeTarget = settings?.config.checks.content?.safeTarget ?? 2.0;
	if (!score) {
		return (
			<div className="mt-4 rounded-lg border border-dashed border-[var(--edh-border)] bg-white p-4 text-sm text-slate-600">
				{hasRun
					? "Not scored yet — upload a sample message below, then Re-score."
					: "No audit yet — run checks to score this domain's sample message."}
			</div>
		);
	}
	const band =
		score.total_score >= score.threshold
			? "red"
			: score.total_score >= safeTarget
				? "amber"
				: "green";
	const bandStyle =
		band === "red"
			? "bg-red-100 text-red-800"
			: band === "amber"
				? "bg-amber-100 text-amber-800"
				: "bg-emerald-100 text-emerald-800";
	const pct = Math.min(100, (score.total_score / score.threshold) * 100);
	return (
		<div className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
			<div className="flex flex-wrap items-center gap-3">
				<Gauge className="h-5 w-5 text-[var(--edh-muted)]" />
				<span
					className={cn("rounded-md px-3 py-1 text-lg font-bold", bandStyle)}
				>
					{score.total_score.toFixed(1)} / {score.threshold.toFixed(1)}
				</span>
				<span className="text-sm text-slate-600">
					{score.passed
						? "Below the spam threshold"
						: "At or above the spam threshold"}{" "}
					— inbox-safe target is &lt; {safeTarget.toFixed(1)}
				</span>
			</div>
			<div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-100">
				<div
					className={cn(
						"h-full rounded-full",
						band === "red"
							? "bg-red-500"
							: band === "amber"
								? "bg-amber-500"
								: "bg-emerald-500",
					)}
					style={{ width: `${pct}%` }}
				/>
			</div>
			<p className="mt-2 text-xs text-[var(--edh-muted)]">
				sample:{" "}
				<span className="font-medium text-slate-700">
					"{score.subject ?? "(no subject)"}"
				</span>{" "}
				from {score.from_header ?? "(unknown sender)"} · scored{" "}
				{new Date(score.checked_at).toLocaleString()} via {score.engine}
				{score.sa_version ? ` · ${score.sa_version}` : ""}
			</p>
		</div>
	);
}

/**
 * One row per fired rule, points descending, with the owning sub-check's copyable fix (§4).
 * Exported so the run report's "Spam & Content ▸ Content scoring" sub-group (RunDetailPage)
 * renders the same table (§8 AC 8).
 */
export function FiredRulesPanel({
	score,
	findings,
}: {
	score?: ContentScoreResults;
	findings: Finding[];
}) {
	const rules = [...(score?.rules_fired ?? [])].sort(
		(a, b) => b.score - a.score,
	);

	// A rule's severity/fix comes from the sub-check finding whose evidence names it.
	const findingFor = (rule: ContentRuleFired): Finding | undefined =>
		findings.find(
			(f) =>
				f.id !== "content.spamassassin_score" &&
				f.evidence?.includes(rule.rule),
		);

	return (
		<section className="rounded-lg border border-[var(--edh-border)] bg-white p-4">
			<h2 className="mb-2 font-semibold">Fired rules</h2>
			{!score ? (
				<p className="text-sm text-slate-600">Not scored yet.</p>
			) : rules.length === 0 ? (
				<p className="text-sm text-slate-600">
					No SpamAssassin rules fired — clean message.
				</p>
			) : (
				<table className="w-full text-sm">
					<thead>
						<tr className="text-left text-xs uppercase text-[var(--edh-muted)]">
							<th className="pb-1 pr-2">sev</th>
							<th className="pb-1 pr-2">rule</th>
							<th className="pb-1 pr-2 text-right">pts</th>
							<th className="pb-1 text-right">fix</th>
						</tr>
					</thead>
					<tbody>
						{rules.map((r) => {
							const finding = findingFor(r);
							const severity =
								r.score <= 0 ? "ok" : (finding?.severity ?? "info");
							const fix = finding?.remediation;
							return (
								<tr
									key={r.rule}
									className="border-t border-[var(--edh-border)] align-top"
								>
									<td className="py-1.5 pr-2">
										<SeverityBadge severity={severity} />
									</td>
									<td className="py-1.5 pr-2">
										<div className="font-mono text-xs font-semibold">
											{r.rule}
										</div>
										<div className="text-xs text-slate-500">
											{r.description}
										</div>
									</td>
									<td className="py-1.5 pr-2 text-right font-mono text-xs">
										{r.score >= 0 ? "+" : ""}
										{r.score.toFixed(1)}
									</td>
									<td className="py-1.5 text-right">
										{fix && <CopyFixButton text={fix} label="Copy" />}
									</td>
								</tr>
							);
						})}
					</tbody>
				</table>
			)}
		</section>
	);
}

/**
 * The "Sample message" panel (§4): drag-drop a .eml or paste the raw source, see which message is
 * currently scored (from/subject + store path), Re-score, and View raw .eml.
 */
function SampleMessagePanel({ domainId }: { domainId: string }) {
	const { data } = useContentSample(domainId);
	const upload = useUploadContentSample(domainId);
	const rescore = useRescoreContent(domainId);
	const [pasted, setPasted] = useState("");
	const [showUpload, setShowUpload] = useState(false);
	const [showRaw, setShowRaw] = useState(false);
	const raw = useContentSampleRaw(domainId, showRaw);
	const fileInput = useRef<HTMLInputElement>(null);
	const [dragging, setDragging] = useState(false);

	const sample = data?.sample ?? null;

	const submit = (rawSource: string) => {
		if (!rawSource.trim()) return;
		upload.mutate(rawSource, {
			onSuccess: () => {
				setPasted("");
				setShowUpload(false);
				toast.success("Sample message saved — re-score to grade it");
			},
			onError: (err) =>
				toast.error(
					`Upload failed: ${err instanceof Error ? err.message : err}`,
				),
		});
	};

	const readFile = (file: File) => {
		const reader = new FileReader();
		reader.onload = () => submit(String(reader.result ?? ""));
		reader.readAsText(file);
	};

	const onDrop = (e: DragEvent) => {
		e.preventDefault();
		setDragging(false);
		const file = e.dataTransfer.files?.[0];
		if (file) readFile(file);
	};

	return (
		<section
			aria-label="Sample message drop zone"
			className={cn(
				"rounded-lg border bg-white p-4",
				dragging ? "border-[var(--edh-primary)]" : "border-[var(--edh-border)]",
			)}
			onDragOver={(e) => {
				e.preventDefault();
				setDragging(true);
			}}
			onDragLeave={() => setDragging(false)}
			onDrop={onDrop}
		>
			<div className="mb-2 flex items-center justify-between">
				<h2 className="font-semibold">Sample message</h2>
				<div className="flex items-center gap-2">
					{sample && (
						<button
							type="button"
							onClick={() => setShowRaw(!showRaw)}
							className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-medium hover:bg-slate-50"
						>
							<FileText className="h-3.5 w-3.5" />
							{showRaw ? "Hide raw" : "View raw .eml"}
						</button>
					)}
					{sample && (
						<button
							type="button"
							onClick={() =>
								rescore.mutate(undefined, {
									onSuccess: () => toast.success("Content re-scored"),
									onError: (err) =>
										toast.error(
											`Re-score failed: ${err instanceof Error ? err.message : err}`,
										),
								})
							}
							disabled={rescore.isPending}
							className="inline-flex items-center gap-1 rounded-md bg-[var(--edh-primary)] px-2 py-1 text-xs font-medium text-white disabled:opacity-50"
						>
							<RefreshCw
								className={cn(
									"h-3.5 w-3.5",
									rescore.isPending && "animate-spin",
								)}
							/>
							{rescore.isPending ? "Scoring…" : "Re-score"}
						</button>
					)}
				</div>
			</div>

			{!sample ? (
				<p className="text-sm text-slate-600">
					No sample message — upload a representative email to enable content
					scoring.
				</p>
			) : (
				<div className="rounded-md border border-[var(--edh-border)] p-2 text-sm">
					<div className="font-medium">
						"{sample.subject ?? "(no subject)"}"
					</div>
					<div className="text-xs text-slate-500">
						from {sample.from_header ?? "(unknown sender)"}
					</div>
					<div className="mt-1 text-xs text-[var(--edh-muted)]">
						uploaded {new Date(sample.uploaded_at).toLocaleString()} ·{" "}
						{sample.byte_size} bytes
						{sample.raw_path && (
							<>
								{" · "}
								<span className="break-all font-mono">{sample.raw_path}</span>
							</>
						)}
					</div>
				</div>
			)}

			{showRaw && (
				<pre className="mt-2 max-h-64 overflow-auto rounded-md bg-slate-50 p-2 font-mono text-xs text-slate-700">
					{raw.isLoading
						? "Loading…"
						: (raw.data?.raw ?? "Could not load the raw source.")}
				</pre>
			)}

			<div className="mt-3">
				{!showUpload ? (
					<button
						type="button"
						onClick={() => setShowUpload(true)}
						className="inline-flex items-center gap-1 rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-medium hover:bg-slate-50"
					>
						<UploadCloud className="h-3.5 w-3.5" />
						{sample ? "Upload new sample" : "Upload sample"}
					</button>
				) : (
					<div>
						<textarea
							value={pasted}
							onChange={(e) => setPasted(e.target.value)}
							placeholder="Paste the raw email source (headers + body) here, or drag-drop a .eml file onto this panel…"
							className="h-32 w-full rounded-md border border-[var(--edh-border)] p-2 font-mono text-xs"
						/>
						<div className="mt-2 flex items-center gap-2">
							<button
								type="button"
								onClick={() => submit(pasted)}
								disabled={upload.isPending || !pasted.trim()}
								className="rounded-md bg-[var(--edh-primary)] px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
							>
								{upload.isPending ? "Saving…" : "Save sample"}
							</button>
							<button
								type="button"
								onClick={() => fileInput.current?.click()}
								className="rounded-md border border-[var(--edh-border)] px-3 py-1.5 text-xs font-medium hover:bg-slate-50"
							>
								Choose .eml file…
							</button>
							<button
								type="button"
								onClick={() => setShowUpload(false)}
								className="text-xs text-[var(--edh-muted)] hover:text-slate-700"
							>
								Cancel
							</button>
							<input
								ref={fileInput}
								type="file"
								accept=".eml,message/rfc822,text/plain"
								className="hidden"
								onChange={(e) => {
									const file = e.target.files?.[0];
									if (file) readFile(file);
									e.target.value = "";
								}}
							/>
						</div>
					</div>
				)}
			</div>
		</section>
	);
}

// ---------------------------------------------------------------------------------------------
// Link / URL Reputation (pm/checks/link_url_reputation.mdx §4 — the content.url_* sub-family)
// ---------------------------------------------------------------------------------------------

/** Availability/degradation notes rendered as amber-outline info rows, not flagged-link rows. */
const URL_AVAILABILITY_IDS = new Set([
	"content.url_ivmuri",
	"content.url_redirect_chain",
	"content.url_reachable",
	"content.url_safe_browsing",
	"content.url_reputation.transient",
]);

/** The first http(s) URL inside a remediation string — powers the [Delist ↗] deep-link. */
function delistUrlFrom(remediation?: string): string | null {
	return remediation?.match(/https?:\/\/[^\s)]+/)?.[0] ?? null;
}

/** Short check label per the spec table, e.g. "url_dbl" from "content.url_dbl:bad.example". */
function urlCheckLabel(findingId: string): { label: string; checkId: string } {
	const base = findingId.split(":")[0];
	return { label: base.replace(/^content\./, ""), checkId: base };
}

/** The offending link domain(s) for one finding row, derived from the structured payload. */
function domainsForFinding(f: Finding, links: UrlLinkResult[]): string {
	const parts = f.id.split(":");
	if (parts.length > 1) return parts[parts.length - 1]; // listing rows carry the domain in the id
	const base = parts[0];
	const pick = (test: (l: UrlLinkResult) => boolean) =>
		[...new Set(links.filter(test).map((l) => l.linkDomain))].join(", ");
	switch (base) {
		case "content.url_shortener":
			return pick((l) => l.isShortener);
		case "content.url_https":
			return pick((l) => !l.isHttps);
		case "content.url_ip_literal":
			return pick((l) => l.isIpLiteral);
		case "content.url_punycode":
			return pick((l) => l.isPunycode || l.homographOf !== null);
		case "content.url_domain_alignment":
			return pick((l) => l.aligned === false);
		default:
			return "—";
	}
}

/** Per-URL chips (§4 "Links in this sample"): scheme, shortener, IP-literal, punycode, zones. */
function LinkChips({ link }: { link: UrlLinkResult }) {
	const chips: { text: string; tone: "ok" | "warn" | "bad" }[] = [
		link.isHttps
			? { text: "https", tone: "ok" }
			: { text: "http", tone: "warn" },
	];
	if (link.isShortener) chips.push({ text: "shortener", tone: "warn" });
	if (link.isIpLiteral) chips.push({ text: "IP-literal", tone: "bad" });
	if (link.homographOf)
		chips.push({ text: `homograph: ${link.homographOf}`, tone: "bad" });
	else if (link.isPunycode) chips.push({ text: "punycode", tone: "warn" });
	if (link.aligned === false) chips.push({ text: "off-brand", tone: "warn" });
	for (const listing of link.listings) {
		if (listing.listed)
			chips.push({ text: `listed: ${listing.zone}`, tone: "bad" });
	}
	return (
		<span className="inline-flex flex-wrap gap-1">
			{chips.map((c) => (
				<span
					key={c.text}
					className={cn(
						"rounded px-1.5 py-0.5 text-[10px] font-medium",
						c.tone === "bad"
							? "bg-red-100 text-red-800"
							: c.tone === "warn"
								? "bg-amber-100 text-amber-800"
								: "bg-emerald-100 text-emerald-800",
					)}
				>
					{c.text}
				</span>
			))}
		</span>
	);
}

/**
 * The "Link / URL Reputation" grouped subsection of Spam & Content
 * (pm/checks/link_url_reputation.mdx §4): a `N flagged · M clean` header badge, one row per
 * flagged link/domain (severity, check + checkId, link domain, observed evidence, [Delist ↗]
 * deep-link + [Copy] remediation), amber-outline availability notes (zone unavailable / paid feed
 * not configured / probe disabled), the all-clean green state, the no-sample gray state, and a
 * "Links in this sample" expander listing every extracted URL with its per-URL chips.
 */
function LinkUrlReputationSection({
	findings,
	results,
	hasRun,
}: {
	findings: Finding[];
	results?: LinkUrlResults;
	hasRun: boolean;
}) {
	const [showLinks, setShowLinks] = useState(false);

	const links = results?.links ?? [];
	const flaggedLinks = links.filter(
		(l) =>
			l.listings.some((z) => z.listed) ||
			l.isShortener ||
			l.isIpLiteral ||
			l.isPunycode ||
			!l.isHttps ||
			l.aligned === false,
	);
	const cleanCount = links.length - flaggedLinks.length;

	// Rows of the flagged table: warning/critical findings plus advisory info rows (alignment,
	// count, resolved) — availability notes and ok/extract rows render separately below.
	const tableRows = findings.filter(
		(f) =>
			!URL_AVAILABILITY_IDS.has(f.id.split(":")[0]) &&
			!f.id.includes(".skipped.") &&
			!f.id.includes(".inconclusive.") &&
			f.id !== "content.url_extract" &&
			f.id !== "content.url_aggregate" &&
			f.id !== "content.url_reputation.clean" &&
			f.severity !== "ok" &&
			// advisory info stays out of the flagged table unless it names a problem (§3 severity map)
			(f.severity !== "info" ||
				f.id === "content.url_domain_alignment" ||
				f.id === "content.url_reputation.resolved"),
	);
	const availabilityNotes = findings.filter(
		(f) =>
			URL_AVAILABILITY_IDS.has(f.id.split(":")[0]) ||
			f.id.includes(".skipped.") ||
			f.id.includes(".inconclusive."),
	);
	const allClean =
		results !== undefined && tableRows.length === 0 && links.length > 0;

	// Never-run / no-sample state (§4): gray, "Add a sample message to check link reputation."
	if (!results) {
		return (
			<section className="mt-4 rounded-lg border border-dashed border-[var(--edh-border)] bg-white p-4">
				<h2 className="flex items-center gap-2 font-semibold">
					<Link2 className="h-4 w-4 text-[var(--edh-muted)]" />
					Link / URL Reputation
					<span className="font-mono text-xs font-normal text-[var(--edh-muted)]">
						(content.url_*)
					</span>
				</h2>
				<p className="mt-2 text-sm text-slate-600">
					{hasRun
						? "Add a sample message to check link reputation — every link in the body is checked against URI blocklists (Spamhaus DBL, SURBL, URIBL) and link-hygiene rules."
						: "No audit yet — run checks (with a sample message) to check link reputation."}
				</p>
			</section>
		);
	}

	return (
		<section className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
			<div className="mb-2 flex flex-wrap items-center justify-between gap-2">
				<h2 className="flex items-center gap-2 font-semibold">
					<Link2 className="h-4 w-4 text-[var(--edh-muted)]" />
					Link / URL Reputation
					<span className="font-mono text-xs font-normal text-[var(--edh-muted)]">
						(content.url_*)
					</span>
				</h2>
				<span
					className={cn(
						"rounded-md px-2 py-0.5 text-xs font-semibold",
						flaggedLinks.length > 0
							? "bg-amber-100 text-amber-800"
							: "bg-emerald-100 text-emerald-800",
					)}
				>
					{flaggedLinks.length} flagged · {cleanCount} clean
				</span>
			</div>

			{allClean && (
				<p className="rounded-md bg-emerald-50 p-2 text-sm text-emerald-800">
					All {links.length} link{links.length === 1 ? "" : "s"} clean across{" "}
					{results.zonesQueried.length > 0
						? results.zonesQueried.join(", ")
						: "the enabled URI zones"}
					.
				</p>
			)}

			{tableRows.length > 0 && (
				<table className="w-full text-sm">
					<thead>
						<tr className="text-left text-xs uppercase text-[var(--edh-muted)]">
							<th className="pb-1 pr-2">severity</th>
							<th className="pb-1 pr-2">check</th>
							<th className="pb-1 pr-2">link domain</th>
							<th className="pb-1 pr-2">observed</th>
							<th className="pb-1 text-right">fix</th>
						</tr>
					</thead>
					<tbody>
						{tableRows.map((f) => {
							const { label, checkId } = urlCheckLabel(f.id);
							const delist = delistUrlFrom(f.remediation);
							return (
								<tr
									key={f.id}
									className="border-t border-[var(--edh-border)] align-top"
								>
									<td className="py-1.5 pr-2">
										<SeverityBadge severity={f.severity} />
									</td>
									<td className="py-1.5 pr-2">
										<div className="font-mono text-xs font-semibold">
											{label}
										</div>
										<div className="font-mono text-[10px] text-slate-500">
											({checkId})
										</div>
									</td>
									<td className="break-all py-1.5 pr-2 font-mono text-xs">
										{domainsForFinding(f, links)}
									</td>
									<td className="py-1.5 pr-2 text-xs text-slate-600">
										{f.evidence ?? f.detail}
									</td>
									<td className="py-1.5 text-right">
										<span className="inline-flex items-center gap-1">
											{delist && (
												<a
													href={delist}
													target="_blank"
													rel="noreferrer"
													className="inline-flex items-center gap-0.5 rounded-md border border-[var(--edh-border)] px-1.5 py-0.5 text-xs font-medium hover:bg-slate-50"
												>
													Delist <ExternalLink className="h-3 w-3" />
												</a>
											)}
											{f.remediation && (
												<CopyFixButton text={f.remediation} label="Copy" />
											)}
										</span>
									</td>
								</tr>
							);
						})}
					</tbody>
				</table>
			)}

			{/* Inconclusive state (§4): amber-outline info rows — zone unavailable / paid feed not
          configured / redirect probe disabled (first round). Never rendered as listings. */}
			{availabilityNotes.length > 0 && (
				<div className="mt-2 grid gap-1">
					{availabilityNotes.map((f) => (
						<div
							key={f.id}
							className="rounded-md border border-amber-300 bg-white px-2 py-1.5 text-xs text-slate-600"
						>
							<span className="font-medium text-amber-800">{f.title}</span> —{" "}
							{f.detail}
						</div>
					))}
				</div>
			)}

			{/* "Links in this sample" expander (§4): every extracted URL with its per-URL chips so the
          operator can see exactly which <a href> to fix. */}
			{links.length > 0 && (
				<div className="mt-3">
					<button
						type="button"
						onClick={() => setShowLinks((v) => !v)}
						aria-expanded={showLinks}
						className="inline-flex items-center gap-1 text-sm font-medium text-[var(--edh-muted)] hover:text-slate-700"
					>
						<ChevronRight
							className={cn(
								"h-4 w-4 transition-transform",
								showLinks && "rotate-90",
							)}
						/>
						Links in this sample ({links.length})
					</button>
					{showLinks && (
						<ul className="mt-2 grid gap-1">
							{links.map((l) => (
								<li
									key={l.url}
									className="flex flex-wrap items-center gap-2 rounded-md bg-slate-50 px-2 py-1.5"
								>
									<span className="break-all font-mono text-xs text-slate-700">
										{l.url}
									</span>
									<span className="font-mono text-[10px] text-slate-500">
										→ {l.linkDomain}
										{l.finalDomain && l.finalDomain !== l.linkDomain
											? ` → ${l.finalDomain}${l.redirectHops !== null ? ` (${l.redirectHops} hops)` : ""}`
											: ""}
									</span>
									<LinkChips link={l} />
								</li>
							))}
						</ul>
					)}
				</div>
			)}

			<p className="mt-2 text-xs text-[var(--edh-muted)]">
				{results.summary.uniqueDomains} unique domain
				{results.summary.uniqueDomains === 1 ? "" : "s"} checked against{" "}
				{results.zonesQueried.length} URI zone
				{results.zonesQueried.length === 1 ? "" : "s"}
				{results.sampleId ? ` · sample: ${results.sampleId}` : ""} · checked{" "}
				{new Date(results.checkedAt).toLocaleString()}
			</p>
		</section>
	);
}
