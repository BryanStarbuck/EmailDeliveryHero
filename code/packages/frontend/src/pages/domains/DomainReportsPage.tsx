import { Link, useNavigate, useParams } from "@tanstack/react-router";
import {
	ArrowLeft,
	ChevronDown,
	ChevronRight,
	Download,
	Info,
	Mailbox,
	ShieldAlert,
	ShieldCheck,
	Wrench,
} from "lucide-react";
import { type ReactNode, useState } from "react";
import { toast } from "sonner";
import { useDomainReports, useIngestReports } from "@/api/reports";
import type {
	DmarcReportAggregate,
	Finding,
	TlsRptReportAggregate,
} from "@/api/types";
import { SeverityBadge } from "@/components/Badges";
import { CopyFixButton } from "@/components/CopyFixButton";

/**
 * The per-domain Reports view (pm/emails.mdx §7.1) — the ingested report emails: DMARC aggregate
 * (rua) and TLS-RPT, grouped by report kind. Each group header shows report count, reporters,
 * volume, and the window; each problem is a finding row (severity badge, observed detail,
 * remediation + copy-fix) that expands to the per-source-IP table (DMARC) or the per-reporter/day
 * table (TLS-RPT). "Ingest now" triggers an on-demand drop-folder/mailbox scan (§4).
 */
export function DomainReportsPage() {
	const { id = "" } = useParams({ strict: false }) as { id?: string };
	const navigate = useNavigate();
	const { data: view, isLoading, isError } = useDomainReports(id);
	const ingest = useIngestReports(id);

	const onIngestNow = () => {
		ingest.mutate(undefined, {
			onSuccess: ({ summary }) => {
				const parts = [
					`${summary.ingested} new report${summary.ingested === 1 ? "" : "s"}`,
					summary.duplicates > 0
						? `${summary.duplicates} duplicate(s) skipped`
						: null,
					summary.skipped > 0
						? `${summary.skipped} non-report file(s) skipped`
						: null,
				].filter(Boolean);
				if (summary.errors.length > 0) toast.error(summary.errors.join("; "));
				else
					toast.success(
						`Ingest complete — ${parts.join(", ")} (${summary.scanned} file(s) scanned)`,
					);
			},
			onError: () =>
				toast.error("Could not run the report ingest — see the backend log."),
		});
	};

	const dmarcFindings = (view?.findings ?? []).filter((f) =>
		f.id.startsWith("dmarc."),
	);
	const tlsFindings = (view?.findings ?? []).filter((f) =>
		f.id.startsWith("infra."),
	);
	const neverIngested =
		view &&
		view.dmarc.totalReportsStored === 0 &&
		view.tlsrpt.totalReportsStored === 0;

	return (
		<div className="mx-auto max-w-5xl">
			<div className="mb-4 flex items-center justify-between">
				<button
					type="button"
					onClick={() => navigate({ to: "/domains/$id", params: { id } })}
					className="inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
				>
					<ArrowLeft className="h-4 w-4" /> Back to the domain
				</button>
				<button
					type="button"
					onClick={onIngestNow}
					disabled={ingest.isPending}
					className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
				>
					<Download
						className={ingest.isPending ? "h-4 w-4 animate-pulse" : "h-4 w-4"}
					/>
					Ingest now
				</button>
			</div>

			<header className="mb-1 flex items-center gap-2">
				<Mailbox className="h-6 w-6 text-[var(--edh-primary)]" />
				<h1 className="text-2xl font-bold">Reports ▸ {view?.domain ?? id}</h1>
			</header>
			<p className="mb-6 text-sm text-[var(--edh-muted)]">
				The report emails receivers sent back — DMARC aggregate (rua) and
				TLS-RPT — turned into problems and fixes.{" "}
				{view && (
					<>
						Window: last {view.windowDays} days
						{view.lastIngestAt && (
							<> · last ingest {new Date(view.lastIngestAt).toLocaleString()}</>
						)}
					</>
				)}
			</p>

			{isLoading ? (
				<div className="space-y-2">
					{["a", "b", "c"].map((k) => (
						<div
							key={k}
							className="h-16 animate-pulse rounded-md bg-slate-100"
						/>
					))}
				</div>
			) : isError || !view ? (
				<div className="rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center">
					<p className="text-slate-600">
						Could not load the ingested reports for this domain.
					</p>
				</div>
			) : neverIngested ? (
				<EmptyState domain={view.domain} enabled={view.ingestionEnabled} />
			) : (
				<div className="space-y-6">
					<DmarcGroup agg={view.dmarc} findings={dmarcFindings} domainId={id} />
					<TlsRptGroup agg={view.tlsrpt} findings={tlsFindings} />
				</div>
			)}
		</div>
	);
}

/** Never-ingested empty state (pm/emails.mdx §7.3) — the exact record strings to publish. */
function EmptyState({ domain, enabled }: { domain: string; enabled: boolean }) {
	const dmarcRecord = `v=DMARC1; p=none; rua=mailto:dmarc@${domain}`;
	const tlsRecord = `v=TLSRPTv1; rua=mailto:tls-reports@${domain}`;
	return (
		<div className="rounded-lg border border-dashed border-[var(--edh-border)] p-8">
			<p className="font-medium text-slate-700">No reports ingested yet.</p>
			<p className="mt-1 text-sm text-slate-600">
				Publish <code className="font-mono">rua=</code> on your DMARC and
				TLS-RPT records so receivers send reports, then point the report mailbox
				or drop folder here in{" "}
				<Link
					to="/settings/$section"
					params={{ section: "admin" }}
					className="text-[var(--edh-primary)] underline"
				>
					Settings → Admin
				</Link>
				. Reports typically take 24–72h to start arriving after publishing{" "}
				<code className="font-mono">rua=</code>.
			</p>
			{!enabled && (
				<p className="mt-2 text-sm font-medium text-amber-700">
					Report ingestion is currently disabled in Settings → Admin.
				</p>
			)}
			<div className="mt-4 space-y-2 text-sm">
				<RecordLine name={`_dmarc.${domain}`} value={dmarcRecord} />
				<RecordLine name={`_smtp._tls.${domain}`} value={tlsRecord} />
			</div>
		</div>
	);
}

function RecordLine({ name, value }: { name: string; value: string }) {
	return (
		<div className="flex items-center justify-between gap-2 rounded-md bg-slate-50 p-2">
			<code className="break-all font-mono text-xs text-slate-700">
				{name} IN TXT "{value}"
			</code>
			<CopyFixButton text={`${name} IN TXT "${value}"`} label="Copy" />
		</div>
	);
}

/** DMARC aggregate group: header stats + finding rows expanding to the per-source-IP table. */
function DmarcGroup({
	agg,
	findings,
	domainId,
}: {
	agg: DmarcReportAggregate;
	findings: Finding[];
	domainId: string;
}) {
	return (
		<section className="overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
			<div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-[var(--edh-border)] bg-slate-50 px-4 py-3">
				<h2 className="font-semibold">DMARC aggregate</h2>
				<span className="text-xs text-[var(--edh-muted)]">
					{agg.reportCount} report{agg.reportCount === 1 ? "" : "s"}
					{agg.reporters.length > 0 && <> · {agg.reporters.join(", ")}</>} ·{" "}
					{agg.totalMessages.toLocaleString()} msgs · {fmtWindow(agg.window)}
					{agg.policyPublished && (
						<>
							{" "}
							· p={agg.policyPublished.p}; adkim={agg.policyPublished.adkim};
							aspf=
							{agg.policyPublished.aspf}
						</>
					)}
				</span>
			</div>
			{agg.reportCount === 0 ? (
				<p className="p-4 text-sm text-slate-600">
					No DMARC aggregate reports in the current window
					{agg.totalReportsStored > 0 && (
						<> ({agg.totalReportsStored} older report(s) stored)</>
					)}
					.
				</p>
			) : (
				<ul className="divide-y divide-[var(--edh-border)]">
					{findings.map((f) => (
						<ReportFindingRow
							key={f.id}
							finding={f}
							detailTable={<DmarcSourceTable agg={agg} />}
							explainer={{ domainId, findingId: f.id }}
						/>
					))}
				</ul>
			)}
		</section>
	);
}

/** TLS-RPT group: header stats + finding rows expanding to the per-reporter/day table. */
function TlsRptGroup({
	agg,
	findings,
}: {
	agg: TlsRptReportAggregate;
	findings: Finding[];
}) {
	return (
		<section className="overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
			<div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-[var(--edh-border)] bg-slate-50 px-4 py-3">
				<h2 className="font-semibold">TLS-RPT (SMTP TLS)</h2>
				<span className="text-xs text-[var(--edh-muted)]">
					{agg.reportCount} report{agg.reportCount === 1 ? "" : "s"}
					{agg.reporters.length > 0 && <> · {agg.reporters.join(", ")}</>}
					{agg.policyTypes.length > 0 && (
						<> · policy: {agg.policyTypes.join(", ")}</>
					)}{" "}
					· {agg.totalSuccess} ok / {agg.totalFailure} failed sessions
				</span>
			</div>
			{agg.reportCount === 0 ? (
				<p className="p-4 text-sm text-slate-600">
					No TLS-RPT reports in the current window
					{agg.totalReportsStored > 0 && (
						<> ({agg.totalReportsStored} older report(s) stored)</>
					)}
					.
				</p>
			) : (
				<ul className="divide-y divide-[var(--edh-border)]">
					{findings.map((f) => (
						<ReportFindingRow
							key={f.id}
							finding={f}
							detailTable={<TlsRptDayTable agg={agg} />}
						/>
					))}
				</ul>
			)}
		</section>
	);
}

function severityIcon(f: Finding) {
	if (f.severity === "critical" || f.severity === "warning") {
		return (
			<ShieldAlert
				className={`h-4 w-4 ${f.severity === "critical" ? "text-red-600" : "text-amber-600"}`}
			/>
		);
	}
	if (f.severity === "ok")
		return <ShieldCheck className="h-4 w-4 text-emerald-600" />;
	return <Info className="h-4 w-4 text-slate-500" />;
}

/**
 * One finding row (pm/emails.mdx §7.1): severity badge + icon, title, the OBSERVED block (the
 * parsed detail), the remediation with copy-to-clipboard, and an expander that reveals the
 * details table (per-source-IP / per-reporter-day).
 */
function ReportFindingRow({
	finding: f,
	detailTable,
	explainer,
}: {
	finding: Finding;
	detailTable: ReactNode;
	/** DMARC-aggregate rows deep-link to the ingested-reports explainer anchor (pm/emails.mdx §7.1 / §16.5). */
	explainer?: { domainId: string; findingId: string };
}) {
	const [open, setOpen] = useState(false);
	const showFix = f.severity !== "ok" && Boolean(f.remediation);
	return (
		<li className="p-3">
			<div className="flex w-full items-center gap-2 text-left">
				<button
					type="button"
					onClick={() => setOpen((o) => !o)}
					className="flex items-center gap-2 text-left"
					aria-expanded={open}
					aria-label={open ? "Collapse details" : "Expand details"}
				>
					{open ? (
						<ChevronDown className="h-4 w-4 shrink-0 text-[var(--edh-muted)]" />
					) : (
						<ChevronRight className="h-4 w-4 shrink-0 text-[var(--edh-muted)]" />
					)}
					{severityIcon(f)}
					<SeverityBadge severity={f.severity} />
				</button>
				{explainer ? (
					<Link
						to="/domains/$id/dmarc/check/$checkKey"
						params={{ id: explainer.domainId, checkKey: "reports" }}
						hash={`finding-${explainer.findingId}`}
						className="font-medium text-[var(--edh-primary)] hover:underline"
					>
						{f.title}
					</Link>
				) : (
					<button
						type="button"
						onClick={() => setOpen((o) => !o)}
						className="font-medium text-left"
					>
						{f.title}
					</button>
				)}
				<span className="ml-auto rounded-full bg-slate-100 px-2 py-0.5 text-[10px] uppercase tracking-wide text-slate-500">
					from reports
				</span>
			</div>
			<p className="mt-1 pl-6 text-sm text-slate-600">{f.detail}</p>
			{showFix && f.remediation && (
				<div className="ml-6 mt-2 flex items-start justify-between gap-2 rounded-md bg-slate-50 p-2 text-sm text-slate-700">
					<span className="flex items-start gap-2">
						<Wrench className="mt-0.5 h-4 w-4 shrink-0 text-[var(--edh-primary)]" />
						<span>
							<span className="font-medium">Fix: </span>
							{f.remediation}
						</span>
					</span>
					<CopyFixButton text={f.evidence ?? f.remediation} label="Copy" />
				</div>
			)}
			{open && <div className="ml-6 mt-3">{detailTable}</div>}
		</li>
	);
}

/** The per-source-IP table (§7.1): Source IP | Count | Disposition | SPF | DKIM | DMARC | … */
function DmarcSourceTable({ agg }: { agg: DmarcReportAggregate }) {
	return (
		<div className="overflow-x-auto rounded-md border border-[var(--edh-border)]">
			<table className="w-full text-xs">
				<thead className="bg-slate-50 text-left uppercase text-[var(--edh-muted)]">
					<tr>
						<th className="px-2 py-1.5">Source IP</th>
						<th className="px-2 py-1.5 text-right">Count</th>
						<th className="px-2 py-1.5">Disposition</th>
						<th className="px-2 py-1.5">SPF (eval/align)</th>
						<th className="px-2 py-1.5">DKIM (eval/align)</th>
						<th className="px-2 py-1.5">DMARC</th>
						<th className="px-2 py-1.5">Header-From</th>
						<th className="px-2 py-1.5">Envelope</th>
					</tr>
				</thead>
				<tbody>
					{agg.rows.map((r) => (
						<tr
							key={`${r.sourceIp}-${r.envelopeSpfDomain}-${r.spfAligned}-${r.dkimAligned}`}
							className="border-t border-[var(--edh-border)]"
						>
							<td className="px-2 py-1 font-mono">{r.sourceIp}</td>
							<td className="px-2 py-1 text-right tabular-nums">{r.count}</td>
							<td className="px-2 py-1">{r.disposition}</td>
							<td className="px-2 py-1">
								{r.spfEvaluated}/{r.spfAligned ? "aligned" : "not aligned"}
							</td>
							<td className="px-2 py-1">
								{r.dkimEvaluated}/{r.dkimAligned ? "aligned" : "not aligned"}
							</td>
							<td
								className={`px-2 py-1 font-medium ${r.dmarcPass ? "text-emerald-700" : "text-red-700"}`}
							>
								{r.dmarcPass ? "pass" : "fail"}
							</td>
							<td className="px-2 py-1">{r.headerFrom || "—"}</td>
							<td className="px-2 py-1">{r.envelopeSpfDomain || "—"}</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}

/** The per-reporter/day table (§7.1) with success/failure counts and failure-details. */
function TlsRptDayTable({ agg }: { agg: TlsRptReportAggregate }) {
	return (
		<div className="overflow-x-auto rounded-md border border-[var(--edh-border)]">
			<table className="w-full text-xs">
				<thead className="bg-slate-50 text-left uppercase text-[var(--edh-muted)]">
					<tr>
						<th className="px-2 py-1.5">Reporter</th>
						<th className="px-2 py-1.5">Date</th>
						<th className="px-2 py-1.5">Policy</th>
						<th className="px-2 py-1.5 text-right">OK</th>
						<th className="px-2 py-1.5 text-right">Failed</th>
						<th className="px-2 py-1.5">Failure details</th>
					</tr>
				</thead>
				<tbody>
					{agg.rows.map((r) => (
						<tr
							key={`${r.reporterOrg}-${r.reportDate}-${r.policyType}`}
							className="border-t border-[var(--edh-border)]"
						>
							<td className="px-2 py-1">{r.reporterOrg}</td>
							<td className="px-2 py-1 tabular-nums">{r.reportDate}</td>
							<td className="px-2 py-1">{r.policyType}</td>
							<td className="px-2 py-1 text-right tabular-nums text-emerald-700">
								{r.successCount}
							</td>
							<td
								className={`px-2 py-1 text-right tabular-nums ${r.failureCount > 0 ? "font-medium text-red-700" : ""}`}
							>
								{r.failureCount}
							</td>
							<td className="px-2 py-1">
								{r.failureDetails.length === 0
									? "—"
									: r.failureDetails
											.map((d) => `${d.resultType} ×${d.count}`)
											.join(", ")}
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}

function fmtWindow(w: { begin: string; end: string }): string {
	const d = (s: string) => (s ? s.slice(5, 10) : "?");
	return `${d(w.begin)}→${d(w.end)}`;
}
