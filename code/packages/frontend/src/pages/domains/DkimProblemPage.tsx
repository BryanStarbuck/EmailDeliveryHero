import { useNavigate, useParams } from "@tanstack/react-router";
import { ArrowLeft, Terminal } from "lucide-react";
import { useAuditResults, useAuditRuns } from "@/api/audit";
import { useDomains } from "@/api/domains";
import type { DkimResults } from "@/api/types";
import { SeverityBadge } from "@/components/Badges";
import { CopyFixButton } from "@/components/CopyFixButton";
import { problemStateById } from "@/lib/dkim-problems";

/**
 * The per-problem DKIM drill-down page (pm/checks/dkim.mdx §7): concept, your data (from THIS
 * run's stored results), diagnose-it-yourself commands (domain and selector substituted in,
 * copyable), tools, extra health metrics, and the numbered path forward. Routes:
 * /domains/:id/runs/:runId/dkim/:problemId and the newest-run alias /domains/:id/dkim/:problemId.
 */
export function DkimProblemPage() {
	const {
		id = "",
		runId,
		problemId = "",
	} = useParams({ strict: false }) as {
		id?: string;
		runId?: string;
		problemId?: string;
	};
	const { data: domains } = useDomains();
	const { data: results } = useAuditResults();
	const { data: runs } = useAuditRuns();
	const navigate = useNavigate();

	const domain = (domains ?? []).find((d) => d.id === id);
	const name = domain?.name ?? id;
	const ps = problemStateById(problemId.toUpperCase());

	// Run-scoped (§7 drill-down rules): render this RUN's data; the alias renders the newest run.
	// Substitute a real selector into the commands: prefer one that is failing this problem's tests.
	const result = runId
		? (runs ?? []).find((r) => r.runId === runId)
		: (results ?? []).find((r) => r.domainId === id);
	const dkimFindings = (result?.findings ?? []).filter(
		(f) => f.checkId === "dkim",
	);
	const failingSelector = ps
		? dkimFindings
				.filter((f) => f.severity === "critical" || f.severity === "warning")
				.filter((f) =>
					ps.findingPrefixes.some(
						(p) => f.id === p || f.id.startsWith(`${p}.`),
					),
				)
				.map((f) => f.id.split(".").pop())
				.find((s) => s && domain?.dkimSelectors.includes(s))
		: undefined;
	const selector = failingSelector ?? domain?.dkimSelectors[0] ?? "selector1";

	const substitute = (raw: string) =>
		raw.replaceAll("<domain>", name).replaceAll("<selector>", selector);

	// The same commands this run itself executed (deduped), reproducible in a terminal (§7).
	const toolCommands = [
		...new Set((result?.results?.dkim?.tool_runs ?? []).map((t) => t.command)),
	];

	return (
		<div className="mx-auto max-w-3xl">
			<button
				type="button"
				onClick={() =>
					runId
						? navigate({
								to: "/domains/$id/runs/$runId/dkim",
								params: { id, runId },
							})
						: navigate({ to: "/domains/$id/dkim", params: { id } })
				}
				className="mb-4 inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
			>
				<ArrowLeft className="h-4 w-4" /> Back to DKIM for {name}
				{result?.startedAt &&
					` · run ${new Date(result.startedAt).toLocaleString()}`}
			</button>

			{!ps ? (
				<p className="text-slate-600">Unknown problem state "{problemId}".</p>
			) : (
				<>
					<div className="flex items-center gap-2 text-xs font-semibold uppercase text-[var(--edh-muted)]">
						<span>{ps.id}</span>
						<SeverityBadge severity={ps.severity} />
					</div>
					<h1 className="mt-1 text-2xl font-bold">{ps.title}</h1>

					<section className="mt-4 space-y-2">
						{ps.concept.map((p) => (
							<p
								key={p.slice(0, 24)}
								className="text-sm leading-relaxed text-slate-700"
							>
								{p}
							</p>
						))}
					</section>

					<Section title="Your data — fields to look at">
						<ul className="list-disc space-y-1 pl-5 text-sm text-slate-700">
							{ps.dataFields.map((d) => (
								<li key={d} className="font-mono text-xs">
									{d}
								</li>
							))}
						</ul>
						<YourDataValues dkim={result?.results?.dkim} />
					</Section>

					<Section title="Diagnose it yourself">
						<ul className="space-y-2">
							{ps.commands.map((raw) => {
								const cmd = substitute(raw);
								return (
									<li
										key={raw}
										className="flex items-center justify-between gap-2 rounded-md bg-slate-900 p-2 text-slate-100"
									>
										<span className="flex min-w-0 items-center gap-2">
											<Terminal className="h-3.5 w-3.5 shrink-0 text-slate-400" />
											<code className="break-all font-mono text-xs">{cmd}</code>
										</span>
										<CopyFixButton text={cmd} label="Copy" />
									</li>
								);
							})}
						</ul>
						{/* The exact commands THIS run executed, pre-filled from tool_runs[].command (§7). */}
						{toolCommands.length > 0 && (
							<div className="mt-3">
								<p className="mb-1 text-xs font-medium uppercase text-[var(--edh-muted)]">
									Commands this run executed
								</p>
								<ul className="space-y-2">
									{toolCommands.map((cmd) => (
										<li
											key={cmd}
											className="flex items-center justify-between gap-2 rounded-md bg-slate-900 p-2 text-slate-100"
										>
											<span className="flex min-w-0 items-center gap-2">
												<Terminal className="h-3.5 w-3.5 shrink-0 text-slate-400" />
												<code className="break-all font-mono text-xs">
													{cmd}
												</code>
											</span>
											<CopyFixButton text={cmd} label="Copy" />
										</li>
									))}
								</ul>
							</div>
						)}
					</Section>

					<Section title="Tools">
						<ul className="list-disc space-y-1 pl-5 text-sm text-slate-700">
							{ps.tools.map((t) => (
								<li key={t}>{t}</li>
							))}
						</ul>
					</Section>

					<Section title="More health metrics">
						<ul className="list-disc space-y-1 pl-5 text-sm text-slate-700">
							{ps.metrics.map((m) => (
								<li key={m}>{m}</li>
							))}
						</ul>
					</Section>

					<Section title="Path forward">
						<ol className="list-decimal space-y-2 pl-5 text-sm text-slate-700">
							{ps.pathForward.map((step) => (
								<li key={step}>{substitute(step)}</li>
							))}
						</ol>
					</Section>
				</>
			)}
		</div>
	);
}

/**
 * The §9 data fields RENDERED from this run's stored YAML (pm/checks/dkim.mdx §7 drill-down
 * "Your data"): one monospace row per probed selector with the observed values, plus the
 * domain-level wildcard/duplicate-key observations. Absent (older run / never run) renders nothing
 * — the fields-to-look-at list above still explains where the data lives.
 */
function YourDataValues({ dkim }: { dkim?: DkimResults }) {
	if (!dkim) return null;
	const cell = (v: boolean) => (v ? "true" : "false");
	return (
		<div className="mt-3 overflow-x-auto rounded-md border border-[var(--edh-border)]">
			<table className="w-full text-left font-mono text-xs">
				<thead className="bg-slate-50 text-[var(--edh-muted)]">
					<tr>
						<th className="px-2 py-1.5 font-medium">selector</th>
						<th className="px-2 py-1.5 font-medium">source</th>
						<th className="px-2 py-1.5 font-medium">present</th>
						<th className="px-2 py-1.5 font-medium">parses</th>
						<th className="px-2 py-1.5 font-medium">via</th>
						<th className="px-2 py-1.5 font-medium">key</th>
						<th className="px-2 py-1.5 font-medium">revoked</th>
						<th className="px-2 py-1.5 font-medium">t=y</th>
						<th className="px-2 py-1.5 font-medium">TXT#</th>
					</tr>
				</thead>
				<tbody>
					{dkim.selectors.length === 0 ? (
						<tr>
							<td colSpan={9} className="px-2 py-1.5 text-[var(--edh-muted)]">
								no selectors probed in this run
							</td>
						</tr>
					) : (
						dkim.selectors.map((s) => (
							<tr
								key={s.selector}
								className="border-t border-[var(--edh-border)]"
							>
								<td className="px-2 py-1.5">{s.selector}</td>
								<td className="px-2 py-1.5">{s.source}</td>
								<td
									className={`px-2 py-1.5 ${s.present ? "" : "text-red-600"}`}
								>
									{cell(s.present)}
								</td>
								<td
									className={`px-2 py-1.5 ${s.parses || !s.present ? "" : "text-red-600"}`}
								>
									{cell(s.parses)}
								</td>
								<td
									className="max-w-56 truncate px-2 py-1.5"
									title={s.cname_target ?? undefined}
								>
									{s.resolved_via === "cname"
										? `cname → ${s.cname_target ?? "?"}`
										: s.resolved_via}
								</td>
								<td className="px-2 py-1.5">
									{s.key_type === "rsa" && s.key_bits
										? `rsa ${s.key_bits}`
										: (s.key_type ?? "—")}
								</td>
								<td
									className={`px-2 py-1.5 ${s.is_revoked ? "text-red-600" : ""}`}
								>
									{cell(s.is_revoked)}
								</td>
								<td
									className={`px-2 py-1.5 ${s.has_test_flag ? "text-amber-600" : ""}`}
								>
									{cell(s.has_test_flag)}
								</td>
								<td
									className={`px-2 py-1.5 ${s.txt_record_count > 1 ? "text-amber-600" : ""}`}
								>
									{s.txt_record_count}
								</td>
							</tr>
						))
					)}
				</tbody>
			</table>
			<p className="border-t border-[var(--edh-border)] bg-slate-50 px-2 py-1.5 font-mono text-xs text-slate-600">
				wildcard_shadow: {cell(dkim.wildcard_shadow)} · working_selectors:{" "}
				{dkim.working_selectors}
				{dkim.duplicate_keys.length > 0 &&
					` · duplicate_keys: ${dkim.duplicate_keys
						.map(
							(d) => `${d.key_sha256.slice(0, 12)}… on ${d.seen_on.join(", ")}`,
						)
						.join("; ")}`}
			</p>
		</div>
	);
}

function Section({
	title,
	children,
}: {
	title: string;
	children: React.ReactNode;
}) {
	return (
		<section className="mt-6">
			<h2 className="mb-2 font-semibold">{title}</h2>
			{children}
		</section>
	);
}
