import { readAppConfig } from "@shared/config-store";
import type { Checker, CheckOutcome, Finding, Severity } from "../types";
import {
	type ContentSampleRecord,
	getActiveSample,
	readSampleRaw,
} from "./sample-store";
import {
	type ContentSubCheckId,
	type FiredRule,
	isHighWeightRule,
	locateSpamAssassin,
	SA_SAFE_TARGET,
	SA_THRESHOLD,
	type SaReport,
	scoreSample,
	subCheckForRule,
} from "./spamassassin";

/**
 * Message content spam scoring (pm/checks/content_scoring.mdx). Scores the domain's stored sample
 * message — the raw RFC 5322 source of a real email the user sends — through the Homebrew
 * `spamassassin`/`spamc` engine, reports every rule that fired with its individual weight, and maps
 * fired rules onto the §2 sub-checks (subject, MIME, HTML hygiene, header sanity, attachments,
 * encoding) so each finding names the exact rules and the concrete fix.
 *
 * Severity bands (§3.5): total < 2.0 → ok, 2.0–4.99 → warning, ≥ 5.0 → critical; a single
 * high-weight rule (hidden text, forged header, executable attachment) makes its sub-check
 * critical regardless of the total. With no sample the checker emits exactly one `info` advisory
 * (§8 AC 1); with no engine it advises `brew install spamassassin` and never crashes (AC 7).
 */

const CHECK_ID = "content";

/** Snake_case machine-readable payload (`results["content.scoring"]`, §5 content_score_results). */
export interface ContentScoreResults {
	schema_version: 1;
	sample_id: string;
	from_header: string | null;
	subject: string | null;
	sample_uploaded_at: string;
	total_score: number;
	threshold: number;
	/** total_score < threshold. */
	passed: boolean;
	rules_fired: FiredRule[];
	/** SpamAssassin engine + ruleset version — rule scores drift with sa-update (§3). */
	sa_version: string | null;
	/** Which binary produced the report: "spamc" (spamd) or "spamassassin" (standalone). */
	engine: string;
	checked_at: string;
}

/** Re-score debounce: never more than once per minute per domain, regardless of trigger (§6). */
const RESCORE_DEBOUNCE_MS = 60_000;

/** §2 sub-check metadata: display title, healthy detail, and the concrete remediation. */
const SUB_CHECKS: Record<
	ContentSubCheckId,
	{ title: string; okDetail: string; remediation: string; advisory?: boolean }
> = {
	"content.subject": {
		title: "Subject line signals",
		okDetail:
			"The subject avoids spam signals (no ALL-CAPS, no excessive '!!!', no fake RE:/FWD:).",
		remediation:
			"Use a concise honest subject in sentence case; at most one '!'; no RE:/FWD: unless it is a real thread; at most one emoji.",
	},
	"content.image_text_ratio": {
		title: "Image-to-text ratio",
		okDetail:
			"The message is not image-heavy — real body copy accompanies any images.",
		remediation:
			"Add real body copy and keep images under ~40% of the body; never ship an image-only email — every image needs alt text and surrounding text.",
	},
	"content.multipart": {
		title: "Plain-text alternative (multipart/alternative)",
		okDetail: "A text/plain alternative exists alongside the HTML part.",
		remediation:
			"Send multipart/alternative with a genuine plain-text version that matches the HTML content.",
	},
	"content.mime_valid": {
		title: "MIME well-formedness",
		okDetail:
			"MIME structure is well-formed: matched boundaries, sane Content-Type, no truncated parts.",
		remediation:
			"Regenerate the message with a correct MIME library; ensure each part's boundary opens and closes and Content-Type matches the bytes.",
	},
	"content.spammy_phrases": {
		title: "Trigger phrases & obfuscation",
		okDetail:
			"The body avoids trigger phrases, gappy text, and filter-dodging obfuscation.",
		remediation:
			"Remove or rewrite the cited phrases; never space-out or HTML-comment-break words to evade filters — that itself scores.",
	},
	"content.header_sanity": {
		title: "Header sanity (Message-ID, Date, forgeries)",
		okDetail:
			"A valid Message-ID is present, the Date is sane, and no forged/duplicated headers were seen.",
		remediation:
			"Have the sending MTA generate a unique Message-ID and a correct RFC 5322 Date; remove hand-injected or duplicated headers.",
	},
	"content.attachment_risk": {
		title: "Attachment risk",
		okDetail:
			"No risky attachment types (executables, macro-enabled Office docs, script/archive payloads).",
		remediation:
			"Do not attach executables or macro documents to bulk mail; link to a scanned download instead; use .pdf/.docx without macros.",
	},
	"content.html_hygiene": {
		title: "HTML hygiene (hidden text, tiny fonts)",
		okDetail:
			"No hidden text, tiny/zero-size fonts, white-on-white content, or off-screen positioning.",
		remediation:
			"Delete hidden/keyword-stuffing text; use readable font sizes (≥ 12px) and adequate contrast; keep inline CSS minimal and legitimate.",
	},
	"content.encoding": {
		title: "Transfer encoding",
		okDetail: "Text parts are not needlessly base64/quoted-printable encoded.",
		remediation:
			"Send ASCII/UTF-8 text as 7bit/8bit or quoted-printable; reserve base64 for genuine binary parts (images/attachments).",
	},
	"content.charset": {
		title: "Charset consistency",
		okDetail: "The declared charset matches the bytes.",
		remediation:
			"Declare UTF-8 and encode the body as UTF-8; do not declare a foreign/obscure charset.",
		advisory: true,
	},
	"content.bayes": {
		title: "Bayesian classifier",
		okDetail: "The Bayes classifier does not flag this message.",
		remediation:
			"Rewrite content until the Bayes score drops; retrain the local corpus with known-good mail if scores are miscalibrated.",
		advisory: true,
	},
	"content.short_body": {
		title: "Thin content (tiny body around one link)",
		okDetail:
			"The message has meaningful body copy — not a one-line wrapper around a single link.",
		remediation:
			"Include meaningful body copy; do not send one-line 'click here' emails.",
		advisory: true,
	},
};

/** The nine core sub-checks that always emit a pass/fail row when a sample was scored. */
const CORE_SUB_CHECKS = (Object.keys(SUB_CHECKS) as ContentSubCheckId[]).filter(
	(id) => !SUB_CHECKS[id].advisory,
);

/** Every finding id this checker can emit (drives the surgical re-score merge in AuditService). */
const OWN_FINDING_IDS = new Set<string>([
	...Object.keys(SUB_CHECKS),
	"content.spamassassin_score",
	"content.no_sample",
	"content.engine_missing",
	"content.engine_unavailable",
	"content.sample_unreadable",
]);

/**
 * Whether a finding was produced by this checker. Peer Spam & Content checkers (BIMI,
 * List-Unsubscribe, …) share the `content` checkId prefix, so ownership is by finding id — plus
 * the runner's synthetic `content.scoring.*` error/timeout findings, which carry the checker id.
 */
export function isContentScoringFinding(f: Finding): boolean {
	return OWN_FINDING_IDS.has(f.id) || f.checkId === "content.scoring";
}

function formatPts(score: number): string {
	return `${score >= 0 ? "+" : ""}${score.toFixed(1)}`;
}

/** §3.5 banding for the total: < safe → ok, safe–threshold → warning, ≥ threshold → critical. */
function bandFor(
	total: number,
	safeTarget: number,
	threshold: number,
): Severity {
	if (total >= threshold) return "critical";
	if (total >= safeTarget) return "warning";
	return "ok";
}

/** Band ordering for the §6 regression diff — higher rank = worse placement. */
const BAND_RANK: Record<Severity, number> = {
	ok: 0,
	info: 0,
	warning: 1,
	critical: 2,
};

/**
 * Derive the finding list from one parsed SpamAssassin report (§3.4/§3.5): the headline
 * `content.spamassassin_score` finding plus one row per sub-check — fired sub-checks list the
 * concrete rules and their summed points; quiet core sub-checks report `ok`.
 */
function deriveFindings(
	report: SaReport,
	sample: ContentSampleRecord,
	opts: { safeTarget: number; engine: string; previous?: ContentScoreResults },
): Finding[] {
	const findings: Finding[] = [];
	const band = bandFor(report.totalScore, opts.safeTarget, report.threshold);
	const sortedRules = [...report.rulesFired].sort((a, b) => b.score - a.score);
	const sampleLabel = `sample "${sample.subject ?? "(no subject)"}" from ${sample.fromHeader ?? "(unknown sender)"}`;

	// Regression diff against the previous content_score_results row (§6 / §8 AC 9): a total
	// crossing 2.0 (green→amber) or 5.0 (amber→red), or a NEWLY fired high-weight rule, is flagged
	// as a new problem — even when the sample bytes are unchanged (ruleset drift via sa-update).
	const previous = opts.previous;
	const previousBand = previous
		? bandFor(previous.total_score, opts.safeTarget, previous.threshold)
		: null;
	const previousRules = new Set(
		(previous?.rules_fired ?? []).map((r) => r.rule),
	);
	const newHighWeightRules = previous
		? report.rulesFired.filter(
				(r) => isHighWeightRule(r) && !previousRules.has(r.rule),
			)
		: [];
	const bandWorsened =
		previousBand !== null && BAND_RANK[band] > BAND_RANK[previousBand];
	const totalIsNewProblem =
		band !== "ok" && (bandWorsened || newHighWeightRules.length > 0);

	findings.push({
		id: "content.spamassassin_score",
		checkId: CHECK_ID,
		title: `SpamAssassin score ${report.totalScore.toFixed(1)} / ${report.threshold.toFixed(1)}`,
		severity: band,
		detail:
			`The ${sampleLabel} scored ${report.totalScore.toFixed(1)} against the ${report.threshold.toFixed(1)} spam threshold ` +
			`(inbox-safe target < ${opts.safeTarget.toFixed(1)}), with ${report.rulesFired.length} rule(s) fired via ${opts.engine}.` +
			(bandWorsened && previous
				? ` The total worsened from ${previous.total_score.toFixed(1)} on the previous score.`
				: "") +
			(newHighWeightRules.length > 0
				? ` Newly fired high-weight rule(s) since the previous score: ${newHighWeightRules.map((r) => r.rule).join(", ")}.`
				: ""),
		evidence:
			sortedRules.map((r) => `${r.rule} ${formatPts(r.score)}`).join("; ") ||
			"no rules fired",
		...(totalIsNewProblem && { isNew: true }),
		...(band !== "ok" && {
			remediation: `Address the highest-scoring fired rules first (${sortedRules
				.filter((r) => r.score > 0)
				.slice(0, 3)
				.map((r) => r.rule)
				.join(
					", ",
				)}); re-score until the total is below ${opts.safeTarget.toFixed(1)}.`,
		}),
	});

	// Attribute positive-scoring rules to their §2 sub-check family.
	const bySubCheck = new Map<ContentSubCheckId, FiredRule[]>();
	for (const fired of report.rulesFired) {
		if (fired.score <= 0) continue; // negative rules are good signals, not problems
		const sub = subCheckForRule(fired.rule);
		if (!sub) continue; // unfamilied rules only show under the total
		const list = bySubCheck.get(sub) ?? [];
		list.push(fired);
		bySubCheck.set(sub, list);
	}

	for (const [sub, rules] of bySubCheck) {
		const meta = SUB_CHECKS[sub];
		const pts = rules.reduce((sum, r) => sum + r.score, 0);
		const hasHighWeight = rules.some(isHighWeightRule);
		// Sub-checks inherit severity from the weight of their fired rules (§3.5): one high-weight
		// rule is critical even when the total is moderate; light rules are warning/info. Bayes is
		// always advisory-info (§2).
		let severity: Severity;
		if (sub === "content.bayes") severity = "info";
		else if (hasHighWeight) severity = "critical";
		else if (pts >= (meta.advisory ? 1.0 : 0.5)) severity = "warning";
		else severity = "info";
		const sorted = [...rules].sort((a, b) => b.score - a.score);
		// A high-weight rule that did NOT fire on the previous score marks this sub-check as a new
		// problem (§6 / §8 AC 9) — the re-score path has no run-level differ, so the flag lives here.
		const hasNewHighWeight =
			previous !== undefined &&
			(severity === "warning" || severity === "critical") &&
			rules.some((r) => isHighWeightRule(r) && !previousRules.has(r.rule));
		findings.push({
			id: sub,
			checkId: CHECK_ID,
			title: meta.title,
			severity,
			detail:
				`SpamAssassin rule(s) fired (${formatPts(pts)} pts total): ` +
				sorted
					.map((r) => `${r.rule} ${formatPts(r.score)} — ${r.description}`)
					.join("; "),
			evidence: sorted.map((r) => `${r.rule} ${formatPts(r.score)}`).join("; "),
			...(hasNewHighWeight && { isNew: true }),
			// Every fired sub-check names its rules and the exact fix (§8 AC 6).
			remediation: `${meta.remediation} (fired: ${sorted.map((r) => r.rule).join(", ")})`,
		});
	}

	// Quiet core sub-checks are explicit passes so the table shows pass and fail alike.
	for (const sub of CORE_SUB_CHECKS) {
		if (bySubCheck.has(sub)) continue;
		const meta = SUB_CHECKS[sub];
		findings.push({
			id: sub,
			checkId: CHECK_ID,
			title: meta.title,
			severity: "ok",
			detail: meta.okDetail,
		});
	}

	return findings;
}

export const contentScoringCheck: Checker = {
	id: "content.scoring",
	label: "Message Content Spam Scoring",
	async run(ctx): Promise<Finding[] | CheckOutcome> {
		const engine = locateSpamAssassin();
		const sample = ctx.domainId ? getActiveSample(ctx.domainId) : null;

		// §3.1 / §8 AC 1: no sample → exactly one info advisory; the cell never goes amber/red.
		if (!sample) {
			const engineHint = engine.installed
				? "The SpamAssassin engine is installed, so scoring can begin as soon as a sample is uploaded."
				: "SpamAssassin is not installed on this host yet — run `brew install spamassassin` so the message can be scored.";
			return [
				{
					id: "content.no_sample",
					checkId: CHECK_ID,
					title: "No sample message uploaded",
					severity: "info",
					detail:
						"Content scoring grades a representative sample email (raw RFC 5322 headers + body) the way a receiving content filter does — subject signals, MIME structure, HTML hygiene, trigger phrases, header sanity, attachment risk, and encoding — reporting every SpamAssassin rule that fires with its individual score (safe 0–2, warning 2–5, critical ≥ 5.0). " +
						engineHint,
					remediation:
						"Upload a representative .eml for this domain (drag-drop the raw email source or paste it) to enable content scoring.",
					evidence: engine.installed
						? "spamassassin: installed"
						: "spamassassin: not found",
				},
			];
		}

		// §8 AC 7: engine absent → one info advisory, never a crash, never amber/red.
		if (!engine.installed) {
			return [
				{
					id: "content.engine_missing",
					checkId: CHECK_ID,
					title: "SpamAssassin not installed",
					severity: "info",
					detail: `A sample message ("${sample.subject ?? "(no subject)"}") is stored for this domain, but the SpamAssassin engine is not installed, so it cannot be scored.`,
					remediation:
						"Install the engine with `brew install spamassassin`, then re-score.",
					evidence: "spamassassin: not found; spamc: not found",
				},
			];
		}

		const cfg = readAppConfig().checks.content ?? {
			threshold: SA_THRESHOLD,
			safeTarget: SA_SAFE_TARGET,
			networkTests: false,
		};

		// Debounce (§6): the same active sample scored less than a minute ago is reused, not re-run.
		const previous = ctx.previousResults?.["content.scoring"] as
			| ContentScoreResults
			| undefined;
		if (
			previous &&
			previous.sample_id === sample.id &&
			Date.now() - Date.parse(previous.checked_at) < RESCORE_DEBOUNCE_MS
		) {
			const report: SaReport = {
				totalScore: previous.total_score,
				threshold: previous.threshold,
				rulesFired: previous.rules_fired ?? [],
			};
			return {
				findings: deriveFindings(report, sample, {
					safeTarget: cfg.safeTarget,
					engine: previous.engine,
				}),
				results: previous,
			};
		}

		const raw = readSampleRaw(sample);
		if (raw === null) {
			return [
				{
					id: "content.sample_unreadable",
					checkId: CHECK_ID,
					title: "Stored sample message could not be read",
					severity: "warning",
					detail: `The active sample (uploaded ${sample.uploadedAt}) is missing from the file store, so content scoring was skipped.`,
					remediation:
						"Upload the sample .eml again to re-enable content scoring.",
					evidence: sample.rawPath ?? "(no stored path)",
				},
			];
		}

		const outcome = await scoreSample(raw, {
			enableNetworkTests: cfg.networkTests,
			signal: ctx.signal,
		});
		if (!outcome) {
			return [
				{
					id: "content.engine_unavailable",
					checkId: CHECK_ID,
					title: "SpamAssassin did not produce a report",
					severity: "info",
					detail:
						"The SpamAssassin binary is installed but no parseable report came back (spamd may be down and the standalone run failed or timed out). The audit continued without a content score.",
					remediation:
						"Check that `spamassassin --lint` passes, then re-score. Starting spamd (`brew services start spamassassin`) makes scoring faster.",
				},
			];
		}

		// Honor the admin threshold override when the engine reports a different required= value.
		const report: SaReport = {
			...outcome.report,
			threshold: cfg.threshold ?? outcome.report.threshold,
		};
		const results: ContentScoreResults = {
			schema_version: 1,
			sample_id: sample.id,
			from_header: sample.fromHeader,
			subject: sample.subject,
			sample_uploaded_at: sample.uploadedAt,
			total_score: report.totalScore,
			threshold: report.threshold,
			passed: report.totalScore < report.threshold,
			rules_fired: report.rulesFired,
			sa_version: outcome.saVersion,
			engine: outcome.engine,
			checked_at: new Date().toISOString(),
		};
		return {
			findings: deriveFindings(report, sample, {
				safeTarget: cfg.safeTarget,
				engine: outcome.engine,
				// §6 regression detection: diff against the previous content_score_results row so a
				// band crossing or newly fired high-weight rule is flagged even on an unchanged sample.
				previous,
			}),
			results,
		};
	},
};
