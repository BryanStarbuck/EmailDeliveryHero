import type { Finding } from "@/api/types";

/**
 * The finding ids owned by Message-content spam scoring (pm/checks/content_scoring.mdx §2/§3) —
 * peer Spam & Content checkers (BIMI, List-Unsubscribe, link reputation, …) share the `content`
 * checkId prefix, so content-scoring ownership is decided by finding id, plus the runner's
 * synthetic `content.scoring.*` error/timeout findings which carry the checker id itself.
 */
export const CONTENT_SCORING_FINDING_IDS = new Set([
	"content.spamassassin_score",
	"content.subject",
	"content.image_text_ratio",
	"content.multipart",
	"content.mime_valid",
	"content.spammy_phrases",
	"content.header_sanity",
	"content.attachment_risk",
	"content.html_hygiene",
	"content.encoding",
	"content.charset",
	"content.bayes",
	"content.short_body",
	"content.no_sample",
	"content.engine_missing",
	"content.engine_unavailable",
	"content.sample_unreadable",
]);

/** Whether a finding was produced by the content-scoring checker (mirrors the backend helper). */
export function isContentScoringFinding(f: Finding): boolean {
	return (
		CONTENT_SCORING_FINDING_IDS.has(f.id) || f.checkId === "content.scoring"
	);
}
