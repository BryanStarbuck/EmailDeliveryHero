import { locateTool, runTool } from "@shared/tool-runner"

/**
 * The SpamAssassin engine adapter (pm/checks/content_scoring.mdx §3): shells the raw sample to the
 * Homebrew engine via execFile (never a shell string) with the bytes on stdin, and parses the
 * score line + per-rule report into `{ rule, score, description }` rows. Preferred path is
 * `spamc -R` (fast, talks to a running spamd); fallback is standalone `spamassassin -t -L` (test
 * mode — no auto-learn, no network side-effects; `-L` keeps URIBL/RBL/Razor/Pyzor/DCC OFF so
 * scoring is deterministic and never double-counts the Blacklists category).
 */

/** The canonical SpamAssassin spam threshold (pm/checks/content_scoring.mdx §1). */
export const SA_THRESHOLD = 5.0
/** EmailDeliveryHero's inbox-safe target: totals below this are `ok`. */
export const SA_SAFE_TARGET = 2.0

export interface FiredRule {
  rule: string
  score: number
  description: string
}

export interface SaReport {
  totalScore: number
  threshold: number
  rulesFired: FiredRule[]
}

export interface SaRunOutcome {
  report: SaReport
  /** Which binary produced the report ("spamc" | "spamassassin"). */
  engine: string
  /** `spamassassin --version` first line (rule scores drift with sa-update, so record it). */
  saVersion: string | null
}

/** Scoring is CPU-bound — give the engine a generous but hard budget. */
const SA_TIMEOUT_MS = 60_000

/**
 * Parse SpamAssassin output into the total/threshold and the fired-rule table. Handles both
 * shapes: `spamc -R` (first line `score/threshold`, then the report) and `spamassassin -t`
 * (the message echoed back with `X-Spam-Status: ... score=n required=n ...` and the appended
 * "Content analysis details" table `pts rule name description`).
 */
export function parseSaOutput(stdout: string): SaReport | null {
  let totalScore: number | null = null
  let threshold: number | null = null

  // spamc -R: the very first line is "3.2/5.0".
  const firstLine = stdout.split(/\r?\n/, 1)[0]?.trim() ?? ""
  const slash = firstLine.match(/^(-?\d+(?:\.\d+)?)\/(\d+(?:\.\d+)?)$/)
  if (slash) {
    totalScore = Number.parseFloat(slash[1])
    threshold = Number.parseFloat(slash[2])
  } else {
    // spamassassin -t: X-Spam-Status: Yes, score=6.2 required=5.0 tests=...
    const status = stdout.match(/X-Spam-Status:.*?score=(-?\d+(?:\.\d+)?)\s+required=(\d+(?:\.\d+)?)/s)
    if (status) {
      totalScore = Number.parseFloat(status[1])
      threshold = Number.parseFloat(status[2])
    }
  }
  if (totalScore === null || Number.isNaN(totalScore)) return null

  // The per-rule table: " pts rule name              description" with wrapped description
  // continuation lines indented past the pts column.
  const rulesFired: FiredRule[] = []
  const ruleLine = /^\s*(-?\d+(?:\.\d+)?)\s+([A-Z][A-Z0-9_]+)\s+(.*)$/
  for (const line of stdout.split(/\r?\n/)) {
    const m = line.match(ruleLine)
    if (m) {
      rulesFired.push({
        rule: m[2],
        score: Number.parseFloat(m[1]),
        description: m[3].trim(),
      })
      continue
    }
    // Continuation of the previous rule's wrapped description.
    const last = rulesFired[rulesFired.length - 1]
    if (last && /^\s{10,}\S/.test(line) && !/^\s*(pts|---)/.test(line)) {
      last.description = `${last.description} ${line.trim()}`.trim()
    }
  }

  return { totalScore, threshold: threshold ?? SA_THRESHOLD, rulesFired }
}

/** `spamassassin --version` first line, best-effort (null when it cannot be read). */
async function readSaVersion(binPath: string): Promise<string | null> {
  const result = await runTool(binPath, ["--version"], { timeoutMs: 10_000 })
  const line = result.stdout.split(/\r?\n/, 1)[0]?.trim()
  return line || null
}

export type SaAvailability = { installed: true; spamc: string | null; spamassassin: string | null } | { installed: false }

/** Locate the Homebrew engine without running anything (pm/run_checks.mdx §5.2 ToolLocator). */
export function locateSpamAssassin(): SaAvailability {
  const spamc = locateTool("spamc")
  const spamassassin = locateTool("spamassassin")
  if (!spamc && !spamassassin) return { installed: false }
  return { installed: true, spamc, spamassassin }
}

/**
 * Score one raw message. Preferred: `spamc -R -x` (report output; `-x` makes a dead spamd an error
 * instead of echoing the message back "safe"). Fallback: `spamassassin -t -L` (test mode; local
 * rules only — network tests stay off by default, `enableNetworkTests` opts in). Returns null when
 * no engine produced a parseable report (the checker degrades to an info finding, never throws).
 */
export async function scoreSample(
  raw: string,
  opts: { enableNetworkTests?: boolean } = {},
): Promise<SaRunOutcome | null> {
  const avail = locateSpamAssassin()
  if (!avail.installed) return null
  const runOpts = {
    timeoutMs: SA_TIMEOUT_MS,
    stdin: raw,
    resource: "cpu" as const,
  }

  if (avail.spamc) {
    const result = await runTool(avail.spamc, ["-R", "-x"], runOpts)
    if (!result.timedOut && result.code === 0) {
      const report = parseSaOutput(result.stdout)
      if (report) {
        return {
          report,
          engine: "spamc",
          saVersion: avail.spamassassin ? await readSaVersion(avail.spamassassin) : null,
        }
      }
    }
    // spamd not running / unreachable → fall through to the standalone binary.
  }

  if (avail.spamassassin) {
    const args = opts.enableNetworkTests ? ["-t"] : ["-t", "-L"]
    const result = await runTool(avail.spamassassin, args, runOpts)
    if (!result.timedOut && (result.code === 0 || result.code === 1)) {
      // Exit 1 = "message is spam" in some configurations; the report is still on stdout.
      const report = parseSaOutput(result.stdout)
      if (report) {
        return { report, engine: "spamassassin", saVersion: await readSaVersion(avail.spamassassin) }
      }
    }
  }

  return null
}

// ---- Rule-family → sub-check mapping (pm/checks/content_scoring.mdx §2/§3.4) -------------------

/** The §2 sub-check ids this check can attribute fired rules to. */
export type ContentSubCheckId =
  | "content.subject"
  | "content.image_text_ratio"
  | "content.multipart"
  | "content.mime_valid"
  | "content.spammy_phrases"
  | "content.header_sanity"
  | "content.attachment_risk"
  | "content.html_hygiene"
  | "content.encoding"
  | "content.charset"
  | "content.bayes"
  | "content.short_body"

/**
 * Map one fired SpamAssassin rule to a §2 sub-check by rule-family prefix. Rules with no family
 * (network tests, Razor, generic scores) return null — they still count in the total but are only
 * shown under `content.spamassassin_score`.
 */
export function subCheckForRule(rule: string): ContentSubCheckId | null {
  const r = rule.toUpperCase()
  // Order matters: the specific families before the broad MIME_/HTML_ catch-alls.
  if (r.startsWith("BAYES_")) return "content.bayes"
  if (r.includes("CHARSET_FARAWAY") || r === "UNWANTED_LANGUAGE_BODY") return "content.charset"
  if (r.includes("EXECUTABLE") || r.includes("ATTACH")) return "content.attachment_risk"
  if (r.startsWith("SUBJ_") || r.startsWith("SUBJECT_") || r.startsWith("FAKE_REPLY")) {
    return "content.subject"
  }
  if (
    r === "MISSING_MID" ||
    r === "INVALID_MSGID" ||
    r === "INVALID_DATE" ||
    r.startsWith("DATE_IN_") ||
    r.startsWith("DUP_") ||
    r.startsWith("FORGED_") ||
    r.startsWith("MISSING_HEADERS") ||
    r === "MISSING_DATE" ||
    r === "MISSING_FROM" ||
    r === "MISSING_SUBJECT" ||
    r.startsWith("HEADER_")
  ) {
    return "content.header_sanity"
  }
  if (r === "MIME_BASE64_TEXT" || r.startsWith("MIME_QP")) return "content.encoding"
  if (r === "MIME_HTML_ONLY" || r.startsWith("MPART_")) return "content.multipart"
  if (r.startsWith("HTML_IMAGE") || r.includes("IMAGE_ONLY") || r.includes("IMAGE_RATIO")) {
    return "content.image_text_ratio"
  }
  if (r.startsWith("MIME_") || r.startsWith("MISSING_MIME")) return "content.mime_valid"
  if (
    r === "HIDDEN_TEXT" ||
    r.includes("FONT_LOW_CONTRAST") ||
    r.includes("FONT_SIZE_TINY") ||
    r.includes("TINY_FONT") ||
    r.startsWith("HTML_")
  ) {
    return "content.html_hygiene"
  }
  if (r === "BODY_SINGLE_WORD" || r === "TVD_SPACE_RATIO" || r.startsWith("SHORT_")) {
    return "content.short_body"
  }
  if (
    r.startsWith("FREE") ||
    r.startsWith("GAPPY") ||
    r.startsWith("OBFUSCAT") ||
    r === "URG_BIZ" ||
    r.startsWith("MONEY") ||
    r.startsWith("DRUG") ||
    r.startsWith("PHARMA") ||
    r.startsWith("GUARANTEE") ||
    r.startsWith("ACT_NOW")
  ) {
    return "content.spammy_phrases"
  }
  return null
}

/**
 * High-weight rule families that make their sub-check `critical` regardless of the total
 * (pm/checks/content_scoring.mdx §3.5/§8 AC 5): hidden text, forged headers, executable
 * attachments, broken MIME, heavy obfuscation.
 */
export function isHighWeightRule(fired: FiredRule): boolean {
  const r = fired.rule.toUpperCase()
  if (r === "HIDDEN_TEXT" || r.startsWith("FORGED_")) return true
  if (r.includes("EXECUTABLE") || r === "SUSPICIOUS_ATTACHMENT") return true
  if (r === "MIME_BAD_BOUNDARY" || r === "MISSING_MIME_HB_SEP") return true
  if (r.startsWith("OBFUSCAT")) return true
  return fired.score >= 3.0
}
