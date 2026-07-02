import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

// Isolate every store the checker touches to a throwaway state dir BEFORE any module import.
process.env.EDH_STATE_DIR = mkdtempSync(join(tmpdir(), "edh-content-scoring-"))

import type { CheckOutcome, Finding } from "../types"
import {
  getActiveSample,
  listSamples,
  MAX_SAMPLE_BYTES,
  readSampleRaw,
  saveSample,
} from "./sample-store"
import { isHighWeightRule, parseSaOutput, subCheckForRule } from "./spamassassin"

// The checker is exercised with the engine mocked (no Homebrew SpamAssassin in CI); the parser and
// mapping functions above are the real ones.
jest.mock("./spamassassin", () => {
  const actual = jest.requireActual("./spamassassin")
  return {
    ...actual,
    locateSpamAssassin: jest.fn(() => ({
      installed: true,
      spamc: null,
      spamassassin: "/opt/homebrew/bin/spamassassin",
    })),
    scoreSample: jest.fn(),
  }
})

import { contentScoringCheck, isContentScoringFinding } from "./content-scoring.check"
import { locateSpamAssassin, scoreSample } from "./spamassassin"

const mockLocate = locateSpamAssassin as jest.Mock
const mockScore = scoreSample as jest.Mock

const RAW_SAMPLE = [
  "From: noreply@shop.example.com",
  "To: list@example.net",
  "Subject: Q3 SALE — 50% OFF!!!",
  "Message-ID: <abc@shop.example.com>",
  "",
  "Buy now.",
  "",
].join("\r\n")

function findingsOf(outcome: Finding[] | CheckOutcome): Finding[] {
  return Array.isArray(outcome) ? outcome : outcome.findings
}

describe("parseSaOutput", () => {
  it("parses the spamc -R shape (score/threshold first line + rule table)", () => {
    const out = [
      "3.2/5.0",
      "",
      "Content analysis details:   (3.2 points, 5.0 required)",
      "",
      " pts rule name              description",
      "---- ---------------------- --------------------------------------------------",
      " 1.2 SUBJ_ALL_CAPS          Subject is all capitals",
      " 1.1 MIME_HTML_ONLY         Message only has text/html MIME parts",
      " 0.9 HTML_IMAGE_RATIO_02    HTML has a low ratio of text to image area",
      "-0.1 DKIM_VALID             Message has at least one valid DKIM signature",
    ].join("\n")
    const report = parseSaOutput(out)
    expect(report).not.toBeNull()
    expect(report?.totalScore).toBe(3.2)
    expect(report?.threshold).toBe(5.0)
    expect(report?.rulesFired.map((r) => r.rule)).toEqual([
      "SUBJ_ALL_CAPS",
      "MIME_HTML_ONLY",
      "HTML_IMAGE_RATIO_02",
      "DKIM_VALID",
    ])
    expect(report?.rulesFired[0]).toEqual({
      rule: "SUBJ_ALL_CAPS",
      score: 1.2,
      description: "Subject is all capitals",
    })
    expect(report?.rulesFired[3].score).toBe(-0.1)
  })

  it("parses the spamassassin -t shape (X-Spam-Status header + appended report)", () => {
    const out = [
      "From: x@example.com",
      "X-Spam-Status: Yes, score=6.5 required=5.0 tests=HIDDEN_TEXT,SUBJ_ALL_CAPS",
      "",
      "body",
      "Content analysis details:   (6.5 points, 5.0 required)",
      " pts rule name              description",
      " 5.0 HIDDEN_TEXT            Message appears to contain hidden text",
      " 1.5 SUBJ_ALL_CAPS          Subject is all capitals",
    ].join("\n")
    const report = parseSaOutput(out)
    expect(report?.totalScore).toBe(6.5)
    expect(report?.threshold).toBe(5.0)
    expect(report?.rulesFired).toHaveLength(2)
  })

  it("returns null when no score is present", () => {
    expect(parseSaOutput("spamc: connect to spamd failed")).toBeNull()
  })
})

describe("subCheckForRule / isHighWeightRule", () => {
  it("maps rule families to the §2 sub-checks", () => {
    expect(subCheckForRule("SUBJ_ALL_CAPS")).toBe("content.subject")
    expect(subCheckForRule("SUBJECT_EXCESS_EXCLAIM")).toBe("content.subject")
    expect(subCheckForRule("FAKE_REPLY_A")).toBe("content.subject")
    expect(subCheckForRule("MIME_HTML_ONLY")).toBe("content.multipart")
    expect(subCheckForRule("MPART_ALT_DIFF")).toBe("content.multipart")
    expect(subCheckForRule("HTML_IMAGE_RATIO_02")).toBe("content.image_text_ratio")
    expect(subCheckForRule("MIME_BAD_BOUNDARY")).toBe("content.mime_valid")
    expect(subCheckForRule("MIME_BASE64_TEXT")).toBe("content.encoding")
    expect(subCheckForRule("MIME_QP_LONG_LINE")).toBe("content.encoding")
    expect(subCheckForRule("MISSING_MID")).toBe("content.header_sanity")
    expect(subCheckForRule("FORGED_OUTLOOK_TAGS")).toBe("content.header_sanity")
    expect(subCheckForRule("MICROSOFT_EXECUTABLE")).toBe("content.attachment_risk")
    expect(subCheckForRule("SUSPICIOUS_ATTACHMENT")).toBe("content.attachment_risk")
    expect(subCheckForRule("HIDDEN_TEXT")).toBe("content.html_hygiene")
    expect(subCheckForRule("HTML_FONT_SIZE_TINY")).toBe("content.html_hygiene")
    expect(subCheckForRule("GAPPY_SUBJECT")).toBe("content.spammy_phrases")
    expect(subCheckForRule("OBFUSCATING_COMMENT")).toBe("content.spammy_phrases")
    expect(subCheckForRule("URG_BIZ")).toBe("content.spammy_phrases")
    expect(subCheckForRule("BAYES_99")).toBe("content.bayes")
    expect(subCheckForRule("CHARSET_FARAWAY")).toBe("content.charset")
    expect(subCheckForRule("TVD_SPACE_RATIO")).toBe("content.short_body")
    // Unfamilied network rules only show under the total.
    expect(subCheckForRule("RCVD_IN_ZEN")).toBeNull()
  })

  it("flags the high-weight families that force a critical sub-check (§8 AC 5)", () => {
    expect(isHighWeightRule({ rule: "HIDDEN_TEXT", score: 1.0, description: "" })).toBe(true)
    expect(isHighWeightRule({ rule: "FORGED_MUA", score: 0.5, description: "" })).toBe(true)
    expect(isHighWeightRule({ rule: "MICROSOFT_EXECUTABLE", score: 0.1, description: "" })).toBe(
      true,
    )
    expect(isHighWeightRule({ rule: "SUBJ_ALL_CAPS", score: 1.2, description: "" })).toBe(false)
    expect(isHighWeightRule({ rule: "ANY_RULE", score: 3.5, description: "" })).toBe(true)
  })
})

describe("sample-store", () => {
  it("persists an upload, parses From/Subject, and deactivates the prior active (§8 AC 2)", () => {
    const first = saveSample("dom-store", RAW_SAMPLE)
    expect(first.active).toBe(true)
    expect(first.fromHeader).toBe("noreply@shop.example.com")
    expect(first.subject).toBe("Q3 SALE — 50% OFF!!!")
    expect(first.rawPath).toContain(join("samples", "dom-store", `${first.id}.eml`))
    expect(readSampleRaw(first)).toBe(RAW_SAMPLE)

    const second = saveSample("dom-store", RAW_SAMPLE.replace("Q3", "Q4"))
    expect(second.active).toBe(true)
    expect(getActiveSample("dom-store")?.id).toBe(second.id)
    const all = listSamples("dom-store")
    expect(all).toHaveLength(2)
    expect(all.filter((s) => s.active)).toHaveLength(1)
  })

  it("rejects empty and oversized samples", () => {
    expect(() => saveSample("dom-store", "")).toThrow(/empty/)
    expect(() => saveSample("dom-store", "x".repeat(MAX_SAMPLE_BYTES + 1))).toThrow(/too large/)
  })
})

describe("contentScoringCheck", () => {
  beforeEach(() => {
    mockScore.mockReset()
    mockLocate.mockReturnValue({
      installed: true,
      spamc: null,
      spamassassin: "/opt/homebrew/bin/spamassassin",
    })
  })

  it("emits exactly one info finding when no sample is uploaded (§8 AC 1)", async () => {
    const findings = findingsOf(
      await contentScoringCheck.run({
        domain: "example.com",
        domainId: "dom-none",
        dkimSelectors: [],
        sendingIps: [],
      }),
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].id).toBe("content.no_sample")
    expect(findings[0].severity).toBe("info")
    expect(findings[0].remediation).toMatch(/Upload a representative \.eml/)
  })

  it("advises brew install when the engine is absent, without crashing (§8 AC 7)", async () => {
    saveSample("dom-noengine", RAW_SAMPLE)
    mockLocate.mockReturnValue({ installed: false })
    const findings = findingsOf(
      await contentScoringCheck.run({
        domain: "example.com",
        domainId: "dom-noengine",
        dkimSelectors: [],
        sendingIps: [],
      }),
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].id).toBe("content.engine_missing")
    expect(findings[0].severity).toBe("info")
    expect(findings[0].remediation).toContain("brew install spamassassin")
  })

  it("scores a sample: warning band, per-rule sub-check attribution, ok rows, payload (§8 AC 4/6)", async () => {
    const sample = saveSample("dom-score", RAW_SAMPLE)
    mockScore.mockResolvedValue({
      report: {
        totalScore: 3.2,
        threshold: 5.0,
        rulesFired: [
          { rule: "SUBJ_ALL_CAPS", score: 1.2, description: "Subject is all capitals" },
          { rule: "MIME_HTML_ONLY", score: 1.1, description: "HTML-only message" },
          { rule: "HTML_IMAGE_RATIO_02", score: 0.9, description: "Low text-to-image ratio" },
        ],
      },
      engine: "spamassassin",
      saVersion: "SpamAssassin version 4.0.1",
    })
    const outcome = (await contentScoringCheck.run({
      domain: "example.com",
      domainId: "dom-score",
      dkimSelectors: [],
      sendingIps: [],
    })) as CheckOutcome
    const findings = outcome.findings

    const total = findings.find((f) => f.id === "content.spamassassin_score")
    expect(total?.severity).toBe("warning")
    expect(total?.title).toContain("3.2 / 5.0")
    expect(total?.remediation).toContain("SUBJ_ALL_CAPS")

    const subject = findings.find((f) => f.id === "content.subject")
    expect(subject?.severity).toBe("warning")
    expect(subject?.remediation).toContain("SUBJ_ALL_CAPS") // names the fired rule (AC 6)
    expect(findings.find((f) => f.id === "content.multipart")?.severity).toBe("warning")
    expect(findings.find((f) => f.id === "content.image_text_ratio")?.severity).toBe("warning")
    // Quiet core sub-checks are explicit passes.
    expect(findings.find((f) => f.id === "content.header_sanity")?.severity).toBe("ok")
    expect(findings.find((f) => f.id === "content.attachment_risk")?.severity).toBe("ok")

    const results = outcome.results as Record<string, unknown>
    expect(results.sample_id).toBe(sample.id)
    expect(results.total_score).toBe(3.2)
    expect(results.threshold).toBe(5.0)
    expect(results.passed).toBe(true)
    expect(results.sa_version).toBe("SpamAssassin version 4.0.1")
    expect(Array.isArray(results.rules_fired)).toBe(true)

    expect(findings.every(isContentScoringFinding)).toBe(true)
  })

  it("bands the total exactly and makes one high-weight rule critical (§8 AC 5)", async () => {
    saveSample("dom-crit", RAW_SAMPLE)
    mockScore.mockResolvedValue({
      report: {
        totalScore: 4.0,
        threshold: 5.0,
        rulesFired: [{ rule: "HIDDEN_TEXT", score: 4.0, description: "Hidden text" }],
      },
      engine: "spamc",
      saVersion: null,
    })
    const outcome = (await contentScoringCheck.run({
      domain: "example.com",
      domainId: "dom-crit",
      dkimSelectors: [],
      sendingIps: [],
    })) as CheckOutcome
    // Total 4.0 is only a warning…
    expect(outcome.findings.find((f) => f.id === "content.spamassassin_score")?.severity).toBe(
      "warning",
    )
    // …but the hidden-text sub-check is critical regardless of the moderate total.
    expect(outcome.findings.find((f) => f.id === "content.html_hygiene")?.severity).toBe("critical")
  })

  it("reuses the previous result within the one-minute debounce (§6)", async () => {
    const sample = saveSample("dom-debounce", RAW_SAMPLE)
    const previous = {
      schema_version: 1,
      sample_id: sample.id,
      from_header: sample.fromHeader,
      subject: sample.subject,
      sample_uploaded_at: sample.uploadedAt,
      total_score: 1.0,
      threshold: 5.0,
      passed: true,
      rules_fired: [],
      sa_version: null,
      engine: "spamc",
      checked_at: new Date().toISOString(),
    }
    const outcome = (await contentScoringCheck.run({
      domain: "example.com",
      domainId: "dom-debounce",
      dkimSelectors: [],
      sendingIps: [],
      previousResults: { "content.scoring": previous },
    })) as CheckOutcome
    expect(mockScore).not.toHaveBeenCalled()
    expect(outcome.results).toBe(previous)
    expect(outcome.findings.find((f) => f.id === "content.spamassassin_score")?.severity).toBe("ok")
  })

  it("emits an info advisory when the engine produces no report", async () => {
    saveSample("dom-noreport", RAW_SAMPLE)
    mockScore.mockResolvedValue(null)
    const findings = findingsOf(
      await contentScoringCheck.run({
        domain: "example.com",
        domainId: "dom-noreport",
        dkimSelectors: [],
        sendingIps: [],
      }),
    )
    expect(findings).toHaveLength(1)
    expect(findings[0].id).toBe("content.engine_unavailable")
    expect(findings[0].severity).toBe("info")
  })
})
