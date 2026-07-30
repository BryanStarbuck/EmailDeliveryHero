import { existsSync, mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

/**
 * The run-time Spam & Content `report_emails` corpus test against the REAL act3ai.com corpus
 * (pm/emails.mdx §13/§13.4): the checker scans the repo `emails/` directory IN PLACE, attributes
 * every report to its payload domain, stores them (deduped), and emits the aggregate
 * `content.report_*` findings plus the §13.3 snapshot. Skips cleanly when the corpus is absent.
 */

// Isolate the store: state-dir reads EDH_STATE_DIR at call time, so set it before any store call.
process.env.EDH_STATE_DIR = mkdtempSync(join(tmpdir(), "edh-report-emails-spec-"))

import { saveDmarcReport } from "@module/reports/report-store"
import * as configStore from "@shared/config-store"
import type { CheckOutcome, Finding } from "../types"
import { reportEmailsCheck, resolveAnalyzeDir } from "./report-emails.check"

const CORPUS_DIR = join(__dirname, "..", "..", "..", "..", "..", "..", "..", "..", "emails")
const hasCorpus = existsSync(CORPUS_DIR)
const describeCorpus = hasCorpus ? describe : describe.skip

const ACT3 = { id: "d-act3", name: "act3ai.com" }
const OTHER = { id: "d-other", name: "example.com" }

/**
 * The corpus is a FIXED historical snapshot but the aggregation window is anchored on the clock, so
 * with the default 7-day window the whole corpus ages out and every row becomes "no current data".
 * These tests are about the ANALYSIS, so they pin a window wide enough to always contain the corpus.
 * The aging-out contract itself is covered deterministically in reports/derive-findings.spec.ts.
 */
function pinWideWindow(): void {
  jest.spyOn(configStore, "readAppConfig").mockReturnValue({
    reports: {
      enabled: true,
      analyzeDir: "",
      dropFolder: "",
      pollMinutes: 60,
      windowDays: 3650,
      imap: { host: "", port: 993, user: "", mailbox: "INBOX" },
    },
  } as ReturnType<typeof configStore.readAppConfig>)
}

function ctxFor(domain: { id: string; name: string }) {
  return {
    domain: domain.name,
    domainId: domain.id,
    dkimSelectors: [],
    sendingIps: [],
    monitoredDomains: [ACT3, OTHER],
  }
}

function byId(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.id === id)
}

/**
 * Freshness is the ONE row that has to stay loud once the corpus ages out, because every scored row
 * has gone to "no current data" and it is the only thing left saying why. It is deliberately NOT
 * corpus-gated: a synthetic store makes the boundary exact and keeps it covered on a clean clone
 * where emails/ is absent.
 */
describe("content.report_freshness — the threshold is the window, not 2× it", () => {
  const DOMAIN_ID = "d-freshness"
  const AGE_DAYS = 10
  const WINDOW_DAYS = 7

  beforeAll(() => {
    const end = new Date(Date.now() - AGE_DAYS * 24 * 60 * 60 * 1000)
    saveDmarcReport(DOMAIN_ID, {
      kind: "dmarc",
      reporterOrg: "google.com",
      reportId: "freshness-spec-1",
      window: {
        begin: new Date(end.getTime() - 24 * 60 * 60 * 1000).toISOString(),
        end: end.toISOString(),
      },
      policyPublished: {
        domain: "stale.example.com",
        p: "reject",
        sp: null,
        adkim: "r",
        aspf: "r",
        pct: "100",
        np: null,
      },
      rows: [
        {
          sourceIp: "203.0.113.77",
          count: 5,
          disposition: "none",
          spfEvaluated: "pass",
          dkimEvaluated: "pass",
          spfAligned: true,
          dkimAligned: true,
          dmarcPass: true,
          headerFrom: "stale.example.com",
          envelopeSpfDomain: "stale.example.com",
          dkimSigningDomains: ["stale.example.com"],
        },
      ],
    })
  })

  afterEach(() => jest.restoreAllMocks())

  it("warns as soon as the newest report leaves the window, not a window later", async () => {
    jest.spyOn(configStore, "readAppConfig").mockReturnValue({
      reports: {
        enabled: true,
        analyzeDir: mkdtempSync(join(tmpdir(), "edh-freshness-corpus-")),
        dropFolder: "",
        pollMinutes: 60,
        windowDays: WINDOW_DAYS,
        imap: { host: "", port: 993, user: "", mailbox: "INBOX" },
      },
    } as ReturnType<typeof configStore.readAppConfig>)

    const outcome = (await reportEmailsCheck.run(
      ctxFor({ id: DOMAIN_ID, name: "stale.example.com" }),
    )) as CheckOutcome

    // The scored row has gone dark: 10 days old against a 7-day window.
    const passRate = byId(outcome.findings, "content.report_pass_rate")
    expect(passRate?.severity).toBe("info")
    expect(passRate?.title).toContain("No DMARC report data in the last")

    // So freshness must be the amber row. At the old 2× threshold (14 days) this said "Reports are
    // current" — a corpus that had already aged out of every scored row reading as a clean bill.
    const freshness = byId(outcome.findings, "content.report_freshness")
    expect(freshness?.severity).toBe("warning")
    expect(freshness?.title).toContain(`${AGE_DAYS} days old`)
    expect(freshness?.title).not.toContain("current")
  })
})

describeCorpus("content.report_emails — the act3ai.com corpus (pm/emails.mdx §13.4)", () => {
  beforeEach(pinWideWindow)
  afterEach(() => jest.restoreAllMocks())

  it("auto-detects the repo emails/ corpus as the analysis directory (§8)", () => {
    expect(resolveAnalyzeDir()).toBe(CORPUS_DIR)
  })

  let outcome: CheckOutcome

  it("scans the corpus in place and reproduces the §13.4 findings for act3ai.com", async () => {
    outcome = (await reportEmailsCheck.run(ctxFor(ACT3))) as CheckOutcome
    const { findings } = outcome

    // Every finding is aggregate, tagged to the family and to report provenance (§13.2).
    for (const f of findings) {
      expect(f.checkId).toBe("content.report_emails")
      expect(f.source).toBe("report")
    }

    const corpus = byId(findings, "content.report_corpus")
    expect(corpus?.severity).toBe("info")
    expect(corpus?.detail).toContain("74 file(s) scanned")

    const attribution = byId(findings, "content.report_domain_attribution")
    expect(attribution?.severity).toBe("info") // every report → act3ai.com, no orphans

    // DMARC passes on EITHER aligned mechanism, so the corpus's real pass rate is high even though
    // only ~73% is dual-aligned. The dual-aligned gap is fragility (below), not lost mail.
    const passRate = byId(findings, "content.report_pass_rate")
    expect(passRate?.title).toContain("passes DMARC")
    expect(passRate?.severity).toBe("info")

    // Four KDDI-reported messages fail both alignments and were rejected — that is spoofing the
    // policy stopped, so the check must SEE it (complaint C01, pm/Email_Complaints.mdx §7) without
    // calling it our fault: amber for the own relay that broke, never red for the blocked forgery.
    const spoofing = byId(findings, "content.report_spoofing")
    expect(spoofing?.severity).toBe("warning")
    expect(spoofing?.detail).toContain("exactly as the policy intends")
    expect(spoofing?.remediation).toContain("Leave the spoofing sources alone")

    // Every dropped message was forged, so nothing of OURS is being lost — never red.
    const enforcement = byId(findings, "content.report_enforcement")
    expect(enforcement?.severity).toBe("info")
    expect(enforcement?.title).toContain("forged msg(s) blocked by policy")

    const fragility = byId(findings, "content.report_fragility")
    expect(fragility?.severity).toBe("warning")
    // Either alignment relaxation, depending on which mechanism the fragile stream leans on.
    expect(fragility?.remediation).toMatch(/a(spf|dkim)=r/)

    expect(byId(findings, "content.report_tls")?.severity).toBe("info")
  })

  it("writes the §13.3 snapshot (spam_content.report_emails)", () => {
    const snapshot = outcome.results as Record<string, any>
    expect(snapshot.dir).toBe(CORPUS_DIR)
    expect(snapshot.scanned_files).toBe(74)
    expect(snapshot.parsed_reports).toBe(74)
    // The corpus itself holds a few re-downloaded copies ("… 2.eml"), which dedupe on first scan.
    expect(snapshot.duplicates).toBe(5)
    expect(snapshot.attribution.this_domain).toBe(74)
    expect(snapshot.attribution.other_domains).toEqual({})
    expect(snapshot.attribution.orphans).toEqual([])
    // dmarc.* is the ROLLING-WINDOW view, which this spec has pinned wide enough to hold the whole
    // corpus — 71 stored reports, none excluded as stale.
    // 71 DMARC aggregates parse, 66 are distinct after the §4.5 dedupe — the store holds 66.
    expect(snapshot.dmarc.reports).toBe(66)
    expect(snapshot.dmarc.stale_reports_excluded).toBe(0)
    expect(snapshot.dmarc.messages).toBeGreaterThan(0)
    expect(snapshot.dmarc.dual_aligned).toBeLessThanOrEqual(snapshot.dmarc.messages)
    expect(snapshot.dmarc.pass_rate_pct).toBeCloseTo(
      (snapshot.dmarc.dual_aligned / snapshot.dmarc.messages) * 100,
      0,
    )
    // The real DMARC pass rate is the one receivers enforce on, and is always the higher of the two.
    expect(snapshot.dmarc.dmarc_pass_rate_pct).toBeGreaterThanOrEqual(
      snapshot.dmarc.pass_rate_pct,
    )
    expect(snapshot.dmarc.quarantined).toBe(0)
    expect(snapshot.dmarc.policy).toContain("p=reject")
    expect(snapshot.tlsrpt.reports).toBe(3)
    expect(snapshot.tlsrpt.sessions_ok).toBe(7)
    expect(snapshot.tlsrpt.sessions_failed).toBe(0)
  })

  it("is idempotent: a re-scan over the unchanged corpus stores nothing new (§4.5/AC 14)", async () => {
    const again = (await reportEmailsCheck.run(ctxFor(ACT3))) as CheckOutcome
    const snapshot = again.results as Record<string, any>
    expect(snapshot.parsed_reports).toBe(74)
    expect(snapshot.duplicates).toBe(74)
    // The analysis is unchanged — same pass rate, same fragility.
    expect(byId(again.findings, "content.report_pass_rate")?.severity).toBe("info")
    expect(byId(again.findings, "content.report_fragility")?.severity).toBe("warning")
  })

  it("ages the corpus out of a narrow window instead of re-firing its findings (§4.6)", async () => {
    // Same store, same corpus — only the window moves. A snapshot whose newest report predates the
    // window must report "no current data", not repeat the verdict it reached when the data was live.
    jest.spyOn(configStore, "readAppConfig").mockReturnValue({
      reports: {
        enabled: true,
        // A drop folder with no files: the scan finds nothing new, so only the STORE is aggregated.
        analyzeDir: mkdtempSync(join(tmpdir(), "edh-empty-corpus-")),
        dropFolder: "",
        pollMinutes: 60,
        windowDays: 0,
        imap: { host: "", port: 993, user: "", mailbox: "INBOX" },
      },
    } as ReturnType<typeof configStore.readAppConfig>)

    const aged = (await reportEmailsCheck.run(ctxFor(ACT3))) as CheckOutcome
    const passRate = byId(aged.findings, "content.report_pass_rate")
    expect(passRate?.severity).toBe("info")
    expect(passRate?.title).toContain("No DMARC report data in the last")
    expect(passRate?.detail).toContain("never re-flagged")

    // The scored rows are gone rather than downgraded, and nothing is amber or red except the one
    // row that IS the live fault: reports stopped arriving.
    expect(byId(aged.findings, "content.report_spoofing")).toBeUndefined()
    expect(byId(aged.findings, "content.report_enforcement")).toBeUndefined()
    expect(byId(aged.findings, "content.report_fragility")).toBeUndefined()
    const amber = aged.findings.filter(
      (f) => f.severity === "warning" || f.severity === "critical",
    )
    expect(amber.map((f) => f.id)).toEqual(["content.report_freshness"])
  })

  it("never surfaces act3ai.com's problems on another monitored domain (§13.4 / AC 16)", async () => {
    const other = (await reportEmailsCheck.run(ctxFor(OTHER))) as CheckOutcome
    const snapshot = other.results as Record<string, any>
    expect(snapshot.attribution.this_domain).toBe(0)
    expect(snapshot.attribution.other_domains).toEqual({ "act3ai.com": 74 })
    expect(snapshot.attribution.orphans).toEqual([])

    const findings = other.findings
    expect(byId(findings, "content.report_pass_rate")?.severity).toBe("info")
    expect(byId(findings, "content.report_pass_rate")?.title).toContain("No DMARC")
    expect(byId(findings, "content.report_tls")?.title).toContain("No TLS-RPT")
    // No fragility/spoofing/enforcement rows can fire without reports for this domain.
    expect(byId(findings, "content.report_fragility")).toBeUndefined()
    expect(byId(findings, "content.report_spoofing")).toBeUndefined()
    expect(byId(findings, "content.report_enforcement")).toBeUndefined()
  })
})
