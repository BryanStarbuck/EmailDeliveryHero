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

import type { CheckOutcome, Finding } from "../types"
import { reportEmailsCheck, resolveAnalyzeDir } from "./report-emails.check"

const CORPUS_DIR = join(__dirname, "..", "..", "..", "..", "..", "..", "..", "..", "emails")
const hasCorpus = existsSync(CORPUS_DIR)
const describeCorpus = hasCorpus ? describe : describe.skip

const ACT3 = { id: "d-act3", name: "act3ai.com" }
const OTHER = { id: "d-other", name: "example.com" }

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

describeCorpus("content.report_emails — the act3ai.com corpus (pm/emails.mdx §13.4)", () => {
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

    const passRate = byId(findings, "content.report_pass_rate")
    expect(passRate?.severity).toBe("warning")

    // Four KDDI-reported messages fail both alignments and were rejected — that is spoofing the
    // policy stopped, so the check must SEE it (complaint C01, pm/Email_Complaints.mdx §7).
    expect(byId(findings, "content.report_spoofing")?.severity).not.toBe("ok")

    const fragility = byId(findings, "content.report_fragility")
    expect(fragility?.severity).toBe("warning")
    // Either alignment relaxation, depending on which mechanism the fragile stream leans on.
    expect(fragility?.remediation).toMatch(/a(spf|dkim)=r/)

    expect(byId(findings, "content.report_enforcement")).toBeDefined()
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
    // dmarc.* is the ROLLING-WINDOW view (default 7 days anchored on the newest report), not the
    // whole corpus — 71 reports are stored, far fewer fall inside the window.
    expect(snapshot.dmarc.reports).toBeGreaterThan(0)
    expect(snapshot.dmarc.reports).toBeLessThanOrEqual(71)
    expect(snapshot.dmarc.messages).toBeGreaterThan(0)
    expect(snapshot.dmarc.dual_aligned).toBeLessThanOrEqual(snapshot.dmarc.messages)
    expect(snapshot.dmarc.pass_rate_pct).toBeCloseTo(
      (snapshot.dmarc.dual_aligned / snapshot.dmarc.messages) * 100,
      0,
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
    // The analysis is unchanged — same pass-rate warning, same fragility.
    expect(byId(again.findings, "content.report_pass_rate")?.severity).toBe("warning")
    expect(byId(again.findings, "content.report_fragility")?.severity).toBe("warning")
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
