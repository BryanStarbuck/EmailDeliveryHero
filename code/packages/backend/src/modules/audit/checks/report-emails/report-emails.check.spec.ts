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
    expect(corpus?.detail).toContain("10 file(s) scanned")

    const attribution = byId(findings, "content.report_domain_attribution")
    expect(attribution?.severity).toBe("info") // all 10 → act3ai.com, no orphans

    const passRate = byId(findings, "content.report_pass_rate")
    expect(passRate?.severity).toBe("warning")
    expect(passRate?.title).toContain("96.8%")

    expect(byId(findings, "content.report_spoofing")?.severity).toBe("ok")

    const fragility = byId(findings, "content.report_fragility")
    expect(fragility?.severity).toBe("warning") // the SendGrid DKIM-only stream (§12)
    expect(fragility?.detail).toContain("em2598.act3ai.com")
    expect(fragility?.remediation).toContain("aspf=r")

    expect(byId(findings, "content.report_enforcement")?.severity).toBe("info")
    expect(byId(findings, "content.report_tls")?.severity).toBe("info")
  })

  it("writes the §13.3 snapshot (spam_content.report_emails)", () => {
    const snapshot = outcome.results as Record<string, any>
    expect(snapshot.dir).toBe(CORPUS_DIR)
    expect(snapshot.scanned_files).toBe(10)
    expect(snapshot.parsed_reports).toBe(10)
    expect(snapshot.duplicates).toBe(0) // first scan into a fresh store
    expect(snapshot.attribution.this_domain).toBe(10)
    expect(snapshot.attribution.other_domains).toEqual({})
    expect(snapshot.attribution.orphans).toEqual([])
    expect(snapshot.dmarc.reports).toBe(7)
    expect(snapshot.dmarc.messages).toBe(1195)
    expect(snapshot.dmarc.dual_aligned).toBe(1157)
    expect(snapshot.dmarc.pass_rate_pct).toBe(96.8)
    expect(snapshot.dmarc.both_fail).toBe(0)
    expect(snapshot.dmarc.quarantined).toBe(0)
    expect(snapshot.dmarc.rejected).toBe(0)
    expect(snapshot.dmarc.policy).toContain("p=reject")
    expect(snapshot.tlsrpt.reports).toBe(3)
    expect(snapshot.tlsrpt.sessions_ok).toBe(7)
    expect(snapshot.tlsrpt.sessions_failed).toBe(0)
  })

  it("is idempotent: a re-scan over the unchanged corpus counts 10 duplicates, 0 new (§4.5/AC 14)", async () => {
    const again = (await reportEmailsCheck.run(ctxFor(ACT3))) as CheckOutcome
    const snapshot = again.results as Record<string, any>
    expect(snapshot.parsed_reports).toBe(10)
    expect(snapshot.duplicates).toBe(10)
    // The analysis is unchanged — same pass-rate warning, same fragility.
    expect(byId(again.findings, "content.report_pass_rate")?.severity).toBe("warning")
    expect(byId(again.findings, "content.report_fragility")?.severity).toBe("warning")
  })

  it("never surfaces act3ai.com's problems on another monitored domain (§13.4 / AC 16)", async () => {
    const other = (await reportEmailsCheck.run(ctxFor(OTHER))) as CheckOutcome
    const snapshot = other.results as Record<string, any>
    expect(snapshot.attribution.this_domain).toBe(0)
    expect(snapshot.attribution.other_domains).toEqual({ "act3ai.com": 10 })
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
