import type { CheckContext, Finding } from "../types"
import { inboxPlacementCheck } from "./inbox-placement.check"

/**
 * pm/checks/inbox_placement.mdx — every sub-check in the family is FUTURE-round (spec §7); until a
 * seed-list integration is configured the whole family must report "not configured" and NEVER a
 * false ok or critical (acceptance criterion #1, spec §6).
 */

const ctx: CheckContext = {
  domain: "example.com",
  dkimSelectors: [],
  sendingIps: [],
}

/** The exact §2 sub-check ids the not-configured round must pre-announce, in table order. */
const SUBCHECK_IDS = [
  "content.seedlist_overall",
  "content.placement_gmail",
  "content.placement_outlook",
  "content.placement_yahoo",
  "content.placement_apple",
  "content.seed_auth_pass",
  "content.seed_tab_placement",
  "content.seed_missing",
  "content.seed_trend",
  "content.placement_longtail",
  "content.seed_delivery_latency",
  "content.seed_coverage",
  "content.seed_spf_receiver",
  "content.seed_dkim_receiver",
  "content.seed_dmarc_receiver",
]

const run = async (): Promise<Finding[]> => {
  const out = await inboxPlacementCheck.run(ctx)
  return Array.isArray(out) ? out : out.findings
}

describe("inboxPlacementCheck (not-configured first round)", () => {
  it("emits only info findings — never a false ok, warning, or critical (criterion #1)", async () => {
    const findings = await run()
    expect(findings.length).toBeGreaterThan(0)
    for (const f of findings) expect(f.severity).toBe("info")
  })

  it("reports every spec §2 sub-check id as not configured, plus the family gate", async () => {
    const findings = await run()
    const ids = findings.map((f) => f.id)
    expect(ids).toContain("content.inbox_placement.pending")
    for (const id of SUBCHECK_IDS) expect(ids).toContain(id)
    // Exactly one finding per sub-check + the gate — no duplicates.
    expect(findings).toHaveLength(SUBCHECK_IDS.length + 1)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it("rolls into the Spam & Content cell via the content checkId prefix", async () => {
    const findings = await run()
    for (const f of findings) expect(f.checkId).toBe("content")
  })

  it("carries a concrete remediation on every finding (criterion #8 — never generic)", async () => {
    const findings = await run()
    for (const f of findings) {
      expect(f.remediation).toBeTruthy()
      expect(f.remediation).toMatch(/seed/i)
    }
  })
})
