import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { updateAppConfig } from "@shared/config-store"
import type { CheckContext, Finding } from "../types"
import { inboxPlacementCheck } from "./inbox-placement.check"
import type { InboxPlacementTest, SeedPlacementResult } from "./placement"
import { canSendSeedTest, recordPlacementTest } from "./placement-store"

/**
 * pm/checks/inbox_placement.mdx — every sub-check in the family is FUTURE-round (spec §7); until a
 * seed-list integration is configured the whole family must report "not configured" and NEVER a
 * false ok or critical (acceptance criterion #1, spec §6). Once configured, recorded seed tests
 * are scored into the §2 finding set and the §5 results.inbox_placement payload.
 */

// Isolate the config + placement stores: state-dir reads EDH_STATE_DIR at call time.
const stateDir = mkdtempSync(join(tmpdir(), "edh-inbox-placement-"))
process.env.EDH_STATE_DIR = stateDir

afterAll(() => {
  rmSync(stateDir, { recursive: true, force: true })
  delete process.env.EDH_STATE_DIR
})

const ctx: CheckContext = {
  domain: "example.com",
  domainId: "dom-1",
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

const run = async (
  context: CheckContext = ctx,
): Promise<{ findings: Finding[]; results?: unknown }> => {
  const out = await inboxPlacementCheck.run(context)
  return Array.isArray(out) ? { findings: out } : { findings: out.findings, results: out.results }
}

const configure = (service: string): void => {
  updateAppConfig((c) => {
    c.seedList.service = service
  })
}

const seed = (
  provider: string,
  folder: SeedPlacementResult["folder"],
  extra: Partial<SeedPlacementResult> = {},
): SeedPlacementResult => ({
  provider,
  folder,
  gmailTab: null,
  spfPass: folder === "missing" ? null : true,
  dkimPass: folder === "missing" ? null : true,
  dmarcPass: folder === "missing" ? null : true,
  latencySecs: folder === "missing" ? null : 40,
  ...extra,
})

const makeTest = (
  results: SeedPlacementResult[],
  overrides: Partial<InboxPlacementTest> = {},
): InboxPlacementTest => ({
  id: overrides.id ?? "t-1",
  seedService: "glockapps",
  sampleId: null,
  testToken: overrides.testToken ?? "edh-token-1",
  sentAt: overrides.sentAt ?? "2026-06-01T10:00:00.000Z",
  settledAt: "2026-06-01T10:12:00.000Z",
  seedCount: results.length,
  deliveredCount: results.filter((r) => r.folder !== "missing").length,
  overallInbox: null,
  results,
  ...overrides,
})

describe("inboxPlacementCheck (not-configured first round)", () => {
  beforeEach(() => configure(""))

  it("emits only info findings — never a false ok, warning, or critical (criterion #1)", async () => {
    const { findings } = await run()
    expect(findings.length).toBeGreaterThan(0)
    for (const f of findings) expect(f.severity).toBe("info")
  })

  it("reports every spec §2 sub-check id as not configured, plus the family gate", async () => {
    const { findings } = await run()
    const ids = findings.map((f) => f.id)
    expect(ids).toContain("content.inbox_placement.pending")
    for (const id of SUBCHECK_IDS) expect(ids).toContain(id)
    // Exactly one finding per sub-check + the gate — no duplicates.
    expect(findings).toHaveLength(SUBCHECK_IDS.length + 1)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it("rolls into the Spam & Content cell via the content checkId prefix", async () => {
    const { findings } = await run()
    for (const f of findings) expect(f.checkId).toBe("content")
  })

  it("carries a concrete remediation on every finding (criterion #8 — never generic)", async () => {
    const { findings } = await run()
    for (const f of findings) {
      expect(f.remediation).toBeTruthy()
      expect(f.remediation).toMatch(/seed/i)
    }
  })

  it("persists configured:false so the UI renders the light-gray CTA state (criterion #11)", async () => {
    const { results } = await run()
    expect(results).toEqual({ configured: false })
  })

  it("refuses Send seed test now while unconfigured (the §6 feature gate)", () => {
    const gate = canSendSeedTest("dom-1")
    expect(gate.allowed).toBe(false)
    expect(gate.reason).toBe("not_configured")
  })
})

describe("inboxPlacementCheck (configured, no test recorded)", () => {
  beforeEach(() => configure("glockapps"))
  afterAll(() => configure(""))

  it("stays info-only and announces the awaiting-first-test state per sub-check", async () => {
    const { findings, results } = await run({ ...ctx, domainId: "dom-empty" })
    expect(findings).toHaveLength(SUBCHECK_IDS.length + 1)
    for (const f of findings) expect(f.severity).toBe("info")
    expect(findings[0].title).toMatch(/no seed test recorded/i)
    expect(results).toMatchObject({ configured: true, testCount: 0 })
  })
})

describe("inboxPlacementCheck (configured, recorded test scored)", () => {
  const domainId = "dom-scored"

  beforeAll(() => {
    configure("glockapps")
    // 8 Gmail (7 inbox + 1 Promotions tab), 2 Outlook all spam, 3 Yahoo inbox, 2 Apple inbox:
    // 12 of 15 delivered seeds inbox = exactly 80% overall.
    recordPlacementTest(
      domainId,
      makeTest([
        ...Array.from({ length: 7 }, () => seed("gmail", "inbox", { gmailTab: "primary" })),
        seed("gmail", "promotions", { gmailTab: "promotions" }),
        seed("outlook", "spam"),
        seed("outlook", "spam"),
        seed("yahoo", "inbox"),
        seed("yahoo", "inbox"),
        seed("yahoo", "inbox"),
        seed("apple", "inbox"),
        seed("apple", "inbox"),
      ]),
    )
  })
  afterAll(() => configure(""))

  it("scores the recorded test into real verdicts (criteria #3–#5)", async () => {
    const { findings } = await run({ ...ctx, domainId })
    const byId = new Map(findings.map((f) => [f.id, f]))
    // Overall: 8 of 10 delivered inboxed = 80% → ok, exact percentage in the detail (criterion #4).
    expect(byId.get("content.seedlist_overall")?.severity).toBe("ok")
    expect(byId.get("content.seedlist_overall")?.detail).toContain("80%")
    // Outlook majority Junk → critical, with the SNDS/JMRP remediation (criterion #5/#8).
    const outlook = byId.get("content.placement_outlook")
    expect(outlook?.severity).toBe("critical")
    expect(outlook?.remediation).toMatch(/SNDS/)
    // Gmail minority Promotions → the provider row stays ok; the tab sub-check warns.
    expect(byId.get("content.placement_gmail")?.severity).toBe("ok")
    expect(byId.get("content.seed_tab_placement")?.severity).toBe("warning")
    // Receiver auth all pass → ok on the aggregate and all three attribution slices.
    expect(byId.get("content.seed_auth_pass")?.severity).toBe("ok")
    expect(byId.get("content.seed_dmarc_receiver")?.severity).toBe("ok")
    // All four majors covered → coverage ok; nothing missing.
    expect(byId.get("content.seed_coverage")?.severity).toBe("ok")
    expect(byId.get("content.seed_missing")?.severity).toBe("ok")
  })

  it("persists the §5 results.inbox_placement payload (criterion #11)", async () => {
    const { results } = await run({ ...ctx, domainId })
    const payload = results as Record<string, unknown>
    expect(payload.configured).toBe(true)
    expect(payload.testToken).toBe("edh-token-1")
    expect(payload.seedCount).toBe(15)
    expect(payload.deliveredCount).toBe(15)
    expect(payload.overallInbox).toBe(80)
    expect(Array.isArray(payload.results)).toBe(true)
    expect((payload.results as unknown[]).length).toBe(15)
    expect(Array.isArray(payload.trend)).toBe(true)
  })

  it("debounces and budget-caps Send seed test now (criteria #2/#10)", () => {
    // A test was just recorded with sentAt 2026-06-01; "now" 5 minutes later → debounced.
    const soonAfter = new Date("2026-06-01T10:05:00.000Z")
    expect(canSendSeedTest(domainId, soonAfter)).toMatchObject({
      allowed: false,
      reason: "debounced",
    })
    // Well past the debounce but still inside the month with budget 4 → allowed.
    const laterSameMonth = new Date("2026-06-20T10:00:00.000Z")
    expect(canSendSeedTest(domainId, laterSameMonth).allowed).toBe(true)
    // Budget of 1 → the June send is spent → budget_exhausted.
    updateAppConfig((c) => {
      c.seedList.monthlyBudget = 1
    })
    expect(canSendSeedTest(domainId, laterSameMonth)).toMatchObject({
      allowed: false,
      reason: "budget_exhausted",
    })
    // A new calendar month resets the window.
    expect(canSendSeedTest(domainId, new Date("2026-07-20T10:00:00.000Z")).allowed).toBe(true)
    updateAppConfig((c) => {
      c.seedList.monthlyBudget = 4
    })
  })

  it("flags a placement regression against the previous test (criterion #13 seed_trend)", async () => {
    // Record a newer, much worse test: Gmail slides to spam.
    recordPlacementTest(
      domainId,
      makeTest(
        [
          seed("gmail", "spam"),
          seed("gmail", "spam"),
          seed("gmail", "spam"),
          seed("gmail", "inbox"),
          seed("outlook", "spam"),
          seed("outlook", "spam"),
          seed("yahoo", "inbox"),
          seed("yahoo", "inbox"),
          seed("apple", "inbox"),
          seed("apple", "inbox"),
        ],
        { id: "t-2", testToken: "edh-token-2", sentAt: "2026-06-08T10:00:00.000Z" },
      ),
    )
    const { findings } = await run({ ...ctx, domainId })
    const byId = new Map(findings.map((f) => [f.id, f]))
    expect(byId.get("content.placement_gmail")?.severity).toBe("critical")
    const trend = byId.get("content.seed_trend")
    expect(trend?.severity).toBe("warning")
    expect(trend?.detail).toContain("80%")
  })
})
