import type { BlacklistRunResults, ZoneResult } from "../blacklist/blacklist-types"
import * as store from "../blacklist/store"
import { blocklistHistory } from "./reputation-metrics.check"

/**
 * content.blocklist_history — the first-round DNSBL-recurrence trend (pm/checks/reputation_metrics.mdx
 * §2/§7, AC #7). Warns when the same DNSBL listed the domain/IP >= 2 times in the trailing window.
 */

const listing = (zone: string, name: string, target: string, listed = true): ZoneResult =>
  ({
    zone,
    name,
    tier: "high",
    kind: "ip",
    target,
    listed,
    return_code: listed ? "127.0.0.2" : null,
    sub_list: null,
    reason_txt: null,
    lookup_url: "",
    delist_url: "",
    severity: listed ? "critical" : null,
    inconclusive: false,
    refusal_code: null,
    query_ms: 1,
    problem_state: null,
    paid_delist_offered: false,
    auto_expires: null,
  }) as ZoneResult

const run = (ranAt: string, results: ZoneResult[]): BlacklistRunResults =>
  ({
    schema_version: 1,
    technology: "blacklists",
    domain: "example.com",
    audit_id: ranAt,
    ran_at: ranAt,
    results,
  }) as unknown as BlacklistRunResults

function mockRuns(runs: BlacklistRunResults[]): void {
  jest.spyOn(store, "readBlacklistRuns").mockReturnValue(runs)
}

afterEach(() => jest.restoreAllMocks())

describe("blocklistHistory", () => {
  const recent = () => new Date().toISOString()

  it("is info when there is no stored blacklist history", () => {
    mockRuns([])
    const f = blocklistHistory("example.com")
    expect(f.id).toBe("content.blocklist_history")
    expect(f.severity).toBe("info")
  })

  it("is ok when no zone recurs (one-off listing only)", () => {
    mockRuns([
      run(recent(), [listing("zen.spamhaus.org", "Spamhaus ZEN", "203.0.113.10")]),
      run(recent(), [listing("zen.spamhaus.org", "Spamhaus ZEN", "203.0.113.10", false)]),
    ])
    const f = blocklistHistory("example.com")
    expect(f.severity).toBe("ok")
  })

  it("warns when the same DNSBL lists the same target across >= 2 runs", () => {
    mockRuns([
      run(recent(), [listing("zen.spamhaus.org", "Spamhaus ZEN", "203.0.113.10")]),
      run(recent(), [listing("zen.spamhaus.org", "Spamhaus ZEN", "203.0.113.10")]),
    ])
    const f = blocklistHistory("example.com")
    expect(f.severity).toBe("warning")
    expect(f.remediation).toContain("root cause")
    expect(f.evidence).toContain("zen.spamhaus.org|203.0.113.10=2")
  })

  it("counts a (zone,target) at most once per run (dedupes within a run)", () => {
    // Same run lists the pair twice — must NOT count as a recurrence on its own.
    mockRuns([
      run(recent(), [
        listing("zen.spamhaus.org", "Spamhaus ZEN", "203.0.113.10"),
        listing("zen.spamhaus.org", "Spamhaus ZEN", "203.0.113.10"),
      ]),
    ])
    expect(blocklistHistory("example.com").severity).toBe("ok")
  })

  it("ignores runs older than the trailing window", () => {
    const old = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString()
    mockRuns([
      run(old, [listing("zen.spamhaus.org", "Spamhaus ZEN", "203.0.113.10")]),
      run(old, [listing("zen.spamhaus.org", "Spamhaus ZEN", "203.0.113.10")]),
    ])
    // Both recurrences are outside the 30-day window → no windowed runs → info.
    expect(blocklistHistory("example.com").severity).toBe("info")
  })
})
