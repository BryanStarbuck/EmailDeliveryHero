import type {
  BlacklistRunResults,
  BlocklistZone,
  PositiveReputation,
  ZoneResult,
} from "./blacklist-types"
import {
  buildQueryName,
  classifyAnswer,
  classifyZoneHealth,
  decodeDnswl,
  decodeSenderScore,
  detectProblemStates,
  diffRuns,
  reverseIpv4,
  spfLiteralIps,
  worstSeverity,
} from "./engine"
import { DEFAULT_ZONES, isDeadZone, loadZones } from "./zones"

function zone(overrides: Partial<BlocklistZone>): BlocklistZone {
  return {
    zone: "test.example",
    name: "Test zone",
    kind: "ip",
    tier: "high",
    weight: 1,
    lookup_url: "https://example.com",
    delist_url: "https://example.com",
    enabled: true,
    severity: "critical",
    ...overrides,
  }
}

function result(overrides: Partial<ZoneResult>): ZoneResult {
  return {
    zone: "test.example",
    name: "Test zone",
    tier: "high",
    kind: "ip",
    target: "203.0.113.24",
    listed: false,
    return_code: null,
    sub_list: null,
    reason_txt: null,
    lookup_url: "https://example.com",
    delist_url: "https://example.com",
    severity: null,
    inconclusive: false,
    refusal_code: null,
    query_ms: 10,
    problem_state: null,
    paid_delist_offered: false,
    auto_expires: null,
    ...overrides,
  }
}

const CLEAN_POSITIVE: PositiveReputation = {
  dnswl: { listed: true, category: "organization", trust: 2 },
  senderscore: { score: 90, severity: "info" },
  mailspike_rep: { code: null, label: null },
}

describe("buildQueryName", () => {
  it("reverses IPv4 octets for IP zones (spec §8 acceptance 1)", () => {
    expect(buildQueryName("203.0.113.24", zone({ zone: "zen.spamhaus.org" }))).toBe(
      "24.113.0.203.zen.spamhaus.org",
    )
  })

  it("queries domains directly with no reversal", () => {
    expect(buildQueryName("Example.COM", zone({ zone: "dbl.spamhaus.org", kind: "domain" }))).toBe(
      "example.com.dbl.spamhaus.org",
    )
  })

  it("returns null for a non-IPv4 target on an IP zone", () => {
    expect(buildQueryName("2001:db8::1", zone({}))).toBeNull()
    expect(reverseIpv4("300.1.1.1")).toBeNull()
  })
})

/** Look up a default-catalog zone; throws in-test when the catalog loses it. */
function catalogZone(host: string): BlocklistZone {
  const found = DEFAULT_ZONES.find((z) => z.zone === host)
  if (!found) throw new Error(`zone ${host} missing from DEFAULT_ZONES`)
  return found
}

describe("classifyAnswer", () => {
  const zen = catalogZone("zen.spamhaus.org")

  it("decodes a ZEN XBL listing to its sub-list and severity", () => {
    const c = classifyAnswer(zen, ["127.0.0.4"])
    expect(c.listed).toBe(true)
    expect(c.sub_list).toContain("XBL")
    expect(c.severity).toBe("critical")
    expect(c.problem_state).toBe("PS-2")
  })

  it("maps PBL codes to warning / PS-3", () => {
    const c = classifyAnswer(zen, ["127.0.0.10"])
    expect(c.severity).toBe("warning")
    expect(c.problem_state).toBe("PS-3")
  })

  it("treats Spamhaus 127.255.255.x as a refusal, never a listing (spec PS-9)", () => {
    const c = classifyAnswer(zen, ["127.255.255.254"])
    expect(c.listed).toBe(false)
    expect(c.refusal_code).toBe("127.255.255.254")
  })

  it("treats URIBL 127.0.0.1 (URIBL_BLOCKED) as a refusal", () => {
    const uribl = catalogZone("multi.uribl.com")
    const c = classifyAnswer(uribl, ["127.0.0.1"])
    expect(c.listed).toBe(false)
    expect(c.refusal_code).toBe("127.0.0.1")
  })

  it("decodes SURBL bitmask answers, combining bits", () => {
    const surbl = catalogZone("multi.surbl.org")
    const c = classifyAnswer(surbl, ["127.0.0.24"]) // 8 (PH) + 16 (MW)
    expect(c.listed).toBe(true)
    expect(c.sub_list).toContain("PH")
    expect(c.sub_list).toContain("MW")
    expect(c.severity).toBe("critical")
  })

  it("treats non-loopback answers as refusals (interception/wildcard)", () => {
    const c = classifyAnswer(zen, ["10.0.0.1"])
    expect(c.listed).toBe(false)
    expect(c.refusal_code).toBe("10.0.0.1")
  })

  it("falls back to the zone default for unmapped codes", () => {
    const c = classifyAnswer(zone({ severity: "warning" }), ["127.0.0.2"])
    expect(c.listed).toBe(true)
    expect(c.severity).toBe("warning")
  })

  it("returns not-listed for an empty answer", () => {
    expect(classifyAnswer(zen, []).listed).toBe(false)
  })
})

describe("classifyZoneHealth (RFC 5782, spec §8 acceptance 6)", () => {
  it("ok when 127.0.0.2 is listed and 127.0.0.1 is not", () => {
    const h = classifyZoneHealth({
      zone: "z",
      positiveAnswers: ["127.0.0.2"],
      negativeAnswers: [],
      probeMs: 40,
    })
    expect(h.status).toBe("ok")
  })

  it("wildcarding when 127.0.0.1 answers", () => {
    const h = classifyZoneHealth({
      zone: "z",
      positiveAnswers: ["127.0.0.2"],
      negativeAnswers: ["127.0.0.2"],
      probeMs: 40,
    })
    expect(h.status).toBe("wildcarding")
  })

  it("dead when the test point is silent", () => {
    const h = classifyZoneHealth({
      zone: "z",
      positiveAnswers: [],
      negativeAnswers: [],
      probeMs: 40,
    })
    expect(h.status).toBe("dead")
  })

  it("blocked when the probe answers with a refusal code", () => {
    const h = classifyZoneHealth({
      zone: "z",
      positiveAnswers: ["127.255.255.254"],
      negativeAnswers: [],
      probeMs: 40,
    })
    expect(h.status).toBe("blocked")
  })

  it("slow when the probe exceeds the threshold", () => {
    const h = classifyZoneHealth({
      zone: "z",
      positiveAnswers: ["127.0.0.2"],
      negativeAnswers: [],
      probeMs: 9000,
    })
    expect(h.status).toBe("slow")
  })
})

describe("decoders", () => {
  it("decodes DNSWL category and trust", () => {
    expect(decodeDnswl(["127.0.4.2"])).toEqual({ listed: true, category: "organization", trust: 2 })
    expect(decodeDnswl([]).listed).toBe(false)
  })

  it("decodes Sender Score and flags <70 as warning", () => {
    expect(decodeSenderScore(["127.0.4.84"])).toEqual({ score: 84, severity: "info" })
    expect(decodeSenderScore(["127.0.4.42"]).severity).toBe("warning")
    expect(decodeSenderScore([]).score).toBeNull()
  })
})

describe("detectProblemStates (spec §16)", () => {
  const base = { zoneHealth: [], zones: DEFAULT_ZONES }

  it("PS-0 when everything is clean and reputation is established", () => {
    const states = detectProblemStates({ ...base, results: [result({})], positive: CLEAN_POSITIVE })
    expect(states).toEqual(["PS-0"])
  })

  it("PS-12 when clean but nothing vouches for the sender", () => {
    const states = detectProblemStates({
      ...base,
      results: [result({})],
      positive: {
        dnswl: { listed: false, category: null, trust: null },
        senderscore: { score: null, severity: "info" },
        mailspike_rep: { code: null, label: null },
      },
    })
    expect(states).toContain("PS-12")
  })

  it("maps listings through their code-map problem states", () => {
    const states = detectProblemStates({
      ...base,
      results: [result({ listed: true, severity: "critical", problem_state: "PS-2" })],
      positive: CLEAN_POSITIVE,
    })
    expect(states).toEqual(["PS-2"])
  })

  it("PS-9 on refusals and PS-10 on dead zones", () => {
    const states = detectProblemStates({
      results: [result({ refusal_code: "127.255.255.254", inconclusive: true })],
      zoneHealth: [
        {
          zone: "dead.example",
          status: "dead",
          positive_probe: "NXDOMAIN",
          negative_probe: "NXDOMAIN",
          probe_ms: 5,
        },
      ],
      positive: CLEAN_POSITIVE,
      zones: DEFAULT_ZONES,
    })
    expect(states).toContain("PS-9")
    expect(states).toContain("PS-10")
  })

  it("PS-13 when the ONLY real listings are on pay-to-delist operators", () => {
    const onlyPaid = detectProblemStates({
      ...base,
      results: [
        result({
          zone: "dnsbl-1.uceprotect.net",
          listed: true,
          severity: "warning",
          paid_delist_offered: true,
          auto_expires: "7 days",
        }),
      ],
      positive: CLEAN_POSITIVE,
    })
    expect(onlyPaid).toContain("PS-13")

    const withReal = detectProblemStates({
      ...base,
      results: [
        result({
          zone: "dnsbl-1.uceprotect.net",
          listed: true,
          severity: "warning",
          paid_delist_offered: true,
        }),
        result({ listed: true, severity: "critical", problem_state: "PS-2" }),
      ],
      positive: CLEAN_POSITIVE,
    })
    expect(withReal).not.toContain("PS-13")
  })

  it("PS-6 for allocation/ASN collateral zones", () => {
    const states = detectProblemStates({
      ...base,
      results: [
        result({
          zone: "dnsbl-2.uceprotect.net",
          listed: true,
          severity: "info",
          paid_delist_offered: true,
        }),
      ],
      positive: CLEAN_POSITIVE,
    })
    expect(states).toContain("PS-6")
  })
})

describe("diffRuns (spec §8 acceptance 9)", () => {
  function runWith(results: ZoneResult[]): BlacklistRunResults {
    return {
      schema_version: 1,
      technology: "blacklists",
      domain: "example.com",
      audit_id: "prev",
      ran_at: "2026-01-01T00:00:00Z",
      duration_ms: 1,
      resolver: { mode: "system", server: null, refusals_detected: false },
      targets: { ips: [], domains: [] },
      zone_health: [],
      results,
      positive_reputation: CLEAN_POSITIVE,
      provider_portals: [],
      summary: {
        zones_enabled: 0,
        pairs_queried: results.length,
        listed: 0,
        clean: 0,
        inconclusive: 0,
        dead_zones_skipped: 0,
        worst_severity: "ok",
        problem_states: [],
      },
      diff: { new_listings: [], cleared: [], escalated: [], first_run: true },
    }
  }

  it("flags first_run with no previous data", () => {
    expect(diffRuns(null, [result({})]).first_run).toBe(true)
  })

  it("flags clean→listed as new and listed→clean as cleared", () => {
    const prev = runWith([
      result({ zone: "a", listed: false }),
      result({ zone: "b", listed: true, severity: "warning" }),
    ])
    const diff = diffRuns(prev, [
      result({ zone: "a", listed: true, severity: "critical", sub_list: "XBL" }),
      result({ zone: "b", listed: false }),
    ])
    expect(diff.new_listings).toEqual([{ zone: "a", target: "203.0.113.24", sub_list: "XBL" }])
    expect(diff.cleared).toHaveLength(1)
    expect(diff.cleared[0].zone).toBe("b")
  })

  it("flags warning→critical as escalated", () => {
    const prev = runWith([result({ zone: "a", listed: true, severity: "warning" })])
    const diff = diffRuns(prev, [result({ zone: "a", listed: true, severity: "critical" })])
    expect(diff.escalated).toEqual([
      { zone: "a", target: "203.0.113.24", from: "warning", to: "critical" },
    ])
  })

  it("ignores inconclusive transitions (no resolver-blockage false alarms)", () => {
    const prev = runWith([
      result({ zone: "a", listed: false, inconclusive: true, refusal_code: "127.0.0.1" }),
    ])
    const diff = diffRuns(prev, [result({ zone: "a", listed: true, severity: "critical" })])
    expect(diff.new_listings).toHaveLength(0)
  })
})

describe("zone catalog", () => {
  it("hard-blocks dead zones including every SORBS sub-zone (spec §9.5)", () => {
    expect(isDeadZone("dnsbl.sorbs.net")).toBe(true)
    expect(isDeadZone("spam.dnsbl.sorbs.net")).toBe(true)
    expect(isDeadZone("ix.dnsbl.manitu.net")).toBe(true)
    expect(isDeadZone("cbl.abuseat.org")).toBe(true)
    expect(isDeadZone("zen.spamhaus.org")).toBe(false)
  })

  it("ships no dead zone in the default catalog and loadZones filters them", () => {
    expect(DEFAULT_ZONES.some((z) => isDeadZone(z.zone))).toBe(false)
    expect(loadZones().some((z) => isDeadZone(z.zone))).toBe(false)
  })

  it("worstSeverity ranks correctly", () => {
    expect(worstSeverity(["info", "critical", "warning"])).toBe("critical")
    expect(worstSeverity([null, undefined])).toBe("ok")
  })

  it("extracts single-host ip4 literals from SPF", () => {
    expect(
      spfLiteralIps("v=spf1 ip4:203.0.113.24 ip4:198.51.100.0/24 include:_spf.google.com ~all"),
    ).toEqual(["203.0.113.24"])
  })
})
