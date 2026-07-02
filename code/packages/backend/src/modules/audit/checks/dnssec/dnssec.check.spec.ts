import type { DnssecResults } from "./dnssec.check"

jest.mock("../dns-util", () => ({ dig: jest.fn(), resolveSoa: jest.fn(), digDnssec: jest.fn() }))
jest.mock("@shared/config-store", () => ({ readAppConfig: jest.fn() }))

import { readAppConfig } from "@shared/config-store"
import { type DigDnssecResponse, dig, digDnssec, resolveSoa } from "../dns-util"
import type { CheckContext, CheckOutcome, Finding } from "../types"
import { dnssecCheck } from "./dnssec.check"

const mockDig = dig as jest.MockedFunction<typeof dig>
const mockResolveSoa = resolveSoa as jest.MockedFunction<typeof resolveSoa>
const mockDigDnssec = digDnssec as jest.MockedFunction<typeof digDnssec>
const mockReadAppConfig = readAppConfig as jest.MockedFunction<typeof readAppConfig>

/**
 * Recorded fixtures (deterministic — spec acceptance #4): the real cloudflare.com apex DNSKEY set
 * and its published DS, captured 2026-07-01. The SHA-256 digest below is exactly what
 * `dig +short DS cloudflare.com` returns and matches the KSK per RFC 4034 §5.1.4; the SHA-1
 * digest was recomputed locally from the same KSK for the deprecated-digest case.
 */
const DOMAIN = "cloudflare.com"
const ZSK_13 =
  "256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8 KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA=="
const KSK_13 =
  "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+ KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="
const DS_SHA256 = "2371 13 2 32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D6 3826F2B9"
const DS_SHA1 = "2371 13 1 6CA5BC6A1277B9FE65FEF4DD3363448FB129B388"
const DS_MISMATCH = "9999 13 2 32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D63826F2BA"

/** A synthetic RSASHA1-NSEC3-SHA1 (alg 7) KSK: RFC 3110 key = [expLen=3][65537][modulus]. */
function rsaDnskey(flags: number, alg: number, modulusBytes: number): string {
  const key = Buffer.concat([Buffer.from([3, 1, 0, 1]), Buffer.alloc(modulusBytes, 0xab)]).toString(
    "base64",
  )
  return `${flags} 3 ${alg} ${key}`
}

const ctx = (): CheckContext => ({ domain: DOMAIN, dkimSelectors: [], sendingIps: [] })

/** Route mocked dig answers by record type. */
function dnsAnswers(map: Record<string, { records?: string[]; empty?: boolean; error?: string }>) {
  mockDig.mockImplementation(async (_name: string, type: string) => {
    const a = map[type]
    if (!a) return { records: [], empty: true }
    return { records: a.records ?? [], empty: a.empty ?? false, error: a.error }
  })
}

async function run(): Promise<{ findings: Finding[]; results: DnssecResults | undefined }> {
  const outcome = (await dnssecCheck.run(ctx())) as CheckOutcome
  return { findings: outcome.findings, results: outcome.results as DnssecResults | undefined }
}

const byId = (findings: Finding[], id: string) => findings.find((f) => f.id === id)
const byCheckId = (findings: Finding[], checkId: string) =>
  findings.filter((f) => f.checkId === checkId)

/** Route mocked digDnssec responses by `<TYPE>:<cd|nocd>` (default: empty NOERROR). */
function deepAnswers(map: Record<string, Partial<DigDnssecResponse>>) {
  mockDigDnssec.mockImplementation(async (_name, type, opts = {}) => {
    const a = map[`${type}:${opts.cd ? "cd" : "nocd"}`]
    return {
      status: a?.status ?? "NOERROR",
      adFlag: a?.adFlag ?? false,
      answers: a?.answers ?? [],
      ...(a?.error !== undefined ? { error: a.error } : {}),
    }
  })
}

/** Enable the deep `validateViaDig` path via the mocked config (pm/checks/dnssec.mdx §4). */
function enableDeep(overrides: Record<string, unknown> = {}) {
  mockReadAppConfig.mockReturnValue({
    checks: {
      dnssec: {
        resolvers: ["1.1.1.1"],
        rrsigLeadHours: 72,
        validateViaDig: true,
        algorithms: [],
        ...overrides,
      },
    },
  } as unknown as ReturnType<typeof readAppConfig>)
}

/** A DigAnswer row for the mocked +dnssec responses. */
function rr(type: string, rdata: string) {
  return { name: DOMAIN, ttl: 3600, type, rdata }
}

/** An RRSIG rdata covering `covered`, expiring at `exp` (YYYYMMDDHHMMSS). */
function rrsig(covered: string, exp: string, keyTag = 2371) {
  return rr("RRSIG", `${covered} 13 2 3600 ${exp} 20190101000000 ${keyTag} ${DOMAIN}. c2ln`)
}

/** Format a Date as the RRSIG presentation timestamp YYYYMMDDHHMMSS (UTC). */
function ts(d: Date): string {
  return d.toISOString().replace(/[-:T]/g, "").slice(0, 14)
}

beforeEach(() => {
  mockDig.mockReset()
  mockResolveSoa.mockReset()
  mockDigDnssec.mockReset()
  mockReadAppConfig.mockReset()
  // Default: no config file → built-in defaults (validateViaDig OFF, presence-only round).
  mockReadAppConfig.mockImplementation(() => {
    throw new Error("no config in unit tests")
  })
  mockResolveSoa.mockResolvedValue({
    record: {
      nsname: "ns1.cloudflare.com",
      hostmaster: "dns.cloudflare.com",
      serial: 1,
      refresh: 1,
      retry: 1,
      expire: 1,
      minttl: 1,
    },
    empty: false,
  })
})

describe("dnssecCheck (pm/checks/dnssec.mdx)", () => {
  it("registers as 'infra.dnssec' with a label and namespaces every finding infra.dnssec_*", async () => {
    expect(dnssecCheck.id).toBe("infra.dnssec")
    expect(dnssecCheck.label).toBeTruthy()
    dnsAnswers({ DNSKEY: { records: [KSK_13, ZSK_13] }, DS: { records: [DS_SHA256] } })
    const { findings } = await run()
    expect(findings.length).toBeGreaterThan(0)
    for (const f of findings) expect(f.checkId).toMatch(/^infra\.dnssec_/)
  })

  it("unsigned zone → exactly ONE info finding naming the DNS provider/registrar (acceptance #2)", async () => {
    dnsAnswers({ DNSKEY: { empty: true } })
    const { findings, results } = await run()
    expect(findings).toHaveLength(1)
    expect(findings[0].checkId).toBe("infra.dnssec_signed")
    expect(findings[0].severity).toBe("info")
    expect(findings[0].remediation).toMatch(/DNS provider|registrar/i)
    expect(results?.signed).toBe(false)
    expect(results?.dane_ready).toBe(false)
  })

  it("signed zone with no DS at the parent → warning telling the operator to publish the DS (acceptance #3)", async () => {
    dnsAnswers({ DNSKEY: { records: [KSK_13, ZSK_13] }, DS: { empty: true } })
    const { findings, results } = await run()
    const f = byId(findings, "infra.dnssec_ds_present.missing")
    expect(f?.severity).toBe("warning")
    expect(f?.remediation).toMatch(/registrar/i)
    expect(results?.ds_present).toBe(false)
    expect(results?.dsPresent).toBe(false)
    expect(results?.dane_ready).toBe(false)
  })

  it("matching SHA-256 DS → ds_present ok + ds_algo_match ok; DANE-ready (acceptance #9, #13)", async () => {
    dnsAnswers({ DNSKEY: { records: [KSK_13, ZSK_13] }, DS: { records: [DS_SHA256] } })
    const { findings, results } = await run()
    expect(byId(findings, "infra.dnssec_ds_present.ok")?.severity).toBe("ok")
    expect(byId(findings, "infra.dnssec_ds_algo_match.ok")?.severity).toBe("ok")
    expect(results?.ds_matches_dnskey).toBe(true)
    expect(results?.dsAlgoMatch).toBe(true)
    expect(results?.dsDigestType).toBe(2)
    expect(results?.dane_ready).toBe(true)
  })

  it("DS matching only via SHA-1 (digest type 1) → warning (acceptance #9)", async () => {
    dnsAnswers({ DNSKEY: { records: [KSK_13, ZSK_13] }, DS: { records: [DS_SHA1] } })
    const { findings, results } = await run()
    const f = byId(findings, "infra.dnssec_ds_algo_match.sha1")
    expect(f?.severity).toBe("warning")
    expect(f?.remediation).toMatch(/SHA-256/i)
    expect(results?.dsDigestType).toBe(1)
  })

  it("no published DS matches any live DNSKEY → critical broken chain (acceptance #9)", async () => {
    dnsAnswers({ DNSKEY: { records: [KSK_13, ZSK_13] }, DS: { records: [DS_MISMATCH] } })
    const { findings, results } = await run()
    const f = byId(findings, "infra.dnssec_ds_algo_match.mismatch")
    expect(f?.severity).toBe("critical")
    expect(f?.remediation).toMatch(/republish the DS/i)
    expect(results?.ds_matches_dnskey).toBe(false)
    expect(results?.dsAlgoMatch).toBe(false)
  })

  it("algorithm 13 passes; algorithm 7 (RSASHA1-NSEC3-SHA1) is flagged warning (acceptance #8)", async () => {
    dnsAnswers({ DNSKEY: { records: [KSK_13, ZSK_13] }, DS: { records: [DS_SHA256] } })
    expect(byId((await run()).findings, "infra.dnssec_algorithm.ok")?.severity).toBe("ok")

    dnsAnswers({ DNSKEY: { records: [rsaDnskey(257, 7, 256)] }, DS: { empty: true } })
    const deprecated = byId((await run()).findings, "infra.dnssec_algorithm.deprecated")
    expect(deprecated?.severity).toBe("warning")
    expect(deprecated?.remediation).toMatch(/ECDSAP256SHA256/)
  })

  it("undersized RSA KSK (< 2048 bits) → key_rollover warning (spec §2 advisory)", async () => {
    dnsAnswers({ DNSKEY: { records: [rsaDnskey(257, 8, 128)] }, DS: { empty: true } })
    const { findings } = await run()
    expect(byId(findings, "infra.dnssec_key_rollover.weak")?.severity).toBe("warning")
  })

  it("validation-dependent sub-checks degrade to info only — never a false critical (acceptance #5)", async () => {
    dnsAnswers({ DNSKEY: { records: [KSK_13, ZSK_13] }, DS: { records: [DS_SHA256] } })
    const { findings } = await run()
    for (const checkId of [
      "infra.dnssec_validates",
      "infra.dnssec_rrsig_expiry",
      "infra.dnssec_nsec3",
      "infra.dnssec_chain_complete",
    ]) {
      const fs = byCheckId(findings, checkId)
      expect(fs.length).toBeGreaterThan(0)
      for (const f of fs) expect(f.severity).toBe("info")
    }
  })

  it("writes the dnssec_check_results-shaped object with the documented field names (acceptance #11)", async () => {
    dnsAnswers({ DNSKEY: { records: [KSK_13, ZSK_13] }, DS: { records: [DS_SHA256] } })
    const { results } = await run()
    expect(results).toMatchObject({
      signed: true,
      dsPresent: true,
      validates: null,
      bogus: false,
      dsDigestType: 2,
      dsAlgoMatch: true,
      nsec3: false,
      nsec3Iterations: null,
      nsec3Optout: null,
      rrsigEarliestExpiry: null,
      resolverUsed: null,
    })
    expect(results?.dnskeyAlgos).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ keyTag: 2371, flags: 257, alg: 13, algName: "ECDSAP256SHA256" }),
      ]),
    )
    expect(typeof results?.checkedAt).toBe("string")
  })

  it("transient DNSKEY lookup failure → one info 'unavailable' finding and NO results snapshot", async () => {
    dnsAnswers({ DNSKEY: { error: "timeout" } })
    const outcome = (await dnssecCheck.run(ctx())) as CheckOutcome
    expect(outcome.findings).toHaveLength(1)
    expect(outcome.findings[0].severity).toBe("info")
    expect(outcome.findings[0].checkId).toBe("infra.dnssec_signed")
    expect(outcome.results).toBeUndefined()
  })

  describe("deep validateViaDig path (spec §3 FUTURE, acceptance #5–#7)", () => {
    const FRESH = ts(new Date(Date.now() + 30 * 24 * 3_600_000))
    const NEAR = ts(new Date(Date.now() + 24 * 3_600_000))
    const EXPIRED = "20200101000000"
    const DNSKEY_CD = {
      answers: [rr("DNSKEY", KSK_13), rr("DNSKEY", ZSK_13), rrsig("DNSKEY", FRESH)],
    }

    beforeEach(() => {
      dnsAnswers({ DNSKEY: { records: [KSK_13, ZSK_13] }, DS: { records: [DS_SHA256] } })
    })

    it("AD=1 → validates ok; fresh RRSIGs ok; chain complete; DANE-ready (acceptance #13)", async () => {
      enableDeep()
      deepAnswers({
        "SOA:nocd": { status: "NOERROR", adFlag: true, answers: [rr("SOA", "ns1 host 1 1 1 1 1")] },
        "DNSKEY:cd": DNSKEY_CD,
        "SOA:cd": { answers: [rr("SOA", "ns1 host 1 1 1 1 1"), rrsig("SOA", FRESH)] },
      })
      const { findings, results } = await run()
      expect(byId(findings, "infra.dnssec_validates.ok")?.severity).toBe("ok")
      expect(byId(findings, "infra.dnssec_rrsig_expiry.ok")?.severity).toBe("ok")
      expect(byId(findings, "infra.dnssec_chain_complete.ok")?.severity).toBe("ok")
      expect(byId(findings, "infra.dnssec_dane_ready.ok")?.severity).toBe("ok")
      expect(results?.validates).toBe(true)
      expect(results?.bogus).toBe(false)
      expect(results?.resolverUsed).toBe("1.1.1.1")
      expect(results?.dane_ready).toBe(true)
      expect(typeof results?.rrsigEarliestExpiry).toBe("string")
    })

    it("SERVFAIL with CD=0 but success with CD=1 → bogus critical (acceptance #6)", async () => {
      enableDeep()
      deepAnswers({
        "SOA:nocd": { status: "SERVFAIL" },
        "SOA:cd": { status: "NOERROR", answers: [rr("SOA", "ns1 host 1 1 1 1 1")] },
        "DNSKEY:cd": DNSKEY_CD,
      })
      const { findings, results } = await run()
      const f = byId(findings, "infra.dnssec_validates.bogus")
      expect(f?.severity).toBe("critical")
      expect(f?.remediation).toMatch(/re-sign|DS/i)
      expect(results?.validates).toBe(false)
      expect(results?.bogus).toBe(true)
    })

    it("SERVFAIL with BOTH CD=0 and CD=1 → ordinary outage, info only — never bogus (acceptance #6)", async () => {
      enableDeep()
      deepAnswers({
        "SOA:nocd": { status: "SERVFAIL" },
        "SOA:cd": { status: "SERVFAIL" },
        "DNSKEY:cd": DNSKEY_CD,
      })
      const { findings, results } = await run()
      expect(byId(findings, "infra.dnssec_validates.bogus")).toBeUndefined()
      const fs = byCheckId(findings, "infra.dnssec_validates")
      expect(fs).toHaveLength(1)
      expect(fs[0].severity).toBe("info")
      expect(results?.bogus).toBe(false)
    })

    it("expired apex RRSIG → critical; within the 72h lead time → warning (acceptance #7)", async () => {
      enableDeep()
      deepAnswers({
        "SOA:nocd": { status: "NOERROR", adFlag: true, answers: [rr("SOA", "x")] },
        "DNSKEY:cd": { answers: [rr("DNSKEY", KSK_13), rrsig("DNSKEY", EXPIRED)] },
      })
      expect(byId((await run()).findings, "infra.dnssec_rrsig_expiry.expired")?.severity).toBe(
        "critical",
      )

      deepAnswers({
        "SOA:nocd": { status: "NOERROR", adFlag: true, answers: [rr("SOA", "x")] },
        "DNSKEY:cd": { answers: [rr("DNSKEY", KSK_13), rrsig("DNSKEY", NEAR)] },
      })
      const { findings, results } = await run()
      expect(byId(findings, "infra.dnssec_rrsig_expiry.near")?.severity).toBe("warning")
      expect(results?.rrsigEarliestExpiry).not.toBeNull()
    })

    it("NSEC3 iterations > 0 → warning per RFC 9276; params land in results", async () => {
      enableDeep()
      deepAnswers({
        "SOA:nocd": { status: "NOERROR", adFlag: true, answers: [rr("SOA", "x")] },
        "DNSKEY:cd": DNSKEY_CD,
        "NSEC3PARAM:cd": { answers: [rr("NSEC3PARAM", "1 0 5 AB12")] },
      })
      const { findings, results } = await run()
      expect(byId(findings, "infra.dnssec_nsec3.params")?.severity).toBe("warning")
      expect(results?.nsec3).toBe(true)
      expect(results?.nsec3Iterations).toBe(5)
      expect(results?.nsec3Optout).toBe(false)
    })

    it("all resolvers unreachable → every deep sub-check degrades to info, never critical (acceptance #5)", async () => {
      enableDeep()
      deepAnswers({
        "SOA:nocd": { error: "timeout" },
        "SOA:cd": { error: "timeout" },
        "DNSKEY:cd": { error: "timeout" },
        "NSEC3PARAM:cd": { error: "timeout" },
        "MX:cd": { error: "timeout" },
        "TXT:cd": { error: "timeout" },
      })
      const { findings, results } = await run()
      for (const checkId of [
        "infra.dnssec_validates",
        "infra.dnssec_rrsig_expiry",
        "infra.dnssec_nsec3",
        "infra.dnssec_soa_signed",
        "infra.dnssec_dane_ready",
      ]) {
        const fs = byCheckId(findings, checkId)
        expect(fs.length).toBeGreaterThan(0)
        for (const f of fs) expect(f.severity).toBe("info")
      }
      expect(results?.validates).toBeNull()
      expect(results?.bogus).toBe(false)
    })
  })
})
