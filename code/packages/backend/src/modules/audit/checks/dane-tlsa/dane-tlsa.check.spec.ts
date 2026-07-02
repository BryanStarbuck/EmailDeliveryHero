import type { DigAnswer } from "../dns-util"
import { parseDigAnswer } from "../dns-util"
import type { DnssecResults } from "../dnssec/dnssec.check"
import {
  analyzeHost,
  domainZonePrereqFindings,
  type HostObservation,
  isNoDaneProviderMx,
  parseTlsa,
} from "./dane-tlsa.check"

const SHA256 = "a".repeat(64)
const SHA512 = "b".repeat(128)

/** Build a TLSA answer RR the way `digAnswer` returns them. */
const rr = (rdata: string, ttl = 3600): DigAnswer => ({
  name: "_25._tcp.mail.example.com",
  ttl,
  type: "TLSA",
  rdata,
})

const observe = (over: Partial<HostObservation> = {}): HostObservation => ({
  host: "mail.example.com",
  priority: 10,
  canonical: "mail.example.com",
  cnamed: false,
  tlsa: { records: [] },
  dnssec: { signed: true, error: false },
  checkedAt: "2026-07-01T12:00:00Z",
  ...over,
})

const byPrefix = <T extends { id: string }>(findings: T[], prefix: string): T[] =>
  findings.filter((f) => f.id.startsWith(prefix))

describe("parseDigAnswer", () => {
  it("parses owner, ttl and rdata from a full-answer line", () => {
    const out = parseDigAnswer(
      `;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n_25._tcp.mail.example.com. 3600 IN TLSA 3 1 1 ${SHA256}\n`,
      "TLSA",
    )
    expect(out).toEqual([
      {
        name: "_25._tcp.mail.example.com",
        ttl: 3600,
        type: "TLSA",
        rdata: `3 1 1 ${SHA256}`,
      },
    ])
  })

  it("skips CNAME-chase lines and comments", () => {
    const out = parseDigAnswer(
      `mx.example.com. 300 IN CNAME mail.example.com.\n_25._tcp.mail.example.com. 60 IN TLSA 3 1 1 ${SHA256}\n`,
      "TLSA",
    )
    expect(out).toHaveLength(1)
    expect(out[0].ttl).toBe(60)
  })
})

describe("parseTlsa", () => {
  it("parses usage/selector/mtype/data and carries the TTL", () => {
    const [t] = parseTlsa([rr(`3 1 1 ${SHA256}`, 1800)])
    expect(t).toMatchObject({ usage: 3, selector: 1, mtype: 1, data: SHA256, ttl: 1800 })
  })

  it("joins dig's space-chunked digest and lower-cases it", () => {
    const upper = SHA256.toUpperCase()
    const [t] = parseTlsa([rr(`3 1 1 ${upper.slice(0, 32)} ${upper.slice(32)}`)])
    expect(t.data).toBe(SHA256)
  })

  it("drops non-numeric garbage rows", () => {
    expect(parseTlsa([rr("not a tlsa record")])).toHaveLength(0)
  })
})

describe("analyzeHost", () => {
  it("healthy 3 1 1 x2 on a signed zone: only ok findings and a fully-populated row (AC2)", () => {
    const { findings, row, summary } = analyzeHost(
      observe({ tlsa: { records: [rr(`3 1 1 ${SHA256}`), rr(`3 1 1 ${"c".repeat(64)}`)] } }),
    )
    expect(findings.every((f) => f.severity === "ok")).toBe(true)
    expect(summary.usableDane).toBe(true)
    expect(row).toEqual({
      mxHost: "mail.example.com",
      mxPreference: 10,
      tlsaName: "_25._tcp.mail.example.com",
      cnameChain: null,
      rawAnswer: [
        `_25._tcp.mail.example.com. 3600 IN TLSA 3 1 1 ${SHA256}`,
        `_25._tcp.mail.example.com. 3600 IN TLSA 3 1 1 ${"c".repeat(64)}`,
      ],
      dnssecSigned: true,
      rrsigObserved: false,
      tlsaPresent: true,
      tlsaRecords: [
        { usage: 3, selector: 1, mtype: 1, data: SHA256, ttl: 3600 },
        { usage: 3, selector: 1, mtype: 1, data: "c".repeat(64), ttl: 3600 },
      ],
      paramsOk: true,
      recommended311: true,
      certMatch: null,
      rolloverReady: true,
      starttlsOffered: null,
      probeError: null,
      checkedAt: "2026-07-01T12:00:00Z",
    })
  })

  it("persists the §11 explainer fields: tlsaName, cnameChain, rawAnswer, rrsigObserved", () => {
    const { row } = analyzeHost(
      observe({
        cnamed: true,
        canonical: "mx.other.net",
        cnameChain: ["mail.example.com", "mx.other.net"],
        tlsa: { records: [rr(`3 1 1 ${SHA256}`)] },
        rrsigObserved: true,
      }),
    )
    expect(row.tlsaName).toBe("_25._tcp.mx.other.net")
    expect(row.cnameChain).toEqual(["mail.example.com", "mx.other.net"])
    expect(row.rawAnswer).toEqual([`_25._tcp.mail.example.com. 3600 IN TLSA 3 1 1 ${SHA256}`])
    expect(row.rrsigObserved).toBe(true)
  })

  it("a failed lookup still records tlsaName and an empty rawAnswer (spec §11)", () => {
    const { row } = analyzeHost(observe({ tlsa: { records: [], error: "SERVFAIL" } }))
    expect(row.tlsaName).toBe("_25._tcp.mail.example.com")
    expect(row.rawAnswer).toEqual([])
    expect(row.cnameChain).toBeNull()
    expect(row.rrsigObserved).toBe(false)
  })

  it("TLSA on an unsigned zone is critical dane_without_dnssec (AC3)", () => {
    const { findings } = analyzeHost(
      observe({
        tlsa: { records: [rr(`3 1 1 ${SHA256}`)] },
        dnssec: { signed: false, error: false },
      }),
    )
    const f = byPrefix(findings, "infra.dane_without_dnssec")[0]
    expect(f.severity).toBe("critical")
    expect(f.remediation).toContain("DS record")
  })

  it("usage 0/1 (PKIX) is a critical params finding (AC4)", () => {
    const { findings } = analyzeHost(observe({ tlsa: { records: [rr(`1 1 1 ${SHA256}`)] } }))
    const f = byPrefix(findings, "infra.dane_tlsa_params")[0]
    expect(f.severity).toBe("critical")
    expect(f.remediation).toContain("3 1 1")
  })

  it("usable-but-not-recommended params (2 1 2) is info", () => {
    const { findings } = analyzeHost(observe({ tlsa: { records: [rr(`2 1 2 ${SHA512}`)] } }))
    expect(byPrefix(findings, "infra.dane_tlsa_params")[0].severity).toBe("info")
    expect(byPrefix(findings, "infra.dane_digest_length")).toHaveLength(0)
  })

  it("a wrong-length digest for the matching type is critical (AC7)", () => {
    const { findings } = analyzeHost(
      observe({ tlsa: { records: [rr(`3 1 1 ${"a".repeat(40)}`)] } }),
    )
    const f = byPrefix(findings, "infra.dane_digest_length")[0]
    expect(f.severity).toBe("critical")
    expect(f.remediation).toContain("64 hex")
  })

  it("exactly one TLSA record is a rollover warning (AC6) and rolloverReady=false", () => {
    const { findings, row } = analyzeHost(observe({ tlsa: { records: [rr(`3 1 1 ${SHA256}`)] } }))
    const f = byPrefix(findings, "infra.dane_rollover")[0]
    expect(f.severity).toBe("warning")
    expect(f.remediation).toContain("BEFORE renewing")
    expect(row.rolloverReady).toBe(false)
  })

  it("evaluates TTL sanity from the RR TTL: >24h is a warning, ≤1h is ok", () => {
    const long = analyzeHost(observe({ tlsa: { records: [rr(`3 1 1 ${SHA256}`, 172800)] } }))
    expect(byPrefix(long.findings, "infra.dane_ttl_sane")[0].severity).toBe("warning")
    const sane = analyzeHost(observe({ tlsa: { records: [rr(`3 1 1 ${SHA256}`, 300)] } }))
    expect(byPrefix(sane.findings, "infra.dane_ttl_sane")[0].severity).toBe("ok")
    const zero = analyzeHost(observe({ tlsa: { records: [rr(`3 1 1 ${SHA256}`, 0)] } }))
    expect(byPrefix(zero.findings, "infra.dane_ttl_sane")[0].severity).toBe("warning")
  })

  it("SERVFAIL on a signed zone is a critical validation error with probeError set (AC10)", () => {
    const { findings, row, summary } = analyzeHost(
      observe({ tlsa: { records: [], error: "SERVFAIL" } }),
    )
    const f = byPrefix(findings, "infra.dane_tlsa_present")[0]
    expect(f.severity).toBe("critical")
    expect(f.detail).toContain("validation failure")
    expect(row.probeError).toBe("SERVFAIL")
    expect(summary.lookupError).toBe(true)
  })

  it("a transient lookup error on an unsigned zone stays info, never a false critical", () => {
    const { findings } = analyzeHost(
      observe({
        tlsa: { records: [], error: "timeout" },
        dnssec: { signed: false, error: false },
      }),
    )
    expect(byPrefix(findings, "infra.dane_tlsa_present")[0].severity).toBe("info")
  })

  it("MX CNAME to an unsigned target is a critical name-alignment finding", () => {
    const { findings } = analyzeHost(
      observe({
        cnamed: true,
        canonical: "mx.other.net",
        tlsa: { records: [rr(`3 1 1 ${SHA256}`)] },
        dnssec: { signed: false, error: false },
      }),
    )
    const f = byPrefix(findings, "infra.dane_name_alignment")[0]
    expect(f.severity).toBe("critical")
  })

  it("no TLSA on an unsigned zone is only a warning (DANE impossible until signed)", () => {
    const { findings, row } = analyzeHost(observe({ dnssec: { signed: false, error: false } }))
    expect(byPrefix(findings, "infra.dane_dnssec_prereq")[0].severity).toBe("warning")
    expect(row.tlsaPresent).toBe(false)
    expect(row.paramsOk).toBeNull()
    expect(row.recommended311).toBeNull()
  })

  it("stays silent per host for a Google MX with no TLSA (provider does not support DANE)", () => {
    const { findings, row } = analyzeHost(
      observe({
        host: "aspmx.l.google.com",
        canonical: "aspmx.l.google.com",
        dnssec: { signed: false, error: false },
      }),
    )
    expect(findings).toHaveLength(0)
    expect(row.tlsaPresent).toBe(false)
  })

  it("warns when the admin-pinned expected next-cert digest is not staged (spec §4)", () => {
    const pin = "d".repeat(64)
    const { findings } = analyzeHost(
      observe({
        tlsa: { records: [rr(`3 1 1 ${SHA256}`), rr(`3 1 1 ${"c".repeat(64)}`)] },
        expectedNextSpki: pin,
      }),
    )
    const f = byPrefix(findings, "infra.dane_rollover.next_missing")[0]
    expect(f.severity).toBe("warning")
    // AC8: the remediation contains the exact record to publish, never a generic hint.
    expect(f.remediation).toContain(`3 1 1 ${pin}`)
    expect(f.remediation).toContain("_25._tcp.mail.example.com")
  })

  it("stays quiet when the pinned next-cert digest IS staged (case-insensitive)", () => {
    const pin = "C".repeat(64)
    const { findings } = analyzeHost(
      observe({
        tlsa: { records: [rr(`3 1 1 ${SHA256}`), rr(`3 1 1 ${"c".repeat(64)}`)] },
        expectedNextSpki: pin,
      }),
    )
    expect(byPrefix(findings, "infra.dane_rollover.next_missing")).toHaveLength(0)
    expect(findings.every((f) => f.severity === "ok")).toBe(true)
  })
})

describe("isNoDaneProviderMx", () => {
  it("matches Google MX hosts (trailing dot / case insensitive) but not lookalikes", () => {
    expect(isNoDaneProviderMx("aspmx.l.google.com")).toBe(true)
    expect(isNoDaneProviderMx("ALT1.ASPMX.L.GOOGLE.COM.")).toBe(true)
    expect(isNoDaneProviderMx("aspmx2.googlemail.com")).toBe(true)
    expect(isNoDaneProviderMx("notgoogle.com")).toBe(false)
    expect(isNoDaneProviderMx("mail.example.com")).toBe(false)
  })
})

describe("domainZonePrereqFindings", () => {
  const dnssec = (signed: boolean): DnssecResults => ({ signed }) as unknown as DnssecResults

  it("returns nothing without an upstream dnssec result (standalone run)", () => {
    expect(domainZonePrereqFindings("example.com", undefined, true)).toHaveLength(0)
  })

  it("TLSA present + unsigned domain zone is critical dane_without_dnssec (spec §2 row 1)", () => {
    const [f] = domainZonePrereqFindings("example.com", dnssec(false), true)
    expect(f.id).toBe("infra.dane_without_dnssec.domain_zone")
    expect(f.severity).toBe("critical")
    expect(f.remediation).toContain("DS record")
  })

  it("no DANE + unsigned domain zone is a warning, never silent", () => {
    const [f] = domainZonePrereqFindings("example.com", dnssec(false), false)
    expect(f.id).toBe("infra.dane_dnssec_prereq.domain_zone")
    expect(f.severity).toBe("warning")
    expect(f.remediation).toContain("3 1 1")
  })

  it("suppresses the no-DANE domain-zone warning when all MX are a no-DANE provider (Google)", () => {
    expect(domainZonePrereqFindings("example.com", dnssec(false), false, true)).toHaveLength(0)
  })

  it("signed domain zone with TLSA present is ok (AC2: never turns the cell amber/red)", () => {
    const [f] = domainZonePrereqFindings("example.com", dnssec(true), true)
    expect(f.severity).toBe("ok")
  })
})
