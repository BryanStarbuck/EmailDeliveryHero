import { analyzeDmarcRecord, parseDmarcRecord, walkUpCandidates } from "./dmarc.check"

const ids = (a: ReturnType<typeof analyzeDmarcRecord>) => a.findings.map((f) => f.id)
const byId = (a: ReturnType<typeof analyzeDmarcRecord>, id: string) =>
  a.findings.find((f) => f.id === id)

describe("parseDmarcRecord", () => {
  it("tokenizes tag=value pairs, trimming and lower-casing names", () => {
    expect(parseDmarcRecord("v=DMARC1; P=reject ;rua=mailto:a@b.com")).toEqual([
      { name: "v", value: "DMARC1" },
      { name: "p", value: "reject" },
      { name: "rua", value: "mailto:a@b.com" },
    ])
  })

  it("tolerates trailing semicolons and empty tokens", () => {
    expect(parseDmarcRecord("v=DMARC1; p=none;;")).toHaveLength(2)
  })
})

describe("walkUpCandidates", () => {
  it("walks toward the 2-label domain and stops there", () => {
    expect(walkUpCandidates("a.b.example.com")).toEqual(["b.example.com", "example.com"])
    expect(walkUpCandidates("example.com")).toEqual([])
  })
})

describe("analyzeDmarcRecord", () => {
  const at = "_dmarc.example.com"

  it("accepts a healthy enforcing record", () => {
    const a = analyzeDmarcRecord(
      "example.com",
      "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=r; aspf=r",
      at,
    )
    expect(byId(a, "dmarc.policy_ok")).toBeDefined()
    expect(byId(a, "dmarc.rua_ok")).toBeDefined()
    expect(byId(a, "dmarc.subdomain_ok")).toBeDefined()
    expect(a.findings.every((f) => f.severity !== "critical" && f.severity !== "warning")).toBe(
      true,
    )
    expect(a.results.is_enforcing).toBe(true)
    expect(a.results.subdomain_policy).toBe("reject")
    expect(a.externalReports).toEqual([])
  })

  it("flags a record that does not start with v=DMARC1 as critical", () => {
    const a = analyzeDmarcRecord("example.com", "p=none; v=DMARC1", at)
    expect(byId(a, "dmarc.syntax")?.severity).toBe("critical")
  })

  it("warns when p= is not the second tag", () => {
    const a = analyzeDmarcRecord("example.com", "v=DMARC1; rua=mailto:d@example.com; p=reject", at)
    expect(byId(a, "dmarc.syntax_p_position")?.severity).toBe("warning")
  })

  it("flags a missing policy as critical and an invalid one too", () => {
    expect(
      byId(
        analyzeDmarcRecord("example.com", "v=DMARC1; rua=mailto:d@example.com", at),
        "dmarc.no_policy",
      )?.severity,
    ).toBe("critical")
    expect(
      byId(analyzeDmarcRecord("example.com", "v=DMARC1; p=monitor", at), "dmarc.policy")?.severity,
    ).toBe("critical")
  })

  it("warns on p=none (monitor-only)", () => {
    const a = analyzeDmarcRecord("example.com", "v=DMARC1; p=none; rua=mailto:d@example.com", at)
    expect(byId(a, "dmarc.p_none")?.severity).toBe("warning")
    expect(a.results.is_enforcing).toBe(false)
  })

  it("warns when sp= is weaker than an enforcing p=", () => {
    const a = analyzeDmarcRecord(
      "example.com",
      "v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com",
      at,
    )
    expect(byId(a, "dmarc.subdomain")?.severity).toBe("warning")
    expect(a.results.subdomain_policy).toBe("none")
  })

  it("suggests np= on enforcing records (info)", () => {
    const a = analyzeDmarcRecord("example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com", at)
    expect(byId(a, "dmarc.np")?.severity).toBe("info")
  })

  it("warns on strict alignment modes", () => {
    const a = analyzeDmarcRecord(
      "example.com",
      "v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:d@example.com",
      at,
    )
    expect(byId(a, "dmarc.adkim_strict")?.severity).toBe("warning")
    expect(byId(a, "dmarc.aspf_strict")?.severity).toBe("warning")
  })

  it("warns on pct<100 and infos on pct=100 (obsolete)", () => {
    expect(
      byId(
        analyzeDmarcRecord(
          "example.com",
          "v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com",
          at,
        ),
        "dmarc.pct",
      )?.severity,
    ).toBe("warning")
    expect(
      byId(
        analyzeDmarcRecord(
          "example.com",
          "v=DMARC1; p=reject; pct=100; rua=mailto:d@example.com",
          at,
        ),
        "dmarc.pct",
      )?.severity,
    ).toBe("info")
  })

  it("warns when rua is missing and when a rua URI is not mailto:", () => {
    expect(
      byId(analyzeDmarcRecord("example.com", "v=DMARC1; p=reject", at), "dmarc.rua")?.severity,
    ).toBe("warning")
    expect(
      byId(
        analyzeDmarcRecord("example.com", "v=DMARC1; p=reject; rua=dmarc@example.com", at),
        "dmarc.rua_invalid",
      )?.severity,
    ).toBe("warning")
  })

  it("flags t=y testing mode as a warning that disables enforcement", () => {
    const a = analyzeDmarcRecord(
      "example.com",
      "v=DMARC1; p=reject; t=y; rua=mailto:d@example.com",
      at,
    )
    expect(byId(a, "dmarc.testing")?.severity).toBe("warning")
  })

  it("flags obsolete ri/rf tags and unknown tags as info", () => {
    const a = analyzeDmarcRecord(
      "example.com",
      "v=DMARC1; p=reject; ri=3600; rf=afrf; foo=bar; rua=mailto:d@example.com",
      at,
    )
    expect(ids(a)).toContain("dmarc.deprecated_tags")
  })

  it("collects external report destinations and strips !size suffixes", () => {
    const a = analyzeDmarcRecord(
      "example.com",
      "v=DMARC1; p=reject; rua=mailto:agg@thirdparty.net!10m,mailto:me@example.com; ruf=mailto:f@thirdparty.net",
      at,
    )
    // Same-domain mailbox is never probed; the external domain is deduped per kind.
    expect(a.externalReports).toEqual([
      { kind: "rua", uri: "mailto:agg@thirdparty.net", domain: "thirdparty.net" },
      { kind: "ruf", uri: "mailto:f@thirdparty.net", domain: "thirdparty.net" },
    ])
    expect(a.results.rua_uris).toEqual(["mailto:agg@thirdparty.net", "mailto:me@example.com"])
  })

  it("flags a malformed !size suffix", () => {
    const a = analyzeDmarcRecord(
      "example.com",
      "v=DMARC1; p=reject; rua=mailto:d@example.com!10mb",
      at,
    )
    expect(byId(a, "dmarc.report_uri_size")?.severity).toBe("info")
  })

  it("populates the structured results payload", () => {
    const a = analyzeDmarcRecord(
      "example.com",
      "v=DMARC1; p=quarantine; sp=reject; np=reject; adkim=s; rua=mailto:d@example.com; fo=1",
      at,
    )
    expect(a.results).toMatchObject({
      query_name: "_dmarc.example.com",
      record_found: true,
      record_count: 1,
      found_at: at,
      policy: "quarantine",
      subdomain_policy: "reject",
      np_policy: "reject",
      adkim: "s",
      aspf: "r",
      fo: "1",
      is_enforcing: true,
    })
  })
})
