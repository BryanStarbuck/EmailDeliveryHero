import type { ArcResults } from "./arc.check"

jest.mock("../dns-util", () => ({ resolveTxt: jest.fn() }))

import { resolveTxt } from "../dns-util"
import type { CheckContext, CheckOutcome, Finding } from "../types"
import { arcCheck } from "./arc.check"

const mockResolveTxt = resolveTxt as jest.MockedFunction<typeof resolveTxt>

/** A base64 p= long enough to estimate as a ~2048-bit RSA modulus. */
const GOOD_P = "A".repeat(400)

function ctx(arc?: CheckContext["arc"]): CheckContext {
  return { domain: "example.com", dkimSelectors: [], sendingIps: [], arc }
}

/** Route mocked TXT answers by query name. */
function dnsAnswers(map: Record<string, { records?: string[]; empty?: boolean; error?: string }>) {
  mockResolveTxt.mockImplementation(async (name: string) => {
    const a = map[name]
    if (!a) return { records: [], empty: true }
    return { records: a.records ?? [], empty: a.empty ?? false, error: a.error }
  })
}

async function run(c: CheckContext): Promise<{ findings: Finding[]; results: ArcResults }> {
  const outcome = (await arcCheck.run(c)) as CheckOutcome
  return { findings: outcome.findings, results: outcome.results as ArcResults }
}

const byId = (findings: Finding[], id: string) => findings.find((f) => f.id === id)

beforeEach(() => mockResolveTxt.mockReset())

describe("arcCheck (pm/checks/arc.mdx)", () => {
  it("registers under id 'arc' so findings roll into the DMARC cell via the arc. prefix", () => {
    expect(arcCheck.id).toBe("arc")
  })

  it("emits a single info 'not applicable' when DMARC is not enforcing (p=none)", async () => {
    dnsAnswers({ "_dmarc.example.com": { records: ["v=DMARC1; p=none"] } })
    const { findings, results } = await run(ctx({ usesForwarding: true, forwarders: [] }))
    expect(findings).toHaveLength(1)
    expect(findings[0].id).toBe("arc.applicable")
    expect(findings[0].severity).toBe("info")
    expect(results.applicable).toBe(false)
    expect(results.forwardingRisk).toBe(false)
    // Sample-derived columns stay null first round (nullable arc_check_results columns, §5).
    expect(results.chainPresent).toBeNull()
    expect(results.cvResult).toBeNull()
    expect(results.sealValid).toBeNull()
  })

  it("emits a single info 'not applicable' when enforcing but no forwarding is declared", async () => {
    dnsAnswers({ "_dmarc.example.com": { records: ["v=DMARC1; p=reject"] } })
    const { findings, results } = await run(ctx(undefined))
    expect(findings).toHaveLength(1)
    expect(findings[0].id).toBe("arc.applicable")
    expect(findings[0].severity).toBe("info")
    expect(results.applicable).toBe(false)
  })

  it("degrades to info (never a false critical) when the DMARC lookup fails transiently", async () => {
    dnsAnswers({ "_dmarc.example.com": { error: "ETIMEOUT" } })
    const { findings, results } = await run(ctx({ usesForwarding: true, forwarders: [] }))
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe("info")
    expect(results.applicable).toBeNull()
    expect(results.notes).toContain("ETIMEOUT")
  })

  it("warns on forwarding risk when usesForwarding is declared but no forwarders are registered", async () => {
    dnsAnswers({ "_dmarc.example.com": { records: ["v=DMARC1; p=quarantine"] } })
    const { findings, results } = await run(ctx({ usesForwarding: true, forwarders: [] }))
    expect(byId(findings, "arc.applicable")?.severity).toBe("info")
    expect(byId(findings, "arc.forwarding_risk")?.severity).toBe("warning")
    // FUTURE sample sub-checks stubbed as a single info — never fabricated verdicts.
    expect(byId(findings, "arc.chain_present")?.severity).toBe("info")
    expect(results.applicable).toBe(true)
    expect(results.forwardingRisk).toBe(true)
  })

  it("verifies each declared forwarder's signer selector in DNS (resolving key → ok)", async () => {
    dnsAnswers({
      "_dmarc.example.com": { records: ["v=DMARC1; p=reject"] },
      "arc1._domainkey.lists.acme.org": { records: [`v=DKIM1; k=rsa; p=${GOOD_P}`] },
    })
    const { findings, results } = await run(
      ctx({
        usesForwarding: true,
        forwarders: [
          {
            label: "Acme Users",
            forwardAddress: "acme-users@lists.acme.org",
            signerDomain: "lists.acme.org",
            signerSelector: "arc1",
          },
        ],
      }),
    )
    expect(byId(findings, "arc.forwarding_risk.acme-users")?.severity).toBe("warning")
    expect(byId(findings, "arc.selector_dns.acme-users")?.severity).toBe("ok")
    // A healthy modern key emits no arc.signature_algorithm problem.
    expect(byId(findings, "arc.signature_algorithm.acme-users")).toBeUndefined()
    expect(results.forwarders).toEqual([
      {
        label: "Acme Users",
        forwardAddress: "acme-users@lists.acme.org",
        signerDomain: "lists.acme.org",
        signerSelector: "arc1",
        selectorResolves: true,
      },
    ])
  })

  it("flags an NXDOMAIN signer selector as critical (arc.selector_dns)", async () => {
    dnsAnswers({
      "_dmarc.example.com": { records: ["v=DMARC1; p=reject"] },
      // arc1._domainkey.lists.acme.org intentionally absent → empty:true default
    })
    const { findings, results } = await run(
      ctx({
        usesForwarding: true,
        forwarders: [
          {
            label: "Acme Users",
            forwardAddress: "acme-users@lists.acme.org",
            signerDomain: "lists.acme.org",
            signerSelector: "arc1",
          },
        ],
      }),
    )
    const f = byId(findings, "arc.selector_dns.acme-users")
    expect(f?.severity).toBe("critical")
    expect(f?.remediation).toContain("arc1._domainkey.lists.acme.org")
    expect(results.forwarders[0].selectorResolves).toBe(false)
  })

  it("flags an empty/revoked p= as critical and a weak RSA key as warning", async () => {
    dnsAnswers({
      "_dmarc.example.com": { records: ["v=DMARC1; p=reject"] },
      "arc1._domainkey.lists.acme.org": { records: ["v=DKIM1; k=rsa; p="] },
      "arc2._domainkey.lists.beta.org": { records: [`v=DKIM1; k=rsa; p=${"A".repeat(120)}`] },
    })
    const { findings } = await run(
      ctx({
        usesForwarding: true,
        forwarders: [
          {
            label: "Acme",
            forwardAddress: "a@lists.acme.org",
            signerDomain: "lists.acme.org",
            signerSelector: "arc1",
          },
          {
            label: "Beta",
            forwardAddress: "b@lists.beta.org",
            signerDomain: "lists.beta.org",
            signerSelector: "arc2",
          },
        ],
      }),
    )
    expect(byId(findings, "arc.selector_dns.acme")?.severity).toBe("critical")
    expect(byId(findings, "arc.signature_algorithm.beta")?.severity).toBe("warning")
  })

  it("emits an info (not critical) when a forwarder's signer is not yet known", async () => {
    dnsAnswers({ "_dmarc.example.com": { records: ["v=DMARC1; p=reject"] } })
    const { findings } = await run(
      ctx({
        usesForwarding: true,
        forwarders: [{ label: "Some List", forwardAddress: "list@example.org" }],
      }),
    )
    expect(byId(findings, "arc.selector_dns.some-list")?.severity).toBe("info")
  })

  it("reads the DMARC policy the sibling dmarc checker already parsed (never re-queries _dmarc)", async () => {
    // No _dmarc answer is mocked: if the checker fell back to DNS it would see "no record" and
    // wrongly conclude not-enforcing. The upstream §5 dmarc section must win (pm/checks/arc.mdx §3.1).
    dnsAnswers({
      "arc1._domainkey.lists.acme.org": { records: [`v=DKIM1; k=rsa; p=${GOOD_P}`] },
    })
    const c: CheckContext = {
      ...ctx({
        usesForwarding: true,
        forwarders: [
          {
            label: "Acme Users",
            forwardAddress: "acme-users@lists.acme.org",
            signerDomain: "lists.acme.org",
            signerSelector: "arc1",
          },
        ],
      }),
      upstream: { dmarc: { record: { policy: "reject", is_enforcing: true } } },
    }
    const { findings, results } = await run(c)
    expect(results.applicable).toBe(true)
    expect(byId(findings, "arc.applicable")?.detail).toContain("p=reject")
    expect(byId(findings, "arc.selector_dns.acme-users")?.severity).toBe("ok")
    const queried = mockResolveTxt.mock.calls.map((call) => call[0])
    expect(queried).not.toContain("_dmarc.example.com")
  })

  it("treats a sibling not-enforcing verdict as not applicable without any DNS lookup", async () => {
    dnsAnswers({})
    const c: CheckContext = {
      ...ctx({ usesForwarding: true, forwarders: [] }),
      upstream: { dmarc: { record: { policy: "none", is_enforcing: false } } },
    }
    const { findings, results } = await run(c)
    expect(findings).toHaveLength(1)
    expect(findings[0].id).toBe("arc.applicable")
    expect(findings[0].severity).toBe("info")
    expect(results.applicable).toBe(false)
    expect(mockResolveTxt).not.toHaveBeenCalled()
  })

  it("every non-ok finding carries a concrete remediation (acceptance §8.1)", async () => {
    dnsAnswers({ "_dmarc.example.com": { records: ["v=DMARC1; p=reject"] } })
    const { findings } = await run(
      ctx({
        usesForwarding: true,
        forwarders: [
          {
            label: "Acme",
            forwardAddress: "a@lists.acme.org",
            signerDomain: "lists.acme.org",
            signerSelector: "arc1",
          },
        ],
      }),
    )
    for (const f of findings) {
      if (f.severity !== "ok") expect(f.remediation).toBeTruthy()
    }
  })
})
