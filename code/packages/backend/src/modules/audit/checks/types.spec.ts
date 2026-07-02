import { type Finding, flagNewProblems, summarize } from "./types"

function finding(severity: Finding["severity"], id = "x"): Finding {
  return { id, checkId: "x", title: "x", severity, detail: "x" }
}

describe("summarize", () => {
  it("scores a clean domain 100 / ok", () => {
    const { score, status, counts } = summarize([finding("ok"), finding("ok")])
    expect(score).toBe(100)
    expect(status).toBe("ok")
    expect(counts.ok).toBe(2)
  })

  it("penalizes warnings and criticals with the default weights and floors at 0", () => {
    const s1 = summarize([finding("warning")])
    expect(s1.score).toBe(85) // 100 - default warning weight (15)
    expect(s1.status).toBe("warning")

    const s2 = summarize([
      finding("critical"),
      finding("critical"),
      finding("critical"),
      finding("critical"),
    ])
    expect(s2.score).toBe(0)
    expect(s2.status).toBe("critical")
  })

  it("honors configured severity weights (config.yaml checks.weights), including info", () => {
    const weights = { critical: 30, warning: 12, info: 2 }
    const { score, status } = summarize(
      [finding("critical"), finding("warning"), finding("info")],
      weights,
    )
    expect(score).toBe(100 - 30 - 12 - 2)
    expect(status).toBe("critical")
  })

  it("info findings alone never drop status below info", () => {
    const { score, status } = summarize([finding("info"), finding("ok")])
    expect(score).toBe(100) // default info weight is 0
    expect(status).toBe("info")
  })

  it("critical outranks warning for overall status", () => {
    const { status } = summarize([finding("warning"), finding("critical")])
    expect(status).toBe("critical")
  })
})

describe("flagNewProblems (pm/engineering.mdx §8 regression detection)", () => {
  it("flags nothing on a domain's first run (no baseline)", () => {
    const current = [finding("critical", "spf.missing")]
    expect(flagNewProblems(undefined, current)).toBe(0)
    expect(current[0].isNew).toBeUndefined()
  })

  it("flags a warning/critical finding whose id was absent from the previous run", () => {
    const previous = [finding("ok", "spf.present")]
    const current = [finding("ok", "spf.present"), finding("critical", "dmarc.missing")]
    expect(flagNewProblems(previous, current)).toBe(1)
    expect(current[1].isNew).toBe(true)
    expect(current[0].isNew).toBeUndefined()
  })

  it("flags a finding that worsened in severity since the previous run", () => {
    const previous = [finding("warning", "dmarc.weak_policy")]
    const current = [finding("critical", "dmarc.weak_policy")]
    expect(flagNewProblems(previous, current)).toBe(1)
    expect(current[0].isNew).toBe(true)
  })

  it("does not flag persisting problems at the same severity, or ok/info findings", () => {
    const previous = [finding("warning", "spf.softfail")]
    const current = [finding("warning", "spf.softfail"), finding("info", "mx.single_host")]
    expect(flagNewProblems(previous, current)).toBe(0)
    expect(current.every((f) => f.isNew === undefined)).toBe(true)
  })
})
