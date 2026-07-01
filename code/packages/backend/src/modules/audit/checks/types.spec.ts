import { type Finding, summarize } from "./types"

function finding(severity: Finding["severity"]): Finding {
  return { id: "x", checkId: "x", title: "x", severity, detail: "x" }
}

describe("summarize", () => {
  it("scores a clean domain 100 / ok", () => {
    const { score, status, counts } = summarize([finding("ok"), finding("ok")])
    expect(score).toBe(100)
    expect(status).toBe("ok")
    expect(counts.ok).toBe(2)
  })

  it("penalizes warnings and criticals and floors at 0", () => {
    const s1 = summarize([finding("warning")])
    expect(s1.score).toBe(88)
    expect(s1.status).toBe("warning")

    const s2 = summarize([finding("critical"), finding("critical"), finding("critical"), finding("critical")])
    expect(s2.score).toBe(0)
    expect(s2.status).toBe("critical")
  })

  it("critical outranks warning for overall status", () => {
    const { status } = summarize([finding("warning"), finding("critical")])
    expect(status).toBe("critical")
  })
})
