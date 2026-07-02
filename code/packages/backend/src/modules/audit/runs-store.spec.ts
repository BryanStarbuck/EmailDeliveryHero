import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { AuditResult } from "./checks/types"
import {
  deleteDomainRuns,
  deleteDomainRunsById,
  deleteRun,
  getRun,
  listRuns,
  migrateLegacyRunsJson,
  pruneRuns,
  runFileTimestamp,
  sanitizeDomainDir,
  saveRun,
} from "./runs-store"

/**
 * The runs/ YAML history tree (pm/storage.mdx §7): one immutable YAML file per run at
 * runs/<domain>/<YYYY_MM_DD_hh_mm{AM|PM}>.yaml. Covers the locked filename grammar (12-hour
 * clock, local tz, zero-padding, midnight/noon edges, _2 collision suffix), the envelope
 * round-trip (run: block + six category keys ↔ AuditResult), whole-file pruning, per-domain
 * directory removal, and the legacy runs.json migration.
 */

const TZ = "America/Los_Angeles"

let stateDir: string

beforeEach(() => {
  stateDir = mkdtempSync(join(tmpdir(), "edh-runs-store-"))
  process.env.EDH_STATE_DIR = stateDir
})

afterEach(() => {
  delete process.env.EDH_STATE_DIR
  rmSync(stateDir, { recursive: true, force: true })
})

function makeRun(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    runId: "run-1",
    domainId: "dom-1",
    domain: "example.com",
    startedAt: "2026-07-01T16:14:02.000Z",
    finishedAt: "2026-07-01T16:14:05.310Z",
    ranAt: "2026-07-01T16:14:05.310Z",
    score: 88,
    status: "warning",
    findings: [
      {
        id: "dmarc.p_none",
        checkId: "dmarc",
        title: "DMARC policy is p=none",
        severity: "warning",
        detail: "v=DMARC1; p=none",
        remediation: "Strengthen to p=quarantine.",
      },
    ],
    counts: { ok: 3, info: 0, warning: 1, critical: 0 },
    newProblemCount: 1,
    results: {
      spf: { record_found: true, all_qualifier: "~all" },
      dkim: { selectors: [{ selector: "google", key_sha256: "abc" }] },
      dmarc: { policy: "none" },
      arc: { applicable: false },
      blacklist: { listed: [] },
      "infra.mx_routing": { mx_found: true },
      "infra.reverse_dns": { ips: [] },
      "content.bimi": { record_found: false },
    },
    ...overrides,
  }
}

describe("runFileTimestamp — the locked filename grammar (pm/storage.mdx §7.2)", () => {
  it("renders YYYY_MM_DD_hh_mm{AM|PM} in the given timezone, zero-padded", () => {
    // 2026-07-01T16:14Z is 09:14 AM PDT — the spec's own example.
    expect(runFileTimestamp("2026-07-01T16:14:02.000Z", TZ)).toBe("2026_07_01_09_14AM")
  })

  it("renders midnight as 12_xxAM and noon as 12_xxPM", () => {
    // 07:05Z = 00:05 PDT (midnight edge); 19:00Z = 12:00 PDT (noon edge).
    expect(runFileTimestamp("2026-07-01T07:05:00.000Z", TZ)).toBe("2026_07_01_12_05AM")
    expect(runFileTimestamp("2026-07-01T19:00:00.000Z", TZ)).toBe("2026_07_01_12_00PM")
  })

  it("falls back to the system timezone when the configured tz is invalid", () => {
    expect(runFileTimestamp("2026-07-01T16:14:02.000Z", "Not/AZone")).toMatch(
      /^\d{4}_\d{2}_\d{2}_\d{2}_\d{2}(AM|PM)$/,
    )
  })
})

describe("sanitizeDomainDir — §7.1 path-segment policy", () => {
  it("lowercases and strips /, \\, .., NUL", () => {
    expect(sanitizeDomainDir("Example.COM")).toBe("example.com")
    expect(sanitizeDomainDir("evil/..\\..\u0000name")).toBe("evilname")
  })
})

describe("saveRun / listRuns / getRun — one YAML file per run", () => {
  it("writes runs/<domain>/<timestamp>.yaml and round-trips the AuditResult", () => {
    const run = makeRun()
    saveRun(run, TZ)

    const file = join(stateDir, "runs", "example.com", "2026_07_01_09_14AM.yaml")
    expect(existsSync(file)).toBe(true)

    // The envelope: a run: block plus the six locked category keys (pm/storage.mdx §7.3).
    const body = readFileSync(file, "utf8")
    expect(body).toContain("run:")
    expect(body).toContain("run_id: run-1")
    for (const key of ["spf:", "dkim:", "dmarc:", "blacklists:", "dns_infra:", "spam_content:"]) {
      expect(body).toContain(key)
    }

    const runs = listRuns()
    expect(runs).toHaveLength(1)
    const loaded = runs[0]
    expect(loaded.runId).toBe("run-1")
    expect(loaded.domainId).toBe("dom-1")
    expect(loaded.domain).toBe("example.com")
    expect(loaded.startedAt).toBe(run.startedAt)
    expect(loaded.finishedAt).toBe(run.finishedAt)
    expect(loaded.score).toBe(88)
    expect(loaded.status).toBe("warning")
    expect(loaded.newProblemCount).toBe(1)
    expect(loaded.findings).toEqual(run.findings)
    expect(loaded.counts).toEqual(run.counts)
    // The category sections map back to the checker-id-keyed results record.
    expect(loaded.results).toEqual(run.results)

    expect(getRun("run-1")?.runId).toBe("run-1")
    expect(getRun("missing")).toBeNull()
  })

  it("appends _2, _3, … on a same-minute collision for the same domain", () => {
    saveRun(makeRun({ runId: "a" }), TZ)
    saveRun(makeRun({ runId: "b" }), TZ)
    saveRun(makeRun({ runId: "c" }), TZ)
    const files = readdirSync(join(stateDir, "runs", "example.com")).sort()
    expect(files).toEqual([
      "2026_07_01_09_14AM.yaml",
      "2026_07_01_09_14AM_2.yaml",
      "2026_07_01_09_14AM_3.yaml",
    ])
    expect(listRuns()).toHaveLength(3)
  })

  it("sorts newest startedAt first and filters by domainId", () => {
    saveRun(makeRun({ runId: "old", startedAt: "2026-06-30T10:00:00.000Z" }), TZ)
    saveRun(makeRun({ runId: "new", startedAt: "2026-07-01T16:14:02.000Z" }), TZ)
    saveRun(
      makeRun({
        runId: "other",
        domainId: "dom-2",
        domain: "act3ai.com",
        startedAt: "2026-07-01T00:00:00.000Z",
      }),
      TZ,
    )
    expect(listRuns().map((r) => r.runId)).toEqual(["new", "other", "old"])
    expect(listRuns("dom-1").map((r) => r.runId)).toEqual(["new", "old"])
    expect(listRuns("dom-2").map((r) => r.runId)).toEqual(["other"])
  })
})

describe("deleteRun / deleteDomainRuns — whole-file deletes only (§7.4)", () => {
  it("deleteRun removes exactly that run's file", () => {
    saveRun(makeRun({ runId: "a", startedAt: "2026-07-01T16:14:02.000Z" }), TZ)
    saveRun(makeRun({ runId: "b", startedAt: "2026-07-01T16:15:02.000Z" }), TZ)
    deleteRun("a")
    expect(listRuns().map((r) => r.runId)).toEqual(["b"])
  })

  it("deleting a domain removes its whole runs/<domain>/ directory", () => {
    saveRun(makeRun(), TZ)
    saveRun(makeRun({ runId: "other", domainId: "dom-2", domain: "act3ai.com" }), TZ)
    deleteDomainRuns("Example.com")
    expect(existsSync(join(stateDir, "runs", "example.com"))).toBe(false)
    expect(listRuns().map((r) => r.domain)).toEqual(["act3ai.com"])
  })

  it("deleteDomainRunsById resolves the directory from run.domain_id", () => {
    saveRun(makeRun(), TZ)
    deleteDomainRunsById("dom-1")
    expect(existsSync(join(stateDir, "runs", "example.com"))).toBe(false)
  })
})

describe("pruneRuns — retention window + per-domain cap (§7.4)", () => {
  it("keeps only the newest N runs per domain", () => {
    for (let i = 0; i < 5; i++) {
      saveRun(
        makeRun({
          runId: `r${i}`,
          startedAt: `2026-07-01T1${i}:00:00.000Z`,
        }),
        TZ,
      )
    }
    pruneRuns(90, 2)
    expect(listRuns().map((r) => r.runId)).toEqual(["r4", "r3"])
  })

  it("deletes runs older than the retention window", () => {
    saveRun(makeRun({ runId: "ancient", startedAt: "2020-01-01T00:00:00.000Z" }), TZ)
    saveRun(makeRun({ runId: "fresh", startedAt: new Date().toISOString() }), TZ)
    pruneRuns(90, 50)
    expect(listRuns().map((r) => r.runId)).toEqual(["fresh"])
  })
})

describe("migrateLegacyRunsJson — pre-§7 single-file history", () => {
  it("splits runs.json into per-run YAML files and removes the legacy file", () => {
    const legacyPath = join(stateDir, "runs.json")
    const legacy = [
      makeRun({ runId: "l1", startedAt: "2026-06-28T13:00:00.000Z" }),
      makeRun({
        runId: "l2",
        domainId: "dom-2",
        domain: "act3ai.com",
        startedAt: "2026-06-29T13:00:00.000Z",
      }),
    ]
    writeFileSync(legacyPath, JSON.stringify(legacy), "utf8")

    migrateLegacyRunsJson(TZ)

    expect(existsSync(legacyPath)).toBe(false)
    expect(listRuns().map((r) => r.runId)).toEqual(["l2", "l1"])
    expect(existsSync(join(stateDir, "runs", "example.com"))).toBe(true)
    expect(existsSync(join(stateDir, "runs", "act3ai.com"))).toBe(true)

    // Idempotent: a second call with no legacy file is a no-op.
    migrateLegacyRunsJson(TZ)
    expect(listRuns()).toHaveLength(2)
  })
})
