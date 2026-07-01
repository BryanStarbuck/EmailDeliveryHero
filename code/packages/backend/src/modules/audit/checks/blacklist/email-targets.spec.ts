import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { gzipSync } from "node:zlib"
import {
  collectEmailReportIps,
  extractReportXml,
  isPublicIp,
  parseRuaXml,
} from "./email-targets"

/** Offline fixtures for the §19 email-derived target pipeline (pm/checks/blacklists.mdx). */

function ruaXml(args: {
  domain: string
  endEpoch: number
  rows: Array<{ ip: string; count: number; dkim: string; spf: string }>
}): string {
  const records = args.rows
    .map(
      (r) => `
  <record>
    <row>
      <source_ip>${r.ip}</source_ip>
      <count>${r.count}</count>
      <policy_evaluated><disposition>none</disposition><dkim>${r.dkim}</dkim><spf>${r.spf}</spf></policy_evaluated>
    </row>
  </record>`,
    )
    .join("")
  return `<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>google.com</org_name>
    <date_range><begin>${args.endEpoch - 86400}</begin><end>${args.endEpoch}</end></date_range>
  </report_metadata>
  <policy_published><domain>${args.domain}</domain><p>quarantine</p></policy_published>
  ${records}
</feedback>`
}

function emlWithGzip(xml: string): string {
  const b64 = gzipSync(Buffer.from(xml, "utf8")).toString("base64")
  const wrapped = b64.replace(/(.{76})/g, "$1\r\n")
  return [
    "From: noreply-dmarc-support@google.com",
    "To: dmarc-reports@example.com",
    "Subject: Report domain: example.com",
    'Content-Type: application/gzip; name="report.xml.gz"',
    "Content-Transfer-Encoding: base64",
    "",
    wrapped,
    "",
  ].join("\r\n")
}

const NOW_EPOCH = Math.floor(Date.now() / 1000)

describe("parseRuaXml", () => {
  it("extracts domain, window end, and per-row alignment", () => {
    const xml = ruaXml({
      domain: "Example.COM",
      endEpoch: 1700000000,
      rows: [
        { ip: "203.0.113.24", count: 42, dkim: "pass", spf: "fail" },
        { ip: "198.51.100.9", count: 7, dkim: "fail", spf: "fail" },
      ],
    })
    const parsed = parseRuaXml(xml)
    expect(parsed.domain).toBe("example.com")
    expect(parsed.endEpoch).toBe(1700000000)
    expect(parsed.rows).toEqual([
      { ip: "203.0.113.24", count: 42, aligned: true },
      { ip: "198.51.100.9", count: 7, aligned: false },
    ])
  })
})

describe("extractReportXml", () => {
  it("decodes a base64 gzip attachment back to the report XML", () => {
    const xml = ruaXml({
      domain: "example.com",
      endEpoch: NOW_EPOCH,
      rows: [{ ip: "203.0.113.24", count: 1, dkim: "pass", spf: "pass" }],
    })
    const found = extractReportXml(emlWithGzip(xml))
    expect(found).toHaveLength(1)
    expect(found[0]).toContain("<source_ip>203.0.113.24</source_ip>")
  })
})

describe("isPublicIp", () => {
  it.each(["10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1"])(
    "rejects private/reserved %s",
    (ip) => expect(isPublicIp(ip)).toBe(false),
  )
  it("accepts public space and rejects non-IPv4", () => {
    expect(isPublicIp("203.0.113.24")).toBe(true)
    expect(isPublicIp("2001:db8::1")).toBe(false)
  })
})

describe("collectEmailReportIps", () => {
  let dir: string
  const prevEnv = process.env.EDH_EMAILS_DIR

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "edh-emails-"))
    process.env.EDH_EMAILS_DIR = dir
  })
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
    if (prevEnv === undefined) delete process.env.EDH_EMAILS_DIR
    else process.env.EDH_EMAILS_DIR = prevEnv
  })

  it("returns only aligned public IPs for the requested domain, aggregated across reports", () => {
    const fresh = ruaXml({
      domain: "example.com",
      endEpoch: NOW_EPOCH - 3600,
      rows: [
        { ip: "203.0.113.24", count: 40, dkim: "pass", spf: "fail" }, // ours — kept
        { ip: "198.51.100.9", count: 500, dkim: "fail", spf: "fail" }, // spoofer — dropped
        { ip: "10.0.0.5", count: 10, dkim: "pass", spf: "pass" }, // private — dropped
      ],
    })
    const otherDomain = ruaXml({
      domain: "other.org",
      endEpoch: NOW_EPOCH - 3600,
      rows: [{ ip: "192.0.2.77", count: 9, dkim: "pass", spf: "pass" }],
    })
    writeFileSync(join(dir, "fresh.eml"), emlWithGzip(fresh))
    writeFileSync(join(dir, "other.eml"), emlWithGzip(otherDomain))

    const { ips, truncated } = collectEmailReportIps("example.com")
    expect(truncated).toBe(0)
    expect(ips).toHaveLength(1)
    expect(ips[0].ip).toBe("203.0.113.24")
    expect(ips[0].message_count).toBe(40)
  })

  it("ignores reports outside the 30-day window", () => {
    const stale = ruaXml({
      domain: "example.com",
      endEpoch: NOW_EPOCH - 40 * 24 * 3600,
      rows: [{ ip: "203.0.113.24", count: 5, dkim: "pass", spf: "pass" }],
    })
    writeFileSync(join(dir, "stale.eml"), emlWithGzip(stale))
    expect(collectEmailReportIps("example.com").ips).toHaveLength(0)
  })
})
