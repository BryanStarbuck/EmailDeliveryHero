import type { DmarcReportRow, ParsedDmarcReport } from "./report.types"

/**
 * DMARC aggregate (rua) XML → ParsedDmarcReport (pm/emails.mdx §4.3/§4.4). Uses a tiny built-in
 * non-validating XML reader (dependency-light, never `eval`) sized for the machine-generated
 * RFC 7489 `<feedback>` documents providers send — elements and text only, attributes ignored.
 */

interface XmlNode {
  name: string
  children: XmlNode[]
  text: string
}

/** Strip prolog/comments/CDATA and build an element tree with a simple tag stack. */
function parseXml(xml: string): XmlNode {
  const cleaned = xml
    .replace(/<\?[\s\S]*?\?>/g, "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, (_, t: string) => escapeText(t))
    .replace(/<!DOCTYPE[^>]*>/gi, "")
  const root: XmlNode = { name: "", children: [], text: "" }
  const stack: XmlNode[] = [root]
  const tagRe = /<(\/?)([A-Za-z_][\w.:-]*)((?:"[^"]*"|'[^']*'|[^"'>])*?)(\/?)>|([^<]+)/g
  let m = tagRe.exec(cleaned)
  while (m) {
    if (m[5] !== undefined) {
      stack[stack.length - 1].text += decodeEntities(m[5])
    } else if (m[1] === "/") {
      // Closing tag: pop back to the matching element (tolerates minor mismatches).
      for (let i = stack.length - 1; i > 0; i--) {
        if (stack[i].name === localName(m[2])) {
          stack.length = i
          break
        }
      }
    } else {
      const node: XmlNode = { name: localName(m[2]), children: [], text: "" }
      stack[stack.length - 1].children.push(node)
      if (m[4] !== "/") stack.push(node)
    }
    m = tagRe.exec(cleaned)
  }
  return root
}

/** Namespace prefixes are dropped ("ns:record" → "record"). */
function localName(name: string): string {
  const colon = name.indexOf(":")
  return colon >= 0 ? name.slice(colon + 1) : name
}

function escapeText(t: string): string {
  return t.replace(/&/g, "&amp;").replace(/</g, "&lt;")
}

function decodeEntities(t: string): string {
  return t
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n: string) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, n: string) => String.fromCodePoint(Number.parseInt(n, 16)))
    .replace(/&amp;/g, "&")
}

function child(node: XmlNode | undefined, name: string): XmlNode | undefined {
  return node?.children.find((c) => c.name === name)
}

function children(node: XmlNode | undefined, name: string): XmlNode[] {
  return node?.children.filter((c) => c.name === name) ?? []
}

function text(node: XmlNode | undefined, name: string): string {
  return (child(node, name)?.text ?? "").trim()
}

/** Epoch seconds → ISO date-time; a non-numeric value passes through untouched. */
function epochToIso(value: string): string {
  const n = Number(value)
  if (!Number.isFinite(n) || n <= 0) return value
  return new Date(n * 1000).toISOString()
}

/**
 * Parse one DMARC aggregate XML document. Returns null when the payload is not a `<feedback>`
 * report. Aligned results come from `<policy_evaluated>` (pass = passed AND aligned); the raw
 * evaluated results and identities come from `<auth_results>`. `dmarcPass = spfAligned || dkimAligned`.
 */
export function parseDmarcAggregateXml(xml: string): ParsedDmarcReport | null {
  const doc = parseXml(xml)
  const feedback = child(doc, "feedback")
  if (!feedback) return null

  const metadata = child(feedback, "report_metadata")
  const dateRange = child(metadata, "date_range")
  const policy = child(feedback, "policy_published")

  const rows: DmarcReportRow[] = children(feedback, "record").map((record) => {
    const row = child(record, "row")
    const evaluated = child(row, "policy_evaluated")
    const identifiers = child(record, "identifiers")
    const auth = child(record, "auth_results")
    const authDkim = children(auth, "dkim")
    const authSpf = children(auth, "spf")

    const spfAligned = text(evaluated, "spf").toLowerCase() === "pass"
    const dkimAligned = text(evaluated, "dkim").toLowerCase() === "pass"
    return {
      sourceIp: text(row, "source_ip"),
      count: Number(text(row, "count")) || 0,
      disposition: text(evaluated, "disposition").toLowerCase() || "none",
      spfEvaluated: (authSpf.map((n) => text(n, "result")).find(Boolean) ?? "none").toLowerCase(),
      dkimEvaluated: (authDkim.map((n) => text(n, "result")).find(Boolean) ?? "none").toLowerCase(),
      spfAligned,
      dkimAligned,
      dmarcPass: spfAligned || dkimAligned,
      headerFrom: text(identifiers, "header_from").toLowerCase(),
      envelopeSpfDomain: (
        authSpf.map((n) => text(n, "domain")).find(Boolean) ?? text(identifiers, "envelope_from")
      ).toLowerCase(),
      dkimSigningDomains: authDkim.map((n) => text(n, "domain").toLowerCase()).filter(Boolean),
    }
  })

  return {
    kind: "dmarc",
    reporterOrg: text(metadata, "org_name") || "unknown",
    reportId: text(metadata, "report_id"),
    window: {
      begin: epochToIso(text(dateRange, "begin")),
      end: epochToIso(text(dateRange, "end")),
    },
    policyPublished: {
      domain: text(policy, "domain").toLowerCase(),
      p: text(policy, "p").toLowerCase() || "none",
      sp: text(policy, "sp").toLowerCase() || null,
      adkim: text(policy, "adkim").toLowerCase() || "r",
      aspf: text(policy, "aspf").toLowerCase() || "r",
      pct: text(policy, "pct") || null,
      np: text(policy, "np").toLowerCase() || null,
    },
    rows,
  }
}
