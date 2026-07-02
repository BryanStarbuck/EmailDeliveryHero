import { gunzipSync, inflateRawSync } from "node:zlib"

/**
 * Minimal, dependency-free MIME + decompression layer for report emails (pm/emails.mdx §2).
 * Walks a raw RFC 822 `.eml`, finds the report attachment(s) by Content-Type media type (never by
 * filename or subject — §4.2), base64-decodes per Content-Transfer-Encoding, and decompresses by
 * MAGIC BYTES: `PK\x03\x04` → ZIP (Google), `\x1f\x8b` → gzip (Outlook / Microsoft TLS-RPT), raw
 * `<?xml`/`{` → already plain. A zip-bomb cap (25 MB uncompressed) guards every inflate.
 */

/** Hard cap on uncompressed report size (pm/emails.mdx §2 robustness rules). */
export const MAX_UNCOMPRESSED_BYTES = 25 * 1024 * 1024

/** One candidate report payload pulled out of an email / file, fully decompressed. */
export interface ReportPayload {
  /** Lowercased media type of the MIME part ("" when read straight from a file). */
  mediaType: string
  /** Attachment filename — a HINT only, never used to classify (§4.2). */
  filename: string
  /** The decompressed bytes (XML or JSON text). */
  content: Buffer
}

interface MimePart {
  headers: Record<string, string>
  body: string
}

/** Unfold header continuation lines and split into a lowercase-keyed map. */
function parseHeaders(raw: string): Record<string, string> {
  const unfolded = raw.replace(/\r?\n[ \t]+/g, " ")
  const headers: Record<string, string> = {}
  for (const line of unfolded.split(/\r?\n/)) {
    const colon = line.indexOf(":")
    if (colon <= 0) continue
    const key = line.slice(0, colon).trim().toLowerCase()
    if (!(key in headers)) headers[key] = line.slice(colon + 1).trim()
  }
  return headers
}

/** Split one raw message/part into headers + body at the first blank line. */
function splitPart(raw: string): MimePart {
  const m = /\r?\n\r?\n/.exec(raw)
  if (!m) return { headers: parseHeaders(raw), body: "" }
  return {
    headers: parseHeaders(raw.slice(0, m.index)),
    body: raw.slice(m.index + m[0].length),
  }
}

/** The media type ("application/zip") of a Content-Type header value. */
function mediaTypeOf(contentType: string | undefined): string {
  if (!contentType) return ""
  return (contentType.split(";")[0] ?? "").trim().toLowerCase()
}

/** A named parameter (boundary, name, filename) from a structured header value. */
function headerParam(value: string | undefined, param: string): string {
  if (!value) return ""
  const re = new RegExp(`${param}\\s*=\\s*("([^"]*)"|[^;\\s]+)`, "i")
  const m = re.exec(value)
  if (!m) return ""
  return (m[2] ?? m[1] ?? "").trim()
}

/** Decode a leaf part's body per its Content-Transfer-Encoding. */
function decodeBody(part: MimePart): Buffer {
  const cte = (part.headers["content-transfer-encoding"] ?? "").trim().toLowerCase()
  if (cte === "base64") return Buffer.from(part.body.replace(/\s+/g, ""), "base64")
  if (cte === "quoted-printable") {
    const text = part.body
      .replace(/=\r?\n/g, "")
      .replace(/=([0-9A-Fa-f]{2})/g, (_, h: string) => String.fromCharCode(Number.parseInt(h, 16)))
    return Buffer.from(text, "latin1")
  }
  return Buffer.from(part.body, "latin1")
}

/** Recursively collect every leaf part of a MIME tree (multipart/mixed, /report, /related …). */
function collectLeafParts(part: MimePart): MimePart[] {
  const mediaType = mediaTypeOf(part.headers["content-type"])
  if (!mediaType.startsWith("multipart/")) return [part]
  const boundary = headerParam(part.headers["content-type"], "boundary")
  if (!boundary) return [part]
  const marker = `--${boundary}`
  const leaves: MimePart[] = []
  // Split on the boundary lines; the first chunk is the preamble, the last (after --boundary--)
  // the epilogue — both ignored.
  const chunks = part.body.split(
    new RegExp(`(?:^|\r?\n)${escapeRe(marker)}(?:--)?[ \t]*(?:\r?\n|$)`),
  )
  for (const chunk of chunks.slice(1)) {
    if (!chunk.trim()) continue
    leaves.push(...collectLeafParts(splitPart(chunk)))
  }
  return leaves
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

// ─── Decompression by magic bytes (pm/emails.mdx §2 step 4) ─────────────────────────────────────

function isGzip(buf: Buffer): boolean {
  return buf.length > 2 && buf[0] === 0x1f && buf[1] === 0x8b
}

function isZip(buf: Buffer): boolean {
  return buf.length > 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04
}

/**
 * Extract every file from a ZIP by walking the local-file-header chain (no directory needed for
 * the single-entry archives providers send). Deflate entries inflate via zlib; stored entries copy.
 */
function unzipAll(buf: Buffer): Buffer[] {
  const out: Buffer[] = []
  let offset = 0
  while (offset + 30 <= buf.length && buf.readUInt32LE(offset) === 0x04034b50) {
    const flags = buf.readUInt16LE(offset + 6)
    const method = buf.readUInt16LE(offset + 8)
    let compressedSize = buf.readUInt32LE(offset + 18)
    const nameLen = buf.readUInt16LE(offset + 26)
    const extraLen = buf.readUInt16LE(offset + 28)
    const dataStart = offset + 30 + nameLen + extraLen
    // Bit 3 (streamed) means sizes live in a trailing data descriptor; providers don't use it for
    // these tiny reports, but tolerate it by scanning to the descriptor signature.
    if ((flags & 0x08) !== 0 && compressedSize === 0) {
      const sig = buf.indexOf(Buffer.from([0x50, 0x4b, 0x07, 0x08]), dataStart)
      compressedSize = sig >= 0 ? sig - dataStart : buf.length - dataStart
    }
    const data = buf.subarray(dataStart, dataStart + compressedSize)
    if (method === 8) {
      out.push(inflateRawSync(data, { maxOutputLength: MAX_UNCOMPRESSED_BYTES }))
    } else if (method === 0) {
      out.push(Buffer.from(data))
    }
    offset = dataStart + compressedSize + ((flags & 0x08) !== 0 ? 16 : 0)
  }
  return out
}

/**
 * Decompress a candidate attachment by MAGIC BYTES, not filename (§2). Returns one buffer per
 * contained file (a ZIP may hold several); a plain XML/JSON payload passes through unchanged.
 */
export function decompressPayload(buf: Buffer): Buffer[] {
  if (isGzip(buf)) return [gunzipSync(buf, { maxOutputLength: MAX_UNCOMPRESSED_BYTES })]
  if (isZip(buf)) return unzipAll(buf)
  return [buf]
}

/** Media types that carry a DMARC aggregate or TLS-RPT report (pm/emails.mdx §1 table). */
const REPORT_MEDIA_TYPES = new Set([
  "application/zip",
  "application/gzip",
  "application/x-gzip",
  "application/x-zip-compressed",
  "application/tlsrpt+gzip",
  "application/tlsrpt+json",
  "text/xml",
  "application/xml",
  "application/json",
])

/** Filename extensions used only as a SECONDARY hint for application/octet-stream parts (§2). */
const REPORT_EXTENSIONS = /\.(zip|gz|xml|json)$/i

/**
 * Walk a raw `.eml` and return every candidate report payload, base64-decoded and decompressed.
 * A message with no matching part returns [] (the caller logs `info` and skips — §2). Also accepts
 * a bare (non-mail) buffer that is itself a zip/gzip/xml/json file, for drop-folder ingestion.
 */
export function extractReportPayloads(raw: Buffer): ReportPayload[] {
  // A drop-folder file may be the report itself, not an email.
  if (isGzip(raw) || isZip(raw) || looksLikeBarePayload(raw)) {
    return decompressPayload(raw).map((content) => ({ mediaType: "", filename: "", content }))
  }

  const message = splitPart(raw.toString("latin1"))
  const payloads: ReportPayload[] = []
  for (const part of collectLeafParts(message)) {
    const mediaType = mediaTypeOf(part.headers["content-type"])
    const filename =
      headerParam(part.headers["content-disposition"], "filename") ||
      headerParam(part.headers["content-type"], "name")
    const isReportType = REPORT_MEDIA_TYPES.has(mediaType)
    const isOctetHint = mediaType === "application/octet-stream" && REPORT_EXTENSIONS.test(filename)
    if (!isReportType && !isOctetHint) continue
    try {
      const decoded = decodeBody(part)
      for (const content of decompressPayload(decoded)) {
        payloads.push({ mediaType, filename, content })
      }
    } catch {
      // A corrupt attachment must not sink the other parts; the caller counts it as skipped.
    }
  }
  return payloads
}

/** True when a bare buffer already looks like a decompressed report (raw `<?xml`/`<feedback`/`{`). */
function looksLikeBarePayload(buf: Buffer): boolean {
  const head = buf.subarray(0, 512).toString("utf8").trimStart()
  return head.startsWith("<?xml") || head.startsWith("<feedback") || head.startsWith("{")
}

/**
 * Classify a decompressed payload by its ROOT content (pm/emails.mdx §4.2): a `<feedback>` XML
 * document ⇒ DMARC aggregate; a JSON object with organization-name/policies ⇒ TLS-RPT. The media
 * type is consulted first when unambiguous; the subject/filename NEVER are. Returns null for
 * anything else (skipped with an info log).
 */
export function classifyPayload(payload: ReportPayload): "dmarc" | "tlsrpt" | null {
  if (payload.mediaType.startsWith("application/tlsrpt")) return "tlsrpt"
  const head = payload.content.subarray(0, 4096).toString("utf8").trimStart()
  if (head.startsWith("{")) {
    return head.includes('"organization-name"') || head.includes('"policies"') ? "tlsrpt" : null
  }
  if (head.startsWith("<")) {
    return /<feedback[\s>]/.test(head) ? "dmarc" : null
  }
  return null
}
