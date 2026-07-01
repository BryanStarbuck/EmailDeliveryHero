import { createHash } from "node:crypto"
import { dig, resolveSoa } from "../dns-util"
import type { Checker, CheckOutcome, Finding } from "../types"

/**
 * DNSSEC (DNS Security Extensions, RFC 4033/4034/4035). Verifies that a mail domain's zone is signed
 * (DNSKEY present), that a DS record links the chain of trust at the parent/registrar, that signing
 * algorithms are modern, and — by locally recomputing the DS digest per RFC 4034 §5.1.4 — that the
 * published DS actually references a live key.
 *
 * First round is presence-only: node:dns/promises cannot expose the AD flag or verify signatures, so
 * DNSKEY/DS/RRSIG are fetched via the Brew `dig` helper and parsed for their public fields. The
 * validation-dependent sub-checks (validates, rrsig_expiry, nsec3, chain_complete) require a
 * validating resolver / RRSIG-expiry parsing that +short cannot give, so they degrade to a single
 * advisory `info` each — never a false `warning`/`critical` (see spec §3, §7).
 */

const CHECK_ID = "infra.dnssec"

/**
 * The structured DNSSEC state persisted at results["infra.dnssec"] (pm/checks/dns.mdx §5) —
 * the DNS page's Zone panel one-liner. Nullable fields mean "could not be determined this run".
 */
export interface DnssecResults {
  signed: boolean
  ds_present: boolean | null
  ds_digest_types: number[]
  algorithms: number[]
  ds_matches_dnskey: boolean | null
  dane_ready: boolean
}

// RRSIG near-expiry lead time (spec default 72h) — used only by the future rrsig_expiry advisory.
const RRSIG_LEAD_HOURS = 72

interface DnskeyRecord {
  flags: number
  algorithm: number
  keyTag: number
  bits: number | null
  rdata: Buffer
}

interface DsRecord {
  keyTag: number
  algorithm: number
  digestType: number
  digest: string
}

const ALG_NAMES: Record<number, string> = {
  1: "RSAMD5",
  3: "DSA",
  5: "RSASHA1",
  6: "DSA-NSEC3-SHA1",
  7: "RSASHA1-NSEC3-SHA1",
  8: "RSASHA256",
  10: "RSASHA512",
  13: "ECDSAP256SHA256",
  14: "ECDSAP384SHA384",
  15: "ED25519",
  16: "ED448",
}

// RSASHA1 family (and other legacy algos) validators are removing.
const DEPRECATED_ALGOS = new Set([1, 3, 5, 6, 7])

function algName(algo: number): string {
  return ALG_NAMES[algo] ?? `algorithm ${algo}`
}

/** Canonical wire form of the owner name: lowercase, length-prefixed labels, root terminator. */
function ownerWire(domain: string): Buffer {
  const name = domain.replace(/\.$/, "").toLowerCase()
  const bufs: Buffer[] = []
  if (name.length > 0) {
    for (const label of name.split(".")) {
      const b = Buffer.from(label, "ascii")
      bufs.push(Buffer.from([b.length]), b)
    }
  }
  bufs.push(Buffer.from([0]))
  return Buffer.concat(bufs)
}

/** DNSKEY key tag per RFC 4034 Appendix B (algorithms other than 1). */
function keyTag(rdata: Buffer): number {
  let ac = 0
  for (let i = 0; i < rdata.length; i++) {
    ac += i & 1 ? rdata[i] : rdata[i] << 8
  }
  ac += (ac >> 16) & 0xffff
  return ac & 0xffff
}

/** Estimate the key size in bits from the DNSKEY public key material. */
function keyBits(algorithm: number, key: Buffer): number | null {
  switch (algorithm) {
    case 5:
    case 7:
    case 8:
    case 10: {
      // RFC 3110 RSA public key: [expLen][exponent][modulus], expLen 1 byte or 0+2 bytes.
      if (key.length < 3) return null
      let offset = 1
      let expLen = key[0]
      if (expLen === 0) {
        expLen = (key[1] << 8) | key[2]
        offset = 3
      }
      const modulusLen = key.length - offset - expLen
      return modulusLen > 0 ? modulusLen * 8 : null
    }
    case 13:
    case 15:
      return 256
    case 14:
      return 384
    case 16:
      return 456
    default:
      return null
  }
}

function parseDnskey(line: string): DnskeyRecord | null {
  const parts = line.trim().split(/\s+/)
  if (parts.length < 4) return null
  const flags = Number(parts[0])
  const protocol = Number(parts[1])
  const algorithm = Number(parts[2])
  if (!Number.isInteger(flags) || !Number.isInteger(algorithm)) return null
  let key: Buffer
  try {
    key = Buffer.from(parts.slice(3).join(""), "base64")
  } catch {
    return null
  }
  const head = Buffer.alloc(4)
  head.writeUInt16BE(flags & 0xffff, 0)
  head.writeUInt8(protocol & 0xff, 2)
  head.writeUInt8(algorithm & 0xff, 3)
  const rdata = Buffer.concat([head, key])
  return { flags, algorithm, keyTag: keyTag(rdata), bits: keyBits(algorithm, key), rdata }
}

function parseDs(line: string): DsRecord | null {
  const parts = line.trim().split(/\s+/)
  if (parts.length < 4) return null
  const keyTagN = Number(parts[0])
  const algorithm = Number(parts[1])
  const digestType = Number(parts[2])
  if (!Number.isInteger(keyTagN) || !Number.isInteger(digestType)) return null
  return {
    keyTag: keyTagN,
    algorithm,
    digestType,
    digest: parts.slice(3).join("").toUpperCase(),
  }
}

function hashForDigestType(type: number): string | null {
  if (type === 1) return "sha1"
  if (type === 2) return "sha256"
  if (type === 4) return "sha384"
  return null
}

/** Recompute the DS digest of a DNSKEY per RFC 4034 §5.1.4: digest = H(owner | DNSKEY_RDATA). */
function computeDsDigest(domain: string, rdata: Buffer, hash: string): string {
  return createHash(hash).update(ownerWire(domain)).update(rdata).digest("hex").toUpperCase()
}

export const dnssecCheck: Checker = {
  id: CHECK_ID,
  label: "DNSSEC",
  async run(ctx): Promise<CheckOutcome> {
    const domain = ctx.domain
    const findings: Finding[] = []

    // ---- infra.dnssec_signed (first round: DNSKEY presence) ----
    const dnskeyRes = await dig(domain, "DNSKEY")
    if (dnskeyRes.error) {
      // Transient: no snapshot — the UI must not render a false "unsigned".
      return {
        findings: [
          {
            id: "infra.dnssec_signed.unavailable",
            checkId: "infra.dnssec_signed",
            title: "DNSSEC status unavailable",
            severity: "info",
            detail: `Could not query DNSKEY for ${domain} (${dnskeyRes.error}). DNSSEC presence could not be determined this run.`,
            remediation:
              "Retry the audit later. If it persists, confirm the Brew `dig` binary is installed and the domain's authoritative nameservers are reachable.",
          },
        ],
      }
    }

    const keys = dnskeyRes.records.map(parseDnskey).filter((k): k is DnskeyRecord => k !== null)

    if (keys.length === 0) {
      // Unsigned zone — advisory only (an upgrade you're missing, not a break). Must NOT go amber.
      findings.push({
        id: "infra.dnssec_signed.unsigned",
        checkId: "infra.dnssec_signed",
        title: "Zone is not DNSSEC-signed",
        severity: "info",
        detail: `${domain} publishes no DNSKEY, so the zone is unsigned. DNS answers (MX, SPF, DKIM, DMARC, MTA-STS) carry no tamper-evidence and DANE/TLSA is impossible.`,
        remediation:
          "Enable DNSSEC at your DNS provider/registrar — it is one-click at most managed providers (Cloudflare, Route 53, Google Domains). After enabling, publish the DS at your registrar to complete the chain of trust.",
      })
      // infra.dnssec_dane_ready (derived): unsigned ⇒ DANE not possible.
      findings.push({
        id: "infra.dnssec_dane_ready.unsigned",
        checkId: "infra.dnssec_dane_ready",
        title: "DANE not possible (zone unsigned)",
        severity: "info",
        detail:
          "TLSA records are only trustworthy in a DNSSEC-signed, validating zone. This zone is unsigned, so DANE cannot be relied on.",
        remediation:
          "Complete DNSSEC first (enable signing + publish the DS), then publish TLSA records per the DANE/TLSA check.",
      })
      return {
        findings,
        results: {
          signed: false,
          ds_present: null,
          ds_digest_types: [],
          algorithms: [],
          ds_matches_dnskey: null,
          dane_ready: false,
        } satisfies DnssecResults,
      }
    }

    // Zone is signed.
    const uniqueAlgos = [...new Set(keys.map((k) => k.algorithm))]
    const ksks = keys.filter((k) => k.flags === 257)
    findings.push({
      id: "infra.dnssec_signed.ok",
      checkId: "infra.dnssec_signed",
      title: "Zone is DNSSEC-signed",
      severity: "ok",
      detail: `${domain} publishes ${keys.length} DNSKEY(s) (${ksks.length} KSK, ${keys.length - ksks.length} ZSK) using ${uniqueAlgos.map(algName).join(", ")}.`,
      evidence: keys
        .map((k) => `${k.flags} ${k.algorithm} (${algName(k.algorithm)}) keyTag=${k.keyTag}`)
        .join("; "),
    })

    // ---- infra.dnssec_algorithm (first round: parse DNSKEY algorithm) ----
    const deprecated = uniqueAlgos.filter((a) => DEPRECATED_ALGOS.has(a))
    if (deprecated.length > 0) {
      findings.push({
        id: "infra.dnssec_algorithm.deprecated",
        checkId: "infra.dnssec_algorithm",
        title: "Deprecated DNSSEC algorithm",
        severity: "warning",
        detail: `DNSKEY uses ${deprecated.map((a) => `${a} (${algName(a)})`).join(", ")} — RSASHA1-family algorithms are deprecated and being removed from validators.`,
        remediation:
          "Roll to a modern algorithm: ECDSAP256SHA256 (13) is compact and fast; RSASHA256 (8) is the RSA fallback. Update (republish) the DS at the registrar after the algorithm roll completes.",
        evidence: uniqueAlgos.map((a) => `${a} (${algName(a)})`).join(", "),
      })
    } else {
      findings.push({
        id: "infra.dnssec_algorithm.ok",
        checkId: "infra.dnssec_algorithm",
        title: "Modern signing algorithm",
        severity: "ok",
        detail: `Signing uses ${uniqueAlgos.map((a) => `${a} (${algName(a)})`).join(", ")} — a current, supported algorithm.`,
      })
    }

    // ---- infra.dnssec_key_rollover (first round advisory: static DNSKEY parse) ----
    const rolloverIssues: string[] = []
    for (const k of ksks) {
      if (
        (k.algorithm === 5 || k.algorithm === 7 || k.algorithm === 8 || k.algorithm === 10) &&
        k.bits !== null &&
        k.bits < 2048
      ) {
        rolloverIssues.push(`KSK keyTag=${k.keyTag} is RSA ${k.bits}-bit (< 2048)`)
      }
    }
    if (keys.length > 6) {
      rolloverIssues.push(
        `${keys.length} DNSKEYs in the set (stale keys from an incomplete rollover bloat responses)`,
      )
    }
    if (rolloverIssues.length > 0) {
      findings.push({
        id: "infra.dnssec_key_rollover.weak",
        checkId: "infra.dnssec_key_rollover",
        title: "Key rollover hygiene",
        severity: "warning",
        detail: `Rollover hygiene issues: ${rolloverIssues.join("; ")}.`,
        remediation:
          "Use ≥ 2048-bit RSA or ECDSA P-256 (algorithm 13); prune retired keys once the rollover completes; follow RFC 6781 rollover timing. Republish the DS after any KSK change.",
      })
    } else {
      findings.push({
        id: "infra.dnssec_key_rollover.ok",
        checkId: "infra.dnssec_key_rollover",
        title: "Key set looks healthy",
        severity: "ok",
        detail: `${keys.length} DNSKEY(s); no undersized RSA keys or stale-key bloat detected.`,
      })
    }

    // ---- infra.dnssec_ds_present + infra.dnssec_ds_algo_match (first round) ----
    let dsPresent: boolean | null = null
    let dsDigestTypes: number[] = []
    let dsMatches: boolean | null = null
    const dsRes = await dig(domain, "DS")
    if (dsRes.error) {
      findings.push({
        id: "infra.dnssec_ds_present.unavailable",
        checkId: "infra.dnssec_ds_present",
        title: "DS lookup unavailable",
        severity: "info",
        detail: `Could not query the parent DS for ${domain} (${dsRes.error}). Chain-of-trust presence could not be determined this run.`,
        remediation:
          "Retry the audit later. If it persists, confirm the parent/registrar nameservers are reachable and the Brew `dig` binary is installed.",
      })
    } else if (dsRes.empty) {
      dsPresent = false
      // Signed but no DS at parent — "island of security": validation impossible.
      findings.push({
        id: "infra.dnssec_ds_present.missing",
        checkId: "infra.dnssec_ds_present",
        title: "No DS at the parent (island of security)",
        severity: "warning",
        detail: `${domain} is signed (has DNSKEY) but publishes no DS in the parent zone, so no resolver on Earth can validate it — the zone provides zero DNSSEC protection.`,
        remediation:
          "Copy the DS/DNSKEY digest from your DNS provider into your registrar's DNSSEC panel so the parent publishes the DS. Use SHA-256 (digest type 2).",
      })
    } else {
      const dsRecords = dsRes.records.map(parseDs).filter((d): d is DsRecord => d !== null)
      dsPresent = true
      dsDigestTypes = [...new Set(dsRecords.map((d) => d.digestType))]
      findings.push({
        id: "infra.dnssec_ds_present.ok",
        checkId: "infra.dnssec_ds_present",
        title: "DS published at the parent",
        severity: "ok",
        detail: `The parent zone publishes ${dsRecords.length} DS record(s) for ${domain}, establishing the chain of trust.`,
        evidence: dsRecords
          .map((d) => `keyTag=${d.keyTag} alg=${d.algorithm} digestType=${d.digestType}`)
          .join("; "),
      })

      // Locally recompute the DS digest (RFC 4034 §5.1.4) and match against a live key.
      let matched: DsRecord | null = null
      let matchedSha256 = false
      for (const ds of dsRecords) {
        const hash = hashForDigestType(ds.digestType)
        if (!hash) continue
        const hit = keys.find(
          (k) => k.keyTag === ds.keyTag && computeDsDigest(domain, k.rdata, hash) === ds.digest,
        )
        if (hit) {
          matched = ds
          if (ds.digestType === 2) matchedSha256 = true
        }
      }

      dsMatches = matched !== null
      if (!matched) {
        findings.push({
          id: "infra.dnssec_ds_algo_match.mismatch",
          checkId: "infra.dnssec_ds_algo_match",
          title: "DS does not match any live key",
          severity: "critical",
          detail: `No published DS matches any live DNSKEY (recomputed digests differ). The chain of trust is broken — validating resolvers will return SERVFAIL and the domain goes dark. This usually follows a key change where the parent DS was not updated.`,
          remediation:
            "Republish the DS at the registrar so it matches the current KSK: the DS key tag and digest must correspond to a key in the live apex DNSKEY RRset. Use SHA-256 (digest type 2), never SHA-1 (type 1).",
          evidence: dsRecords
            .map((d) => `DS keyTag=${d.keyTag} digestType=${d.digestType}`)
            .join("; "),
        })
      } else if (!matchedSha256) {
        // Matches, but only via a deprecated SHA-1 (digest type 1) DS.
        findings.push({
          id: "infra.dnssec_ds_algo_match.sha1",
          checkId: "infra.dnssec_ds_algo_match",
          title: "DS uses deprecated SHA-1 digest",
          severity: "warning",
          detail: `The published DS matches a live KSK but uses SHA-1 (digest type 1), which is deprecated for DS digests.`,
          remediation:
            "Republish the DS at the registrar using SHA-256 (digest type 2). Remove the SHA-1 (type 1) DS once the SHA-256 DS is live and validating.",
          evidence: `keyTag=${matched.keyTag} digestType=${matched.digestType}`,
        })
      } else {
        findings.push({
          id: "infra.dnssec_ds_algo_match.ok",
          checkId: "infra.dnssec_ds_algo_match",
          title: "DS matches a live KSK",
          severity: "ok",
          detail: `The published SHA-256 DS (keyTag=${matched.keyTag}) matches the recomputed digest of a live KSK — the parent correctly references the current key.`,
          evidence: `keyTag=${matched.keyTag} digestType=${matched.digestType}`,
        })
      }
    }

    // ---- infra.dnssec_soa_signed (first round: presence heuristic) ----
    const soa = await resolveSoa(domain)
    if (soa.record) {
      findings.push({
        id: "infra.dnssec_soa_signed.present",
        checkId: "infra.dnssec_soa_signed",
        title: "Core RRsets present (RRSIG coverage pending deep check)",
        severity: "info",
        detail: `The apex SOA resolves for ${domain}. Confirming that SOA/MX/TXT (SPF/DMARC/MTA-STS) are each covered by an RRSIG — not just the apex DNSKEY — requires the future +dnssec deep check.`,
        remediation:
          "Ensure your signer covers all RRsets, not only the apex; re-sign the full zone. Verification of per-RRset RRSIG coverage will run once the +dnssec probe path ships.",
      })
    }

    // ---- infra.dnssec_dane_ready (first round: derived from signed only) ----
    findings.push({
      id: "infra.dnssec_dane_ready.signed",
      checkId: "infra.dnssec_dane_ready",
      title: "DANE-capable (pending validation)",
      severity: "info",
      detail:
        "The zone is signed, so it can host TLSA records. Full DANE trust also requires that a validating resolver accepts the chain (AD=1), which is confirmed by the future validation probe.",
      remediation:
        "Complete DNSSEC validation (publish/verify the DS), then publish TLSA records per the DANE/TLSA check to enable DANE.",
    })

    // ---- FUTURE sub-checks: presence-only Node cannot validate. One advisory info each. ----
    findings.push({
      id: "infra.dnssec_validates.pending",
      checkId: "infra.dnssec_validates",
      title: "Chain validation pending",
      severity: "info",
      detail:
        "node:dns/promises returns cached answers and does not expose the AD flag. Confirming a validating resolver accepts the chain (AD=1) and disambiguating bogus (SERVFAIL with CD=0 but success with CD=1) requires the future `dig +dnssec` / validating-resolver probe.",
      remediation:
        "When the deep-check path ships it will query 1.1.1.1 / 8.8.8.8 with +dnssec and read the AD flag. If it reports bogus, re-sign the zone or correct the DS to match the live KSK.",
    })
    findings.push({
      id: "infra.dnssec_rrsig_expiry.pending",
      checkId: "infra.dnssec_rrsig_expiry",
      title: "RRSIG expiry check pending",
      severity: "info",
      detail: `RRSIG Signature Expiration is not exposed by node:dns/promises. Checking apex RRSIGs for expiry (and near-expiry within the ${RRSIG_LEAD_HOURS}h lead time) requires the future +dnssec probe.`,
      remediation:
        "Keep automatic re-signing enabled on your signer so RRSIGs auto-refresh well before expiry. The scheduled deep check will warn within the lead time and flag an already-expired RRSIG as critical.",
    })
    findings.push({
      id: "infra.dnssec_nsec3.pending",
      checkId: "infra.dnssec_nsec3",
      title: "NSEC3 parameter check pending",
      severity: "info",
      detail:
        "Reading NSEC3PARAM (hash, iterations, salt, opt-out) requires querying a nonexistent name with +dnssec, which node:dns/promises cannot do. This runs in the future deep check.",
      remediation:
        "Per RFC 9276, set NSEC3 iterations to 0 with an empty/short salt and disable opt-out unless you run a large delegation-heavy zone. The deep check will verify these parameters.",
    })
    findings.push({
      id: "infra.dnssec_chain_complete.pending",
      checkId: "infra.dnssec_chain_complete",
      title: "Full chain walk pending",
      severity: "info",
      detail:
        "Walking the complete chain root → TLD → zone (DS → DNSKEY → RRSIG at every hop) requires a validator library or +dnssec probe. First round confirms the local DS-to-KSK link only (see DS match above).",
      remediation:
        "Ensure the parent DS key tag exists in the apex DNSKEY RRset. The future chain-walk deep check will verify every delegation hop links.",
    })

    return {
      findings,
      results: {
        signed: true,
        ds_present: dsPresent,
        ds_digest_types: dsDigestTypes,
        algorithms: uniqueAlgos,
        ds_matches_dnskey: dsMatches,
        dane_ready: dsPresent === true,
      } satisfies DnssecResults,
    }
  },
}
