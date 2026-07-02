import { createHash, X509Certificate } from "node:crypto"

/**
 * The `3 1 1` TLSA record generator (pm/checks/dane_tlsa.mdx §4): given a pasted PEM certificate
 * (or, in the FUTURE probe round, the live cert grabbed off `:25` STARTTLS) it emits the exact
 * DANE-EE / SPKI / SHA-256 record to publish at `_25._tcp.<mx-host>`. Selector 1 pins the
 * SubjectPublicKeyInfo, so the digest is SHA-256 over the DER-encoded SPKI — the pin survives a
 * cert renewal that reuses the key pair.
 */

/** What the generator returns — the record line plus the pieces the UI shows/copies. */
export interface GeneratedTlsaRecord {
  /** The canonical MX host the record is for (trailing dot / whitespace trimmed, lower-cased). */
  mxHost: string
  /** The TLSA owner name, e.g. `_25._tcp.mail.example.com.` */
  recordName: string
  /** Hex SHA-256 of the certificate's DER SubjectPublicKeyInfo (the association data). */
  spkiSha256: string
  /** The complete zone-file line: `_25._tcp.<mx>. <ttl> IN TLSA 3 1 1 <digest>`. */
  record: string
  /** Certificate subject CN/DN — lets the user confirm they pasted the right cert. */
  subject: string
  /** Certificate notAfter — a heads-up when the pasted cert is already expired. */
  validTo: string
}

/** Recommended TLSA TTL (spec §2 `infra.dane_ttl_sane`): 1h so re-pins propagate quickly. */
const DEFAULT_TTL = 3600

/**
 * Build the `3 1 1` TLSA record for one MX host from a PEM certificate. Throws an `Error` with a
 * user-readable message when the PEM does not parse — the controller maps it to a 400.
 */
export function generateTlsa311(
  pem: string,
  mxHost: string,
  ttl: number = DEFAULT_TTL,
): GeneratedTlsaRecord {
  const host = mxHost.trim().replace(/\.$/, "").toLowerCase()
  if (host.length === 0) throw new Error("An MX hostname is required")

  let cert: X509Certificate
  try {
    cert = new X509Certificate(pem)
  } catch {
    throw new Error(
      "Could not parse the pasted certificate — paste the full PEM including the BEGIN/END CERTIFICATE lines",
    )
  }

  // Selector 1 (SPKI) + matching type 1 (SHA-256): digest the DER SubjectPublicKeyInfo.
  const spkiDer = cert.publicKey.export({ type: "spki", format: "der" })
  const spkiSha256 = createHash("sha256").update(spkiDer).digest("hex")

  const recordName = `_25._tcp.${host}.`
  return {
    mxHost: host,
    recordName,
    spkiSha256,
    record: `${recordName} ${ttl} IN TLSA 3 1 1 ${spkiSha256}`,
    subject: cert.subject,
    validTo: cert.validTo,
  }
}
