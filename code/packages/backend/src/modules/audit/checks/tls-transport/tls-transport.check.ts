import { resolveMx } from "./dns-util"
import type { Checker, Finding } from "./types"

/**
 * STARTTLS Transport Encryption & MX TLS Certificate Health (pm/checks/tls_transport.mdx).
 *
 * This checker audits opportunistic transport TLS on a domain's inbound MX hosts: whether each MX
 * advertises STARTTLS (RFC 3207), and whether the presented certificate is valid, name-matching,
 * chain-trusted, current on protocol/cipher, etc. It is the enforcement-free sibling of MTA-STS and
 * DANE — it measures whether TLS is *offered and healthy*, not whether it is *enforced*.
 *
 * Per the spec's §7 "First round vs future" table, EVERY sub-check here is FUTURE: the entire check
 * is gated behind an outbound SMTP+TLS probe harness (EHLO -> STARTTLS -> handshake -> certificate
 * inspection via node:net/node:tls or shelling to `openssl s_client` / `swaks`), plus an admin
 * toggle for hosts where outbound port 25 is blocked. None of it runs on first-round
 * `node:dns/promises`, so we do NOT fabricate handshake/cert results. We emit a single `info`
 * "pending" finding describing exactly what the probe will verify, enriched with the MX host list
 * (the spec's only DNS dependency — reused from ./mx_routing.mdx, never re-derived here). We never
 * emit `warning`/`critical` from this future check, and we never throw.
 */
export const tlsTransportCheck: Checker = {
  id: "infra.tls_transport",
  label: "STARTTLS & MX TLS",
  async run(ctx): Promise<Finding[]> {
    // The spec's sole first-round-safe DNS dependency: the MX host list. Resolve it gracefully so
    // the pending finding can name the hosts a future probe would connect to. Any failure here
    // still degrades to the same single `info` — never a crash, never a false critical.
    const mx = await resolveMx(ctx.domain)
    const hosts = [...mx.records].sort((a, b) => a.priority - b.priority).map((r) => r.exchange)

    const willVerify =
      "Once the SMTP+TLS probe harness ships, each MX host will be probed on port 25: connect, " +
      "EHLO, confirm the 250-STARTTLS capability, run the TLS handshake with SNI, then inspect the " +
      "leaf certificate — validity window, hostname (SAN/CN) match per RFC 6125, chain trust against " +
      "Node's bundled Mozilla CA store, negotiated protocol (>= TLS 1.2), cipher strength/forward " +
      "secrecy, expiry runway (14/30-day thresholds), downgrade resistance, SNI handling, OCSP " +
      "staple, key strength, and signature algorithm."

    if (mx.error) {
      // Transient DNS failure (SERVFAIL/timeout) — distinct from "genuinely no MX". Still info: the
      // probe is future regardless, and we must not manufacture a problem.
      return [
        {
          id: "infra.tls_transport.pending",
          checkId: "infra",
          title: "TLS transport probe pending (MX lookup failed)",
          severity: "info",
          detail: `The STARTTLS & MX TLS audit is an outbound SMTP+TLS probe that is not yet enabled in this round, and the MX lookup for ${ctx.domain} failed transiently (${mx.error}), so the host list could not be enumerated. ${willVerify}`,
          remediation:
            "Retry the audit later; if it persists, verify the domain's authoritative nameservers. Enable the TLS probe once the SMTP+TLS harness (and the admin toggle for port-25-blocked hosts) ships.",
        },
      ]
    }

    if (hosts.length === 0) {
      // No MX at all: the spec says skip with info and defer to the MX-routing finding.
      return [
        {
          id: "infra.tls_transport.pending",
          checkId: "infra",
          title: "TLS transport probe pending (no MX records)",
          severity: "info",
          detail: `${ctx.domain} has no MX records, so there are no inbound mail hosts to probe for STARTTLS/MX TLS. This audit consumes the MX host list rather than re-deriving it — see the MX routing check for the missing-MX finding. ${willVerify}`,
          remediation:
            "Publish MX records for the domain (see the MX routing check), then enable the TLS probe once the SMTP+TLS harness ships to audit each MX host's transport encryption.",
        },
      ]
    }

    return [
      {
        id: "infra.tls_transport.pending",
        checkId: "infra",
        title: "TLS transport probe pending",
        severity: "info",
        detail: `The STARTTLS & MX TLS certificate audit is an outbound SMTP+TLS probe (EHLO -> STARTTLS -> handshake -> certificate inspection) that is not part of this first round, so no TLS/certificate findings are reported yet for ${ctx.domain}'s ${hosts.length} MX host(s). ${willVerify}`,
        remediation:
          "Enable the TLS probe once the SMTP+TLS harness ships (and configure the admin 'TLS probe' toggle for hosts where outbound port 25 is blocked). No DNS-only fix applies — this audit requires a live handshake to each MX host.",
        evidence: hosts.join(", "),
      },
    ]
  },
}
