import { resolveMx } from "./dns-util"
import type { Checker, Finding } from "./types"

/**
 * SMTP Server Security & Hardening (pm/checks/smtp_security.mdx).
 *
 * This checker audits the SMTP-conversation layer of a domain's MX and submission hosts: open-relay
 * posture, VRFY/EXPN address harvesting, AUTH-in-cleartext, submission-port hygiene (587/465 vs 25),
 * banner leakage, greylisting/backscatter behavior, and pipelining/flood limits — prescribing the
 * exact MTA config to close each hole.
 *
 * Per the spec's §3, §6 and §7 "First round vs future" table, EVERY sub-check here is FUTURE: there
 * is NO pure-DNS SMTP-hardening signal. The whole check is gated behind an outbound SMTP-probe
 * subsystem (an internal net/tls SMTP client with a strict state machine, or shelling to `swaks`)
 * plus port-25/587/465 egress. None of it runs on first-round `node:dns/promises`, and the relay
 * probe's safety invariants are load-bearing (never send DATA, reserved non-routable identities only,
 * one connection per host, bounded commands) — fabricating results or half-implementing a probe would
 * risk getting the auditor's own IP blacklisted. So we do NOT manufacture open-relay/VRFY/AUTH
 * verdicts. We emit a single `info` "pending" finding describing exactly what the probe will verify,
 * enriched with the MX host list (the spec's only first-round-safe DNS dependency, reused from
 * ./mx_routing.mdx and never re-derived). We never emit `warning`/`critical` from this future check,
 * and we never throw.
 */
export const smtpSecurityCheck: Checker = {
  id: "infra.smtp_security",
  label: "SMTP Server Security",
  async run(ctx): Promise<Finding[]> {
    // The spec's sole first-round-safe DNS dependency: the MX host list. These are the hosts a future
    // probe would connect to on 25 (MX relay) and 587/465 (submission, defaulting to the MX names).
    // Resolve gracefully so the pending finding can name them — any failure still degrades to the
    // same single `info`, never a crash, never a false critical.
    const mx = await resolveMx(ctx.domain)
    const hosts = [...mx.records].sort((a, b) => a.priority - b.priority).map((r) => r.exchange)

    const willVerify =
      "Once the outbound SMTP-probe subsystem ships (an internal net/tls SMTP client or `swaks`, with " +
      "port-25/587/465 egress), each MX host will be probed on 25 and each submission endpoint on " +
      "587/465 with a SAFE, non-destructive conversation (one connection per host, <= ~12 commands, " +
      "5s timeouts). It will verify: open relay (infra.open_relay) via a MAIL FROM / RCPT TO to the " +
      "reserved non-routable off-domain recipient probe.invalid-audit.test that must be 5xx-rejected " +
      "-- NEVER sending DATA, so no message is ever relayed -- plus relay-evasion address forms " +
      "(infra.open_relay_variants: percent-hack, bang-path, source-route, quoted); VRFY/EXPN refusal " +
      "(infra.vrfy_disabled / infra.expn_disabled); AUTH advertised only after STARTTLS " +
      "(infra.auth_requires_tls, via a pre/post-STARTTLS EHLO capability diff); submission ports " +
      "present and AUTH-gated (infra.submission_ports / infra.submission_auth_required); banner " +
      "hygiene (infra.banner_hygiene: no software/version or generic/IP-literal host); required valid " +
      "HELO (infra.helo_required); not an open proxy (infra.no_open_proxy); and the advisory " +
      "greylisting / backscatter / pipelining-sanity / max-RCPT / STARTTLS-presence-and-downgrade " +
      "signals. A healthy server 5xx-rejects the relay probe and is recorded as 'correctly refused'."

    const enableFix =
      "Enable the SMTP-probe subsystem (config.yaml `infra.smtpProbe`) and ensure outbound SMTP egress " +
      "on ports 25/587/465 from this host; where egress is blocked, use the domain's skip-SMTP-probe " +
      "switch. No DNS-only fix applies -- this audit requires a live (safe, no-DATA) SMTP conversation " +
      "to each MX and submission host."

    if (mx.error) {
      // Transient DNS failure (SERVFAIL/timeout) -- distinct from "genuinely no MX". Still info: the
      // probe is future regardless, and we must not manufacture a problem.
      return [
        {
          id: "infra.smtp_security.pending",
          checkId: "infra",
          title: "SMTP server security probe pending (MX lookup failed)",
          severity: "info",
          detail: `The SMTP Server Security audit is an outbound SMTP probe that is not yet enabled in this round, and the MX lookup for ${ctx.domain} failed transiently (${mx.error}), so the host list could not be enumerated. ${willVerify}`,
          remediation: `Retry the audit later; if it persists, verify the domain's authoritative nameservers. ${enableFix}`,
        },
      ]
    }

    if (hosts.length === 0) {
      // No MX at all: no inbound mail hosts to probe. Defer the missing-MX finding to the MX check.
      return [
        {
          id: "infra.smtp_security.pending",
          checkId: "infra",
          title: "SMTP server security probe pending (no MX records)",
          severity: "info",
          detail: `${ctx.domain} has no MX records, so there are no inbound mail hosts to speak SMTP to. This audit consumes the MX host list rather than re-deriving it -- see the MX routing check for the missing-MX finding. ${willVerify}`,
          remediation: `Publish MX records for the domain (see the MX routing check), then enable the SMTP probe to audit each host's relay, submission and banner posture. ${enableFix}`,
        },
      ]
    }

    const targets = hosts.map((h) => `${h}:25 (mx), ${h}:587/465 (submission)`).join("; ")
    return [
      {
        id: "infra.smtp_security.pending",
        checkId: "infra",
        title: "SMTP server security probe pending",
        severity: "info",
        detail: `The SMTP Server Security audit (open relay, VRFY/EXPN, AUTH-after-TLS, submission ports, banner hygiene, backscatter/greylisting) is an outbound SMTP conversation, not a DNS lookup, so it is not part of this first round -- no relay/auth/banner findings are reported yet for ${ctx.domain}'s ${hosts.length} MX host(s). ${willVerify}`,
        remediation: enableFix,
        evidence: targets,
      },
    ]
  },
}
