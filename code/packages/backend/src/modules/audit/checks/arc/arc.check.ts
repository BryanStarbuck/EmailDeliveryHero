import { resolveTxt } from "../dns-util"
import type { Checker, Finding } from "../types"

/**
 * ARC (Authenticated Received Chain, RFC 8617) — advisory companion to DMARC. ARC lets a forwarder
 * or mailing list preserve the SPF/DKIM/DMARC results it observed, cryptographically sealed, across a
 * hop that would otherwise break DMARC. It is *not* a published DNS record: the chain lives in three
 * header fields (ARC-Seal / ARC-Message-Signature / ARC-Authentication-Results) added to a message in
 * transit, so most of ARC can only be audited from a captured forwarded message sample.
 *
 * First round (pure DNS/config, deterministic):
 *   - arc.applicable          — is ARC even relevant? (enforcing DMARC + declared forwarding)
 *   - arc.forwarding_risk     — enforcing DMARC + declared forwarder with no verified chain
 *   - arc.selector_dns        — the ARC signer's <selector>._domainkey.<signer> resolves
 *   - arc.signature_algorithm — the resolved signer key is modern (rsa-sha256/ed25519, adequate bits)
 *
 * Future (needs a swaks-through-forwarder capture + OpenARC/validator over a real message):
 *   arc.chain_present, arc.seal_valid, arc.ams_valid, arc.instance_ordering, arc.oldest_pass,
 *   arc.cv_at_i1, arc.aar_completeness, arc.receiver_honors — stubbed as a single `info`, never a
 *   fabricated warning/critical.
 *
 * All findings use checkId "arc" (the sub-check prefix) and roll into the DMARC dashboard cell.
 */

interface ArcForwarder {
  label: string
  forwardAddress: string
  /** Expected ARC signing domain (d=); learned from config or an observed sample. */
  signerDomain?: string
  /** Expected ARC signing selector (s=). */
  signerSelector?: string
}

/**
 * The forwarders / mailing lists a domain declares it sends through (spec §4 per-domain config,
 * `arc_forwarders` table). `CheckContext` carries no forwarder config this round, so this is empty;
 * once the store surfaces `domains.arc.forwarders` the same loop below verifies each signer. Returning
 * a typed array (not a literal) keeps the downstream logic exercised rather than narrowed to `never`.
 */
function declaredForwarders(_ctx: { domain: string }): ArcForwarder[] {
  return []
}

/** Parse the DMARC policy tag (p=) from a domain's `_dmarc` TXT records. */
function dmarcPolicy(records: string[]): string | null {
  const rec = records.find((r) => /^v=DMARC1\b/i.test(r.trim()))
  if (!rec) return null
  const m = /(?:^|;)\s*p\s*=\s*([a-zA-Z]+)/.exec(rec)
  return m ? m[1].toLowerCase() : null
}

/** A stable, filesystem/id-safe token derived from a human label. */
function slug(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
}

/** Read one tag (e.g. "p", "k") out of a DKIM-style key record. */
function tag(record: string, name: string): string | null {
  const m = new RegExp(`(?:^|;)\\s*${name}\\s*=\\s*([^;]*)`, "i").exec(record)
  return m ? m[1].trim() : null
}

/** Rough RSA modulus size (bits) from the base64 `p=` public key. SPKI DER wrapper is ~38 bytes. */
function estimateRsaBits(p: string): number {
  const clean = p.replace(/[^A-Za-z0-9+/]/g, "")
  const bytes = Math.floor((clean.length * 3) / 4)
  return Math.max(0, bytes - 38) * 8
}

/**
 * Verify one ARC signer's DKIM-style selector in DNS: resolve `<selector>._domainkey.<signerDomain>`,
 * confirm a non-empty key is published, and sanity-check the algorithm/key strength (RFC 8301, mirrors
 * DKIM). Covers `arc.selector_dns` and `arc.signature_algorithm`.
 */
async function inspectSigner(f: ArcForwarder): Promise<Finding[]> {
  const key = slug(f.label)
  if (!f.signerDomain || !f.signerSelector) {
    return [
      {
        id: `arc.selector_dns.${key}`,
        checkId: "arc",
        title: `ARC signer not yet known for ${f.label}`,
        severity: "info",
        detail: `No ARC signing domain (d=) / selector (s=) is recorded for forwarder "${f.label}", so its ARC key cannot be verified in DNS yet. The selector is entered in the forwarder config or auto-discovered from a captured forwarded sample.`,
        remediation: `In this domain's ARC / forwarding settings, record the ARC signing domain and selector that "${f.label}" uses, or capture a forwarded sample so EmailDeliveryHero can discover it.`,
      },
    ]
  }

  const name = `${f.signerSelector}._domainkey.${f.signerDomain}`
  const { records, empty, error } = await resolveTxt(name)

  if (error) {
    return [
      {
        id: `arc.selector_dns.${key}`,
        checkId: "arc",
        title: `Could not resolve ARC signer selector for ${f.label}`,
        severity: "info",
        detail: `DNS lookup for TXT ${name} failed transiently (${error}); the ARC signer key could not be checked this run.`,
        remediation:
          "Retry the audit. If it persists, verify the signer domain's authoritative nameservers.",
        evidence: name,
      },
    ]
  }

  if (empty || records.length === 0) {
    return [
      {
        id: `arc.selector_dns.${key}`,
        checkId: "arc",
        title: `ARC signer selector does not resolve for ${f.label}`,
        severity: "critical",
        detail: `The ARC signer's selector ${name} returned no record (NXDOMAIN / empty). The ARC-Message-Signature and ARC-Seal from "${f.label}" cannot be verified, so receivers will discard the ARC evidence and fall back to the raw DMARC failure.`,
        remediation: `Ask "${f.label}" to publish (or repair) its ARC signing key. If you operate the sealer, publish the 2048-bit key TXT record at ${name} with "v=DKIM1; k=rsa; p=<base64 public key>".`,
        evidence: name,
      },
    ]
  }

  const rec = records.find((r) => /(?:^|;)\s*p\s*=/i.test(r)) ?? records[0]
  const p = tag(rec, "p")
  if (p === null || p === "") {
    return [
      {
        id: `arc.selector_dns.${key}`,
        checkId: "arc",
        title: `ARC signer key is revoked/empty for ${f.label}`,
        severity: "critical",
        detail: `The selector ${name} exists but publishes an empty p= (a revoked key). The ARC signatures from "${f.label}" cannot be verified.`,
        remediation: `Ask "${f.label}" to republish a valid public key at ${name}. If you operate the sealer, restore the 2048-bit key: "v=DKIM1; k=rsa; p=<base64 public key>".`,
        evidence: rec,
      },
    ]
  }

  const out: Finding[] = [
    {
      id: `arc.selector_dns.${key}`,
      checkId: "arc",
      title: `ARC signer selector resolves for ${f.label}`,
      severity: "ok",
      detail: `${name} publishes a key, so the ARC-Message-Signature / ARC-Seal from "${f.label}" can be verified against DNS.`,
      evidence: rec,
    },
  ]

  const k = (tag(rec, "k") ?? "rsa").toLowerCase()
  if (k !== "rsa" && k !== "ed25519") {
    out.push({
      id: `arc.signature_algorithm.${key}`,
      checkId: "arc",
      title: `ARC signer uses a legacy key type for ${f.label}`,
      severity: "warning",
      detail: `The ARC signer key at ${name} declares k=${k}. Modern ARC uses rsa-sha256 or ed25519-sha256; SHA-1 / legacy key types are not trusted (RFC 8301).`,
      remediation: `Ask "${f.label}" to reissue the ARC signing key as RSA-SHA256 (2048-bit) or ed25519 and republish it at ${name}.`,
      evidence: rec,
    })
  } else if (k === "rsa") {
    const bits = estimateRsaBits(p)
    if (bits < 1024) {
      out.push({
        id: `arc.signature_algorithm.${key}`,
        checkId: "arc",
        title: `ARC signer key is weak for ${f.label}`,
        severity: "warning",
        detail: `The RSA key at ${name} is approximately ${bits}-bit — below the RFC 8301 minimum of 1024-bit (2048-bit recommended). Weak keys can be forged and are increasingly distrusted.`,
        remediation: `Ask "${f.label}" to reissue a 2048-bit RSA (or ed25519) ARC signing key and republish it at ${name}.`,
        evidence: rec,
      })
    }
  }

  return out
}

export const arcCheck: Checker = {
  id: "dmarc.arc",
  label: "ARC (Authenticated Received Chain)",
  async run(ctx): Promise<Finding[]> {
    // 1. Applicability rests on the DMARC policy — resolve it ourselves (CheckContext has no policy).
    const dmarc = await resolveTxt(`_dmarc.${ctx.domain}`)
    if (dmarc.error) {
      return [
        {
          id: "arc.applicable",
          checkId: "arc",
          title: "Could not determine ARC applicability",
          severity: "info",
          detail: `DNS lookup for TXT _dmarc.${ctx.domain} failed transiently (${dmarc.error}); ARC applicability depends on the DMARC policy, so it could not be evaluated this run.`,
          remediation:
            "Retry the audit. If it persists, check the domain's authoritative nameservers.",
          evidence: `_dmarc.${ctx.domain}`,
        },
      ]
    }

    const policy = dmarcPolicy(dmarc.records)
    const enforcing = policy === "quarantine" || policy === "reject"

    // 2. Not enforcing → ARC brings nothing; a directly-sent or p=none message is never rescued by it.
    if (!enforcing) {
      return [
        {
          id: "arc.applicable",
          checkId: "arc",
          title: "ARC not applicable — DMARC is not enforcing",
          severity: "info",
          detail: policy
            ? `DMARC policy is p=${policy}. ARC only matters when a message that PASSED DMARC at origin is broken by a forwarding hop under an enforcing policy (p=quarantine/reject). At p=none there is no rejection for ARC to override.`
            : `${ctx.domain} publishes no enforcing DMARC policy. ARC only matters under p=quarantine/reject, where forwarded mail would otherwise be rejected.`,
          remediation:
            "No action needed for ARC. Revisit this once you move DMARC to p=quarantine or p=reject and begin sending through mailing lists or forwarders.",
          evidence: policy ? `p=${policy}` : undefined,
        },
      ]
    }

    // 3. Enforcing DMARC. ARC now matters only for mail routed through forwarders/lists.
    const forwarders = declaredForwarders(ctx)
    if (forwarders.length === 0) {
      return [
        {
          id: "arc.applicable",
          checkId: "arc",
          title: "ARC not applicable — no forwarding declared",
          severity: "info",
          detail: `DMARC is enforcing (p=${policy}), but no forwarders or mailing lists are declared for ${ctx.domain}. ARC only helps on hops that mutate the message (forwarders, listservs, .forward rules, security gateways); with none declared there is no chain to verify.`,
          remediation:
            "If this domain does send through any forwarder or mailing list, declare it in the domain's ARC / forwarding settings — that unlocks the signer-selector DNS check today and the forwarded-sample capture later.",
          evidence: `p=${policy}`,
        },
      ]
    }

    // 4. Enforcing DMARC + declared forwarders: run the deterministic per-forwarder DNS/config checks.
    const findings: Finding[] = [
      {
        id: "arc.applicable",
        checkId: "arc",
        title: "ARC applies to this domain",
        severity: "info",
        detail: `DMARC is enforcing (p=${policy}) and ${forwarders.length} forwarder(s)/list(s) are declared, so ARC preservation matters on those paths.`,
        remediation:
          "Confirm each declared forwarder applies a valid ARC chain (cv=pass); the sub-checks below verify each signer's DNS key.",
        evidence: `p=${policy}`,
      },
    ]

    for (const f of forwarders) {
      findings.push({
        id: `arc.forwarding_risk.${slug(f.label)}`,
        checkId: "arc",
        title: `Forwarding path may break DMARC without ARC — ${f.label}`,
        severity: "warning",
        detail: `${ctx.domain} enforces DMARC (p=${policy}) and sends through "${f.label}" (${f.forwardAddress}). Forwarding breaks SPF alignment and often the DKIM signature, so unless "${f.label}" seals a valid ARC chain, legitimate mail through it is silently quarantined or rejected. No verified chain exists for it yet.`,
        remediation: `Confirm "${f.label}" applies ARC (cv=pass). For lists you run, enable ARC sealing on the MLM (e.g. Mailman 3, or mlmmj + OpenARC); for third-party forwarders, ask them to enable ARC sealing.`,
      })
      findings.push(...(await inspectSigner(f)))
    }

    // 5. Everything about a real chain needs a captured forwarded message (FUTURE). Stub as one info;
    //    never fabricate a chain verdict.
    findings.push({
      id: "arc.chain_present",
      checkId: "arc",
      title: "ARC chain not yet sampled",
      severity: "info",
      detail:
        "Verifying an actual ARC chain — chain present, ARC-Seal valid (cv=pass), ARC-Message-Signature valid, contiguous/ordered i= instances, i=1 seal cv=none, oldest-hop origin authentication pass, and AAR completeness — requires a captured forwarded message. No sample has been captured for this domain yet.",
      remediation:
        'Use the admin-only "Capture sample" probe to send a swaks test through a declared forwarder and retrieve the forwarded copy; EmailDeliveryHero will then parse and validate the ARC-Seal / ARC-Message-Signature / ARC-Authentication-Results headers.',
    })

    return findings
  },
}
