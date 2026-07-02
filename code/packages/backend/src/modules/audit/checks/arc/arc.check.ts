import { resolveTxt } from "../dns-util"
import type { ArcForwarderConfig, CheckContext, Checker, CheckOutcome, Finding } from "../types"

/**
 * ARC (Authenticated Received Chain, RFC 8617) — advisory companion to DMARC. ARC lets a forwarder
 * or mailing list preserve the SPF/DKIM/DMARC results it observed, cryptographically sealed, across a
 * hop that would otherwise break DMARC. It is *not* a published DNS record: the chain lives in three
 * header fields (ARC-Seal / ARC-Message-Signature / ARC-Authentication-Results) added to a message in
 * transit, so most of ARC can only be audited from a captured forwarded message sample.
 *
 * First round (pure DNS/config, deterministic — pm/checks/arc.mdx §3/§7):
 *   - arc.applicable          — is ARC even relevant? (enforcing DMARC + declared forwarding)
 *   - arc.forwarding_risk     — enforcing DMARC + declared forwarder with no verified chain
 *   - arc.selector_dns        — the ARC signer's <selector>._domainkey.<signer> resolves
 *   - arc.signature_algorithm — the resolved signer key is modern (rsa-sha256/ed25519, adequate bits)
 *
 * Future (needs a swaks-through-forwarder capture + OpenARC/validator over a real message):
 *   arc.chain_present, arc.seal_valid, arc.ams_valid, arc.instance_ordering, arc.oldest_pass,
 *   arc.cv_at_i1, arc.aar_completeness, arc.receiver_honors — stubbed as a single `info`, never a
 *   fabricated warning/critical. Their columns in the structured payload stay null until a sample
 *   exists (the nullable arc_check_results columns, pm/checks/arc.mdx §5).
 *
 * All findings use checkId "arc" (the sub-check prefix) and roll into the DMARC dashboard cell.
 */

/** One declared forwarder's first-round DNS observation (feeds `results.arc.forwarders`). */
interface ArcForwarderObservation {
  label: string
  forwardAddress: string
  signerDomain: string | null
  signerSelector: string | null
  /** `<selector>._domainkey.<signerDomain>` resolved with a non-empty key; null when unknown. */
  selectorResolves: boolean | null
  /**
   * The raw TXT answer at `<selector>._domainkey.<signer>` — the explainer's signer-key card body
   * (pm/checks/arc.mdx §9.11). Null when the signer is unknown or the name did not resolve.
   */
  rawKeyRecord: string | null
  /** The parsed `k=` tag, defaulted "rsa" when the record resolves (pm/checks/arc.mdx §9.11). */
  keyType: string | null
  /** Estimated RSA modulus bits; null for ed25519 / unresolved keys (pm/checks/arc.mdx §9.11). */
  keyBits: number | null
}

/**
 * The structured per-run ARC observation persisted as `results.arc` inside the audit file —
 * the file-store mapping of the `arc_check_results` row (pm/checks/arc.mdx §5). Almost everything
 * is nullable: first-round runs record only applicability, forwarding risk, and the selector-DNS
 * results; the sample-derived columns fill in once a forwarded message is captured.
 */
export interface ArcResults {
  /** DMARC enforcing AND forwarding declared; null when the DMARC policy could not be read. */
  applicable: boolean | null
  /** Enforcing DMARC + declared forwarding with no verified chain (the first-round warning). */
  forwardingRisk: boolean | null
  /** Per-declared-forwarder signer/selector DNS observations (the arc_forwarders reference). */
  forwarders: ArcForwarderObservation[]
  /** id/hash of the captured forwarded message; null until a sample exists (FUTURE). */
  messageSampleId: string | null
  /** ARC header set found on the sample (FUTURE). */
  chainPresent: boolean | null
  /** Highest i= observed — hop count (FUTURE). */
  chainLength: number | null
  /** Newest ARC-Seal cv= — "none" | "pass" | "fail" (FUTURE). */
  cvResult: string | null
  /** Entire seal chain verified (FUTURE). */
  sealValid: boolean | null
  /** Newest ARC-Message-Signature verified (FUTURE). */
  amsValid: boolean | null
  /** i= contiguous, ordered, complete (FUTURE). */
  instancesOk: boolean | null
  /** i=1 AAR shows origin dmarc/dkim/spf pass (FUTURE). */
  oldestPass: boolean | null
  /** Per-hop detail: [{i, d, s, ams_valid, as_cv, aar}] (FUTURE). */
  instances: unknown[] | null
  /** When the swaks-through-forwarder probe last ran (FUTURE, admin-gated). */
  probeSentAt: string | null
  /** Freeform note (e.g. why applicability could not be evaluated). */
  notes: string | null
  /**
   * The DMARC `p=` the applicability verdict used (pm/checks/arc.mdx §9.11) — the explainer's
   * applicability panel renders it without re-querying DNS. Null when it could not be read.
   */
  dmarcPolicy: string | null
  /**
   * Where the policy came from: the sibling `dmarc` result of THIS run, or the checker's own
   * fallback `_dmarc` lookup (the applicability panel's provenance line, pm/checks/arc.mdx §9.11).
   */
  policySource: "sibling" | "dns" | null
}

/** The all-null sample-derived columns — first round is advisory-only, no message sample exists. */
function emptyResults(): ArcResults {
  return {
    applicable: null,
    forwardingRisk: null,
    forwarders: [],
    messageSampleId: null,
    chainPresent: null,
    chainLength: null,
    cvResult: null,
    sealValid: null,
    amsValid: null,
    instancesOk: null,
    oldestPass: null,
    instances: null,
    probeSentAt: null,
    notes: null,
    dmarcPolicy: null,
    policySource: null,
  }
}

/**
 * The forwarders / mailing lists a domain declares it sends through (pm/checks/arc.mdx §4
 * per-domain config, the `arc_forwarders` table — stored as `arc.forwarders` on the domain record
 * and surfaced on the CheckContext).
 */
function declaredForwarders(ctx: {
  arc?: { forwarders: ArcForwarderConfig[] }
}): ArcForwarderConfig[] {
  return ctx.arc?.forwarders ?? []
}

/** Parse the DMARC policy tag (p=) from a domain's `_dmarc` TXT records. */
function dmarcPolicy(records: string[]): string | null {
  const rec = records.find((r) => /^v=DMARC1\b/i.test(r.trim()))
  if (!rec) return null
  const m = /(?:^|;)\s*p\s*=\s*([a-zA-Z]+)/.exec(rec)
  return m ? m[1].toLowerCase() : null
}

/**
 * The sibling `dmarc` checker's already-parsed policy from THIS run (pm/checks/arc.mdx §2/§3 —
 * "read the DMARC policy the DMARC checker already parsed"). The run graph guarantees dmarc
 * finishes before arc starts (run-graph.ts: `arc: ["dmarc"]`), so the policy is read from
 * `ctx.upstream.dmarc` instead of re-querying `_dmarc.<domain>`. The dmarc checker publishes its
 * §5 `dmarc:` section — `{ record: { policy, is_enforcing, … }, … }`; a flat shape is tolerated
 * for older persisted payloads. Returns null when the sibling result is absent (checker disabled
 * or errored) — the caller then falls back to its own memoized DNS lookup.
 */
function dmarcFromSibling(ctx: CheckContext): { policy: string | null; enforcing: boolean } | null {
  const dmarc = ctx.upstream?.dmarc
  if (!dmarc || typeof dmarc !== "object") return null
  const record = (dmarc as { record?: unknown }).record
  const src = (record && typeof record === "object" ? record : dmarc) as {
    policy?: unknown
    is_enforcing?: unknown
  }
  if (typeof src.is_enforcing !== "boolean") return null
  return {
    policy: typeof src.policy === "string" ? src.policy.toLowerCase() : null,
    enforcing: src.is_enforcing,
  }
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
async function inspectSigner(
  f: ArcForwarderConfig,
): Promise<{ findings: Finding[]; observation: ArcForwarderObservation }> {
  const key = slug(f.label)
  const observation: ArcForwarderObservation = {
    label: f.label,
    forwardAddress: f.forwardAddress,
    signerDomain: f.signerDomain ?? null,
    signerSelector: f.signerSelector ?? null,
    selectorResolves: null,
    rawKeyRecord: null,
    keyType: null,
    keyBits: null,
  }

  if (!f.signerDomain || !f.signerSelector) {
    return {
      observation,
      findings: [
        {
          id: `arc.selector_dns.${key}`,
          checkId: "arc",
          title: `ARC signer not yet known for ${f.label}`,
          severity: "info",
          detail: `No ARC signing domain (d=) / selector (s=) is recorded for forwarder "${f.label}", so its ARC key cannot be verified in DNS yet. The selector is entered in the forwarder config or auto-discovered from a captured forwarded sample.`,
          remediation: `In this domain's ARC / forwarding settings, record the ARC signing domain and selector that "${f.label}" uses, or capture a forwarded sample so EmailDeliveryHero can discover it.`,
        },
      ],
    }
  }

  const name = `${f.signerSelector}._domainkey.${f.signerDomain}`
  const { records, empty, error } = await resolveTxt(name)

  if (error) {
    return {
      observation,
      findings: [
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
      ],
    }
  }

  if (empty || records.length === 0) {
    observation.selectorResolves = false
    return {
      observation,
      findings: [
        {
          id: `arc.selector_dns.${key}`,
          checkId: "arc",
          title: `ARC signer selector does not resolve for ${f.label}`,
          severity: "critical",
          detail: `The ARC signer's selector ${name} returned no record (NXDOMAIN / empty). The ARC-Message-Signature and ARC-Seal from "${f.label}" cannot be verified, so receivers will discard the ARC evidence and fall back to the raw DMARC failure.`,
          remediation: `Ask "${f.label}" to publish (or repair) its ARC signing key. If you operate the sealer, publish the 2048-bit key TXT record at ${name} with "v=DKIM1; k=rsa; p=<base64 public key>".`,
          evidence: name,
        },
      ],
    }
  }

  const rec = records.find((r) => /(?:^|;)\s*p\s*=/i.test(r)) ?? records[0]
  // §9.11 recorded data: the raw TXT (the signer-key card's body) and the parsed key type — kept
  // even for a revoked (empty p=) record so the drill-down can show what is actually published.
  observation.rawKeyRecord = rec
  observation.keyType = (tag(rec, "k") ?? "rsa").toLowerCase()
  const p = tag(rec, "p")
  if (p === null || p === "") {
    observation.selectorResolves = false
    return {
      observation,
      findings: [
        {
          id: `arc.selector_dns.${key}`,
          checkId: "arc",
          title: `ARC signer key is revoked/empty for ${f.label}`,
          severity: "critical",
          detail: `The selector ${name} exists but publishes an empty p= (a revoked key). The ARC signatures from "${f.label}" cannot be verified.`,
          remediation: `Ask "${f.label}" to republish a valid public key at ${name}. If you operate the sealer, restore the 2048-bit key: "v=DKIM1; k=rsa; p=<base64 public key>".`,
          evidence: rec,
        },
      ],
    }
  }

  observation.selectorResolves = true
  const findings: Finding[] = [
    {
      id: `arc.selector_dns.${key}`,
      checkId: "arc",
      title: `ARC signer selector resolves for ${f.label}`,
      severity: "ok",
      detail: `${name} publishes a key, so the ARC-Message-Signature / ARC-Seal from "${f.label}" can be verified against DNS.`,
      evidence: rec,
    },
  ]

  const k = observation.keyType ?? "rsa"
  if (k === "rsa") observation.keyBits = estimateRsaBits(p)
  if (k !== "rsa" && k !== "ed25519") {
    findings.push({
      id: `arc.signature_algorithm.${key}`,
      checkId: "arc",
      title: `ARC signer uses a legacy key type for ${f.label}`,
      severity: "warning",
      detail: `The ARC signer key at ${name} declares k=${k}. Modern ARC uses rsa-sha256 or ed25519-sha256; SHA-1 / legacy key types are not trusted (RFC 8301).`,
      remediation: `Ask "${f.label}" to reissue the ARC signing key as RSA-SHA256 (2048-bit) or ed25519 and republish it at ${name}.`,
      evidence: rec,
    })
  } else if (k === "rsa") {
    const bits = observation.keyBits ?? 0
    if (bits < 1024) {
      findings.push({
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

  return { findings, observation }
}

export const arcCheck: Checker = {
  id: "arc",
  label: "ARC (Authenticated Received Chain)",
  async run(ctx): Promise<CheckOutcome> {
    const results = emptyResults()

    // 1. Applicability rests on the DMARC policy. Prefer the policy the sibling dmarc checker
    //    already parsed this run (pm/checks/arc.mdx §3.1; the run graph orders arc after dmarc).
    //    Fall back to resolving `_dmarc.<domain>` ourselves only when the sibling result is absent
    //    (dmarc checker disabled/errored) — the per-run DNS memo makes the fallback cost one query.
    let policy: string | null
    let enforcing: boolean
    const sibling = dmarcFromSibling(ctx)
    if (sibling) {
      policy = sibling.policy
      enforcing = sibling.enforcing
      results.policySource = "sibling"
    } else {
      const dmarc = await resolveTxt(`_dmarc.${ctx.domain}`)
      if (dmarc.error) {
        results.notes = `DMARC policy lookup failed transiently (${dmarc.error}); applicability not evaluated.`
        return {
          results,
          findings: [
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
          ],
        }
      }
      policy = dmarcPolicy(dmarc.records)
      enforcing = policy === "quarantine" || policy === "reject"
      results.policySource = "dns"
    }
    // §9.11: persist the policy the applicability verdict used, so the explainer's applicability
    // panel renders provenance from `results.arc` alone (never re-querying DNS).
    results.dmarcPolicy = policy

    // 2. Not enforcing → ARC brings nothing; a directly-sent or p=none message is never rescued by it.
    if (!enforcing) {
      results.applicable = false
      results.forwardingRisk = false
      return {
        results,
        findings: [
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
        ],
      }
    }

    // 3. Enforcing DMARC. ARC now matters only for mail routed through forwarders/lists — read the
    //    operator's declared config (usesForwarding flag + forwarder list, pm/checks/arc.mdx §4).
    const forwarders = declaredForwarders(ctx)
    const usesForwarding = (ctx.arc?.usesForwarding ?? false) || forwarders.length > 0
    if (!usesForwarding) {
      results.applicable = false
      results.forwardingRisk = false
      return {
        results,
        findings: [
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
        ],
      }
    }

    // 4. Enforcing DMARC + declared forwarding: run the deterministic per-forwarder DNS/config checks.
    //    No chain has been verified yet (no sample), so forwarding risk stands.
    results.applicable = true
    results.forwardingRisk = true
    const findings: Finding[] = [
      {
        id: "arc.applicable",
        checkId: "arc",
        title: "ARC applies to this domain",
        severity: "info",
        detail:
          forwarders.length > 0
            ? `DMARC is enforcing (p=${policy}) and ${forwarders.length} forwarder(s)/list(s) are declared, so ARC preservation matters on those paths.`
            : `DMARC is enforcing (p=${policy}) and the domain is declared to send through forwarders/mailing lists, so ARC preservation matters on those paths.`,
        remediation:
          "Confirm each declared forwarder applies a valid ARC chain (cv=pass); the sub-checks below verify each signer's DNS key.",
        evidence: `p=${policy}`,
      },
    ]

    if (forwarders.length === 0) {
      // usesForwarding is on but no individual forwarder is registered yet — the risk is declared
      // but nothing can be verified until the operator lists the forwarders.
      findings.push({
        id: "arc.forwarding_risk",
        checkId: "arc",
        title: "Forwarding declared but no forwarders registered",
        severity: "warning",
        detail: `${ctx.domain} enforces DMARC (p=${policy}) and is declared to send through forwarders/mailing lists, but none are registered. Forwarding breaks SPF alignment and often the DKIM signature, so without a verified ARC chain legitimate forwarded mail is silently quarantined or rejected — and nothing can be verified until each forwarder is listed.`,
        remediation:
          "Register each forwarder / mailing list (label + forwarding address, plus its ARC signing domain/selector if known) in the domain's ARC / forwarding settings so its signer key can be verified in DNS and a forwarded sample can be captured later.",
      })
    }

    for (const f of forwarders) {
      findings.push({
        id: `arc.forwarding_risk.${slug(f.label)}`,
        checkId: "arc",
        title: `Forwarding path may break DMARC without ARC — ${f.label}`,
        severity: "warning",
        detail: `${ctx.domain} enforces DMARC (p=${policy}) and sends through "${f.label}" (${f.forwardAddress}). Forwarding breaks SPF alignment and often the DKIM signature, so unless "${f.label}" seals a valid ARC chain, legitimate mail through it is silently quarantined or rejected. No verified chain exists for it yet.`,
        remediation: `Confirm "${f.label}" applies ARC (cv=pass). For lists you run, enable ARC sealing on the MLM (e.g. Mailman 3, or mlmmj + OpenARC); for third-party forwarders, ask them to enable ARC sealing.`,
      })
      const { findings: signerFindings, observation } = await inspectSigner(f)
      findings.push(...signerFindings)
      results.forwarders.push(observation)
    }

    // 5. Everything about a real chain needs a captured forwarded message (FUTURE). Stub as one info;
    //    never fabricate a chain verdict. The sample-derived columns in `results` stay null.
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

    return { findings, results }
  },
}
