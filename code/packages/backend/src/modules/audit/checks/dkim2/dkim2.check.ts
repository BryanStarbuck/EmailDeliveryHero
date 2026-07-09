import { resolveTxt } from "../dns-util";
import type {
	CheckContext,
	Checker,
	CheckOutcome,
	Finding,
} from "../types";

/**
 * DKIM2 (DomainKeys Identified Mail v2, IETF draft-clayton-dkim2-spec-04 — "draft-04") — the advisory
 * companion to DKIM (pm/checks/dkim2.mdx). DKIM2 is the redesigned successor to DKIM1: it keeps the
 * public key at the same `<selector>._domainkey.<domain>` DNS location but replaces the single
 * `DKIM-Signature` with two headers stamped by every hop in transit — `Message-Instance` (revision
 * `m=`, fingerprints, and a reversible `r=` recipe when a hop mutates the message) and
 * `DKIM2-Signature` (the signed SMTP envelope `mf=`/`rt=`, an ordered sequence `i=`, and the
 * `donotexplode`/`exploded`/`feedback`/`feedhere` flags). Because the mechanism lives in message
 * headers, not DNS, DKIM2 *cannot* be audited from DNS alone — so most of this check is FUTURE
 * (message-sample-dependent), and the parts that ship first round are advisory + DNS-readiness only.
 *
 * DKIM2 is brand-new (a July-2026 draft; Stalwart v0.16.12 is the FIRST server to implement it), so
 * for almost every domain the honest verdict is "not yet applicable / your provider does not speak
 * DKIM2 yet" — an `info`, never a fabricated problem.
 *
 * First round (pure DNS/config, deterministic — pm/checks/dkim2.mdx §3/§7):
 *   - dkim2.applicability  — is DKIM2 even relevant? (enforcing DMARC OR declared forwarding)
 *   - dkim2.server_support — does the MTA speak DKIM2? (no first-round signal → unknown)
 *   - dkim2.selector_dns   — a DKIM2 signing selector resolves at `<selector>._domainkey.<domain>`
 *   - dkim2.key_readiness  — that key is modern (ed25519 preferred, RSA-2048 acceptable)
 *
 * Future (needs a captured DKIM2 `.eml` sample + a DKIM2 validator — mail-auth / Stalwart — that does
 * not yet ship in brew): dkim2.chain_present, dkim2.chain_valid, dkim2.envelope_consistency,
 * dkim2.recipe_reversible, dkim2.counters_ordered, dkim2.canonicalization, dkim2.replay_flags,
 * dkim2.bounce_validity, dkim2.legacy_coexistence — stubbed as a single `info` (dkim2.chain_present),
 * never a fabricated verdict. Their columns in the structured payload stay null until a sample exists.
 *
 * All findings use checkId "dkim2" and the `dkim2.` id prefix; they roll into the DKIM dashboard cell
 * (the orchestrator maps the prefix). DKIM2 has no dashboard column of its own.
 */

/** One signing selector's first-round DNS observation (feeds `results.dkim2.selectors`). */
interface Dkim2SelectorObservation {
	selector: string;
	/** `<selector>._domainkey.<domain>` published a usable (non-empty) key; null on lookup error. */
	resolves: boolean | null;
	/** The raw TXT answer at the selector — the readiness UI's signer-key card body; null when absent. */
	rawKeyRecord: string | null;
	/** The parsed `k=` tag, defaulted "rsa" when a key resolves; null when unresolved. */
	keyType: string | null;
	/** Estimated RSA modulus bits; null for ed25519 / unresolved keys. */
	keyBits: number | null;
}

/**
 * The structured per-run DKIM2 observation persisted as `results.dkim2` inside the audit file — the
 * file-store mapping of the `dkim2_check_results` row (pm/checks/dkim2.mdx §5). Almost everything is
 * nullable: first-round runs record only applicability, server support, the signing-selector DNS
 * result, and key readiness; the sample-derived fields fill in once a DKIM2 message is captured.
 */
export interface Dkim2Results {
	// ---- advisory / first-round (populated every run) ----
	/** DKIM2 relevance: enforcing DMARC OR declared forwarding; null when it could not be evaluated. */
	applicable: boolean | null;
	/** dkim2Supported flag / observed DKIM2-Signature; null = unknown (no first-round signal). */
	serverSupported: boolean | null;
	/** d= of the DKIM2 signing selector (readiness) — the audited domain (key shares the DKIM location). */
	signerDomain: string | null;
	/** s= of the DKIM2 signing selector. */
	signerSelector: string | null;
	/** `<selector>._domainkey.<signerDomain>` resolved with a usable key. */
	selectorResolves: boolean | null;
	/** rsa | ed25519 | null (readiness key type of the first resolving selector). */
	keyType: string | null;
	/** RSA modulus bits; null for ed25519 / absent. */
	keyBits: number | null;
	/** Per-signing-selector readiness observations (analogous to ArcResults.forwarders). */
	selectors: Dkim2SelectorObservation[];
	// ---- message-sample derived (NULL until a sample exists — FUTURE) ----
	/** id/hash of the captured DKIM2 message; null until a sample exists. */
	messageSampleId: string | null;
	/** Message-Instance + DKIM2-Signature found on the sample. */
	chainPresent: boolean | null;
	/** Highest i= observed (hop count). */
	chainLength: number | null;
	/** Number of DKIM2-Signature headers. */
	signatureCount: number | null;
	/** Highest m= observed (content revisions). */
	revisionCount: number | null;
	/** Every signature in the chain verified. */
	chainValid: boolean | null;
	/** mf=/rt= line up hop-to-hop; d= within mf=. */
	envelopeConsistent: boolean | null;
	/** Every modifying hop's r= recipe rebuilds the prior revision. */
	recipesReversible: boolean | null;
	/** i= contiguous/ordered; m= incremented only on a real change. */
	countersOrdered: boolean | null;
	/** The fixed DKIM2 canonicalization/hashing scheme was used. */
	canonicalizationOk: boolean | null;
	/** donotexplode/exploded consistent with fan-out. */
	replayFlagsOk: boolean | null;
	/** DSN addressed to the signed mf=; mf=<> honored; bounce re-verifies. */
	bounceValid: boolean | null;
	/** Per-hop detail: [{i, m, d, s, mf, rt, recipe_present, sig_valid}] (FUTURE). */
	instances: unknown[] | null;
	/** The DKIM2 draft the parser pinned to (pm/checks/dkim2.mdx §3 "pin parsing to draft-04"). */
	draftVersion: string | null;
	/** When the swaks capture probe last ran (FUTURE, admin-gated). */
	probeSentAt: string | null;
	/** Freeform note (e.g. why applicability could not be evaluated). */
	notes: string | null;
	/** The DMARC p= the applicability verdict used; null when it could not be read. */
	dmarcPolicy: string | null;
	/** Where the policy came from: the sibling `dmarc` result of THIS run, or a DNS fallback. */
	policySource: "sibling" | "dns" | null;
}

/** The all-null sample-derived fields — first round is advisory-only, no message sample exists. */
function emptyResults(): Dkim2Results {
	return {
		applicable: null,
		serverSupported: null,
		signerDomain: null,
		signerSelector: null,
		selectorResolves: null,
		keyType: null,
		keyBits: null,
		selectors: [],
		messageSampleId: null,
		chainPresent: null,
		chainLength: null,
		signatureCount: null,
		revisionCount: null,
		chainValid: null,
		envelopeConsistent: null,
		recipesReversible: null,
		countersOrdered: null,
		canonicalizationOk: null,
		replayFlagsOk: null,
		bounceValid: null,
		instances: null,
		draftVersion: null,
		probeSentAt: null,
		notes: null,
		dmarcPolicy: null,
		policySource: null,
	};
}

/**
 * The sibling `dmarc` checker's already-parsed policy from THIS run (pm/checks/dkim2.mdx §3 — "read
 * the DMARC policy the DMARC checker already parsed"). The run graph orders dkim2 after dmarc, so the
 * policy is read from `ctx.upstream.dmarc` rather than re-querying `_dmarc.<domain>`. The dmarc
 * checker publishes `{ record: { policy, is_enforcing, … }, … }`; a flat shape is tolerated for older
 * persisted payloads. Returns null when the sibling result is absent (checker disabled/errored).
 */
function dmarcFromSibling(
	ctx: CheckContext,
): { policy: string | null; enforcing: boolean } | null {
	const dmarc = ctx.upstream?.dmarc;
	if (!dmarc || typeof dmarc !== "object") return null;
	const record = (dmarc as { record?: unknown }).record;
	const src = (record && typeof record === "object" ? record : dmarc) as {
		policy?: unknown;
		is_enforcing?: unknown;
	};
	if (typeof src.is_enforcing !== "boolean") return null;
	return {
		policy: typeof src.policy === "string" ? src.policy.toLowerCase() : null,
		enforcing: src.is_enforcing,
	};
}

/** Read one tag (e.g. "p", "k") out of a DKIM-style key record. */
function tag(record: string, name: string): string | null {
	const m = new RegExp(`(?:^|;)\\s*${name}\\s*=\\s*([^;]*)`, "i").exec(record);
	return m ? m[1].trim() : null;
}

/** Rough RSA modulus size (bits) from the base64 `p=` public key. SPKI DER wrapper is ~38 bytes. */
function estimateRsaBits(p: string): number {
	const clean = p.replace(/[^A-Za-z0-9+/]/g, "");
	const bytes = Math.floor((clean.length * 3) / 4);
	return Math.max(0, bytes - 38) * 8;
}

/**
 * Inspect one DKIM2 signing selector's key in DNS: resolve `<selector>._domainkey.<domain>`, confirm
 * a usable (non-empty `p=`) key is published, and sanity-check its algorithm/strength for DKIM2's
 * fixed hashing (ed25519 preferred, RSA-2048 acceptable). Covers the per-selector `dkim2.selector_dns`
 * and `dkim2.key_readiness` findings. Never throws — a transient lookup error degrades to an `info`.
 *
 * First round cannot know a domain's real DKIM2 selector, so a selector that does NOT resolve emits no
 * per-selector finding here; the caller emits a single advisory `info` only when NONE resolve.
 */
async function inspectSelector(
	domain: string,
	selector: string,
): Promise<{ findings: Finding[]; observation: Dkim2SelectorObservation }> {
	const observation: Dkim2SelectorObservation = {
		selector,
		resolves: null,
		rawKeyRecord: null,
		keyType: null,
		keyBits: null,
	};
	const name = `${selector}._domainkey.${domain}`;
	const { records, empty, error } = await resolveTxt(name);

	if (error) {
		return {
			observation,
			findings: [
				{
					id: `dkim2.selector_dns.${selector}`,
					checkId: "dkim2",
					title: `Could not resolve DKIM2 selector "${selector}"`,
					severity: "info",
					detail: `DNS lookup for TXT ${name} failed transiently (${error}); the DKIM2 readiness key could not be checked this run.`,
					remediation:
						"Retry the audit. If it persists, verify the domain's authoritative nameservers respond for _domainkey names.",
					evidence: name,
				},
			],
		};
	}

	if (empty || records.length === 0) {
		// No key published for this candidate selector. First round is advisory: a missing key is
		// only meaningful once ALL candidates miss, which the caller reports as a single info.
		observation.resolves = false;
		return { observation, findings: [] };
	}

	const rec = records.find((r) => /(?:^|;)\s*p\s*=/i.test(r)) ?? records[0];
	observation.rawKeyRecord = rec;
	const p = tag(rec, "p");
	if (p === null || p === "") {
		// Selector exists but publishes an empty p= (a revoked key) — not usable for DKIM2 signing.
		observation.resolves = false;
		observation.keyType = (tag(rec, "k") ?? "rsa").toLowerCase();
		return { observation, findings: [] };
	}

	observation.resolves = true;
	observation.keyType = (tag(rec, "k") ?? "rsa").toLowerCase();
	const findings: Finding[] = [
		{
			id: `dkim2.selector_dns.${selector}`,
			checkId: "dkim2",
			title: `DKIM2 selector "${selector}" resolves`,
			severity: "ok",
			detail: `${name} publishes a key, so if the sending stack gains DKIM2 it can sign against this DNS-published selector (DKIM2 reuses the DKIM key location).`,
			evidence: rec,
		},
	];

	const k = observation.keyType ?? "rsa";
	if (k === "ed25519") {
		findings.push({
			id: `dkim2.key_readiness.${selector}`,
			checkId: "dkim2",
			title: `DKIM2-ready ed25519 key on selector "${selector}"`,
			severity: "ok",
			detail:
				"Ed25519 is the preferred key type for DKIM2's fixed hashing — this selector is ready the moment the stack signs DKIM2.",
		});
	} else if (k === "rsa") {
		observation.keyBits = estimateRsaBits(p);
		const bits = observation.keyBits;
		if (bits < 1024) {
			findings.push({
				id: `dkim2.key_readiness.${selector}`,
				checkId: "dkim2",
				title: `Weak RSA key on selector "${selector}" is not DKIM2-ready`,
				severity: "warning",
				detail: `The RSA key at ${name} is approximately ${bits}-bit — below the RFC 8301 minimum of 1024-bit (2048-bit recommended). A weak key would put DKIM2 signing on a bad footing.`,
				remediation: `Reissue a modern key at ${name} — prefer ed25519 for DKIM2, or RSA-2048 at minimum: "v=DKIM1; k=ed25519; p=<base64 public key>".`,
				evidence: rec,
			});
		} else {
			findings.push({
				id: `dkim2.key_readiness.${selector}`,
				checkId: "dkim2",
				title: `RSA key on selector "${selector}" is DKIM2-acceptable`,
				severity: "ok",
				detail: `The RSA key at ${name} is approximately ${bits}-bit (RSA-2048 is acceptable for DKIM2). An ed25519 selector is still preferred for DKIM2's fixed hashing.`,
			});
		}
	} else {
		// Unknown key type — advisory only (DKIM2 readiness cannot judge a key it does not understand).
		findings.push({
			id: `dkim2.key_readiness.${selector}`,
			checkId: "dkim2",
			title: `Unknown key type k=${k} on selector "${selector}"`,
			severity: "info",
			detail: `The key at ${name} declares k=${k}; DKIM2 (like DKIM) expects k=rsa or k=ed25519, so its readiness cannot be judged.`,
			remediation: `Publish an ed25519 (preferred) or RSA-2048 key at ${name}: "v=DKIM1; k=ed25519; p=<base64 public key>".`,
			evidence: rec,
		});
	}

	return { findings, observation };
}

export const dkim2Check: Checker = {
	id: "dkim2",
	label: "DKIM2 (signature chain of custody)",
	async run(ctx): Promise<CheckOutcome> {
		const results = emptyResults();
		results.draftVersion = "draft-04";
		results.signerDomain = ctx.domain;
		const findings: Finding[] = [];

		// 1. Applicability — read the DMARC policy the sibling dmarc checker already parsed this run
		//    (pm/checks/dkim2.mdx §3; the run graph orders dkim2 after dmarc). DKIM2 is relevant when
		//    the domain enforces DMARC OR declares forwarding — both are cases where a durable,
		//    forwarding-surviving, replay-proof chain would matter.
		const sibling = dmarcFromSibling(ctx);
		let policy: string | null = null;
		let enforcing = false;
		if (sibling) {
			policy = sibling.policy;
			enforcing = sibling.enforcing;
			results.policySource = "sibling";
		}
		results.dmarcPolicy = policy;

		const forwarders = ctx.arc?.forwarders ?? [];
		const usesForwarding =
			(ctx.arc?.usesForwarding ?? false) || forwarders.length > 0;
		const applicable = enforcing || usesForwarding;
		results.applicable = applicable;

		if (applicable) {
			findings.push({
				id: "dkim2.applicability",
				checkId: "dkim2",
				title: "DKIM2 could apply to this domain (advisory)",
				severity: "info",
				detail: enforcing
					? `DMARC is enforcing (${policy ? `p=${policy}` : "quarantine/reject"})${
							usesForwarding ? " and forwarding is declared" : ""
						}, so DKIM2's forwarding-surviving, replay-proof chain would matter here once your stack speaks it. DKIM2 is a July-2026 draft (Stalwart v0.16.12 is the first server to implement it), so this remains advisory today.`
					: `Forwarding is declared for ${ctx.domain}, so DKIM2's reversible recipes and chain of custody would help preserve authentication across hops once your stack speaks it. DKIM2 is a July-2026 draft (Stalwart v0.16.12 is the first server to implement it), so this remains advisory today.`,
				remediation:
					"No action required today. Track your provider's DKIM2 roadmap (currently only Stalwart ≥ v0.16.12), and keep a modern readiness key published (see the selector checks below).",
				evidence: policy ? `p=${policy}` : undefined,
			});
		} else {
			results.notes = sibling
				? "DMARC is not enforcing and no forwarding is declared — DKIM2 is not applicable yet."
				: "No enforcing DMARC (sibling result absent) and no forwarding declared — DKIM2 is not applicable yet.";
			findings.push({
				id: "dkim2.applicability",
				checkId: "dkim2",
				title: "DKIM2 not applicable yet",
				severity: "info",
				detail: `Nothing in ${ctx.domain}'s path relies on DKIM2 yet: DMARC is not enforcing${
					policy ? ` (p=${policy})` : ""
				} and no forwarding is declared, and DKIM2 itself is a brand-new July-2026 draft that virtually no provider speaks (Stalwart ≥ v0.16.12 is the first). This is the correct, non-alarming default — there is nothing to fail.`,
				remediation:
					"No action needed for DKIM2. Revisit once you adopt enforcing DMARC (p=quarantine/reject) with forwarding, or your MTA/ESP adds DKIM2 signing — meanwhile publishing a modern readiness key keeps the DNS side correct.",
				evidence: policy ? `p=${policy}` : undefined,
			});
		}

		// 2. Server support — there is no first-round signal that a domain's MTA speaks DKIM2 (that
		//    requires a captured DKIM2-Signature), so support is genuinely unknown. Never guess.
		findings.push({
			id: "dkim2.server_support",
			checkId: "dkim2",
			title: "DKIM2 server support unknown — no DKIM2-Signature observed yet",
			severity: "info",
			detail:
				"No captured sample has shown a DKIM2-Signature for this domain, and there is no DNS/config signal that its MTA signs DKIM2. In 2026 the near-universal answer is 'not yet' — only Stalwart ≥ v0.16.12 signs or verifies DKIM2.",
			remediation:
				"Track your provider's DKIM2 roadmap; set the domain's dkim2Supported flag once your stack signs DKIM2, and capture a sample so support can be confirmed from an observed DKIM2-Signature.",
		});
		results.serverSupported = null;

		// 3. Selector DNS + key readiness — reuse the DKIM `_domainkey` selector machinery. For each
		//    configured selector (or "default" when none), resolve the key and judge its DKIM2 fitness.
		const selectorList =
			ctx.dkimSelectors.length > 0 ? ctx.dkimSelectors : ["default"];
		let firstResolving: Dkim2SelectorObservation | null = null;
		for (const selector of selectorList) {
			const { findings: selFindings, observation } = await inspectSelector(
				ctx.domain,
				selector,
			);
			findings.push(...selFindings);
			results.selectors.push(observation);
			if (observation.resolves === true && !firstResolving)
				firstResolving = observation;
		}

		// Reuse the first resolving selector's key for the top-level results.signer* fields (falling
		// back to the first candidate so the readiness UI always has a selector to render).
		const signer = firstResolving ?? results.selectors[0] ?? null;
		if (signer) {
			results.signerSelector = signer.selector;
			results.selectorResolves = signer.resolves;
			results.keyType = signer.keyType;
			results.keyBits = signer.keyBits;
		}

		// Domain-scoped: NO candidate selector resolved. First round cannot know the real DKIM2
		// selector, so this is advisory info — never a critical (pm/checks/dkim2.mdx §3).
		const anyResolves = results.selectors.some((s) => s.resolves === true);
		if (!anyResolves) {
			findings.push({
				id: "dkim2.selector_dns",
				checkId: "dkim2",
				title: "No DKIM2 readiness selector resolves yet",
				severity: "info",
				detail: `None of the probed selectors (${selectorList
					.map((s) => `${s}._domainkey.${ctx.domain}`)
					.join(
						", ",
					)}) published a usable key. DKIM2 reuses the DKIM key location, so this only means no readiness key is staged — first round cannot know the domain's real DKIM2 selector, so this is advisory, not a failure.`,
				remediation: `Publish an ed25519 readiness key at <selector>._domainkey.${ctx.domain} (e.g. "d2._domainkey.${ctx.domain} TXT v=DKIM1; k=ed25519; p=<base64 public key>"), or record your DKIM2 signing selector in the domain settings.`,
			});
		}

		// Domain-scoped: only RSA readiness keys resolve — nudge toward ed25519 for DKIM2's fixed hashing.
		const resolvingKeys = results.selectors.filter((s) => s.resolves === true);
		if (
			resolvingKeys.length > 0 &&
			resolvingKeys.every((s) => s.keyType === "rsa")
		) {
			findings.push({
				id: "dkim2.key_readiness",
				checkId: "dkim2",
				title: "Only RSA readiness keys — add an ed25519 selector for DKIM2",
				severity: "info",
				detail:
					"DKIM2 uses a single fixed hashing scheme and prefers ed25519. The domain publishes only RSA readiness keys; RSA-2048 is acceptable, but an ed25519 selector alongside it makes the stack fully DKIM2-ready.",
				remediation: `Publish an ed25519 selector alongside RSA (e.g. "d2._domainkey.${ctx.domain} TXT v=DKIM1; k=ed25519; p=<base64 public key>") so DKIM2 signing starts on the preferred algorithm.`,
			});
		}

		// 4. FUTURE — everything about a real chain needs a captured DKIM2 message + a DKIM2 validator
		//    (mail-auth / Stalwart) that does not yet ship in brew. Stub as one info; never fabricate a
		//    chain verdict. The sample-derived fields in `results` stay null. Only surfaced once DKIM2
		//    is even applicable, to keep the near-universal not-applicable case quiet.
		if (applicable) {
			findings.push({
				id: "dkim2.chain_present",
				checkId: "dkim2",
				title: "DKIM2 chain not yet sampled",
				severity: "info",
				detail:
					"Verifying an actual DKIM2 chain — chain present, every DKIM2-Signature valid, envelope consistency (mf=/rt= line up hop-to-hop), reversible recipes on modifying hops, ordered i=/m= counters, fixed canonicalization, replay flags, bounce validity, and DKIM1 legacy coexistence — requires a captured DKIM2 message plus a DKIM2 validator (mail-auth / Stalwart), which no sample or validator provides yet.",
				remediation:
					'Use the admin-only "Capture sample" probe to send a swaks test through the domain\'s MTA (optionally via a forwarder) and retrieve the delivered copy; EmailDeliveryHero will then parse the Message-Instance / DKIM2-Signature headers and validate the chain once a DKIM2 validator (Stalwart mail-auth) is installed.',
			});
		}

		return { findings, results };
	},
};
