import { createHash } from "node:crypto";
import { type DnssecAlgorithmEntry, readAppConfig } from "@shared/config-store";
import {
	type DigDnssecResponse,
	dig,
	digDnssec,
	resolveSoa,
} from "../dns-util";
import type { Checker, CheckOutcome, Finding } from "../types";

/**
 * DNSSEC (DNS Security Extensions, RFC 4033/4034/4035). Verifies that a mail domain's zone is signed
 * (DNSKEY present), that a DS record links the chain of trust at the parent/registrar, that signing
 * algorithms are modern, and — by locally recomputing the DS digest per RFC 4034 §5.1.4 — that the
 * published DS actually references a live key.
 *
 * First round is presence-only: node:dns/promises cannot expose the AD flag or verify signatures, so
 * DNSKEY/DS/RRSIG are fetched via the Brew `dig` helper and parsed for their public fields. The
 * validation-dependent sub-checks (validates, rrsig_expiry, nsec3, chain_complete) are gated behind
 * the admin "validate via `dig`" toggle (pm/checks/dnssec.mdx §4, `config.yaml →
 * checks.dnssec.validateViaDig`): OFF, they degrade to a single advisory `info` each — never a
 * false `warning`/`critical` (spec acceptance #5); ON, the deep path shells `dig +dnssec` against
 * the configured validating resolvers (default 1.1.1.1 / 8.8.8.8) to read the AD flag, run the
 * CD-flag bogus disambiguation (acceptance #6), parse RRSIG expirations against the configured
 * lead time (acceptance #7), and inspect NSEC3 parameters per RFC 9276.
 */

const CHECK_ID = "infra.dnssec";

/** One apex DNSKEY, parsed (pm/checks/dnssec.mdx §5 `dnskey_algos` JSONB element). */
export interface DnskeyAlgoInfo {
	keyTag: number;
	flags: number;
	alg: number;
	algName: string;
	bits: number | null;
}

/** One published DS record, parsed (pm/checks/dnssec.mdx §11 `dsRecords[]` element). */
export interface DsRecordInfo {
	keyTag: number;
	algorithm: number;
	digestType: number;
}

/** One apex RRSIG, parsed — deep path only (pm/checks/dnssec.mdx §11 `rrsigs[]` element). */
export interface RrsigRecordInfo {
	typeCovered: string;
	keyTag: number;
	/** Signature Expiration as ISO date-time; null when the timestamp was unparseable. */
	expiration: string | null;
}

/**
 * The structured DNSSEC state persisted at results["infra.dnssec"]. Two documented shapes overlap
 * here and both are kept in sync:
 *  - the snake_case Zone-panel one-liner fields (pm/checks/dns.mdx §5) read by the DNS page;
 *  - the `dnssec_check_results` row fields (pm/checks/dnssec.mdx §5): signed, dsPresent, validates,
 *    bogus, dnskeyAlgos, dsDigestType, dsAlgoMatch, the nsec3 trio, rrsigEarliestExpiry,
 *    resolverUsed, checkedAt — so the file-store-to-Postgres migration is a direct mapping.
 * Nullable fields mean "could not be determined this run" (validation-dependent ones stay null
 * until the `dig +dnssec` / validating-resolver path ships).
 */
export interface DnssecResults {
	signed: boolean;
	ds_present: boolean | null;
	ds_digest_types: number[];
	algorithms: number[];
	ds_matches_dnskey: boolean | null;
	dane_ready: boolean;
	// ---- dnssec_check_results fields (pm/checks/dnssec.mdx §5) ----
	/** DS at parent/registrar (mirrors ds_present). */
	dsPresent: boolean | null;
	/** AD=1 from a validating resolver — NULL until the validating-resolver path ships. */
	validates: boolean | null;
	/** SERVFAIL with CD=0 but success with CD=1 ⇒ broken chain. False until the probe ships. */
	bogus: boolean;
	/** The parsed apex DNSKEY set: [{keyTag, flags, alg, algName, bits}]. */
	dnskeyAlgos: DnskeyAlgoInfo[];
	/**
	 * The parsed DS RRset, one entry per published DS (pm/checks/dnssec.mdx §11) — lets the
	 * explainer's parsed breakdown render one row per DS with its own SHA-1/SHA-256 + match chip.
	 * Empty when no DS is published or the DS lookup failed.
	 */
	dsRecords: DsRecordInfo[];
	/**
	 * The parsed apex RRSIGs behind `rrsigEarliestExpiry` (pm/checks/dnssec.mdx §11) — deep path
	 * only; stays empty on the presence-only first round.
	 */
	rrsigs: RrsigRecordInfo[];
	/** Digest type of the DS that matched a live KSK (1=SHA1, 2=SHA256); else the published type. */
	dsDigestType: number | null;
	/** Published DS matches a live KSK (mirrors ds_matches_dnskey). */
	dsAlgoMatch: boolean | null;
	/** NSEC3 in use — stays false (the SQL DEFAULT) until the +dnssec NXDOMAIN probe ships. */
	nsec3: boolean;
	nsec3Iterations: number | null;
	nsec3Optout: boolean | null;
	/** Soonest apex RRSIG expiration (ISO) — NULL until the +dnssec probe ships. */
	rrsigEarliestExpiry: string | null;
	/** Validating resolver queried (e.g. "1.1.1.1") — NULL on the presence-only first round. */
	resolverUsed: string | null;
	/** ISO date-time this DNSSEC observation was taken. */
	checkedAt: string;
}

/** The future-gated `dnssec_check_results` fields at their first-round defaults (spec §5/§7). */
function futureFieldDefaults(): Pick<
	DnssecResults,
	| "validates"
	| "bogus"
	| "nsec3"
	| "nsec3Iterations"
	| "nsec3Optout"
	| "rrsigEarliestExpiry"
	| "rrsigs"
	| "resolverUsed"
> {
	return {
		validates: null,
		bogus: false,
		nsec3: false,
		nsec3Iterations: null,
		nsec3Optout: null,
		rrsigEarliestExpiry: null,
		rrsigs: [],
		resolverUsed: null,
	};
}

// RRSIG near-expiry lead time (spec §4 default 72h) — overridable via checks.dnssec.rrsigLeadHours.
const RRSIG_LEAD_HOURS = 72;

// Validating resolvers the deep check queries (spec §4 default) — checks.dnssec.resolvers.
const DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8"];

/** The admin-owned DNSSEC settings (pm/checks/dnssec.mdx §4) resolved to safe values. */
interface DnssecCheckConfig {
	resolvers: string[];
	rrsigLeadHours: number;
	validateViaDig: boolean;
	algorithms: DnssecAlgorithmEntry[];
}

/**
 * Read `config.yaml → checks.dnssec` (spec §4/§5). Every field falls back to the spec default so
 * a missing block — or an unreadable config — degrades to the presence-only first round rather
 * than failing the audit.
 */
function loadDnssecConfig(): DnssecCheckConfig {
	try {
		const c = readAppConfig().checks?.dnssec;
		if (c) {
			return {
				resolvers:
					Array.isArray(c.resolvers) && c.resolvers.length > 0
						? c.resolvers.filter(
								(r): r is string => typeof r === "string" && r.trim() !== "",
							)
						: DEFAULT_RESOLVERS,
				rrsigLeadHours:
					typeof c.rrsigLeadHours === "number" && c.rrsigLeadHours > 0
						? c.rrsigLeadHours
						: RRSIG_LEAD_HOURS,
				validateViaDig: c.validateViaDig === true,
				algorithms: Array.isArray(c.algorithms) ? c.algorithms : [],
			};
		}
	} catch {
		/* config unreadable → built-in defaults, presence-only round */
	}
	return {
		resolvers: DEFAULT_RESOLVERS,
		rrsigLeadHours: RRSIG_LEAD_HOURS,
		validateViaDig: false,
		algorithms: [],
	};
}

interface DnskeyRecord {
	flags: number;
	algorithm: number;
	keyTag: number;
	bits: number | null;
	rdata: Buffer;
}

interface DsRecord {
	keyTag: number;
	algorithm: number;
	digestType: number;
	digest: string;
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
};

// RSASHA1 family (and other legacy algos) validators are removing — built-in fallback when the
// config.yaml `checks.dnssec.algorithms` seed (the dnssec_algorithms reference table, spec §5)
// is absent.
const DEPRECATED_ALGOS = new Set([1, 3, 5, 6, 7]);

/** Name/deprecation lookups resolved from the config seed, falling back to the built-ins. */
interface AlgorithmRegistry {
	name(algo: number): string;
	deprecated(algo: number): boolean;
}

/**
 * Build the algorithm registry from the `dnssec_algorithms` config seed (spec §5 — "so the UI and
 * severity logic don't hard-code magic numbers"). Seed entries override the built-in tables;
 * unknown numbers fall through to the built-ins, then to a generic label / not-deprecated.
 */
function buildAlgorithmRegistry(
	seed: DnssecAlgorithmEntry[],
): AlgorithmRegistry {
	const names = new Map<number, string>();
	const deprecated = new Map<number, boolean>();
	for (const e of seed) {
		if (typeof e?.algo_num !== "number") continue;
		if (typeof e.name === "string" && e.name !== "")
			names.set(e.algo_num, e.name);
		deprecated.set(e.algo_num, e.deprecated === true);
	}
	return {
		name: (algo) => names.get(algo) ?? ALG_NAMES[algo] ?? `algorithm ${algo}`,
		deprecated: (algo) => deprecated.get(algo) ?? DEPRECATED_ALGOS.has(algo),
	};
}

/** Canonical wire form of the owner name: lowercase, length-prefixed labels, root terminator. */
function ownerWire(domain: string): Buffer {
	const name = domain.replace(/\.$/, "").toLowerCase();
	const bufs: Buffer[] = [];
	if (name.length > 0) {
		for (const label of name.split(".")) {
			const b = Buffer.from(label, "ascii");
			bufs.push(Buffer.from([b.length]), b);
		}
	}
	bufs.push(Buffer.from([0]));
	return Buffer.concat(bufs);
}

/** DNSKEY key tag per RFC 4034 Appendix B (algorithms other than 1). */
function keyTag(rdata: Buffer): number {
	let ac = 0;
	for (let i = 0; i < rdata.length; i++) {
		ac += i & 1 ? rdata[i] : rdata[i] << 8;
	}
	ac += (ac >> 16) & 0xffff;
	return ac & 0xffff;
}

/** Estimate the key size in bits from the DNSKEY public key material. */
function keyBits(algorithm: number, key: Buffer): number | null {
	switch (algorithm) {
		case 5:
		case 7:
		case 8:
		case 10: {
			// RFC 3110 RSA public key: [expLen][exponent][modulus], expLen 1 byte or 0+2 bytes.
			if (key.length < 3) return null;
			let offset = 1;
			let expLen = key[0];
			if (expLen === 0) {
				expLen = (key[1] << 8) | key[2];
				offset = 3;
			}
			const modulusLen = key.length - offset - expLen;
			return modulusLen > 0 ? modulusLen * 8 : null;
		}
		case 13:
		case 15:
			return 256;
		case 14:
			return 384;
		case 16:
			return 456;
		default:
			return null;
	}
}

function parseDnskey(line: string): DnskeyRecord | null {
	const parts = line.trim().split(/\s+/);
	if (parts.length < 4) return null;
	const flags = Number(parts[0]);
	const protocol = Number(parts[1]);
	const algorithm = Number(parts[2]);
	if (!Number.isInteger(flags) || !Number.isInteger(algorithm)) return null;
	let key: Buffer;
	try {
		key = Buffer.from(parts.slice(3).join(""), "base64");
	} catch {
		return null;
	}
	const head = Buffer.alloc(4);
	head.writeUInt16BE(flags & 0xffff, 0);
	head.writeUInt8(protocol & 0xff, 2);
	head.writeUInt8(algorithm & 0xff, 3);
	const rdata = Buffer.concat([head, key]);
	return {
		flags,
		algorithm,
		keyTag: keyTag(rdata),
		bits: keyBits(algorithm, key),
		rdata,
	};
}

function parseDs(line: string): DsRecord | null {
	const parts = line.trim().split(/\s+/);
	if (parts.length < 4) return null;
	const keyTagN = Number(parts[0]);
	const algorithm = Number(parts[1]);
	const digestType = Number(parts[2]);
	if (!Number.isInteger(keyTagN) || !Number.isInteger(digestType)) return null;
	return {
		keyTag: keyTagN,
		algorithm,
		digestType,
		digest: parts.slice(3).join("").toUpperCase(),
	};
}

function hashForDigestType(type: number): string | null {
	if (type === 1) return "sha1";
	if (type === 2) return "sha256";
	if (type === 4) return "sha384";
	return null;
}

/** Recompute the DS digest of a DNSKEY per RFC 4034 §5.1.4: digest = H(owner | DNSKEY_RDATA). */
function computeDsDigest(domain: string, rdata: Buffer, hash: string): string {
	return createHash(hash)
		.update(ownerWire(domain))
		.update(rdata)
		.digest("hex")
		.toUpperCase();
}

/**
 * Parse an RRSIG presentation-format timestamp (RFC 4034 §3.2): `YYYYMMDDHHMMSS` in UTC, or —
 * some tools print the wire form — seconds since the epoch. Returns null when unparseable.
 */
export function parseRrsigTime(token: string): Date | null {
	if (/^\d{14}$/.test(token)) {
		const y = Number(token.slice(0, 4));
		const mo = Number(token.slice(4, 6));
		const d = Number(token.slice(6, 8));
		const h = Number(token.slice(8, 10));
		const mi = Number(token.slice(10, 12));
		const s = Number(token.slice(12, 14));
		if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60)
			return null;
		return new Date(Date.UTC(y, mo - 1, d, h, mi, s));
	}
	if (/^\d{1,10}$/.test(token)) return new Date(Number(token) * 1000);
	return null;
}

/**
 * One RRSIG's presentation-format RDATA fields the deep check reads (RFC 4034 §3.2):
 * `<typeCovered> <alg> <labels> <origTTL> <expiration> <inception> <keyTag> <signer> <sig...>`.
 */
interface RrsigInfo {
	typeCovered: string;
	keyTag: number;
	expiration: Date | null;
}

function parseRrsig(rdata: string): RrsigInfo | null {
	const tok = rdata.trim().split(/\s+/);
	if (tok.length < 8) return null;
	const keyTagN = Number(tok[6]);
	return {
		typeCovered: tok[0].toUpperCase(),
		keyTag: Number.isInteger(keyTagN) ? keyTagN : -1,
		expiration: parseRrsigTime(tok[4]),
	};
}

/** The deep-path (`validateViaDig`) verdicts merged into findings + `results` (spec §3/§7). */
interface DeepOutcome {
	findings: Finding[];
	validates: boolean | null;
	bogus: boolean;
	nsec3: boolean;
	nsec3Iterations: number | null;
	nsec3Optout: boolean | null;
	rrsigEarliestExpiry: string | null;
	/** The parsed apex RRSIGs (pm/checks/dnssec.mdx §11) — which RRset expires when. */
	rrsigs: RrsigRecordInfo[];
	resolverUsed: string | null;
}

/**
 * The FUTURE validation path (pm/checks/dnssec.mdx §3), live when the admin enables the
 * "validate via `dig`" toggle: shells `dig +dnssec` against the configured validating resolvers
 * (default 1.1.1.1 / 8.8.8.8, tried in order — back-off on resolver timeouts, spec §6) to read
 * the AD flag, run the CD-flag bogus disambiguation (acceptance #6), parse RRSIG expirations
 * against the configured lead time (acceptance #7), inspect NSEC3 parameters per RFC 9276, walk
 * the DS→DNSKEY→RRSIG chain link, and confirm the mail-relevant RRsets carry RRSIGs. Every probe
 * failure degrades to `info` "validation unavailable" — never a false `critical` (acceptance #5).
 * Queries are memoized per audit run by the dns-util pipeline (one validation per domain per run).
 */
async function runDeepChecks(
	domain: string,
	cfg: DnssecCheckConfig,
	keys: DnskeyRecord[],
	dsPresent: boolean | null,
	dsRecords: DsRecord[],
): Promise<DeepOutcome> {
	const findings: Finding[] = [];
	const out: DeepOutcome = {
		findings,
		validates: null,
		bogus: false,
		nsec3: false,
		nsec3Iterations: null,
		nsec3Optout: null,
		rrsigEarliestExpiry: null,
		rrsigs: [],
		resolverUsed: null,
	};

	// ---- infra.dnssec_validates: AD flag from a validating resolver + CD bogus disambiguation ----
	let probe: DigDnssecResponse | null = null;
	for (const resolver of cfg.resolvers) {
		const r = await digDnssec(domain, "SOA", { resolver });
		if (!r.error) {
			probe = r;
			out.resolverUsed = resolver;
			break;
		}
		// exec-level failure (dig missing, resolver timeout) → back off to the next resolver.
	}

	if (!probe) {
		// All resolvers unreachable → advisory only, never a false critical (spec §6 back-off).
		findings.push({
			id: "infra.dnssec_validates.unavailable",
			checkId: "infra.dnssec_validates",
			title: "Validation unavailable",
			severity: "info",
			detail: `Could not reach any configured validating resolver (${cfg.resolvers.join(", ")}) to read the AD flag for ${domain}. Chain validation could not be determined this run.`,
			remediation:
				"Retry the audit later. If it persists, confirm outbound DNS (port 53) to the configured validating resolvers is permitted and the Brew `dig` binary is installed.",
		});
	} else if (probe.adFlag) {
		out.validates = true;
		findings.push({
			id: "infra.dnssec_validates.ok",
			checkId: "infra.dnssec_validates",
			title: "Chain validates",
			severity: "ok",
			detail: `AD=1 via ${out.resolverUsed} — a validating resolver accepts the full chain of trust (root → TLD → ${domain}).`,
			evidence: `dig +dnssec @${out.resolverUsed} ${domain} SOA → status ${probe.status ?? "?"}, flags include ad`,
		});
	} else if (probe.status === "SERVFAIL") {
		// CD-flag disambiguation (acceptance #6): bogus only when CD=1 succeeds where CD=0 SERVFAILs.
		const cdProbe = await digDnssec(domain, "SOA", {
			resolver: out.resolverUsed ?? undefined,
			cd: true,
		});
		if (
			!cdProbe.error &&
			cdProbe.status === "NOERROR" &&
			cdProbe.answers.length > 0
		) {
			out.validates = false;
			out.bogus = true;
			findings.push({
				id: "infra.dnssec_validates.bogus",
				checkId: "infra.dnssec_validates",
				title: "DNSSEC chain is bogus — domain dark to validating resolvers",
				severity: "critical",
				detail: `${out.resolverUsed} returns SERVFAIL for ${domain} with checking enabled (CD=0) but answers with checking disabled (CD=1): the data exists but its signatures do not verify. Validating resolvers (roughly a third of the internet, including most large mailbox providers) cannot resolve the domain — mail to and from it is failing right now.`,
				remediation:
					"Fix the signing chain immediately: re-sign the zone, correct the DS at the registrar so it matches the live KSK, or roll back the broken key. If a fast fix is not possible, temporarily removing the DS at the registrar (going insecure) beats staying bogus.",
				evidence: `@${out.resolverUsed} CD=0 → SERVFAIL; CD=1 → NOERROR (${cdProbe.answers.length} answer RR)`,
			});
		} else {
			// Both fail (or CD probe also unusable) — an ordinary outage/NXDOMAIN, never mislabeled
			// as a DNSSEC failure (acceptance #6).
			findings.push({
				id: "infra.dnssec_validates.unavailable",
				checkId: "infra.dnssec_validates",
				title: "Validation inconclusive (lookup failure, not a DNSSEC verdict)",
				severity: "info",
				detail: `${out.resolverUsed} returned SERVFAIL for ${domain} with checking both enabled and disabled — an ordinary resolution outage, not a DNSSEC signature failure. No bogus verdict is recorded.`,
				remediation:
					"Retry the audit later; investigate the domain's authoritative nameservers if the outage persists (see the DNS health check).",
			});
		}
	} else {
		// NOERROR but AD=0: the resolver answered without validating. Expected when no DS links the
		// chain (insecure delegation); suspicious when a DS is published.
		out.validates = false;
		findings.push({
			id: "infra.dnssec_validates.no_ad",
			checkId: "infra.dnssec_validates",
			title: "Chain does not validate (AD=0)",
			severity: dsPresent === true ? "warning" : "info",
			detail:
				dsPresent === true
					? `${out.resolverUsed} answers for ${domain} without the AD flag even though a DS is published at the parent — the chain of trust is not being validated end-to-end.`
					: `${out.resolverUsed} answers for ${domain} without the AD flag. With no DS at the parent the delegation is insecure, so this is expected until the DS is published.`,
			remediation:
				dsPresent === true
					? "Verify the published DS matches the live KSK (see the DS-match sub-check) and that every RRset is re-signed; validation should yield AD=1 once the chain links."
					: "Publish the DS/DNSKEY digest at your registrar so the parent links the chain of trust; validating resolvers will then return AD=1.",
			evidence: `dig +dnssec @${out.resolverUsed} ${domain} SOA → status ${probe.status ?? "?"}, no ad flag`,
		});
	}

	// Shared +cd DNSKEY probe: returns the apex RRSIGs even when the chain is bogus.
	const probeResolver = out.resolverUsed ?? cfg.resolvers[0];
	const dnskeyProbe = await digDnssec(domain, "DNSKEY", {
		resolver: probeResolver,
		cd: true,
	});
	const rrsigs = dnskeyProbe.answers
		.filter((a) => a.type.toUpperCase() === "RRSIG")
		.map((a) => parseRrsig(a.rdata))
		.filter((r): r is RrsigInfo => r !== null);
	// Record the parsed apex RRSIGs (pm/checks/dnssec.mdx §11) so the explainer's parsed breakdown
	// can show which RRset expires when, not only the earliest timestamp.
	out.rrsigs = rrsigs.map((r) => ({
		typeCovered: r.typeCovered,
		keyTag: r.keyTag,
		expiration: r.expiration ? r.expiration.toISOString() : null,
	}));

	// ---- infra.dnssec_rrsig_expiry: apex RRSIG Signature Expiration vs now + lead time ----
	const expirations = rrsigs
		.map((r) => r.expiration)
		.filter((d): d is Date => d !== null)
		.sort((a, b) => a.getTime() - b.getTime());
	if (dnskeyProbe.error || dnskeyProbe.answers.length === 0) {
		findings.push({
			id: "infra.dnssec_rrsig_expiry.unavailable",
			checkId: "infra.dnssec_rrsig_expiry",
			title: "RRSIG expiry unavailable",
			severity: "info",
			detail: `Could not fetch the apex DNSKEY RRSIGs for ${domain}${dnskeyProbe.error ? ` (${dnskeyProbe.error})` : ""}. Signature expiry could not be determined this run.`,
			remediation:
				"Retry the audit later. Keep automatic re-signing enabled on your signer so RRSIGs refresh well before expiry.",
		});
	} else if (expirations.length === 0) {
		// The zone answered DNSKEY but returned no RRSIG alongside — partial signing / broken signer.
		findings.push({
			id: "infra.dnssec_rrsig_expiry.no_rrsig",
			checkId: "infra.dnssec_rrsig_expiry",
			title: "No RRSIG over the apex DNSKEY",
			severity: "warning",
			detail: `${domain} returns its DNSKEY RRset without an accompanying RRSIG (+dnssec via ${probeResolver}) — the apex key set is not verifiably signed.`,
			remediation:
				"Re-sign the zone so the DNSKEY RRset carries an RRSIG; confirm the signer covers the apex and that automatic re-signing is running.",
		});
	} else {
		const earliest = expirations[0];
		out.rrsigEarliestExpiry = earliest.toISOString();
		const now = Date.now();
		const leadMs = cfg.rrsigLeadHours * 3_600_000;
		if (earliest.getTime() <= now) {
			// Already expired → validators return bogus: the domain is dark (acceptance #7).
			findings.push({
				id: "infra.dnssec_rrsig_expiry.expired",
				checkId: "infra.dnssec_rrsig_expiry",
				title: "RRSIG expired",
				severity: "critical",
				detail: `An apex RRSIG for ${domain} expired ${earliest.toISOString()} — validating resolvers treat the zone as bogus and SERVFAIL every lookup. The re-signing job has stalled.`,
				remediation:
					"Re-sign the zone now and restore the automatic re-signing job on your signer. Investigate why re-signing stalled (cron/HSM/permissions) so signatures refresh well before expiry.",
				evidence: `earliest Signature Expiration ${earliest.toISOString()} (via @${probeResolver} +cd)`,
			});
		} else if (earliest.getTime() <= now + leadMs) {
			findings.push({
				id: "infra.dnssec_rrsig_expiry.near",
				checkId: "infra.dnssec_rrsig_expiry",
				title: "RRSIG expiring soon",
				severity: "warning",
				detail: `The earliest apex RRSIG for ${domain} expires ${earliest.toISOString()} — within the ${cfg.rrsigLeadHours}h lead time. If re-signing does not refresh it, the domain goes dark to validating resolvers at expiry.`,
				remediation:
					"Restore automatic re-signing on your signer; if signing is manual, re-sign immediately. Investigate why the re-sign job stalled before the signature lapses.",
				evidence: `earliest Signature Expiration ${earliest.toISOString()}`,
			});
		} else {
			findings.push({
				id: "infra.dnssec_rrsig_expiry.ok",
				checkId: "infra.dnssec_rrsig_expiry",
				title: "RRSIGs fresh",
				severity: "ok",
				detail: `The earliest apex RRSIG for ${domain} expires ${earliest.toISOString()} — comfortably beyond the ${cfg.rrsigLeadHours}h lead time.`,
			});
		}
	}

	// ---- infra.dnssec_nsec3: NSEC3PARAM hygiene per RFC 9276 ----
	const n3 = await digDnssec(domain, "NSEC3PARAM", {
		resolver: probeResolver,
		cd: true,
	});
	if (n3.error) {
		findings.push({
			id: "infra.dnssec_nsec3.unavailable",
			checkId: "infra.dnssec_nsec3",
			title: "NSEC3 parameters unavailable",
			severity: "info",
			detail: `Could not query NSEC3PARAM for ${domain} (${n3.error}). Authenticated-denial parameters could not be inspected this run.`,
			remediation: "Retry the audit later.",
		});
	} else {
		const rec = n3.answers.find((a) => a.type.toUpperCase() === "NSEC3PARAM");
		if (!rec) {
			findings.push({
				id: "infra.dnssec_nsec3.nsec",
				checkId: "infra.dnssec_nsec3",
				title: "Authenticated denial via NSEC",
				severity: "ok",
				detail: `${domain} publishes no NSEC3PARAM — authenticated denial of existence uses plain NSEC (or the zone delegates denial elsewhere). No NSEC3 iteration/opt-out concerns apply.`,
			});
		} else {
			// NSEC3PARAM RDATA: <hash-alg> <flags> <iterations> <salt> (RFC 5155 §4).
			const tok = rec.rdata.trim().split(/\s+/);
			const flags = Number(tok[1]);
			const iterations = Number(tok[2]);
			const salt = tok[3] ?? "-";
			out.nsec3 = true;
			out.nsec3Iterations = Number.isInteger(iterations) ? iterations : null;
			out.nsec3Optout = Number.isInteger(flags)
				? (flags & 0x01) === 0x01
				: null;
			const issues: string[] = [];
			if (Number.isInteger(iterations) && iterations > 0) {
				issues.push(
					`iterations=${iterations} (RFC 9276 says 0 — excess CPU; some resolvers treat high counts as insecure)`,
				);
			}
			if (out.nsec3Optout === true) {
				issues.push(
					"opt-out flag is set (only appropriate for large delegation-heavy zones)",
				);
			}
			if (issues.length > 0) {
				findings.push({
					id: "infra.dnssec_nsec3.params",
					checkId: "infra.dnssec_nsec3",
					title: "NSEC3 parameters need tightening",
					severity: "warning",
					detail: `${domain} NSEC3PARAM: ${issues.join("; ")}.`,
					remediation:
						"Set NSEC3 iterations to 0 with an empty/short salt (RFC 9276) and disable opt-out unless you run a large delegation-heavy zone; then re-sign.",
					evidence: `NSEC3PARAM ${rec.rdata}`,
				});
			} else {
				findings.push({
					id: "infra.dnssec_nsec3.ok",
					checkId: "infra.dnssec_nsec3",
					title: "NSEC3 parameters sane",
					severity: "ok",
					detail: `${domain} uses NSEC3 with iterations=${out.nsec3Iterations ?? "?"}, salt=${salt}, opt-out off — per RFC 9276 guidance.`,
					evidence: `NSEC3PARAM ${rec.rdata}`,
				});
			}
		}
	}

	// ---- infra.dnssec_chain_complete: DS (parent) → DNSKEY (child) → RRSIG links ----
	if (dsPresent !== true) {
		findings.push({
			id: "infra.dnssec_chain_complete.no_ds",
			checkId: "infra.dnssec_chain_complete",
			title: "Chain incomplete — no DS at the parent",
			severity: "info",
			detail:
				dsPresent === false
					? `The chain root → TLD → ${domain} cannot be complete: the parent publishes no DS (see the DS-presence sub-check, reported there as a warning).`
					: `The parent DS for ${domain} could not be queried this run, so the chain walk is inconclusive.`,
			remediation:
				"Publish the DS at the registrar so the parent links to the zone's KSK; the chain walk will then verify every hop.",
		});
	} else {
		const dsTagsInKeys = dsRecords.filter((d) =>
			keys.some((k) => k.keyTag === d.keyTag),
		);
		const dnskeyRrsig = rrsigs.find((r) => r.typeCovered === "DNSKEY");
		if (dsTagsInKeys.length === 0) {
			findings.push({
				id: "infra.dnssec_chain_complete.broken",
				checkId: "infra.dnssec_chain_complete",
				title: "Chain broken — DS references a missing key",
				severity: "critical",
				detail: `The parent DS for ${domain} references key tag(s) ${dsRecords.map((d) => d.keyTag).join(", ")}, none of which exist in the live apex DNSKEY RRset (${keys.map((k) => k.keyTag).join(", ") || "empty"}). Validating resolvers cannot link the chain — the domain goes dark to them. This usually follows a key change where the parent DS was not updated.`,
				remediation:
					"Re-align the parent DS with the child KSK at the registrar: the DS key tag must exist in the apex DNSKEY RRset. Republish the DS (SHA-256, digest type 2) for the current KSK.",
				evidence: `DS keyTags=[${dsRecords.map((d) => d.keyTag).join(", ")}]; DNSKEY keyTags=[${keys.map((k) => k.keyTag).join(", ")}]`,
			});
		} else if (dnskeyProbe.error || dnskeyProbe.answers.length === 0) {
			findings.push({
				id: "infra.dnssec_chain_complete.unavailable",
				checkId: "infra.dnssec_chain_complete",
				title: "Chain walk inconclusive",
				severity: "info",
				detail: `The DS at the parent references a live key (tag ${dsTagsInKeys[0].keyTag}), but the apex RRSIGs could not be fetched this run, so the final DS → DNSKEY → RRSIG hop is unverified.`,
				remediation: "Retry the audit later.",
			});
		} else if (!dnskeyRrsig) {
			findings.push({
				id: "infra.dnssec_chain_complete.no_dnskey_rrsig",
				checkId: "infra.dnssec_chain_complete",
				title: "DNSKEY RRset not signed",
				severity: "warning",
				detail: `The parent DS links to a live key (tag ${dsTagsInKeys[0].keyTag}), but no RRSIG covers the apex DNSKEY RRset — the last hop of the chain does not verify.`,
				remediation:
					"Re-sign the zone so the KSK signs the DNSKEY RRset; confirm the signer is running and covers the apex.",
			});
		} else {
			findings.push({
				id: "infra.dnssec_chain_complete.ok",
				checkId: "infra.dnssec_chain_complete",
				title: "Chain complete",
				severity: "ok",
				detail: `Every hop links for ${domain}: the parent DS (key tag ${dsTagsInKeys[0].keyTag}) exists in the apex DNSKEY RRset, and an RRSIG (key tag ${dnskeyRrsig.keyTag}) covers the DNSKEY RRset.`,
				evidence: `DS→DNSKEY keyTag=${dsTagsInKeys[0].keyTag}; RRSIG(DNSKEY) keyTag=${dnskeyRrsig.keyTag}`,
			});
		}
	}

	// ---- infra.dnssec_soa_signed: mail-relevant RRsets each carry an RRSIG (not just the apex) ----
	const coverage: { type: string; covered: boolean }[] = [];
	const unavailableTypes: string[] = [];
	for (const type of ["SOA", "MX", "TXT"]) {
		const r = await digDnssec(domain, type, {
			resolver: probeResolver,
			cd: true,
		});
		if (r.error) {
			unavailableTypes.push(type);
			continue;
		}
		const hasRecords = r.answers.some((a) => a.type.toUpperCase() === type);
		if (!hasRecords) continue; // no such RRset — nothing that needs covering
		const covered = r.answers.some(
			(a) =>
				a.type.toUpperCase() === "RRSIG" &&
				parseRrsig(a.rdata)?.typeCovered === type,
		);
		coverage.push({ type, covered });
	}
	const uncovered = coverage.filter((c) => !c.covered).map((c) => c.type);
	if (uncovered.length > 0) {
		findings.push({
			id: "infra.dnssec_soa_signed.partial",
			checkId: "infra.dnssec_soa_signed",
			title: "Partially signed zone",
			severity: "warning",
			detail: `${uncovered.join("/")} RRset(s) for ${domain} are returned without an RRSIG on a signed zone — partial signing. Receivers cannot authenticate the ${uncovered.join("/")} data (MX routing, SPF/DMARC/MTA-STS TXT).`,
			remediation:
				"Ensure the signer covers all RRsets, not only the apex; re-sign the full zone so SOA, MX and TXT each carry an RRSIG.",
			evidence: coverage
				.map((c) => `${c.type}: ${c.covered ? "RRSIG ✓" : "no RRSIG"}`)
				.join("; "),
		});
	} else if (coverage.length === 0) {
		findings.push({
			id: "infra.dnssec_soa_signed.unavailable",
			checkId: "infra.dnssec_soa_signed",
			title: "RRset coverage inconclusive",
			severity: "info",
			detail: `Could not confirm RRSIG coverage of the mail-relevant RRsets for ${domain}${unavailableTypes.length > 0 ? ` (${unavailableTypes.join("/")} lookups failed)` : " (no SOA/MX/TXT records answered)"}.`,
			remediation: "Retry the audit later.",
		});
	} else {
		findings.push({
			id: "infra.dnssec_soa_signed.ok",
			checkId: "infra.dnssec_soa_signed",
			title: "Core RRsets signed",
			severity: "ok",
			detail: `${coverage.map((c) => c.type).join("/")} RRset(s) for ${domain} each carry an RRSIG — the mail-relevant data (MX, SPF/DMARC/MTA-STS TXT) is verifiably signed, not just the apex.`,
			evidence: coverage.map((c) => `${c.type}: RRSIG ✓`).join("; "),
		});
	}

	// ---- infra.dnssec_dane_ready: signed AND validates (spec §2/§7 future column) ----
	if (out.validates === true) {
		findings.push({
			id: "infra.dnssec_dane_ready.ok",
			checkId: "infra.dnssec_dane_ready",
			title: "DANE-ready",
			severity: "ok",
			detail: `${domain} is signed and a validating resolver accepts the chain (AD=1 via ${out.resolverUsed}) — TLSA records published for this zone are trustworthy. See the DANE/TLSA check.`,
		});
	} else if (out.validates === false) {
		findings.push({
			id: "infra.dnssec_dane_ready.not_validating",
			checkId: "infra.dnssec_dane_ready",
			title: "Not DANE-ready — chain does not validate",
			severity: "info",
			detail:
				"The zone is signed but a validating resolver does not (yet) accept the chain, so DANE/TLSA would not be trusted. Complete validation first (see the chain sub-checks above).",
			remediation:
				"Fix the chain of trust (DS at the registrar, fresh RRSIGs); once AD=1, publish TLSA records per the DANE/TLSA check.",
		});
	} else {
		findings.push({
			id: "infra.dnssec_dane_ready.signed",
			checkId: "infra.dnssec_dane_ready",
			title: "DANE-capable (validation inconclusive)",
			severity: "info",
			detail:
				"The zone is signed, so it can host TLSA records; full DANE trust also requires that a validating resolver accepts the chain (AD=1), which could not be confirmed this run.",
			remediation:
				"Complete DNSSEC validation (publish/verify the DS), then publish TLSA records per the DANE/TLSA check to enable DANE.",
		});
	}

	return out;
}

export const dnssecCheck: Checker = {
	id: CHECK_ID,
	label: "DNSSEC",
	async run(ctx): Promise<CheckOutcome> {
		const domain = ctx.domain;
		const findings: Finding[] = [];
		const cfg = loadDnssecConfig();
		const reg = buildAlgorithmRegistry(cfg.algorithms);

		// ---- infra.dnssec_signed (first round: DNSKEY presence) ----
		const dnskeyRes = await dig(domain, "DNSKEY");
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
			};
		}

		const keys = dnskeyRes.records
			.map(parseDnskey)
			.filter((k): k is DnskeyRecord => k !== null);

		if (keys.length === 0) {
			// Unsigned zone — advisory only (an upgrade you're missing, not a break). Must NOT go amber.
			// Spec acceptance #2: exactly ONE `info` finding — the DANE consequence rides in its detail
			// (and results.dane_ready=false signals the DANE/TLSA check, spec acceptance #13).
			findings.push({
				id: "infra.dnssec_signed.unsigned",
				checkId: "infra.dnssec_signed",
				title: "Zone is not DNSSEC-signed",
				severity: "info",
				detail: `${domain} publishes no DNSKEY, so the zone is unsigned — optional, but required for DANE. DNS answers (MX, SPF, DKIM, DMARC, MTA-STS) carry no tamper-evidence and DANE/TLSA is impossible until the zone is signed and validates.`,
				remediation:
					"Enable DNSSEC at your DNS provider/registrar — it is one-click at most managed providers (Cloudflare, Route 53, Google Domains). After enabling, publish the DS at your registrar to complete the chain of trust; then TLSA/DANE becomes possible (see the DANE/TLSA check).",
			});
			return {
				findings,
				results: {
					signed: false,
					ds_present: null,
					ds_digest_types: [],
					algorithms: [],
					ds_matches_dnskey: null,
					dane_ready: false,
					dsPresent: null,
					dnskeyAlgos: [],
					dsRecords: [],
					dsDigestType: null,
					dsAlgoMatch: null,
					...futureFieldDefaults(),
					checkedAt: new Date().toISOString(),
				} satisfies DnssecResults,
			};
		}

		// Zone is signed.
		const uniqueAlgos = [...new Set(keys.map((k) => k.algorithm))];
		const ksks = keys.filter((k) => k.flags === 257);
		findings.push({
			id: "infra.dnssec_signed.ok",
			checkId: "infra.dnssec_signed",
			title: "Zone is DNSSEC-signed",
			severity: "ok",
			detail: `${domain} publishes ${keys.length} DNSKEY(s) (${ksks.length} KSK, ${keys.length - ksks.length} ZSK) using ${uniqueAlgos.map((a) => reg.name(a)).join(", ")}.`,
			evidence: keys
				.map(
					(k) =>
						`${k.flags} ${k.algorithm} (${reg.name(k.algorithm)}) keyTag=${k.keyTag}`,
				)
				.join("; "),
		});

		// ---- infra.dnssec_algorithm (first round: parse DNSKEY algorithm) ----
		const deprecated = uniqueAlgos.filter((a) => reg.deprecated(a));
		if (deprecated.length > 0) {
			findings.push({
				id: "infra.dnssec_algorithm.deprecated",
				checkId: "infra.dnssec_algorithm",
				title: "Deprecated DNSSEC algorithm",
				severity: "warning",
				detail: `DNSKEY uses ${deprecated.map((a) => `${a} (${reg.name(a)})`).join(", ")} — RSASHA1-family algorithms are deprecated and being removed from validators.`,
				remediation:
					"Roll to a modern algorithm: ECDSAP256SHA256 (13) is compact and fast; RSASHA256 (8) is the RSA fallback. Update (republish) the DS at the registrar after the algorithm roll completes.",
				evidence: uniqueAlgos.map((a) => `${a} (${reg.name(a)})`).join(", "),
			});
		} else {
			findings.push({
				id: "infra.dnssec_algorithm.ok",
				checkId: "infra.dnssec_algorithm",
				title: "Modern signing algorithm",
				severity: "ok",
				detail: `Signing uses ${uniqueAlgos.map((a) => `${a} (${reg.name(a)})`).join(", ")} — a current, supported algorithm.`,
			});
		}

		// ---- infra.dnssec_key_rollover (first round advisory: static DNSKEY parse) ----
		const rolloverIssues: string[] = [];
		for (const k of ksks) {
			if (
				(k.algorithm === 5 ||
					k.algorithm === 7 ||
					k.algorithm === 8 ||
					k.algorithm === 10) &&
				k.bits !== null &&
				k.bits < 2048
			) {
				rolloverIssues.push(
					`KSK keyTag=${k.keyTag} is RSA ${k.bits}-bit (< 2048)`,
				);
			}
		}
		if (keys.length > 6) {
			rolloverIssues.push(
				`${keys.length} DNSKEYs in the set (stale keys from an incomplete rollover bloat responses)`,
			);
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
			});
		} else {
			findings.push({
				id: "infra.dnssec_key_rollover.ok",
				checkId: "infra.dnssec_key_rollover",
				title: "Key set looks healthy",
				severity: "ok",
				detail: `${keys.length} DNSKEY(s); no undersized RSA keys or stale-key bloat detected.`,
			});
		}

		// ---- infra.dnssec_ds_present + infra.dnssec_ds_algo_match (first round) ----
		let dsPresent: boolean | null = null;
		let dsDigestTypes: number[] = [];
		let dsMatches: boolean | null = null;
		let dsDigestType: number | null = null;
		let dsRecordsParsed: DsRecord[] = [];
		const dsRes = await dig(domain, "DS");
		if (dsRes.error) {
			findings.push({
				id: "infra.dnssec_ds_present.unavailable",
				checkId: "infra.dnssec_ds_present",
				title: "DS lookup unavailable",
				severity: "info",
				detail: `Could not query the parent DS for ${domain} (${dsRes.error}). Chain-of-trust presence could not be determined this run.`,
				remediation:
					"Retry the audit later. If it persists, confirm the parent/registrar nameservers are reachable and the Brew `dig` binary is installed.",
			});
		} else if (dsRes.empty) {
			dsPresent = false;
			// Signed but no DS at parent — "island of security": validation impossible.
			findings.push({
				id: "infra.dnssec_ds_present.missing",
				checkId: "infra.dnssec_ds_present",
				title: "No DS at the parent (island of security)",
				severity: "warning",
				detail: `${domain} is signed (has DNSKEY) but publishes no DS in the parent zone, so no resolver on Earth can validate it — the zone provides zero DNSSEC protection.`,
				remediation:
					"Copy the DS/DNSKEY digest from your DNS provider into your registrar's DNSSEC panel so the parent publishes the DS. Use SHA-256 (digest type 2).",
			});
		} else {
			const dsRecords = dsRes.records
				.map(parseDs)
				.filter((d): d is DsRecord => d !== null);
			dsRecordsParsed = dsRecords;
			dsPresent = true;
			dsDigestTypes = [...new Set(dsRecords.map((d) => d.digestType))];
			findings.push({
				id: "infra.dnssec_ds_present.ok",
				checkId: "infra.dnssec_ds_present",
				title: "DS published at the parent",
				severity: "ok",
				detail: `The parent zone publishes ${dsRecords.length} DS record(s) for ${domain}, establishing the chain of trust.`,
				evidence: dsRecords
					.map(
						(d) =>
							`keyTag=${d.keyTag} alg=${d.algorithm} digestType=${d.digestType}`,
					)
					.join("; "),
			});

			// Locally recompute the DS digest (RFC 4034 §5.1.4) and match against a live key.
			let matched: DsRecord | null = null;
			let matchedSha256 = false;
			for (const ds of dsRecords) {
				const hash = hashForDigestType(ds.digestType);
				if (!hash) continue;
				const hit = keys.find(
					(k) =>
						k.keyTag === ds.keyTag &&
						computeDsDigest(domain, k.rdata, hash) === ds.digest,
				);
				if (hit) {
					matched = ds;
					if (ds.digestType === 2) matchedSha256 = true;
				}
			}

			dsMatches = matched !== null;
			// The single dsDigestType column (spec §5): the digest type of the DS that matched a live
			// KSK; on a mismatch, the strongest published type so the row still records what exists.
			dsDigestType =
				matched?.digestType ??
				(dsDigestTypes.includes(2) ? 2 : (dsDigestTypes[0] ?? null));
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
				});
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
				});
			} else {
				findings.push({
					id: "infra.dnssec_ds_algo_match.ok",
					checkId: "infra.dnssec_ds_algo_match",
					title: "DS matches a live KSK",
					severity: "ok",
					detail: `The published SHA-256 DS (keyTag=${matched.keyTag}) matches the recomputed digest of a live KSK — the parent correctly references the current key.`,
					evidence: `keyTag=${matched.keyTag} digestType=${matched.digestType}`,
				});
			}
		}

		// ---- Validation-dependent sub-checks (spec §3/§7): deep path when the admin enables the
		// "validate via `dig`" toggle; otherwise each degrades to one advisory info (acceptance #5). ----
		let deep: DeepOutcome | null = null;
		if (cfg.validateViaDig) {
			deep = await runDeepChecks(domain, cfg, keys, dsPresent, dsRecordsParsed);
			findings.push(...deep.findings);
		} else {
			// ---- infra.dnssec_soa_signed (first round: presence heuristic) ----
			const soa = await resolveSoa(domain);
			if (soa.record) {
				findings.push({
					id: "infra.dnssec_soa_signed.present",
					checkId: "infra.dnssec_soa_signed",
					title: "Core RRsets present (RRSIG coverage pending deep check)",
					severity: "info",
					detail: `The apex SOA resolves for ${domain}. Confirming that SOA/MX/TXT (SPF/DMARC/MTA-STS) are each covered by an RRSIG — not just the apex DNSKEY — requires the future +dnssec deep check.`,
					remediation:
						"Ensure your signer covers all RRsets, not only the apex; re-sign the full zone. Verification of per-RRset RRSIG coverage will run once the +dnssec probe path ships.",
				});
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
			});

			// ---- FUTURE sub-checks with the deep path disabled: one advisory info each. ----
			findings.push({
				id: "infra.dnssec_validates.pending",
				checkId: "infra.dnssec_validates",
				title: "Chain validation pending",
				severity: "info",
				detail:
					'node:dns/promises returns cached answers and does not expose the AD flag. Confirming a validating resolver accepts the chain (AD=1) and disambiguating bogus (SERVFAIL with CD=0 but success with CD=1) requires the `dig +dnssec` / validating-resolver probe — enable "validate via dig" in Settings to run it.',
				remediation:
					"Enable the deep-check path (Settings → checks.dnssec.validateViaDig) to query 1.1.1.1 / 8.8.8.8 with +dnssec and read the AD flag. If it reports bogus, re-sign the zone or correct the DS to match the live KSK.",
			});
			findings.push({
				id: "infra.dnssec_rrsig_expiry.pending",
				checkId: "infra.dnssec_rrsig_expiry",
				title: "RRSIG expiry check pending",
				severity: "info",
				detail: `RRSIG Signature Expiration is not exposed by node:dns/promises. Checking apex RRSIGs for expiry (and near-expiry within the ${cfg.rrsigLeadHours}h lead time) requires the +dnssec deep check — enable "validate via dig" in Settings to run it.`,
				remediation:
					"Keep automatic re-signing enabled on your signer so RRSIGs auto-refresh well before expiry. The scheduled deep check will warn within the lead time and flag an already-expired RRSIG as critical.",
			});
			findings.push({
				id: "infra.dnssec_nsec3.pending",
				checkId: "infra.dnssec_nsec3",
				title: "NSEC3 parameter check pending",
				severity: "info",
				detail:
					'Reading NSEC3PARAM (hash, iterations, salt, opt-out) requires a +dnssec query, which node:dns/promises cannot do. This runs in the deep check — enable "validate via dig" in Settings.',
				remediation:
					"Per RFC 9276, set NSEC3 iterations to 0 with an empty/short salt and disable opt-out unless you run a large delegation-heavy zone. The deep check will verify these parameters.",
			});
			findings.push({
				id: "infra.dnssec_chain_complete.pending",
				checkId: "infra.dnssec_chain_complete",
				title: "Full chain walk pending",
				severity: "info",
				detail:
					"Walking the complete chain root → TLD → zone (DS → DNSKEY → RRSIG at every hop) requires a validator library or +dnssec probe. First round confirms the local DS-to-KSK link only (see DS match above).",
				remediation:
					"Ensure the parent DS key tag exists in the apex DNSKEY RRset. Enable the deep-check path to verify every delegation hop links.",
			});
		}

		return {
			findings,
			results: {
				signed: true,
				ds_present: dsPresent,
				ds_digest_types: dsDigestTypes,
				algorithms: uniqueAlgos,
				ds_matches_dnskey: dsMatches,
				// Deep path: signed AND validates (spec §7); presence round: derived from signed + DS.
				dane_ready: deep ? deep.validates === true : dsPresent === true,
				dsPresent,
				dnskeyAlgos: keys.map((k) => ({
					keyTag: k.keyTag,
					flags: k.flags,
					alg: k.algorithm,
					algName: reg.name(k.algorithm),
					bits: k.bits,
				})),
				// One entry per published DS (pm/checks/dnssec.mdx §11) — empty when none/unavailable.
				dsRecords: dsRecordsParsed.map((d) => ({
					keyTag: d.keyTag,
					algorithm: d.algorithm,
					digestType: d.digestType,
				})),
				dsDigestType,
				dsAlgoMatch: dsMatches,
				...futureFieldDefaults(),
				...(deep
					? {
							validates: deep.validates,
							bogus: deep.bogus,
							nsec3: deep.nsec3,
							nsec3Iterations: deep.nsec3Iterations,
							nsec3Optout: deep.nsec3Optout,
							rrsigEarliestExpiry: deep.rrsigEarliestExpiry,
							rrsigs: deep.rrsigs,
							resolverUsed: deep.resolverUsed,
						}
					: {}),
				checkedAt: new Date().toISOString(),
			} satisfies DnssecResults,
		};
	},
};
