import { resolve4, resolve6, resolveMx } from "../dns-util";
import type { Finding } from "../types";

/**
 * The second-round DMARC sub-checks (pm/checks/dmarc.mdx §2) that extend dmarc.check.ts:
 *
 *  - record hygiene: `dmarc.duplicate_tags` (same tag published twice), `dmarc.grammar`
 *    (cosmetic grammar — empty tokens, trailing semicolons, bare tokens), `dmarc.psd`
 *    (RFC 9989 public-suffix-domain flag sanity);
 *  - `dmarc.rua_mx` / `dmarc.rua_mx_ok`: the report-destination DELIVERABILITY probe — every
 *    rua/ruf mail domain must be able to receive mail (MX, or A/AAAA fallback, and not a
 *    RFC 7505 null MX), or the owner is flying blind while believing they monitor;
 *  - `dmarc.alignment_basis`: the alignment simulation against THIS run's actual SPF/DKIM
 *    posture (ctx.upstream) — which mechanism(s) can produce an aligned pass, whether the
 *    domain is forwarding-fragile (SPF-only), or cannot pass DMARC at all (PS-15);
 *  - `dmarc.bulk_sender`: the Gmail/Yahoo (2024) + Microsoft (2025) bulk-sender minimum —
 *    a valid DMARC record with at least p=none (PS-14);
 *  - `dmarc.misplaced` / `dmarc.cname`: finding builders for the PS-03 misplaced-record
 *    heuristics and the CNAME-at-_dmarc indirection.
 *
 * Everything here is pure `node:dns/promises` (via dns-util) or pure functions — no shell-outs,
 * so nothing in this module produces `tool_runs[]` entries (§3: in-process lookups are not tool
 * runs). Kept separate from dmarc.check.ts so the first-round checker stays readable.
 */

/** One rua/ruf mail-domain deliverability probe row (§5 `record.report_destination_probes[]`). */
export interface DmarcDestinationProbe {
	report_domain: string;
	/** MX present? null = lookup error (unverified). */
	mx_found: boolean | null;
	/** A/AAAA fallback present? Only probed when MX is absent; null = not probed / error. */
	a_found: boolean | null;
	/** Can the domain receive report mail at all? null = could not verify this run. */
	deliverable: boolean | null;
}

/** The §5 `record.alignment_simulation` block — this run's aligned-pass posture. */
export interface DmarcAlignmentSimulation {
	/** SPF can contribute an aligned pass (record found + evaluates valid). null = unknown. */
	spf_ready: boolean | null;
	/** DKIM can contribute an aligned pass (≥1 working selector). null = unknown. */
	dkim_ready: boolean | null;
	/** Which mechanism(s) carry DMARC for this domain right now. */
	basis: "dkim+spf" | "dkim-only" | "spf-only" | "none" | "unknown";
	/** True when the ONLY aligned path is SPF — forwarded mail will fail DMARC (PS-13). */
	forwarding_fragile: boolean;
}

/** Tag names DMARCbis knows (mirrors dmarc.check.ts KNOWN_TAGS; psd validated here). */
const PSD_VALUES = new Set(["y", "n", "u"]);

interface HygieneTag {
	name: string;
	value: string;
	/** The raw token before splitting (for bare-token grammar evidence). */
	raw: string;
}

/** Local tokenizer (kept here to avoid a dmarc.check.ts import cycle). */
function tokenize(raw: string): HygieneTag[] {
	return raw
		.split(";")
		.map((t) => t.trim())
		.filter(Boolean)
		.map((token) => {
			const eq = token.indexOf("=");
			if (eq === -1)
				return { name: token.toLowerCase(), value: "", raw: token };
			return {
				name: token.slice(0, eq).trim().toLowerCase(),
				value: token.slice(eq + 1).trim(),
				raw: token,
			};
		});
}

export interface RecordHygiene {
	findings: Finding[];
	/** Tag names that appear ≥2 times (first occurrence wins in our parser; receivers vary). */
	duplicateTags: string[];
	/** The psd= value as published (lower-cased) or null. */
	psd: string | null;
}

/**
 * Record hygiene (§2 `dmarc.duplicate_tags` / `dmarc.grammar` / `dmarc.psd`): duplicate tag
 * names, cosmetic grammar receivers tolerate but that signals copy-paste damage, and the RFC 9989
 * `psd=` flag that only public-suffix operators should ever publish.
 */
export function analyzeRecordHygiene(raw: string): RecordHygiene {
	const findings: Finding[] = [];
	const tags = tokenize(raw);

	// Duplicate tags — RFC 7489/9989 grammar allows each tag once; receivers disagree on which
	// occurrence wins (our parser keeps the first), so behavior becomes resolver-dependent.
	const counts = new Map<string, number>();
	for (const t of tags) counts.set(t.name, (counts.get(t.name) ?? 0) + 1);
	const duplicateTags = [...counts.entries()]
		.filter(([, n]) => n > 1)
		.map(([name]) => name);
	if (duplicateTags.length > 0) {
		findings.push({
			id: "dmarc.duplicate_tags",
			checkId: "dmarc",
			title: `Duplicate DMARC tag${duplicateTags.length === 1 ? "" : "s"}: ${duplicateTags.join(", ")}`,
			severity: "warning",
			detail:
				"The same tag is published more than once. The grammar allows each tag once; receivers disagree on which copy wins, so the effective policy becomes receiver-dependent.",
			remediation: `Keep exactly one occurrence of ${duplicateTags.join(", ")} and delete the rest.`,
			evidence: raw,
		});
	}

	// Cosmetic grammar — tolerated by us and most receivers (§4 edge cases), but flagged because
	// stray tokens and doubled semicolons usually mean a mangled copy-paste that will get worse.
	const issues: string[] = [];
	if (/;\s*;/.test(raw)) issues.push("empty tag token (doubled semicolon)");
	if (/;\s*$/.test(raw)) issues.push("trailing semicolon");
	for (const t of tags) {
		if (!t.raw.includes("=")) issues.push(`token without "=": "${t.raw}"`);
	}
	if (/[‘’“”]/.test(raw)) issues.push("smart quotes present");
	if (issues.length > 0) {
		findings.push({
			id: "dmarc.grammar",
			checkId: "dmarc",
			title: "Cosmetic grammar issues in the DMARC record",
			severity: "info",
			detail: `Tolerated by most receivers, but worth cleaning: ${issues.join("; ")}.`,
			remediation:
				"Rewrite the record as clean semicolon-separated tag=value pairs with plain ASCII quotes, e.g. v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
			evidence: raw,
		});
	}

	// psd= (RFC 9989): only Public Suffix Domain operators (registries) should publish it.
	const psdTag = tags.find((t) => t.name === "psd");
	const psd = psdTag ? psdTag.value.toLowerCase() : null;
	if (psd !== null) {
		if (!PSD_VALUES.has(psd)) {
			findings.push({
				id: "dmarc.psd",
				checkId: "dmarc",
				title: `Invalid psd=${psdTag?.value}`,
				severity: "info",
				detail:
					"psd must be y, n, or u (RFC 9989); anything else is ignored by receivers.",
				remediation:
					"Remove the psd tag — ordinary organizational domains never need it.",
				evidence: raw,
			});
		} else if (psd === "y") {
			findings.push({
				id: "dmarc.psd",
				checkId: "dmarc",
				title: "psd=y on an organizational domain",
				severity: "info",
				detail:
					"psd=y declares this domain a Public Suffix Domain (like a TLD registry), which changes how the DMARCbis tree walk picks the organizational domain. Only PSD operators should publish it.",
				remediation: "Remove psd=y unless you operate a public-suffix zone.",
				evidence: raw,
			});
		}
	}

	return { findings, duplicateTags, psd };
}

/** The mail domain of a mailto: report URI (null for non-mailto or malformed). */
function mailDomainOf(uri: string): string | null {
	const m = /^mailto:[^@]+@([a-z0-9.-]+)/i.exec(uri.trim());
	return m ? m[1].toLowerCase().replace(/\.$/, "") : null;
}

/** RFC 7505 null MX ("0 ."): the domain explicitly declares it receives no mail. */
function isNullMx(records: { exchange: string; priority: number }[]): boolean {
	return (
		records.length === 1 &&
		(records[0].exchange === "" || records[0].exchange === ".")
	);
}

/**
 * §2 `dmarc.rua_mx` / `dmarc.rua_mx_ok`: probe every DISTINCT rua/ruf mail domain (own-domain
 * destinations included — a dead in-domain mailbox loses reports just the same) for MX, falling
 * back to A/AAAA (RFC 5321 implicit MX), treating a null MX as explicitly non-receiving. Pure
 * in-process DNS — produces NO tool_runs entries.
 */
export async function probeReportDestinations(
	ruaUris: string[],
	rufUris: string[],
): Promise<{ probes: DmarcDestinationProbe[]; findings: Finding[] }> {
	const domains = [
		...new Set(
			[...ruaUris, ...rufUris]
				.map(mailDomainOf)
				.filter((d): d is string => d !== null),
		),
	];
	const probes: DmarcDestinationProbe[] = [];
	const findings: Finding[] = [];
	for (const rd of domains) {
		const mx = await resolveMx(rd);
		let mx_found: boolean | null;
		let a_found: boolean | null = null;
		let deliverable: boolean | null;
		if (mx.error) {
			mx_found = null;
			deliverable = null;
		} else if (mx.records.length > 0 && !isNullMx(mx.records)) {
			mx_found = true;
			deliverable = true;
		} else if (isNullMx(mx.records)) {
			// Null MX: the domain says "no mail, ever" — an A record cannot rescue it.
			mx_found = false;
			a_found = false;
			deliverable = false;
		} else {
			mx_found = false;
			const [a, aaaa] = await Promise.all([resolve4(rd), resolve6(rd)]);
			if (a.error && aaaa.error) {
				a_found = null;
				deliverable = null;
			} else {
				a_found = a.records.length > 0 || aaaa.records.length > 0;
				deliverable = a_found;
			}
		}
		probes.push({ report_domain: rd, mx_found, a_found, deliverable });

		if (deliverable === false) {
			findings.push({
				id: "dmarc.rua_mx",
				checkId: "dmarc",
				title: `Report mailbox domain ${rd} cannot receive mail`,
				severity: "warning",
				detail: isNullMx(mx.records)
					? `${rd} publishes a null MX (RFC 7505 "0 .") — it explicitly receives no mail, so every aggregate report sent there bounces. You believe you are monitoring, but you are flying blind.`
					: `${rd} has no MX record and no A/AAAA fallback — aggregate reports addressed there can never be delivered. You believe you are monitoring, but you are flying blind.`,
				remediation: `Point rua=/ruf= at a mailbox whose domain has a working MX (e.g. mailto:dmarc@<your-domain>), or fix the MX for ${rd}.`,
				evidence: `MX ${rd} → ${mx.records.length === 0 ? "none" : mx.records.map((r) => `${r.priority} ${r.exchange || "."}`).join(", ")}`,
			});
		} else if (deliverable === null) {
			findings.push({
				id: "dmarc.rua_mx",
				checkId: "dmarc",
				title: `Could not verify report mailbox domain ${rd}`,
				severity: "info",
				detail: `The MX/A lookup for ${rd} failed (${mx.error ?? "resolver error"}); re-run to confirm reports can be delivered.`,
			});
		}
	}
	if (domains.length > 0 && probes.every((p) => p.deliverable === true)) {
		findings.push({
			id: "dmarc.rua_mx_ok",
			checkId: "dmarc",
			title: `Report destination${domains.length === 1 ? "" : "s"} can receive mail (${domains.length} domain${domains.length === 1 ? "" : "s"} with MX)`,
			severity: "ok",
			detail: `Every rua/ruf mail domain (${domains.join(", ")}) resolves to a working mail host.`,
		});
	}
	return { probes, findings };
}

/**
 * §2 `dmarc.alignment_basis`: simulate which mechanism(s) can deliver an ALIGNED pass from this
 * run's actual posture — SPF (upstream `results.spf`: record found + evaluates valid) and DKIM
 * (upstream `results.dkim`: ≥1 working selector). DMARC passes only via an aligned SPF or DKIM
 * pass, so a domain with neither can NEVER pass (PS-15 — the Gmail 550-5.7.26
 * "unauthenticated mail" rejection), and a domain carried only by SPF breaks on every forwarder
 * (PS-13). Upstream results absent (partial run, unit tests) → basis "unknown", no finding.
 */
export function deriveAlignmentBasis(
	upstream: Record<string, unknown> | undefined,
	opts: { enforcing: boolean },
): { sim: DmarcAlignmentSimulation; finding: Finding | null } {
	const spf = upstream?.spf as
		| { record_found?: boolean; eval_result?: string }
		| undefined;
	const dkim = upstream?.dkim as { working_selectors?: number } | undefined;
	const spf_ready =
		spf && typeof spf.record_found === "boolean"
			? spf.record_found &&
				(spf.eval_result === undefined || spf.eval_result === "valid")
			: null;
	const dkim_ready =
		dkim && typeof dkim.working_selectors === "number"
			? dkim.working_selectors > 0
			: null;

	if (spf_ready === null || dkim_ready === null) {
		return {
			sim: {
				spf_ready,
				dkim_ready,
				basis: "unknown",
				forwarding_fragile: false,
			},
			finding: null,
		};
	}

	let basis: DmarcAlignmentSimulation["basis"];
	let finding: Finding;
	if (dkim_ready && spf_ready) {
		basis = "dkim+spf";
		finding = {
			id: "dmarc.alignment_basis",
			checkId: "dmarc",
			title: "Two aligned authentication paths (SPF + DKIM)",
			severity: "ok",
			detail:
				"Both SPF and DKIM are healthy on this domain, so DMARC has two independent ways to pass. DKIM carries forwarded mail (the connecting IP changes downstream, so SPF fails there); SPF backs it up for direct delivery.",
		};
	} else if (dkim_ready) {
		basis = "dkim-only";
		finding = {
			id: "dmarc.alignment_basis",
			checkId: "dmarc",
			title: "DKIM is the only aligned path (SPF unhealthy)",
			severity: "info",
			detail:
				"DMARC currently passes only via DKIM. That survives forwarding, so enforcement is safe — but a single DKIM key-rotation mistake would take every message with it. Fix the SPF category for redundancy.",
			remediation:
				"Repair the SPF record (see the SPF category) so both mechanisms carry DMARC.",
		};
	} else if (spf_ready) {
		basis = "spf-only";
		finding = {
			id: "dmarc.alignment_basis",
			checkId: "dmarc",
			title: "SPF is the only aligned path — forwarding-fragile",
			severity: "warning",
			detail:
				"No working DKIM selector was found, so every DMARC pass rides on SPF alone. Forwarders change the connecting IP, so legitimate forwarded mail WILL fail DMARC — spam-foldered at p=quarantine, bounced at p=reject.",
			remediation:
				"Set up aligned DKIM signing (d= your domain) on every sending system before raising the policy — a DKIM signature survives forwarding; SPF does not.",
		};
	} else {
		basis = "none";
		finding = {
			id: "dmarc.alignment_basis",
			checkId: "dmarc",
			title: "No aligned authentication path — DMARC can never pass",
			severity: opts.enforcing ? "critical" : "warning",
			detail: `Neither SPF nor DKIM is healthy on this domain, so no message can produce an aligned pass${
				opts.enforcing
					? " — with an enforcing policy published, receivers are being told to junk/reject 100% of this domain's mail"
					: ""
			}. Receivers like Gmail reject such mail outright (550-5.7.26 "this message does not pass authentication checks").`,
			remediation:
				"Publish a valid SPF record and set up at least one working DKIM selector (see the SPF and DKIM categories), then re-run.",
		};
	}
	return {
		sim: {
			spf_ready,
			dkim_ready,
			basis,
			forwarding_fragile: basis === "spf-only",
		},
		finding,
	};
}

/**
 * §2 `dmarc.bulk_sender`: the Gmail/Yahoo (Feb 2024) and Microsoft (May 2025) bulk-sender rules
 * require senders of ~5,000+ messages/day to publish at least `v=DMARC1; p=none` with a From:
 * aligned to SPF or DKIM. A usable record (exactly one, syntactically valid, with a real p=)
 * meets the DNS half of that minimum; a missing/broken record fails it (PS-14).
 */
export function bulkSenderFinding(domain: string, usable: boolean): Finding {
	if (usable) {
		return {
			id: "dmarc.bulk_sender",
			checkId: "dmarc",
			title: "Bulk-sender DMARC minimum met",
			severity: "ok",
			detail:
				"A valid DMARC record with a policy is published — the minimum Gmail, Yahoo (2024) and Microsoft (2025) require before accepting bulk mail (≥5,000 msgs/day). Alignment of each stream still matters (see dmarc.alignment_basis).",
		};
	}
	return {
		id: "dmarc.bulk_sender",
		checkId: "dmarc",
		title: "Bulk-sender DMARC minimum NOT met",
		severity: "warning",
		detail:
			"Gmail and Yahoo (since Feb 2024) and Microsoft (since May 2025) require bulk senders (~5,000+ msgs/day) to publish a valid DMARC record of at least p=none. Without one, bulk mail is rate-limited (4xx) or rejected outright regardless of content.",
		remediation: `Publish TXT at _dmarc.${domain}: "v=DMARC1; p=none; rua=mailto:dmarc@${domain}" — the zero-risk monitoring starter meets the minimum.`,
	};
}

/**
 * §2 `dmarc.misplaced` (PS-03): a DMARC-looking record exists at the WRONG name (apex,
 * dmarc.<domain> without the underscore, or a dead-target _dmarc CNAME) while `_dmarc.<domain>`
 * answers nothing — the owner published something, receivers never see a policy. Emitted
 * alongside the `dmarc.missing` critical.
 */
export function misplacedFinding(domain: string, hits: string[]): Finding {
	return {
		id: "dmarc.misplaced",
		checkId: "dmarc",
		title: "DMARC-looking record published in the wrong place",
		severity: "warning",
		detail: `Receivers only read _dmarc.${domain}, but a v=DMARC1-looking record was found at: ${hits.join("; ")}. It is invisible where it matters.`,
		remediation: `Move the record: publish the TXT at exactly _dmarc.${domain} and delete the misplaced copy.`,
		evidence: hits.join("; "),
	};
}

/**
 * §2 `dmarc.cname`: `_dmarc.<name>` is a CNAME — legal (resolvers follow it transparently) and
 * common with managed-DMARC vendors, but a fragile indirection: if the target zone lapses, the
 * policy silently vanishes. Recorded as `record.cname_target` and surfaced as an info row.
 */
export function cnameFinding(name: string, target: string): Finding {
	return {
		id: "dmarc.cname",
		checkId: "dmarc",
		title: `_dmarc is a CNAME to ${target}`,
		severity: "info",
		detail: `${name} does not hold the TXT record itself; it aliases ${target}, and the policy lives in that zone. Legal and receiver-transparent, but if the target record ever lapses (vendor churn, expired contract), your DMARC silently disappears.`,
		remediation: `Nothing to fix now — but monitor ${target}, or inline the TXT record at ${name} if you no longer need the vendor indirection.`,
		evidence: `${name} CNAME ${target}`,
	};
}
