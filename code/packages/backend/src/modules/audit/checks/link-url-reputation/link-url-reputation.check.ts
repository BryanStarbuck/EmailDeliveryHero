import { mapLimit, withResource } from "@shared/concurrency";
import { readAppConfig } from "@shared/config-store";
import type { BlocklistZone } from "../blacklist/blacklist-types";
import {
	buildQueryName,
	classifyAnswer,
	classifyZoneHealth,
} from "../blacklist/engine";
import { loadZones } from "../blacklist/zones";
import {
	getActiveSample,
	readSampleRaw,
} from "../content-scoring/sample-store";
import { resolve4, resolveTxt } from "../dns-util";
import type { Checker, CheckOutcome, Finding, Severity } from "../types";
import {
	DEFAULT_SHORTENERS,
	extractLinks,
	extractSampleParts,
	type LinkUrl,
	registrableDomain,
} from "./url-extract";

/**
 * Link / URL Reputation (pm/checks/link_url_reputation.mdx — the `content.url_*` sub-family of
 * Spam & Content). Extracts every link from the domain's sample message (the shared
 * content_sample_messages store owned by content_scoring), reduces each host to its Public-Suffix
 * registrable domain, and queries the URI/RHSBL blocklists — `dnsbl_zones WHERE kind='domain'`
 * from the blacklists registry (Spamhaus DBL, SURBL multi, URIBL multi, …), the RHSBL half of
 * RFC 5782: the domain is queried directly, with no reversal. It also flags link-hygiene problems
 * (URL shorteners, raw-IP hosts, punycode/homograph hosts, http-not-https links, off-brand links)
 * that filters penalize even when SPF/DKIM/DMARC are perfect.
 *
 * With no sample it emits exactly one `info` "add a sample" finding — never a false pass or false
 * listing — and records no per-URL rows (spec §3, AC#2). FUTURE sub-checks (redirect-chain /
 * reachability probes, Google Safe Browsing, paid ivmURI) each degrade to one `info` (AC#8).
 *
 * The structured payload lands at `results["content.url"]` — the audit-JSON `content.url` key of
 * spec §5: one `links[]` element per extracted URL (= one `message_urls` row) plus the one
 * `summary` roll-up (= the `url_check_results` row), round-tripping 1:1 (AC#9).
 */

const CHECK_ID = "content";

/** §3/§6 etiquette: URI-zone queries capped at ~8 in flight (also gated process-globally). */
const QUERY_CONCURRENCY = 8;

// ---------------------------------------------------------------------------------------------
// Structured results payload (spec §5 "File-store mapping" — the `content.url` key).
// ---------------------------------------------------------------------------------------------

/** One decoded URI-zone answer for a link domain (`message_urls.listings[]` element). */
export interface UrlZoneListing {
	zone: string;
	listed: boolean;
	/** The 127.0.0.x / 127.0.1.x return code. */
	code: string;
	/** Decoded sub-list / bitmask label, e.g. "phishing domain" or "black". */
	bit: string;
}

/** One extracted URL (= one `message_urls` row, camelCase per the spec §5 JSON example). */
export interface UrlLinkResult {
	url: string;
	/** PSL-registrable domain of the URL host (the raw IP for IP-literal hosts). */
	linkDomain: string;
	/** Registrable domain after redirect/shortener expansion — null until the probe round. */
	finalDomain: string | null;
	isShortener: boolean;
	isHttps: boolean;
	isIpLiteral: boolean;
	isPunycode: boolean;
	/** Brand a punycode host impersonates (critical homograph), or null. */
	homographOf: string | null;
	/** Redirect hops followed — null while the probe is disabled (first round). */
	redirectHops: number | null;
	listings: UrlZoneListing[];
	/** Link domain matches sender/org/allow-list; null = not evaluated (e.g. IP literal). */
	aligned: boolean | null;
}

/** The per-run roll-up (= the `url_check_results` row of spec §5). */
export interface UrlCheckSummary {
	totalLinks: number;
	uniqueDomains: number;
	listedDomains: number;
	shortenerCount: number;
	httpCount: number;
	ipLiteralCount: number;
	punycodeCount: number;
	offbrandCount: number;
	/** Zone(s) unavailable / paid feed unconfigured / redirect probe disabled. */
	inconclusive: boolean;
	weightedWorst: Severity;
}

/** §6 scheduler diff over the pinned sample's link-domain set (inconclusive transitions ignored). */
export interface UrlRunDiff {
	/** clean → listed this run: "zone|domain" pairs. */
	newListings: string[];
	/** listed → clean this run (domain still linked, zone conclusive both runs). */
	resolved: string[];
	/** The compared runs used different samples (diff is advisory across a sample change). */
	sampleChanged: boolean;
}

/** `results["content.url"]` — the audit-JSON `content.url` payload (spec §5, AC#9). */
export interface LinkUrlResults {
	schema_version: 1;
	/** The pinned content_sample_messages id this audit ran against (reproducibility, §3). */
	sampleId: string | null;
	summary: UrlCheckSummary;
	links: UrlLinkResult[];
	/** URI zones queried conclusively this run. */
	zonesQueried: string[];
	/** Zones whose RFC 5782 test point failed / answers were refused — inconclusive, never listed. */
	zonesInconclusive: string[];
	/** Zones skipped for missing registration/paid credentials (AC#6). */
	zonesSkipped: Array<{ zone: string; reason: string }>;
	diff: UrlRunDiff;
	checkedAt: string;
}

// ---------------------------------------------------------------------------------------------
// Sample plumbing: the shared content-scoring sample store, with a context override for tests.
// ---------------------------------------------------------------------------------------------

interface SampleObject {
	html?: string;
	text?: string;
	raw?: string;
	id?: number | string;
}
type SampleInput = string | SampleObject;

interface SampleSource {
	raw: string;
	id: string | null;
}

/** An inline sample handed straight through the context (unit tests / snippet flows). */
function readContextSample(ctx: unknown): SampleSource | null {
	const c = ctx as { sample?: SampleInput; sampleMessage?: SampleInput };
	const input = c.sample ?? c.sampleMessage;
	if (!input) return null;
	if (typeof input === "string") {
		const raw = input.trim();
		return raw ? { raw, id: null } : null;
	}
	const parts = [input.html, input.text, input.raw].filter(
		(p): p is string => typeof p === "string",
	);
	const raw = parts.join("\n").trim();
	if (!raw) return null;
	return { raw, id: input.id !== undefined ? String(input.id) : null };
}

// ---------------------------------------------------------------------------------------------
// URI zones: dnsbl_zones WHERE kind='domain' (spec §5 "Zone reuse" — no second zone table).
// ---------------------------------------------------------------------------------------------

/**
 * The distinct sub-check id per named URI zone (spec §2): a finding names the exact offending
 * body domain AND zone. Every other `kind='domain'` zone rolls under `content.url_dnsbl_cross`.
 */
const ZONE_SUBCHECK: Record<string, string> = {
	"dbl.spamhaus.org": "content.url_dbl",
	"multi.surbl.org": "content.url_surbl",
	"multi.uribl.com": "content.url_uribl",
	"uri.invaluement.com": "content.url_ivmuri",
};

function subCheckFor(zone: string): string {
	return ZONE_SUBCHECK[zone] ?? "content.url_dnsbl_cross";
}

function uriZones(): BlocklistZone[] {
	return loadZones().filter((z) => z.kind === "domain" && !z.positive);
}

/**
 * RFC 5782 test-point probe, once per zone per audit (§3, AC#6): `2.0.0.127.<zone>` must answer
 * and `1.0.0.127.<zone>` must be NXDOMAIN. Failure ⇒ the zone is inconclusive (info), never
 * false-listed. Runs through the process-global `dnsbl` semaphore — the same mirrors and rate
 * limits as the blacklists checker (pm/run_checks.mdx §3.1).
 */
async function probeZone(
	zone: BlocklistZone,
): Promise<{ usable: boolean; reason: string }> {
	const started = Date.now();
	const positive = await withResource("dnsbl", () =>
		resolve4(`2.0.0.127.${zone.zone}`),
	);
	const negative = await withResource("dnsbl", () =>
		resolve4(`1.0.0.127.${zone.zone}`),
	);
	const health = classifyZoneHealth({
		zone: zone.zone,
		positiveAnswers: positive.records,
		negativeAnswers: negative.records,
		probeMs: Date.now() - started,
	});
	switch (health.status) {
		case "dead":
			return {
				usable: false,
				reason:
					"test point 2.0.0.127 not listed (zone dead or resolver blocked)",
			};
		case "wildcarding":
			return {
				usable: false,
				reason:
					"test point 1.0.0.127 wrongly listed (zone wildcards / resolver intercepting)",
			};
		case "blocked":
			return {
				usable: false,
				reason: `test point returned an in-band refusal (${health.positive_probe})`,
			};
		default:
			return { usable: true, reason: "" };
	}
}

interface ZoneQueryRow {
	zone: BlocklistZone;
	domain: string;
	listed: boolean;
	inconclusive: boolean;
	code: string | null;
	bit: string | null;
	severity: Severity | null;
	reasonTxt: string | null;
	queryName: string;
}

/** One `<linkdomain>.<zone>` RHSBL lookup, decoded via the zone's return-code map / bitmask. */
async function queryZonePair(
	zone: BlocklistZone,
	domain: string,
): Promise<ZoneQueryRow> {
	const queryName = buildQueryName(domain, zone) ?? `${domain}.${zone.zone}`;
	const base: ZoneQueryRow = {
		zone,
		domain,
		listed: false,
		inconclusive: false,
		code: null,
		bit: null,
		severity: null,
		reasonTxt: null,
		queryName,
	};
	const answer = await withResource("dnsbl", () => resolve4(queryName));
	if (answer.error) return { ...base, inconclusive: true }; // SERVFAIL/timeout — never a listing
	if (answer.records.length === 0) return base; // NXDOMAIN / no data = not listed (AC#3)
	const decoded = classifyAnswer(zone, answer.records);
	if (decoded.refusal_code)
		return { ...base, inconclusive: true, code: decoded.refusal_code };
	if (!decoded.listed) return base;
	const txt = await withResource("dnsbl", () => resolveTxt(queryName));
	return {
		...base,
		listed: true,
		code: decoded.return_code,
		bit: decoded.sub_list,
		severity: decoded.severity ?? zone.severity,
		reasonTxt: txt.records.length > 0 ? txt.records.join(" | ") : null,
	};
}

// ---------------------------------------------------------------------------------------------
// Findings.
// ---------------------------------------------------------------------------------------------

const SEVERITY_RANK: Record<Severity, number> = {
	ok: 0,
	info: 1,
	warning: 2,
	critical: 3,
};

function noSampleFinding(): Finding {
	return {
		id: "content.url_extract",
		checkId: CHECK_ID,
		title: "No sample message — add one to check link reputation",
		severity: "info",
		detail:
			"Link/URL reputation needs a message body to inspect. No sample message is stored for this domain, so no links were extracted and no URI blocklists were queried (no false pass).",
		remediation:
			"Add a sample: paste or upload a raw .eml (Sample Message panel), paste an HTML/text snippet, or send a real campaign to this domain's ingest/seed address, then re-run the audit.",
	};
}

/**
 * The link-domains counted as aligned: the sending domain's registrable domain plus the
 * operator-configured own/related/allow-listed domains (spec §4 per-domain config inputs).
 */
function alignmentFor(
	link: LinkUrl,
	orgDomain: string,
	allowed: ReadonlySet<string>,
): boolean | null {
	if (link.isIpLiteral) return null; // evaluated by content.url_ip_literal instead
	const d = link.linkDomain;
	if (
		d === orgDomain ||
		d.endsWith(`.${orgDomain}`) ||
		orgDomain.endsWith(`.${d}`)
	)
		return true;
	return allowed.has(d);
}

/** Aggregate weighting (§3 "Severity mapping"): a low-weight zone listing never counts critical. */
function weightedSeverity(severity: Severity, weight: number): Severity {
	if (severity === "critical" && weight < 0.5) return "warning";
	return severity;
}

interface PreviousListingIndex {
	pairs: Set<string>;
	inconclusiveZones: Set<string>;
	sampleId: string | null;
}

function indexPrevious(
	previous: LinkUrlResults | undefined,
): PreviousListingIndex | null {
	if (!previous || !Array.isArray(previous.links)) return null;
	const pairs = new Set<string>();
	for (const link of previous.links) {
		for (const listing of link.listings ?? []) {
			if (listing.listed) pairs.add(`${listing.zone}|${link.linkDomain}`);
		}
	}
	return {
		pairs,
		inconclusiveZones: new Set(previous.zonesInconclusive ?? []),
		sampleId: previous.sampleId ?? null,
	};
}

// ---------------------------------------------------------------------------------------------
// The checker.
// ---------------------------------------------------------------------------------------------

export const linkUrlReputationCheck: Checker = {
	id: "content.url",
	label: "Link / URL Reputation",
	async run(ctx): Promise<Finding[] | CheckOutcome> {
		try {
			// --- Sample source (§3): context override (tests/snippets) else the shared sample store. --
			let sample = readContextSample(ctx);
			if (!sample && ctx.domainId) {
				const record = getActiveSample(ctx.domainId);
				if (record) {
					const raw = readSampleRaw(record);
					if (raw !== null) sample = { raw, id: record.id };
					else {
						return [
							{
								id: "content.url_extract",
								checkId: CHECK_ID,
								title: "Stored sample message could not be read",
								severity: "info",
								detail: `The active sample (uploaded ${record.uploadedAt}) is missing from the file store, so link/URL reputation was skipped — no false pass, no false listing.`,
								remediation:
									"Upload the sample .eml again to re-enable link-reputation checking.",
								evidence: record.rawPath ?? "(no stored path)",
							},
						];
					}
				}
			}
			// AC#2: no sample ⇒ exactly one info finding, no message_urls rows, no results payload.
			if (!sample) return [noSampleFinding()];
			return await analyzeSample(sample, ctx);
		} catch (err) {
			// Never throw out of run(): degrade to a retryable info finding (pm/errors.mdx).
			const msg = err instanceof Error ? err.message : String(err);
			return [
				{
					id: "content.url_extract",
					checkId: CHECK_ID,
					title: "Link/URL reputation check could not complete",
					severity: "info",
					detail: `The link/URL reputation check hit an unexpected error (${msg}).`,
					remediation:
						"Retry the audit; if it persists, verify the sample message and resolver.",
				},
			];
		}
	},
};

async function analyzeSample(
	sample: { raw: string; id: string | null },
	ctx: {
		domain: string;
		linkUrl?: { allowedDomains: string[] };
		previousResults?: Record<string, unknown>;
	},
): Promise<CheckOutcome> {
	const findings: Finding[] = [];
	const orgDomain = registrableDomain(ctx.domain);
	const allowedDomains = new Set(
		(ctx.linkUrl?.allowedDomains ?? [])
			.map((d) => registrableDomain(d.trim().toLowerCase()))
			.filter(Boolean),
	);

	// Shortener list is config, not code (spec §5): config.yaml → checks.content.url.shorteners.
	const urlConfig = readAppConfig().checks.content?.url;
	const shorteners = new Set(
		(urlConfig?.shorteners?.length
			? urlConfig.shorteners
			: DEFAULT_SHORTENERS
		).map((s) => s.trim().toLowerCase()),
	);
	const safeBrowsingConfigured = Boolean(urlConfig?.safeBrowsingKey);

	// --- content.url_extract (§3 extraction & normalization, AC#1) ------------------------------
	const parts = extractSampleParts(sample.raw);
	const htmlish = parts.html !== null;
	const links = extractLinks(parts, shorteners);
	const linkDomains = [
		...new Set(links.filter((l) => !l.isIpLiteral).map((l) => l.linkDomain)),
	];

	if (links.length === 0) {
		findings.push({
			id: "content.url_extract",
			checkId: CHECK_ID,
			title: htmlish
				? "HTML message has no parseable links"
				: "No links in sample",
			severity: htmlish ? "warning" : "info",
			detail: htmlish
				? "The sample is HTML but no parseable links were found. If links are present but malformed, receivers (and recipients) cannot resolve them either."
				: "No http(s) links were found in the sample; nothing to check against URI blocklists.",
			...(htmlish
				? {
						remediation:
							"Fix malformed href/encoded URLs so links parse (and so receivers can follow them).",
					}
				: {}),
			evidence: sample.id ? `sample ${sample.id}` : undefined,
		});
	} else {
		findings.push({
			id: "content.url_extract",
			checkId: CHECK_ID,
			title: `${linkDomains.length} unique link domain(s) found`,
			severity: "info",
			detail: `Extracted ${links.length} link(s) from the HTML/text parts, reducing to ${linkDomains.length} unique PSL-registrable domain(s), de-duplicated before any DNS query.${sample.id ? ` Sample: ${sample.id}.` : ""}`,
			evidence: linkDomains.join(", ") || links.map((l) => l.url).join(", "),
		});
	}

	// --- Per-URL hygiene flags (AC#4): https / ip_literal / punycode+homograph / shortener -------
	const httpLinks = links.filter((l) => !l.isHttps);
	if (httpLinks.length > 0) {
		findings.push({
			id: "content.url_https",
			checkId: CHECK_ID,
			title: `${httpLinks.length} link(s) use http:// (not https)`,
			severity: "warning",
			detail:
				"One or more links use http://, an interception/downgrade risk and a classic phishing signal that raises spam score.",
			remediation:
				"Change these links to https:// and ensure the landing site has a valid TLS certificate so https does not break.",
			evidence: httpLinks.map((l) => l.url).join(", "),
		});
	} else if (links.length > 0) {
		findings.push({
			id: "content.url_https",
			checkId: CHECK_ID,
			title: "All links use https",
			severity: "ok",
			detail: `All ${links.length} link(s) use https.`,
		});
	}

	const ipLinks = links.filter((l) => l.isIpLiteral);
	if (ipLinks.length > 0) {
		findings.push({
			id: "content.url_ip_literal",
			checkId: CHECK_ID,
			title: `${ipLinks.length} link(s) use a raw IP host`,
			severity: "critical",
			detail:
				"One or more links use a raw IP-literal host (e.g. http://203.0.113.9/...). This is a strong phishing/malware signal and a near-guaranteed spam-score hit.",
			remediation:
				"Replace the IP-literal with a proper hostname on an authenticated domain you control.",
			evidence: ipLinks.map((l) => l.url).join(", "),
		});
	} else if (links.length > 0) {
		findings.push({
			id: "content.url_ip_literal",
			checkId: CHECK_ID,
			title: "No raw-IP links",
			severity: "ok",
			detail: "No link uses a raw IP-literal host.",
		});
	}

	const punyLinks = links.filter((l) => l.isPunycode);
	const homographLinks = links.filter((l) => l.homographOf !== null);
	if (homographLinks.length > 0) {
		// Brand homograph = unambiguous phishing shape ⇒ critical (§3 severity mapping, AC#5).
		const brands = [...new Set(homographLinks.map((l) => l.homographOf))].join(
			", ",
		);
		findings.push({
			id: "content.url_punycode",
			checkId: CHECK_ID,
			title: `Homograph link host(s) impersonating ${brands}`,
			severity: "critical",
			detail: `One or more punycode (xn--) link hosts are confusable lookalikes of a protected brand (${brands}) — the classic IDN-homograph phishing shape (e.g. Cyrillic "аpple.com").`,
			remediation:
				"Use the real ASCII domain. A lookalike of a protected brand will be treated as phishing by every major filter — remove the link entirely if it is not yours.",
			evidence: homographLinks.map((l) => l.url).join(", "),
		});
	} else if (punyLinks.length > 0) {
		findings.push({
			id: "content.url_punycode",
			checkId: CHECK_ID,
			title: `${punyLinks.length} punycode/IDN link host(s)`,
			severity: "warning",
			detail:
				"One or more link hosts are punycode (xn-- labels), a common homograph/lookalike phishing technique.",
			remediation:
				"Use the real ASCII domain. If the IDN is intentional and legitimate, confirm it is not a lookalike of a protected brand.",
			evidence: punyLinks.map((l) => l.url).join(", "),
		});
	} else if (links.length > 0) {
		findings.push({
			id: "content.url_punycode",
			checkId: CHECK_ID,
			title: "No punycode/homograph link hosts",
			severity: "ok",
			detail:
				"No link host uses punycode (xn--) labels or impersonates a known brand.",
		});
	}

	const shortenerLinks = links.filter((l) => l.isShortener);
	if (shortenerLinks.length > 0) {
		const domains = [...new Set(shortenerLinks.map((l) => l.linkDomain))];
		findings.push({
			id: "content.url_shortener",
			checkId: CHECK_ID,
			title: `${shortenerLinks.length} link(s) go through a URL shortener`,
			severity: "warning",
			detail: `Message routes recipients through public shortener(s) (${domains.join(", ")}) that hide — and cannot vouch for — the true destination; filters penalize this on principle.`,
			remediation:
				"Replace shortener links with the full destination URL, or use a branded/custom-domain shortener you authenticate; once the redirect probe is enabled the final domain is re-checked (content.url_redirect_chain).",
			evidence: shortenerLinks.map((l) => l.url).join(", "),
		});
	} else if (links.length > 0) {
		findings.push({
			id: "content.url_shortener",
			checkId: CHECK_ID,
			title: "No public URL shorteners",
			severity: "ok",
			detail: "No link routes through a public URL shortener.",
		});
	}

	// --- content.url_domain_alignment (advisory; sender/org domain + configured allow-list) ------
	const alignedByDomain = new Map<string, boolean>();
	for (const link of links) {
		const aligned = alignmentFor(link, orgDomain, allowedDomains);
		if (aligned !== null) alignedByDomain.set(link.linkDomain, aligned);
	}
	const offBrand = linkDomains.filter((d) => alignedByDomain.get(d) === false);
	if (linkDomains.length > 0) {
		if (offBrand.length > linkDomains.length / 2) {
			findings.push({
				id: "content.url_domain_alignment",
				checkId: CHECK_ID,
				title: `${offBrand.length}/${linkDomains.length} link domains are off-brand`,
				severity: "warning",
				detail: `Most links point at domains unrelated to ${orgDomain}${allowedDomains.size > 0 ? " (and its configured allow-list)" : ""}, which looks forwarded/spoofed to filters.`,
				remediation:
					"Advisory: link primarily to your own authenticated domains; register tracking/click domains under your org and add them to this domain's allowed link domains (see content_scoring).",
				evidence: offBrand.join(", "),
			});
		} else {
			findings.push({
				id: "content.url_domain_alignment",
				checkId: CHECK_ID,
				title: "Links are mostly on-brand",
				severity: "info",
				detail: `${linkDomains.length - offBrand.length}/${linkDomains.length} link domains align with ${orgDomain}${allowedDomains.size > 0 ? " or its configured allow-list" : ""}.`,
				...(offBrand.length > 0
					? { evidence: `off-brand: ${offBrand.join(", ")}` }
					: {}),
			});
		}
	}

	// --- content.url_count (advisory info unless the spam-shaped thresholds cross) ---------------
	if (links.length > 0) {
		const spamShaped = links.length > 25 || offBrand.length > 15;
		findings.push({
			id: "content.url_count",
			checkId: CHECK_ID,
			title: spamShaped
				? "Link volume looks spam-shaped"
				: "Link volume looks reasonable",
			severity: spamShaped ? "warning" : "info",
			detail: `Message has ${links.length} link(s) across ${linkDomains.length} distinct domain(s) (${offBrand.length} off-brand).${spamShaped ? " High link counts and many off-domain hosts correlate with spam." : ""}`,
			...(spamShaped
				? {
						remediation:
							"Reduce the link count, consolidate to your own domain, and balance text vs. links.",
					}
				: {}),
		});
	}

	// --- URI zones: dnsbl_zones kind='domain' (content.url_dbl/_surbl/_uribl/_dnsbl_cross) -------
	const zones = uriZones();
	// AC#6: registration-gated / paid zones without credentials are skipped with an info note.
	const gatedZones = zones.filter((z) => z.requires_registration || z.is_paid);
	const activeZones = zones.filter(
		(z) => z.enabled && !z.requires_registration && !z.is_paid,
	);

	const zonesSkipped: Array<{ zone: string; reason: string }> = [];
	for (const z of gatedZones) {
		const reason = z.is_paid
			? "paid subscription/licensed resolver required"
			: "registration/API key required";
		zonesSkipped.push({ zone: z.zone, reason });
		findings.push({
			id: `${subCheckFor(z.zone)}.skipped.${z.zone}`,
			checkId: CHECK_ID,
			title: `${z.name} skipped (${reason})`,
			severity: "info",
			detail: `${z.name} (${z.zone}) is a ${z.is_paid ? "paid" : "registration-gated"} URI zone and no credentials are configured, so link domains were not checked against it — inconclusive, not clean.`,
			remediation: `Configure access for ${z.name} in the Blocklist Zones settings panel (lookups at ${z.lookup_url}), then re-run. Listings there are removed via ${z.delist_url}.`,
		});
	}

	// RFC 5782 preflight, once per zone per audit (§3, AC#6).
	const health = await mapLimit(activeZones, QUERY_CONCURRENCY, async (z) => ({
		zone: z,
		...(await probeZone(z)),
	}));
	const usableZones = health.filter((h) => h.usable).map((h) => h.zone);
	const zonesInconclusive: string[] = [];
	for (const h of health) {
		if (h.usable) continue;
		zonesInconclusive.push(h.zone.zone);
		findings.push({
			id: `${subCheckFor(h.zone.zone)}.inconclusive.${h.zone.zone}`,
			checkId: CHECK_ID,
			title: `${h.zone.name} unavailable this run`,
			severity: "info",
			detail: `${h.zone.name} (${h.zone.zone}) failed its RFC 5782 test point (${h.reason}); its results are inconclusive — not treated as clean or listed.`,
			remediation: `Query ${h.zone.name} from a dedicated non-public resolver (public resolvers like 8.8.8.8/1.1.1.1 and high-volume clients are blocked — set EDH_DNS_RESOLVER), or register/license access, then re-run.`,
		});
	}

	// The sweep: every usable zone × unique link domain (deduped BEFORE querying, §3/§6), plus
	// final domains once the redirect probe lands (null in first round — nothing extra to query).
	const pairs = usableZones.flatMap((zone) =>
		linkDomains.map((domain) => ({ zone, domain })),
	);
	const rows = await mapLimit(pairs, QUERY_CONCURRENCY, (p) =>
		queryZonePair(p.zone, p.domain),
	);

	const listingsByDomain = new Map<string, UrlZoneListing[]>();
	const listedDomains = new Set<string>();
	let transient = false;
	for (const row of rows) {
		if (row.inconclusive) {
			transient = true;
			if (!zonesInconclusive.includes(row.zone.zone))
				zonesInconclusive.push(row.zone.zone);
			continue;
		}
		if (!row.listed) continue;
		listedDomains.add(row.domain);
		const list = listingsByDomain.get(row.domain) ?? [];
		list.push({
			zone: row.zone.zone,
			listed: true,
			code: row.code ?? "",
			bit: row.bit ?? row.zone.name,
		});
		listingsByDomain.set(row.domain, list);
		const severity = row.severity ?? "warning";
		const subCheck = subCheckFor(row.zone.zone);
		findings.push({
			// Distinct id per (sub-check, zone, domain): one finding per bad domain per zone (deduped
			// across repeated links), and stable across runs so the §6 diff flags clean→listed as new.
			id:
				subCheck === "content.url_dnsbl_cross"
					? `${subCheck}:${row.zone.zone}:${row.domain}`
					: `${subCheck}:${row.domain}`,
			checkId: CHECK_ID,
			title: `Linked domain ${row.domain} is listed on ${row.zone.name}${row.bit ? ` (${row.bit})` : ""}`,
			severity,
			detail: `The link domain ${row.domain} is on ${row.zone.name} (${row.queryName} answered ${row.code}${row.bit ? ` = ${row.bit}` : ""}).${row.reasonTxt ? ` Reason: ${row.reasonTxt}.` : ""} Content filters (SpamAssassin URIBL_*, Rspamd SURBL_*/DBL, commercial gateways) weight body-URL reputation heavily, so this can spam-file the whole message even with perfect SPF/DKIM/DMARC.`,
			remediation: `Stop linking ${row.domain}. If it is yours, secure the compromised site/shortener first, then request removal at ${row.reasonTxt?.match(/https?:\/\/\S+/)?.[0] ?? row.zone.delist_url} (return code ${row.code}${row.bit ? ` = ${row.bit}` : ""}).`,
			evidence: `${row.queryName} → ${row.code}${row.reasonTxt ? `; TXT: ${row.reasonTxt}` : ""}`,
		});
	}

	if (linkDomains.length > 0 && usableZones.length > 0) {
		if (listedDomains.size === 0) {
			findings.push({
				id: "content.url_reputation.clean",
				checkId: CHECK_ID,
				title: "All link domains clean on checked URI blocklists",
				severity: "ok",
				detail: `Checked ${linkDomains.length} link domain(s) against ${usableZones.length} URI zone(s) (${usableZones.map((z) => z.name).join(", ")}) — none listed.`,
				evidence: linkDomains.join(", "),
			});
		}
		if (transient) {
			findings.push({
				id: "content.url_reputation.transient",
				checkId: CHECK_ID,
				title: "Some URI-zone lookups failed transiently",
				severity: "info",
				detail:
					"One or more URI-blocklist lookups returned SERVFAIL/timeout or an in-band refusal; those domains were not conclusively cleared (inconclusive, never false-listed).",
				remediation:
					"Retry the audit later; if it persists, use a dedicated non-public resolver (EDH_DNS_RESOLVER).",
			});
		}
	}

	// --- §6 diff vs the previous run over the link-domain set (AC#10) ----------------------------
	const previous = indexPrevious(
		ctx.previousResults?.["content.url"] as LinkUrlResults | undefined,
	);
	const currentPairs = new Set<string>();
	for (const [domain, listings] of listingsByDomain) {
		for (const l of listings) currentPairs.add(`${l.zone}|${domain}`);
	}
	const diff: UrlRunDiff = {
		newListings: [],
		resolved: [],
		sampleChanged: false,
	};
	if (previous) {
		diff.sampleChanged = previous.sampleId !== sample.id;
		const conclusiveZones = new Set(usableZones.map((z) => z.zone));
		for (const pair of currentPairs) {
			const [zone] = pair.split("|");
			// clean→listed is new only when the zone was conclusive last run (inconclusive↔listed
			// transitions are ignored to avoid resolver-blockage false alarms, §6).
			if (!previous.pairs.has(pair) && !previous.inconclusiveZones.has(zone)) {
				diff.newListings.push(pair);
			}
		}
		for (const pair of previous.pairs) {
			const [zone, domain] = pair.split("|");
			if (!linkDomains.includes(domain)) continue; // domain no longer linked — not "resolved"
			if (!conclusiveZones.has(zone) || zonesInconclusive.includes(zone))
				continue;
			if (!currentPairs.has(pair)) diff.resolved.push(pair);
		}
		if (diff.resolved.length > 0) {
			findings.push({
				id: "content.url_reputation.resolved",
				checkId: CHECK_ID,
				title: `${diff.resolved.length} URI listing(s) resolved since the previous run`,
				severity: "info",
				detail: `Previously-listed link domain(s) now answer clean: ${diff.resolved
					.map((p) => {
						const [zone, domain] = p.split("|");
						return `${domain} on ${zone}`;
					})
					.join(
						"; ",
					)}.${diff.sampleChanged ? " Note: the sample message changed between runs, so the comparison is over the current link-domain set." : ""}`,
			});
		}
	}

	// --- FUTURE sub-checks: one info each, never warning/critical (spec §7, AC#8) ----------------
	const hasIvmUriZone = zones.some(
		(z) =>
			z.zone in ZONE_SUBCHECK && subCheckFor(z.zone) === "content.url_ivmuri",
	);
	if (!hasIvmUriZone) {
		findings.push({
			id: "content.url_ivmuri",
			checkId: CHECK_ID,
			title: "Invaluement ivmURI check pending (paid feed)",
			severity: "info",
			detail:
				"ivmURI requires a paid Invaluement subscription and a licensed resolver, so link domains were not checked against it this round — inconclusive, not clean.",
			remediation:
				"Once licensed, configure the ivmURI resolver/key in the Blocklist Zones settings panel; listed domains are checked/removed via https://www.invaluement.com/lookup/.",
		});
	}
	findings.push({
		id: "content.url_redirect_chain",
		checkId: CHECK_ID,
		title: "Redirect-chain expansion disabled (first round)",
		severity: "info",
		detail:
			"Following shortener/redirect hops to reveal the true final domain needs an outbound HTTP probe (hop cap 5, 5s timeout, no cookies/JS), which is off in the first round; final_domain is null and shortener destinations were not expanded or re-checked against the URI zones.",
		remediation:
			"Enable the bounded redirect probe to expand shorteners and re-check the final landing domain against the URI zones.",
	});
	findings.push({
		id: "content.url_reachable",
		checkId: CHECK_ID,
		title: "Link reachability check disabled (first round)",
		severity: "info",
		detail:
			"Classifying dead/parked/NXDOMAIN destinations needs an outbound HTTP HEAD probe, off in the first round.",
		remediation:
			"Enable the reachability probe to flag broken/parked links that hurt engagement and look spammy.",
	});
	findings.push({
		id: "content.url_safe_browsing",
		checkId: CHECK_ID,
		title: safeBrowsingConfigured
			? "Google Safe Browsing screening pending (probe round)"
			: "Google Safe Browsing check pending (API key required)",
		severity: "info",
		detail: safeBrowsingConfigured
			? "A Safe Browsing API key is configured, but the hashed Lookup/Update v4 screening of link/final domains ships with the probe round."
			: "Checking link/final domains against Google Safe Browsing (malware/phishing/unwanted software) needs a Safe Browsing API key, which is not configured.",
		remediation: safeBrowsingConfigured
			? "No action needed — screening activates automatically when the probe round ships."
			: "Add a Google Safe Browsing API key (config.yaml → checks.content.url.safeBrowsingKey) to enable phishing/malware screening of body links.",
	});

	// --- content.url_aggregate: worst WEIGHTED severity roll-up (§3, AC#5) -----------------------
	const considered: Severity[] = [];
	for (const row of rows) {
		if (row.listed && row.severity)
			considered.push(weightedSeverity(row.severity, row.zone.weight));
	}
	for (const f of findings) {
		// Hygiene/extract findings carry full weight; listing rows were weighted above (skip their ids).
		if (f.id.includes(":")) continue;
		if (f.severity === "warning" || f.severity === "critical")
			considered.push(f.severity);
	}
	const worst = considered.reduce<Severity>(
		(acc, s) => (SEVERITY_RANK[s] > SEVERITY_RANK[acc] ? s : acc),
		"ok",
	);
	// Advisory info alone never turns the Spam & Content cell amber (§3 severity mapping).
	const aggregateSeverity: Severity =
		worst === "critical" || worst === "warning" ? worst : "ok";
	findings.push({
		id: "content.url_aggregate",
		checkId: CHECK_ID,
		title:
			aggregateSeverity === "ok"
				? "Link/URL reputation clean"
				: `Link/URL reputation: ${aggregateSeverity} issue(s) found`,
		severity: aggregateSeverity,
		detail:
			aggregateSeverity === "ok"
				? "No URI listing, raw-IP, homograph, shortener, http, or alignment problem fired for this sample."
				: "One or more link/URL problems fired; fix the highest-weight listing/link first — each finding above carries its delisting URL or exact link-hygiene edit.",
		...(aggregateSeverity === "ok"
			? {}
			: {
					remediation:
						"Work the prioritized list above: resolve any critical URI listing / raw-IP / homograph link first, then shortener/http/alignment warnings.",
				}),
	});

	// --- Structured payload: the audit-JSON `content.url` key (spec §5, AC#9) --------------------
	const linkResults: UrlLinkResult[] = links.map((l) => ({
		url: l.url,
		linkDomain: l.linkDomain,
		finalDomain: null, // redirect/shortener expansion is a future-round probe (§3, AC#8)
		isShortener: l.isShortener,
		isHttps: l.isHttps,
		isIpLiteral: l.isIpLiteral,
		isPunycode: l.isPunycode,
		homographOf: l.homographOf,
		redirectHops: null,
		listings: listingsByDomain.get(l.linkDomain) ?? [],
		aligned: alignmentFor(l, orgDomain, allowedDomains),
	}));
	const results: LinkUrlResults = {
		schema_version: 1,
		sampleId: sample.id,
		summary: {
			totalLinks: links.length,
			uniqueDomains: linkDomains.length,
			listedDomains: listedDomains.size,
			shortenerCount: shortenerLinks.length,
			httpCount: httpLinks.length,
			ipLiteralCount: ipLinks.length,
			punycodeCount: punyLinks.length,
			offbrandCount: offBrand.length,
			inconclusive:
				zonesInconclusive.length > 0 || zonesSkipped.length > 0 || transient,
			weightedWorst: aggregateSeverity,
		},
		links: linkResults,
		zonesQueried: usableZones.map((z) => z.zone),
		zonesInconclusive,
		zonesSkipped,
		diff,
		checkedAt: new Date().toISOString(),
	};

	return { findings, results };
}
