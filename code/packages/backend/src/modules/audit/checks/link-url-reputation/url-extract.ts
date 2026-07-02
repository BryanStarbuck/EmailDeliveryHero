import { domainToUnicode } from "node:url";

/**
 * Pure link-extraction machinery for the Link / URL Reputation check
 * (pm/checks/link_url_reputation.mdx §3 "Extraction & normalization") — no I/O, unit-testable:
 *
 *  - MIME part extraction: the raw RFC 5322 sample from the shared content-scoring sample store is
 *    split into its HTML and text parts (multipart recursion, base64 / quoted-printable transfer
 *    decoding) so QP soft line breaks never corrupt a URL. A pasted HTML/text snippet (no header
 *    block) is accepted as-is.
 *  - URL harvesting: `a[href]`, `area[href]`, `img[src]`, `[background]`, inline CSS `url(...)`,
 *    and AMP hrefs from HTML parts; an RFC 3986-aware matcher over text parts.
 *  - Normalization: RFC 3986 parse via `new URL()` (lowercases + IDNA-encodes the host), reduction
 *    to the Public-Suffix registrable domain, and the per-URL flags `is_https` / `is_ip_literal` /
 *    `is_punycode` / `is_shortener` plus brand-homograph detection (IDNA2008 / RFC 5890-5891).
 */

// ---------------------------------------------------------------------------------------------
// MIME part extraction
// ---------------------------------------------------------------------------------------------

export interface SampleParts {
	/** Decoded text/html part bodies (joined). Null when the sample has no HTML content. */
	html: string | null;
	/** Decoded text/plain part bodies (joined). Null when the sample has no text content. */
	text: string | null;
}

/** RFC 5322 header field line: printable ASCII field name (no colon) followed by ":". */
const HEADER_LINE_RE = /^[\x21-\x39\x3b-\x7e]+:/;

/** Header names whose presence makes a leading block a real message header, not coincidence. */
const KNOWN_HEADER_RE =
	/^(from|to|cc|subject|date|received|return-path|reply-to|sender|message-id|mime-version|content-type|content-transfer-encoding|dkim-signature|list-unsubscribe|x-[a-z0-9-]+):/i;

/** True when `head` parses as an RFC 5322 header block naming at least one well-known header. */
function looksLikeHeaderBlock(head: string): boolean {
	let named = false;
	for (const line of head.split(/\r?\n/)) {
		if (line === "") continue;
		if (/^[ \t]/.test(line)) continue; // folded continuation
		if (!HEADER_LINE_RE.test(line)) return false;
		if (KNOWN_HEADER_RE.test(line)) named = true;
	}
	return named;
}

/** Unfold one header value from a header block; null when absent. */
function getHeader(head: string, name: string): string | null {
	const lines = head.split(/\r?\n/);
	const prefix = `${name.toLowerCase()}:`;
	for (let i = 0; i < lines.length; i++) {
		if (lines[i].toLowerCase().startsWith(prefix)) {
			let value = lines[i].slice(prefix.length);
			for (let j = i + 1; j < lines.length && /^[ \t]/.test(lines[j]); j++)
				value += ` ${lines[j].trim()}`;
			return value.trim() || null;
		}
	}
	return null;
}

function parseContentType(value: string | null): {
	type: string;
	params: Record<string, string>;
} {
	if (!value) return { type: "", params: {} };
	const [typePart, ...rest] = value.split(";");
	const params: Record<string, string> = {};
	const paramRe = /([a-z0-9-]+)\s*=\s*(?:"([^"]*)"|([^;\s]+))/gi;
	const paramText = rest.join(";");
	let m: RegExpExecArray | null;
	// biome-ignore lint/suspicious/noAssignInExpressions: standard regex-exec loop
	while ((m = paramRe.exec(paramText)) !== null) {
		params[m[1].toLowerCase()] = m[2] ?? m[3] ?? "";
	}
	return { type: typePart.trim().toLowerCase(), params };
}

/** Decode quoted-printable: strip soft line breaks (=\n) then =XX escapes. URLs are ASCII-safe. */
function decodeQuotedPrintable(s: string): string {
	return s
		.replace(/=\r?\n/g, "")
		.replace(/=([0-9A-Fa-f]{2})/g, (_, hex: string) =>
			String.fromCharCode(Number.parseInt(hex, 16)),
		);
}

function decodeTransfer(body: string, cte: string | null): string {
	const enc = (cte ?? "").trim().toLowerCase();
	if (enc === "base64") {
		try {
			return Buffer.from(body.replace(/\s+/g, ""), "base64").toString("utf8");
		} catch {
			return body;
		}
	}
	if (enc === "quoted-printable") return decodeQuotedPrintable(body);
	return body;
}

/** Split a multipart body into its raw parts (each still headed by its own MIME headers). */
function splitMultipart(body: string, boundary: string): string[] {
	const marker = `--${boundary}`;
	const parts: string[] = [];
	let current: string[] | null = null;
	for (const line of body.split(/\r?\n/)) {
		const trimmed = line.trimEnd();
		if (trimmed === marker || trimmed === `${marker}--`) {
			if (current) parts.push(current.join("\n"));
			if (trimmed === `${marker}--`) return parts;
			current = [];
		} else if (current) {
			current.push(line);
		}
	}
	if (current) parts.push(current.join("\n"));
	return parts;
}

function splitHeadBody(entity: string): { head: string; body: string } {
	const match = /\r?\n\r?\n/.exec(entity);
	if (!match) return { head: entity, body: "" };
	return {
		head: entity.slice(0, match.index),
		body: entity.slice(match.index + match[0].length),
	};
}

function walkEntity(
	head: string,
	body: string,
	out: { html: string[]; text: string[] },
	depth: number,
): void {
	if (depth > 8) return; // pathological nesting guard
	const ct = parseContentType(getHeader(head, "content-type"));
	if (ct.type.startsWith("multipart/") && ct.params.boundary) {
		for (const part of splitMultipart(body, ct.params.boundary)) {
			const inner = splitHeadBody(part);
			walkEntity(inner.head, inner.body, out, depth + 1);
		}
		return;
	}
	if (ct.type === "message/rfc822") {
		const inner = splitHeadBody(
			decodeTransfer(body, getHeader(head, "content-transfer-encoding")),
		);
		walkEntity(inner.head, inner.body, out, depth + 1);
		return;
	}
	const decoded = decodeTransfer(
		body,
		getHeader(head, "content-transfer-encoding"),
	);
	if (ct.type === "text/html") out.html.push(decoded);
	else if (ct.type === "text/plain" || ct.type === "") out.text.push(decoded); // default = text/plain
	// other leaf types (images, attachments) carry no body links
}

/**
 * Split a stored sample into decoded HTML and text parts (§3). A raw .eml is MIME-walked with
 * transfer decoding; a pasted snippet with no header block is taken whole (HTML when it has tags).
 */
export function extractSampleParts(raw: string): SampleParts {
	const out = { html: [] as string[], text: [] as string[] };
	const { head, body } = splitHeadBody(raw);
	if (looksLikeHeaderBlock(head)) {
		walkEntity(head, body, out, 0);
	} else {
		const trimmed = raw.trim();
		if (/<[a-z!]/i.test(trimmed)) out.html.push(trimmed);
		else out.text.push(trimmed);
	}
	return {
		html: out.html.length > 0 ? out.html.join("\n") : null,
		text: out.text.length > 0 ? out.text.join("\n") : null,
	};
}

// ---------------------------------------------------------------------------------------------
// Registrable-domain reduction (Public Suffix List)
// ---------------------------------------------------------------------------------------------

// Common second-level public suffixes so foo.bar.co.uk reduces to bar.co.uk, not co.uk. This is a
// compact first-round stand-in for the full Public Suffix List (bundle+refresh the real PSL later —
// see spec maintenance notes); it covers the overwhelming majority of real-world links.
const MULTI_PART_SUFFIXES = new Set([
	"co.uk",
	"org.uk",
	"gov.uk",
	"ac.uk",
	"me.uk",
	"ltd.uk",
	"plc.uk",
	"net.uk",
	"sch.uk",
	"com.au",
	"net.au",
	"org.au",
	"edu.au",
	"gov.au",
	"id.au",
	"co.jp",
	"or.jp",
	"ne.jp",
	"ac.jp",
	"go.jp",
	"com.br",
	"net.br",
	"org.br",
	"gov.br",
	"co.nz",
	"net.nz",
	"org.nz",
	"govt.nz",
	"co.za",
	"org.za",
	"co.in",
	"net.in",
	"org.in",
	"gen.in",
	"firm.in",
	"co.kr",
	"or.kr",
	"com.sg",
	"com.hk",
	"com.tw",
	"com.mx",
	"com.cn",
	"net.cn",
	"org.cn",
	"gov.cn",
]);

/** PSL-registrable domain of a host: last two labels, or three when the last two are a public suffix. */
export function registrableDomain(host: string): string {
	const h = host.replace(/\.+$/, "").toLowerCase();
	const labels = h.split(".").filter(Boolean);
	if (labels.length <= 2) return h;
	const lastTwo = labels.slice(-2).join(".");
	if (MULTI_PART_SUFFIXES.has(lastTwo)) return labels.slice(-3).join(".");
	return lastTwo;
}

// ---------------------------------------------------------------------------------------------
// Homograph detection (punycode / IDN lookalikes of protected brands — §2, AC#4/#5)
// ---------------------------------------------------------------------------------------------

/** Cyrillic/Greek/latin-lookalike → ASCII skeleton map (the classic confusable set). */
const CONFUSABLES: Record<string, string> = {
	а: "a",
	е: "e",
	о: "o",
	р: "p",
	с: "c",
	х: "x",
	у: "y",
	і: "i",
	ї: "i",
	ј: "j",
	ѕ: "s",
	һ: "h",
	ԁ: "d",
	ԛ: "q",
	ԝ: "w",
	ѵ: "v",
	ɡ: "g",
	ɑ: "a",
	ɩ: "i",
	ł: "l",
	α: "a",
	ε: "e",
	ι: "i",
	κ: "k",
	ν: "v",
	ο: "o",
	ρ: "p",
	τ: "t",
	υ: "u",
	ω: "w",
};

/** Brand labels a homograph most often impersonates; matched against the confusable skeleton. */
const BRAND_LABELS = new Set([
	"apple",
	"google",
	"gmail",
	"youtube",
	"microsoft",
	"outlook",
	"office365",
	"icloud",
	"paypal",
	"amazon",
	"facebook",
	"instagram",
	"whatsapp",
	"netflix",
	"linkedin",
	"twitter",
	"ebay",
	"walmart",
	"chase",
	"wellsfargo",
	"bankofamerica",
	"citibank",
	"coinbase",
	"binance",
	"usps",
	"fedex",
	"ups",
	"dhl",
	"irs",
]);

/** Reduce a unicode host to an ASCII confusable skeleton (NFKD, strip marks, map lookalikes). */
function confusableSkeleton(host: string): string {
	const stripped = host.normalize("NFKD").replace(/\p{M}/gu, "");
	let out = "";
	for (const ch of stripped) out += CONFUSABLES[ch] ?? ch;
	return out;
}

/**
 * When an `xn--` host is a confusable lookalike of a protected brand (e.g. `аpple.com` with a
 * Cyrillic а), return the impersonated brand label — a critical phishing shape. Real brand domains
 * are pure ASCII, so a punycode host that skeletons to a brand is never the brand itself.
 */
export function homographBrandFor(host: string): string | null {
	if (!/(^|\.)xn--/.test(host)) return null;
	let unicode: string;
	try {
		unicode = domainToUnicode(host);
	} catch {
		return null;
	}
	const skeleton = confusableSkeleton(unicode);
	if (!/^\p{ASCII}+$/u.test(skeleton)) return null; // still non-ASCII → not a plain-brand lookalike
	const sld = registrableDomain(skeleton).split(".")[0] ?? "";
	return BRAND_LABELS.has(sld) ? sld : null;
}

// ---------------------------------------------------------------------------------------------
// URL harvesting + per-URL flags
// ---------------------------------------------------------------------------------------------

/**
 * Default public-shortener list. The live list is config
 * (`config.yaml → checks.content.url.shorteners`, pm/checks/link_url_reputation.mdx §5) — this is
 * the seed default the config store ships.
 */
export const DEFAULT_SHORTENERS: string[] = [
	"bit.ly",
	"t.co",
	"tinyurl.com",
	"ow.ly",
	"buff.ly",
	"goo.gl",
	"is.gd",
	"rebrand.ly",
	"lnkd.in",
	"t.ly",
	"cutt.ly",
	"rb.gy",
	"shorturl.at",
	"bl.ink",
	"tiny.cc",
	"soo.gd",
	"s.id",
	"trib.al",
	"dlvr.it",
	"shar.es",
	"mcaf.ee",
	"adf.ly",
	"clck.ru",
];

export interface LinkUrl {
	url: string;
	/** PSL-registrable domain of the URL host (the raw IP for IP-literal hosts). */
	linkDomain: string;
	isHttps: boolean;
	isIpLiteral: boolean;
	isPunycode: boolean;
	isShortener: boolean;
	/** Brand label a punycode host impersonates (critical), or null. */
	homographOf: string | null;
}

const ATTR_URL_RE = /(?:href|src|background)\s*=\s*["']?\s*([^"'\s>]+)/gi;
const CSS_URL_RE = /url\(\s*['"]?\s*([^'")\s]+)/gi;
const TEXT_URL_RE = /\bhttps?:\/\/[^\s"'<>()[\]{}]+/gi;

function isIpv4(host: string): boolean {
	const parts = host.split(".");
	return (
		parts.length === 4 &&
		parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)
	);
}

function collect(re: RegExp, body: string, into: Set<string>): void {
	re.lastIndex = 0;
	let m: RegExpExecArray | null;
	// biome-ignore lint/suspicious/noAssignInExpressions: standard regex-exec loop
	while ((m = re.exec(body)) !== null) into.add(m[1]);
}

/** Parse one raw URL string into a normalized LinkUrl, or null when it is not a reputation-bearing http(s) URL. */
export function parseLink(
	raw: string,
	shorteners: ReadonlySet<string>,
): LinkUrl | null {
	// HTML attribute values carry entity-encoded ampersands.
	const trimmed = raw.trim().replace(/&amp;/gi, "&");
	// Skip non-reputation schemes and fragments/anchors (mailto:/tel:/data: excluded per §3).
	if (/^(mailto:|tel:|data:|cid:|javascript:|#)/i.test(trimmed)) return null;
	let parsed: URL;
	try {
		parsed = new URL(trimmed);
	} catch {
		return null;
	}
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
	// new URL() lowercases and IDNA-encodes the host; IPv6 hosts come back bracketed.
	const bracketed =
		parsed.hostname.startsWith("[") && parsed.hostname.endsWith("]");
	const host = bracketed ? parsed.hostname.slice(1, -1) : parsed.hostname;
	const isIpLiteral = bracketed || isIpv4(host);
	const linkDomain = isIpLiteral ? host : registrableDomain(host);
	return {
		url: trimmed,
		linkDomain,
		isHttps: parsed.protocol === "https:",
		isIpLiteral,
		isPunycode: !isIpLiteral && /(^|\.)xn--/.test(host),
		isShortener: !isIpLiteral && shorteners.has(linkDomain),
		homographOf: isIpLiteral ? null : homographBrandFor(host),
	};
}

/**
 * Harvest, parse, and de-duplicate every link in the sample's parts (§3): HTML attributes
 * (`href`/`src`/`background`, covering `a`, `area`, `img`, and AMP hrefs), inline CSS `url()`,
 * and RFC 3986 URL matches over both HTML source and text parts. De-duplicated by URL.
 */
export function extractLinks(
	parts: SampleParts,
	shorteners: ReadonlySet<string>,
): LinkUrl[] {
	const rawUrls = new Set<string>();
	if (parts.html) {
		collect(ATTR_URL_RE, parts.html, rawUrls);
		collect(CSS_URL_RE, parts.html, rawUrls);
		collect(TEXT_URL_RE, parts.html, rawUrls);
	}
	if (parts.text) collect(TEXT_URL_RE, parts.text, rawUrls);
	const parsed = [...rawUrls]
		.map((u) => parseLink(u, shorteners))
		.filter((l): l is LinkUrl => l !== null);
	return [...new Map(parsed.map((l) => [l.url, l])).values()];
}
