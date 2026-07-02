import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { gunzipSync, inflateRawSync } from "node:zlib";
import { reverseIpv4 } from "./engine";

/**
 * Email-derived blacklist targets (pm/checks/blacklists.mdx §19): mine the DMARC aggregate (rua)
 * report emails saved in the repo's emails/ directory for the source IPs that actually transmitted
 * mail as the domain. Rows where SPF or DKIM passed (alignment-evaluated) are OUR mail stream —
 * those IPs join the blacklist sweep with source "email_report". Rows that failed both are
 * spoofers: context for the Reports page, never delist targets. Windowed to the last 30 days,
 * private ranges dropped, capped at the top 20 by message volume (truncation is never silent —
 * the caller logs it).
 */

export interface EmailReportIp {
	ip: string;
	first_seen: string;
	last_seen: string;
	message_count: number;
}

const WINDOW_DAYS = 30;
export const EMAIL_IP_CAP = 20;

/** The emails directory: EDH_EMAILS_DIR wins; otherwise walk upward looking for an emails/ dir. */
export function emailsDir(): string | null {
	const fromEnv = process.env.EDH_EMAILS_DIR?.trim();
	if (fromEnv) return existsSync(fromEnv) ? fromEnv : null;
	for (const start of [process.cwd(), __dirname]) {
		let dir = start;
		for (let i = 0; i < 7; i++) {
			const candidate = join(dir, "emails");
			if (existsSync(candidate) && statSync(candidate).isDirectory())
				return candidate;
			const parent = dirname(dir);
			if (parent === dir) break;
			dir = parent;
		}
	}
	return null;
}

/** Private/reserved space never joins the sweep (RFC 1918, loopback, link-local, CGNAT). */
export function isPublicIp(ip: string): boolean {
	if (!reverseIpv4(ip)) return false;
	const [a, b] = ip.split(".").map(Number);
	if (a === 10 || a === 127 || a === 0) return false;
	if (a === 172 && b >= 16 && b <= 31) return false;
	if (a === 192 && b === 168) return false;
	if (a === 169 && b === 254) return false;
	if (a === 100 && b >= 64 && b <= 127) return false;
	return true;
}

/** Pull every plausible DMARC-report XML document out of one .eml (base64 gzip / zip / raw XML). */
export function extractReportXml(eml: string): string[] {
	const xmls: string[] = [];
	const push = (buf: Buffer) => {
		const text = buf.toString("utf8");
		if (text.includes("<feedback") && text.includes("<record>"))
			xmls.push(text);
	};
	// Base64 attachment bodies: every base64-looking block after an encoding header.
	const blocks = eml.split(/\r?\n\r?\n/);
	for (let i = 0; i < blocks.length; i++) {
		if (!/content-transfer-encoding:\s*base64/i.test(blocks[i] ?? "")) continue;
		const body = (blocks[i + 1] ?? "").split(/\r?\n--/)[0] ?? "";
		const b64 = body.replace(/[^A-Za-z0-9+/=]/g, "");
		if (b64.length < 100) continue;
		let buf: Buffer;
		try {
			buf = Buffer.from(b64, "base64");
		} catch {
			continue;
		}
		if (buf[0] === 0x1f && buf[1] === 0x8b) {
			try {
				push(gunzipSync(buf));
			} catch {
				/* corrupt gzip — skip */
			}
		} else if (buf[0] === 0x50 && buf[1] === 0x4b) {
			for (const entry of unzip(buf)) push(entry);
		} else {
			push(buf);
		}
	}
	return xmls;
}

/** Minimal ZIP reader (local-file-header walk) — DMARC report zips are single-entry, sizes known. */
function unzip(buf: Buffer): Buffer[] {
	const out: Buffer[] = [];
	let offset = 0;
	while (offset + 30 <= buf.length && buf.readUInt32LE(offset) === 0x04034b50) {
		const method = buf.readUInt16LE(offset + 8);
		const compressedSize = buf.readUInt32LE(offset + 18);
		const nameLen = buf.readUInt16LE(offset + 26);
		const extraLen = buf.readUInt16LE(offset + 28);
		const dataStart = offset + 30 + nameLen + extraLen;
		const data = buf.subarray(dataStart, dataStart + compressedSize);
		try {
			out.push(method === 8 ? inflateRawSync(data) : Buffer.from(data));
		} catch {
			/* corrupt entry — skip */
		}
		offset = dataStart + compressedSize;
	}
	return out;
}

function tag(xml: string, name: string): string | null {
	const m = new RegExp(`<${name}>\\s*([^<]*?)\\s*</${name}>`, "i").exec(xml);
	return m ? m[1] : null;
}

interface ParsedReport {
	domain: string | null;
	endEpoch: number | null;
	rows: Array<{ ip: string; count: number; aligned: boolean }>;
	/** DKIM d= / SPF envelope domains that PASSED in <auth_results> (§19.1 RHSBL candidates). */
	authDomains: Array<{ domain: string; kind: "dkim_d" | "return_path" }>;
}

/** Regex-level rua parse — enough for source_ip + policy_evaluated without an XML dependency. */
export function parseRuaXml(xml: string): ParsedReport {
	const policy =
		/<policy_published>([\s\S]*?)<\/policy_published>/i.exec(xml)?.[1] ?? "";
	const range = /<date_range>([\s\S]*?)<\/date_range>/i.exec(xml)?.[1] ?? "";
	const end = Number(tag(range, "end"));
	const rows: ParsedReport["rows"] = [];
	const authDomains: ParsedReport["authDomains"] = [];
	const seenAuth = new Set<string>();
	for (const record of xml.match(/<record>[\s\S]*?<\/record>/gi) ?? []) {
		const ip = tag(record, "source_ip");
		if (!ip) continue;
		const evaluated =
			/<policy_evaluated>([\s\S]*?)<\/policy_evaluated>/i.exec(record)?.[1] ??
			"";
		const aligned =
			tag(evaluated, "dkim")?.toLowerCase() === "pass" ||
			tag(evaluated, "spf")?.toLowerCase() === "pass";
		rows.push({
			ip: ip.trim(),
			count: Number(tag(record, "count")) || 1,
			aligned,
		});
		// §19.1: DKIM d= / SPF envelope domains seen authenticating for us in <auth_results> —
		// RHSBL domain-sweep candidates when they are ours (the caller filters to subdomains).
		const auth =
			/<auth_results>([\s\S]*?)<\/auth_results>/i.exec(record)?.[1] ?? "";
		for (const [element, kind] of [
			["dkim", "dkim_d"],
			["spf", "return_path"],
		] as const) {
			for (const block of auth.match(
				new RegExp(`<${element}>[\\s\\S]*?</${element}>`, "gi"),
			) ?? []) {
				if (tag(block, "result")?.toLowerCase() !== "pass") continue;
				const d = tag(block, "domain")?.toLowerCase().trim();
				if (!d || seenAuth.has(`${kind}|${d}`)) continue;
				seenAuth.add(`${kind}|${d}`);
				authDomains.push({ domain: d, kind });
			}
		}
	}
	return {
		domain: tag(policy, "domain")?.toLowerCase() ?? null,
		endEpoch: Number.isFinite(end) && end > 0 ? end : null,
		rows,
		authDomains,
	};
}

/**
 * The §19 pipeline: every public IPv4 that authenticated as `domain` in a rua report from the last
 * 30 days, aggregated and capped at the top EMAIL_IP_CAP by message volume.
 */
export function collectEmailReportIps(domain: string): {
	ips: EmailReportIp[];
	truncated: number;
} {
	const dir = emailsDir();
	if (!dir) return { ips: [], truncated: 0 };
	const cutoff = Date.now() / 1000 - WINDOW_DAYS * 24 * 3600;
	const wanted = domain.toLowerCase();
	const byIp = new Map<string, EmailReportIp>();

	let files: string[];
	try {
		files = readdirSync(dir).filter((f) => f.toLowerCase().endsWith(".eml"));
	} catch {
		return { ips: [], truncated: 0 };
	}

	for (const file of files) {
		let eml: string;
		try {
			eml = readFileSync(join(dir, file), "utf8");
		} catch {
			continue;
		}
		for (const xml of extractReportXml(eml)) {
			const report = parseRuaXml(xml);
			if (report.domain !== wanted) continue;
			if (report.endEpoch !== null && report.endEpoch < cutoff) continue;
			const seen = new Date(
				(report.endEpoch ?? Date.now() / 1000) * 1000,
			).toISOString();
			for (const row of report.rows) {
				if (!row.aligned || !isPublicIp(row.ip)) continue;
				const existing = byIp.get(row.ip);
				if (existing) {
					existing.message_count += row.count;
					if (seen < existing.first_seen) existing.first_seen = seen;
					if (seen > existing.last_seen) existing.last_seen = seen;
				} else {
					byIp.set(row.ip, {
						ip: row.ip,
						first_seen: seen,
						last_seen: seen,
						message_count: row.count,
					});
				}
			}
		}
	}

	const all = [...byIp.values()].sort(
		(a, b) => b.message_count - a.message_count,
	);
	return {
		ips: all.slice(0, EMAIL_IP_CAP),
		truncated: Math.max(0, all.length - EMAIL_IP_CAP),
	};
}

export interface EmailReportDomain {
	domain: string;
	source: "dkim_d" | "return_path";
}

/**
 * §19.1 RHSBL domain targets: DKIM d= / SPF envelope domains that PASSED in rua <auth_results>
 * for `domain` (last 30 days) and are OURS — subdomains of the primary. Third-party ESP domains
 * and the primary itself (already the primary target) are excluded.
 */
export function collectEmailReportDomains(domain: string): EmailReportDomain[] {
	const dir = emailsDir();
	if (!dir) return [];
	const cutoff = Date.now() / 1000 - WINDOW_DAYS * 24 * 3600;
	const wanted = domain.toLowerCase();
	const suffix = `.${wanted}`;
	const out = new Map<string, EmailReportDomain>();

	let files: string[];
	try {
		files = readdirSync(dir).filter((f) => f.toLowerCase().endsWith(".eml"));
	} catch {
		return [];
	}

	for (const file of files) {
		let eml: string;
		try {
			eml = readFileSync(join(dir, file), "utf8");
		} catch {
			continue;
		}
		for (const xml of extractReportXml(eml)) {
			const report = parseRuaXml(xml);
			if (report.domain !== wanted) continue;
			if (report.endEpoch !== null && report.endEpoch < cutoff) continue;
			for (const { domain: d, kind } of report.authDomains) {
				if (d === wanted || !d.endsWith(suffix)) continue;
				// A domain seen as both dkim_d and return_path keeps the first-seen source tag.
				if (!out.has(d)) out.set(d, { domain: d, source: kind });
			}
		}
	}
	return [...out.values()];
}
