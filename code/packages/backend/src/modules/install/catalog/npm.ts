import type { ToolCatalogEntry } from "./types";

/**
 * The canonical npm/pnpm catalog (pm/install_npm.mdx §3). Verified against the npm registry for the
 * week of 2026-06-22…28. Three layers (pm/install_npm.mdx §1):
 *   L0 — pnpm itself (corepack enable pnpm)
 *   L1 — declared dependencies restored by `pnpm install`
 *   L2 — optional on-demand packages (`pnpm --filter backend add <pkg>`)
 */

/** An L1/L2 npm package row. */
function pkg(e: {
	id: string;
	pkg: string;
	category: ToolCatalogEntry["category"];
	tier: ToolCatalogEntry["tier"];
	summary: string;
	usedBy: ToolCatalogEntry["usedBy"];
	notes?: string;
}): ToolCatalogEntry {
	return {
		id: e.id,
		manager: "npm",
		category: e.category,
		tier: e.tier,
		label: e.pkg,
		summary: e.summary,
		binaries: [],
		pkg: e.pkg,
		detect: "node-module",
		install: "pnpm-add",
		installCmd: `pnpm --filter backend add ${e.pkg}`,
		spawns: [
			{
				file: "pnpm",
				args: ["--filter", "backend", "add", e.pkg],
				cwd: "code",
			},
		],
		autoInstallable: true,
		usedBy: e.usedBy,
		notes: e.notes,
	};
}

/** A Node built-in — always satisfied, never on the missing list (pm/install_npm.mdx §3.3). */
function builtin(e: {
	id: string;
	category: ToolCatalogEntry["category"];
	summary: string;
	usedBy: ToolCatalogEntry["usedBy"];
}): ToolCatalogEntry {
	return {
		id: e.id,
		manager: "npm",
		category: e.category,
		tier: "default",
		label: e.id,
		summary: e.summary,
		binaries: [],
		detect: "builtin",
		install: "copy",
		installCmd: "(Node built-in — no install)",
		autoInstallable: false,
		usedBy: e.usedBy,
	};
}

export const NPM_CATALOG: ToolCatalogEntry[] = [
	// ── L0: pnpm itself ───────────────────────────────────────────────────────────────────────────
	{
		id: "pnpm",
		manager: "npm",
		category: "general",
		tier: "default",
		label: "pnpm",
		summary:
			"The package manager the monorepo runs on. Enabled via corepack (Node built-in shim).",
		binaries: ["pnpm"],
		detect: "pnpm",
		install: "corepack",
		installCmd: "corepack enable pnpm",
		spawns: [{ file: "corepack", args: ["enable", "pnpm"] }],
		autoInstallable: true,
		usedBy: ["general"],
		notes:
			"Prefers corepack (no global npm write, no sudo); falls back to `npm i -g pnpm`.",
	},
	// ── L1: workspace restore (one row installs every declared dependency) ───────────────────────
	{
		id: "workspace",
		manager: "npm",
		category: "general",
		tier: "default",
		label: "workspace dependencies",
		summary:
			"Restore node_modules for the whole monorepo (mailauth, dnsbl, …) — one shot.",
		binaries: [],
		detect: "workspace",
		install: "pnpm-install",
		installCmd: "pnpm install",
		spawns: [{ file: "pnpm", args: ["install"], cwd: "code" }],
		autoInstallable: true,
		usedBy: ["general"],
	},

	// ── L1: the email-authentication core (declared deps; shown for coverage/versions) ────────────
	pkg({
		id: "mailauth",
		pkg: "mailauth",
		category: "general",
		tier: "default",
		summary: "SPF + DKIM verify + DMARC + ARC + BIMI + MTA-STS in one MIT lib.",
		usedBy: ["spf", "dkim", "dmarc", "general"],
	}),
	pkg({
		id: "dnsbl",
		pkg: "dnsbl",
		category: "blacklist",
		tier: "default",
		summary: "DNSBL lookup/batch over blacklist zones.",
		usedBy: ["blacklist"],
		notes:
			"Gotcha: default servers are OpenDNS resolvers — override with the configured resolver.",
	}),
	pkg({
		id: "spf-parse",
		pkg: "spf-parse",
		category: "spf",
		tier: "default",
		summary:
			"Pure SPF record-string parser with per-term validity (syntax second opinion).",
		usedBy: ["spf"],
	}),
	pkg({
		id: "fast-xml-parser",
		pkg: "fast-xml-parser",
		category: "dmarc",
		tier: "default",
		summary: "Parse DMARC aggregate (<feedback>) XML from rua reports.",
		usedBy: ["dmarc"],
	}),
	pkg({
		id: "mailparser",
		pkg: "mailparser",
		category: "dmarc",
		tier: "default",
		summary: "MIME-parse report emails; extract DMARC/TLS-RPT attachments.",
		usedBy: ["dmarc"],
		notes:
			"License EUPL-1.1 (copyleft) — deliberate call; emailjs-mime-parser (MIT) is the fallback.",
	}),
	pkg({
		id: "peculiar-x509",
		pkg: "@peculiar/x509",
		category: "tls",
		tier: "default",
		summary: "TS-native X.509 parsing beyond node:tls getPeerCertificate().",
		usedBy: ["tls"],
	}),
	pkg({
		id: "rdapper",
		pkg: "rdapper",
		category: "dns",
		tier: "default",
		summary:
			"RDAP-first domain health: registrar, nameservers, EPP, DNSSEC flag.",
		usedBy: ["dns"],
	}),
	pkg({
		id: "tldts",
		pkg: "tldts",
		category: "spam",
		tier: "default",
		summary:
			"Public-Suffix reduction to the registrable domain (RHSBL query key).",
		usedBy: ["spam", "blacklist"],
	}),

	// ── Node built-ins — always satisfied ─────────────────────────────────────────────────────────
	builtin({
		id: "node:dns",
		category: "dns",
		summary:
			"All TXT/MX/NS/CAA lookups + reverse() PTR; DNSBL reverse-IP A/TXT queries.",
		usedBy: ["dns", "spf", "dkim", "dmarc", "blacklist"],
	}),
	builtin({
		id: "node:tls",
		category: "tls",
		summary:
			"STARTTLS connect + getPeerCertificate(true) — most TLS-transport checks.",
		usedBy: ["tls"],
	}),
	builtin({
		id: "node:zlib",
		category: "dmarc",
		summary:
			"TLS-RPT report parsing (RFC 8460 gzipped JSON — no npm parser exists).",
		usedBy: ["dmarc"],
	}),

	// ── L2: optional / on-demand (unchecked by default) ───────────────────────────────────────────
	pkg({
		id: "dmarc-report-parser",
		pkg: "dmarc-report-parser",
		category: "dmarc",
		tier: "extended",
		summary:
			"Convenience DMARC zip/gz/xml → object pipeline (vet the code; low adoption).",
		usedBy: ["dmarc"],
	}),
	pkg({
		id: "dmarc-parse",
		pkg: "dmarc-parse",
		category: "dmarc",
		tier: "extended",
		summary: "Display parsed DMARC DNS-record tags separately from full auth.",
		usedBy: ["dmarc"],
	}),
	pkg({
		id: "dns2",
		pkg: "dns2",
		category: "dns",
		tier: "extended",
		summary:
			"Pure-JS DNS with DoH/DoT — add only for DNSSEC (RRSIG/DS) or DoH.",
		usedBy: ["dns"],
	}),
	pkg({
		id: "whoiser",
		pkg: "whoiser",
		category: "dns",
		tier: "extended",
		summary: "Higher-usage WHOIS alternative to rdapper (still 2.0 beta).",
		usedBy: ["dns"],
	}),
	pkg({
		id: "emailjs-mime-parser",
		pkg: "emailjs-mime-parser",
		category: "dmarc",
		tier: "extended",
		summary:
			"MIT MIME-parser fallback if avoiding mailparser's EUPL license (stale).",
		usedBy: ["dmarc"],
	}),
];
