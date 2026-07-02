import type { ToolCatalogEntry } from "./types";

/**
 * The canonical Homebrew catalog (pm/install_brew.mdx §3). Every formula was verified against the
 * live Homebrew API (formulae.brew.sh/api/formula/<name>.json) on 2026-07-02.
 *
 * Load-bearing gotchas baked in (pm/install_brew.mdx §3.4):
 *   - `drill` is provided by the `ldns` formula — `brew install drill` is an unrelated Rust HTTP
 *     load-tester. NEVER emit `brew install drill`.
 *   - `whois` is keg-only (/opt/homebrew/opt/whois/bin/whois) — locateTool's fallback knows it.
 *   - SpamAssassin / rspamd / opendkim / opendmarc / rblcheck are NOT brew formulas.
 *   - `dog`→`doggo`, `mailhog`→`mailpit` (both originals removed from brew).
 */

/** brew install <formula> — the common shape for a plain core formula. */
function brew(e: {
	id: string;
	formula: string;
	binaries: string[];
	category: ToolCatalogEntry["category"];
	tier: ToolCatalogEntry["tier"];
	summary: string;
	usedBy: ToolCatalogEntry["usedBy"];
	notes?: string;
}): ToolCatalogEntry {
	return {
		id: e.id,
		manager: "brew",
		category: e.category,
		tier: e.tier,
		label: e.binaries.join("  "),
		summary: e.summary,
		binaries: e.binaries,
		formula: e.formula,
		detect: "binary",
		install: "brew",
		installCmd: `brew install ${e.formula}`,
		spawns: [{ file: "brew", args: ["install", e.formula] }],
		autoInstallable: true,
		usedBy: e.usedBy,
		notes: e.notes,
	};
}

export const BREW_CATALOG: ToolCatalogEntry[] = [
	// ── Default baseline (pre-checked) — lights up the entire first-round audit path ──────────────
	brew({
		id: "bind",
		formula: "bind",
		binaries: ["dig", "host", "nslookup", "delv"],
		category: "dns",
		tier: "default",
		summary:
			"BIND utilities: every record lookup; delv DNSSEC-validated resolution.",
		usedBy: ["dns", "spf", "dkim", "dmarc", "blacklist"],
	}),
	brew({
		id: "knot",
		formula: "knot",
		binaries: ["kdig", "kzonecheck"],
		category: "dns",
		tier: "default",
		summary:
			"dig-compatible with native DoH/DoT + +json; cross-resolver agreement.",
		usedBy: ["dns"],
	}),
	brew({
		id: "ldns",
		formula: "ldns",
		binaries: ["drill"],
		category: "dns",
		tier: "default",
		summary: "DNSSEC-aware chain tracing (drill -TD).",
		usedBy: ["dns"],
		notes:
			"The DNS `drill` tool ships in `ldns` — `brew install drill` is an unrelated Rust load-tester.",
	}),
	brew({
		id: "doggo",
		formula: "doggo",
		binaries: ["doggo"],
		category: "dns",
		tier: "default",
		summary: "Modern dig with native JSON — record lookups for SPF/DKIM/DMARC.",
		usedBy: ["dns", "spf", "dkim", "dmarc"],
	}),
	brew({
		id: "dnsx",
		formula: "dnsx",
		binaries: ["dnsx"],
		category: "dns",
		tier: "default",
		summary: "Bulk/NDJSON resolution; bulk DKIM-selector probing.",
		usedBy: ["dns", "dkim"],
	}),
	brew({
		id: "whois",
		formula: "whois",
		binaries: ["whois"],
		category: "dns",
		tier: "default",
		summary: "Registrar/expiry/EPP; netblock owner for delisting.",
		usedBy: ["dns", "blacklist"],
		notes:
			"Keg-only: /opt/homebrew/opt/whois/bin/whois (does not symlink over the macOS system whois).",
	}),
	brew({
		id: "openssl",
		formula: "openssl@3",
		binaries: ["openssl"],
		category: "tls",
		tier: "default",
		summary: "MX cert chain / TLS version; decode DKIM p= key size.",
		usedBy: ["tls", "dkim"],
	}),
	brew({
		id: "swaks",
		formula: "swaks",
		binaries: ["swaks"],
		category: "tls",
		tier: "default",
		summary:
			"Live SMTP transaction / seed-send probe (STARTTLS, AUTH, delivery).",
		usedBy: ["tls", "spam"],
	}),
	brew({
		id: "testssl",
		formula: "testssl",
		binaries: ["testssl.sh", "testssl"],
		category: "tls",
		tier: "default",
		summary: "Full cipher/protocol/vuln audit of an MX endpoint.",
		usedBy: ["tls"],
	}),
	brew({
		id: "checkdmarc",
		formula: "checkdmarc",
		binaries: ["checkdmarc"],
		category: "dmarc",
		tier: "default",
		summary:
			"SPF/DMARC/MTA-STS/TLS-RPT/BIMI/MX/DNSSEC cross-validation in one JSON pass.",
		usedBy: ["dmarc", "spf", "dns"],
	}),
	brew({
		id: "parsedmarc",
		formula: "parsedmarc",
		binaries: ["parsedmarc"],
		category: "dmarc",
		tier: "default",
		summary: "Parse DMARC rua/ruf report files or an IMAP mailbox → JSON.",
		usedBy: ["dmarc"],
	}),

	// ── Extended / diagnostic (opt-in, unchecked) — all Homebrew core ─────────────────────────────
	brew({
		id: "q",
		formula: "q",
		binaries: ["q"],
		category: "dns",
		tier: "extended",
		summary:
			"Tiny DNS client (UDP/TCP/DoT/DoH/DoQ) — resolver-consistency cross-checks.",
		usedBy: ["dns"],
	}),
	brew({
		id: "zns",
		formula: "zns",
		binaries: ["zns"],
		category: "dns",
		tier: "extended",
		summary: "Readable colorized record dumps.",
		usedBy: ["dns"],
	}),
	brew({
		id: "rdap",
		formula: "rdap",
		binaries: ["rdap"],
		category: "dns",
		tier: "extended",
		summary: "Structured JSON registration data (WHOIS successor).",
		usedBy: ["dns"],
	}),
	brew({
		id: "asn",
		formula: "asn",
		binaries: ["asn"],
		category: "blacklist",
		tier: "extended",
		summary: "ASN/prefix lookup — sending-IP network neighborhood.",
		usedBy: ["blacklist", "dns"],
	}),
	brew({
		id: "dnstwist",
		formula: "dnstwist",
		binaries: ["dnstwist"],
		category: "blacklist",
		tier: "extended",
		summary: "Typosquat/lookalike generation → infra.name_similarity.",
		usedBy: ["blacklist", "dns"],
	}),
	brew({
		id: "dnsviz",
		formula: "dnsviz",
		binaries: ["dnsviz"],
		category: "dns",
		tier: "extended",
		summary: "DNSSEC chain-of-trust grading (probe … | grok).",
		usedBy: ["dns"],
	}),
	brew({
		id: "dnstracer",
		formula: "dnstracer",
		binaries: ["dnstracer"],
		category: "dns",
		tier: "extended",
		summary: "Delegation-chain trace / lame-delegation hunting.",
		usedBy: ["dns"],
	}),
	brew({
		id: "dnsperf",
		formula: "dnsperf",
		binaries: ["dnsperf"],
		category: "dns",
		tier: "extended",
		summary: "Per-NS latency (future ns_response_time probe).",
		usedBy: ["dns"],
	}),
	brew({
		id: "massdns",
		formula: "massdns",
		binaries: ["massdns"],
		category: "dns",
		tier: "extended",
		summary: "Very-large-volume sweeps (future subdomain/dangling PS).",
		usedBy: ["dns"],
	}),
	brew({
		id: "ipcalc",
		formula: "ipcalc",
		binaries: ["ipcalc"],
		category: "blacklist",
		tier: "extended",
		summary: "IP-class sanity (private/CGNAT/loopback); allocation width.",
		usedBy: ["blacklist", "dns"],
	}),
	brew({
		id: "sslscan",
		formula: "sslscan",
		binaries: ["sslscan"],
		category: "tls",
		tier: "extended",
		summary: "Fast cipher enumeration.",
		usedBy: ["tls"],
	}),
	brew({
		id: "gnutls",
		formula: "gnutls",
		binaries: ["gnutls-cli"],
		category: "tls",
		tier: "extended",
		summary: "DANE-aware TLS client — validates TLSA vs the live cert.",
		usedBy: ["tls"],
	}),
	brew({
		id: "certigo",
		formula: "certigo",
		binaries: ["certigo"],
		category: "tls",
		tier: "extended",
		summary: "Cert-chain parse: expiry, SAN coverage of the MX name.",
		usedBy: ["tls"],
	}),
	brew({
		id: "nmap",
		formula: "nmap",
		binaries: ["nmap"],
		category: "tls",
		tier: "extended",
		summary: "NSE smtp-commands / smtp-open-relay / ssl-enum-ciphers.",
		usedBy: ["tls"],
	}),
	brew({
		id: "socat",
		formula: "socat",
		binaries: ["socat"],
		category: "tls",
		tier: "extended",
		summary: "Raw banner reads / scripted SMTP dialogs.",
		usedBy: ["tls"],
	}),
	brew({
		id: "tidy-html5",
		formula: "tidy-html5",
		binaries: ["tidy"],
		category: "spam",
		tier: "extended",
		summary: "HTML well-formedness lint → content.html_hygiene.",
		usedBy: ["spam"],
	}),
	brew({
		id: "lychee",
		formula: "lychee",
		binaries: ["lychee"],
		category: "spam",
		tier: "extended",
		summary: "Bulk link liveness + redirect JSON (future url_reachable).",
		usedBy: ["spam"],
	}),
	brew({
		id: "curl",
		formula: "curl",
		binaries: ["curl"],
		category: "spam",
		tier: "extended",
		summary:
			"Single-URL redirect-chain expansion for shorteners (also ships with the OS).",
		usedBy: ["spam"],
	}),
	brew({
		id: "msmtp",
		formula: "msmtp",
		binaries: ["msmtp"],
		category: "dkim",
		tier: "extended",
		summary: "Lightweight MTA capability probe (STARTTLS, size).",
		usedBy: ["dkim", "tls"],
	}),
	brew({
		id: "mailpit",
		formula: "mailpit",
		binaries: ["mailpit"],
		category: "general",
		tier: "extended",
		summary:
			"Local SMTP sink (:1025) + JSON API to test our own probe-signing.",
		usedBy: ["general"],
	}),

	// ── `special` — NOT on Homebrew (pm/install_brew.mdx §3.3) ────────────────────────────────────
	{
		id: "spamassassin",
		manager: "special",
		category: "spam",
		tier: "extended",
		label: "spamassassin  spamc",
		summary: "Content spam scoring. Installs via perl + cpanminus, then CPAN.",
		binaries: ["spamassassin", "spamc"],
		detect: "binary",
		install: "cpanm",
		installCmd:
			"brew install perl cpanminus && cpanm --notest Mail::SpamAssassin",
		spawns: [
			{ file: "brew", args: ["install", "perl", "cpanminus"] },
			{ file: "cpanm", args: ["--notest", "Mail::SpamAssassin"] },
		],
		autoInstallable: true,
		usedBy: ["spam"],
		notes:
			"Not a Homebrew formula — installed through CPAN (may take several minutes).",
	},
	copyOnly({
		id: "rspamd",
		binaries: ["rspamc", "rspamadm"],
		category: "spam",
		cmd: "docker run … rspamd/rspamd",
		usedBy: ["spam"],
		notes: "No brew formula (MacPorts stale) — run via Docker.",
	}),
	copyOnly({
		id: "opendkim",
		binaries: ["opendkim-testkey"],
		category: "dkim",
		cmd: "sudo apt install opendkim-tools  # macOS: MacPorts",
		usedBy: ["dkim"],
		notes:
			"Not on brew — Linux apt / macOS MacPorts. Optional second opinion; dig+openssl cover DKIM keys.",
	}),
	copyOnly({
		id: "opendmarc",
		binaries: ["opendmarc-check"],
		category: "dmarc",
		cmd: "sudo apt install opendmarc  # macOS: build from source",
		usedBy: ["dmarc"],
		notes: "Not on brew — Linux apt / macOS source.",
	}),
	copyOnly({
		id: "rblcheck",
		binaries: ["rblcheck"],
		category: "blacklist",
		cmd: "sudo apt install rblcheck  # macOS: build logic/rblcheck",
		usedBy: ["blacklist"],
		notes:
			"Not on brew. Optional — DNSBL is a reverse-IP lookup via dig/doggo/dnsx.",
	}),
	pipx({
		id: "dkimpy",
		binaries: ["dkimverify", "dknewkey"],
		category: "dkim",
		pkg: "dkimpy",
		usedBy: ["dkim"],
	}),
	pipx({
		id: "oletools",
		binaries: ["olevba"],
		category: "spam",
		pkg: "oletools",
		usedBy: ["spam"],
	}),
	pipx({
		id: "sslyze",
		binaries: ["sslyze"],
		category: "tls",
		pkg: "sslyze",
		usedBy: ["tls"],
	}),
	copyOnly({
		id: "zonemaster-cli",
		binaries: ["zonemaster-cli"],
		category: "dns",
		cmd: "cpanm Zonemaster::CLI  # or Docker",
		usedBy: ["dns"],
		notes:
			"Perl/CPAN or Docker — gold-standard delegation auditor; mirrored natively already.",
	}),
];

/** A row that needs root/Docker — copy-only, never batch-installed (pm/install_brew.mdx §6.4). */
function copyOnly(e: {
	id: string;
	binaries: string[];
	category: ToolCatalogEntry["category"];
	cmd: string;
	usedBy: ToolCatalogEntry["usedBy"];
	notes?: string;
}): ToolCatalogEntry {
	return {
		id: e.id,
		manager: "special",
		category: e.category,
		tier: "extended",
		label: e.binaries.join("  "),
		summary: e.notes ?? "",
		binaries: e.binaries,
		detect: "binary",
		install: "copy",
		installCmd: e.cmd,
		autoInstallable: false,
		usedBy: e.usedBy,
		notes: e.notes,
	};
}

/** A pipx tool — auto-installable when `pipx` is present, else the service downgrades it to copy. */
function pipx(e: {
	id: string;
	binaries: string[];
	category: ToolCatalogEntry["category"];
	pkg: string;
	usedBy: ToolCatalogEntry["usedBy"];
}): ToolCatalogEntry {
	return {
		id: e.id,
		manager: "special",
		category: e.category,
		tier: "extended",
		label: e.binaries.join("  "),
		summary: `Installs via pipx (${e.pkg}).`,
		binaries: e.binaries,
		pkg: e.pkg,
		detect: "binary",
		install: "pipx",
		installCmd: `pipx install ${e.pkg}`,
		spawns: [{ file: "pipx", args: ["install", e.pkg] }],
		autoInstallable: true,
		usedBy: e.usedBy,
		notes: "Requires pipx; if absent, copy the command.",
	};
}
